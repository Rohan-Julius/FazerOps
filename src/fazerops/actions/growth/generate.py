"""W42 — candidate generation, the corpus-replay gate, and the PR bundle.

`docs/catalog_self_extension.md` §2a, §7a and §8.

A mined gap becomes a catalog candidate by the **cheapest rung that can express it**, tried in
order, because each rung carries strictly more trust surface than the one before:

1. **Widen an existing parameter.** The agent may only *select* a widening from `WIDENINGS`, a
   human-authored table of widenings the hand-written executor, inverse, dry run and
   preconditions already support. The PR changes the action's `params` block and nothing else,
   and CI rejects any agent change to an existing entry that is not exactly a declared widening.
2. **A declarative `actions.yaml` entry** over a registered, human-authored writer (W41's
   interpreter), filled from the gap's enums and the writer's own declaration.
3. **A generated writer**, only when no registered writer can express the gap. `generate`
   reports `writer_authoring_required`; `growth/authoring.py` does the authoring, because it is
   the one rung that calls a model.

**Rungs 1 and 2 call no model.** Selecting from a table and filling a form from a typed
aggregate are deterministic, and a model there would add an injection surface for nothing.

**What the agent never writes** (§7.7, §8): a tier, an approver, an executor, a dry run, an
inverse, preconditions or IAM permissions. A generated entry has no `tier:` line and does not
load until a human declares one; it carries `provisional: true`, which W45 reads.

**The correctness gate is the corpus replay** (§7a), identical for every rung: the candidate is
replayed in dry run against every remediation a human performed after the gap, comparing what
it would write (`inverse.writes`) to what the human wrote. Any disagreement — or no corpus at
all — blocks the bundle, and `emit_pr_bundle` refuses anything else.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from contextlib import nullcontext
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ...models import NormalizedAction
from .miner import Gap, GapAggregate, IneligibleReason, MinerThresholds, mine
from .signals import FieldPath, GapKey, GapSignalStore, ResourceKind, SignalKind

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...ledger.store import LedgerStore
    from ..catalog import ActionSpec, Catalog
    from ..writers.registry import WriterRegistry, WriterSpec

__all__ = [
    "AGENT_MAY_NOT_AUTHOR",
    "CatalogCandidate",
    "CorpusDisagreement",
    "GenerationResult",
    "MismatchReason",
    "NotEligible",
    "ReplayReport",
    "ReplayResult",
    "RungOutcome",
    "RungReason",
    "WIDENINGS",
    "Widening",
    "apply_params",
    "authorable",
    "candidate_id_for",
    "emit_pr_bundle",
    "evaluation_catalog",
    "generate",
    "params_of",
    "render_entry",
    "replay_corpus",
]

AGENT_MAY_NOT_AUTHOR = frozenset(
    {"tier", "requires_approval_from", "executor", "dry_run", "inverse", "preconditions", "iam_actions"}
)

# An entry cannot load without a tier, and replay has to load it. The most restrictive tier is
# used, and it lives only in the in-memory evaluation catalog.
_EVALUATION_TIER = {"tier": 2, "requires_approval_from": "manager"}


# --------------------------------------------------------------------------------------
# Rung 1 — declared widenings
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Widening:
    """One widening the hand-written code already supports, for one change class."""

    action_id: str
    source: str
    resource_kind: ResourceKind
    verb: NormalizedAction
    field_path: FieldPath
    adds: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    relaxes: tuple[str, ...] = ()

    def fits(self, key: GapKey) -> bool:
        return (key.source, key.resource_kind, key.verb, key.field_path) == (
            self.source,
            self.resource_kind,
            self.verb,
            self.field_path,
        )

    def apply(self, params: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
        widened = {name: dict(spec) for name, spec in params.items()}
        for name in self.relaxes:
            widened[name]["required"] = False
        for name, spec in self.adds.items():
            widened[name] = dict(spec)
        return widened

    def applied_to(self, params: Mapping[str, Any]) -> bool:
        return all(name in params for name in self.adds)


# **The agent selects from this table and never adds to it.** Each entry is a promise that the
# human-written code already handles the widened form, so merging the PR changes what the
# catalog *declares* and nothing that executes:
#
# `revert_configmap_key` gains `keys: list[str]` — every key a multi-key edit changed, restored
# together — and relaxes `key` and `target_value` to optional so the single-key form still
# validates. Supported, and tested in `tests/unit/test_widening.py`, by `inverse.recorded_keys`
# (shared by the forward builder, the inverse, the dry run, `prior_value_known` and the
# executor), which takes target values only from the collector's recorded hint and refuses a
# key set other than exactly the recorded one or a different ConfigMap. The audit collector
# already records multi-key hints; until this widening is merged the schema rejects them.
WIDENINGS: tuple[Widening, ...] = (
    Widening(
        action_id="revert_configmap_key",
        source="k8s_audit",
        resource_kind=ResourceKind.CONFIGMAP,
        verb=NormalizedAction.UPDATE,
        field_path=FieldPath.DATA,
        adds={"keys": {"type": "list[str]", "required": False}},
        relaxes=("key", "target_value"),
    ),
)


def params_of(action: ActionSpec) -> dict[str, dict[str, Any]]:
    """An action's params as the plain mappings `actions.yaml` holds."""
    return {name: _param(spec.model_dump()) for name, spec in action.params.items()}


def _param(spec: Mapping[str, Any]) -> dict[str, Any]:
    normal = {"type": spec.get("type"), "required": spec.get("required", True)}
    if spec.get("enum") is not None:
        normal["enum"] = list(spec["enum"])
    return normal


def apply_params(actions_text: str, action_id: str, params: Mapping[str, Mapping[str, Any]]) -> str:
    """Replace one entry's `params:` block in `actions.yaml` text, leaving every other line —
    comments included — exactly as it was. The reviewer's diff is the params block and only it.
    """
    lines = actions_text.splitlines(keepends=True)
    start = next(
        (i for i, line in enumerate(lines) if line.rstrip() == f"  - id: {action_id}"), None
    )
    if start is None:
        raise ValueError(f"{action_id} is not an entry in this catalog")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("  - id:")), len(lines))
    header = next((i for i in range(start, end) if lines[i].rstrip() == "    params:"), None)
    if header is None:
        raise ValueError(f"{action_id} has no block-style `params:` to rewrite")

    body_end = header + 1
    while body_end < end and lines[body_end].startswith("      "):
        body_end += 1

    block = [f"      {name}: {_flow(_param(spec))}\n" for name, spec in params.items()]
    return "".join(lines[: header + 1] + block + lines[body_end:])


def _flow(spec: Mapping[str, Any]) -> str:
    return "{" + ", ".join(f"{key}: {_flow_value(value)}" for key, value in spec.items()) + "}"


def _flow_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + ", ".join(_flow_value(item) for item in value) + "]"
    text = str(value)
    return f'"{text}"' if any(char in text for char in "[]{},:#") else text


# --------------------------------------------------------------------------------------
# Rung 3's contract — which gaps a writer could be authored for at all
# --------------------------------------------------------------------------------------


def authorable(key: GapKey) -> bool:
    """A generated writer has a contract only for a namespaced map whose values a collector
    records and that can be restored — a ConfigMap's `data` or `binaryData`. A Secret's recorded
    values are redactions, so nothing could be restored and nothing is authored for it. See
    `writers/k8s_support.py`."""
    from ..writers.k8s_support import has_contract

    return (
        key.source == "k8s_audit"
        and key.verb is NormalizedAction.UPDATE
        and has_contract(key.resource_kind.value, key.field_path.value)
    )


# --------------------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------------------


class RungReason(str, Enum):
    GENERATED = "generated"
    NO_SUPPORTED_WIDENING = "no_supported_widening"
    NO_REGISTERED_WRITER = "no_registered_writer"
    ALREADY_IN_CATALOG = "already_in_catalog"
    ID_TAKEN = "id_taken"
    WRITER_AUTHORING_REQUIRED = "writer_authoring_required"
    NO_AUTHORABLE_CONTRACT = "no_authorable_contract"
    WRITER_REJECTED = "writer_rejected"


class RungOutcome(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    rung: int = Field(ge=1, le=3)
    reason: RungReason


class CatalogCandidate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: str
    gap: GapAggregate
    rung: int = Field(ge=1, le=3)
    writer: str | None = None
    entry: dict[str, Any]
    cited_event_ids: tuple[str, ...]
    rungs: tuple[RungOutcome, ...]
    # Rung 3 only: the generated module, where it goes, and which model wrote it.
    module_path: str | None = None
    module_source: str | None = None
    authored_by_model: str | None = None

    @property
    def action_id(self) -> str:
        return self.entry["id"]

    @property
    def key(self) -> GapKey:
        return self.gap.key


class GenerationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    key: GapKey
    rungs: tuple[RungOutcome, ...]
    candidate: CatalogCandidate | None = None
    # Why rung 3 rejected an authored writer, in the validator's own words.
    problems: tuple[str, ...] = ()


class NotEligible(ValueError):
    """The gap does not clear the miner's thresholds — re-checked here, not trusted."""


def candidate_id_for(key: GapKey) -> str:
    """Deterministic, so regenerating the same gap names the same candidate and bundle."""
    return "gap-" + hashlib.sha256(key.model_dump_json().encode("utf-8")).hexdigest()[:12]


def generate(
    gap: Gap,
    store: GapSignalStore,
    *,
    catalog: Catalog | None = None,
    registry: WriterRegistry | None = None,
    thresholds: MinerThresholds | None = None,
    widenings: tuple[Widening, ...] = WIDENINGS,
) -> GenerationResult:
    """The cheapest deterministic rung that expresses `gap`, or a record of why none did."""
    from ..catalog import default_catalog
    from ..writers.registry import default_registry

    require_eligible(gap, thresholds)
    catalog = catalog if catalog is not None else default_catalog()
    registry = registry if registry is not None else default_registry()
    key = gap.key

    if _closed(catalog, registry, key, widenings):
        return GenerationResult(key=key, rungs=(RungOutcome(rung=1, reason=RungReason.ALREADY_IN_CATALOG),))

    widening = next((w for w in widenings if w.fits(key) and w.action_id in catalog), None)
    if widening is not None:
        base = catalog.get(widening.action_id)
        rungs = (RungOutcome(rung=1, reason=RungReason.GENERATED),)
        return GenerationResult(
            key=key,
            rungs=rungs,
            candidate=CatalogCandidate(
                candidate_id=candidate_id_for(key),
                gap=gap.aggregate,
                rung=1,
                entry={"id": base.id, "params": widening.apply(params_of(base))},
                cited_event_ids=cited(store, key),
                rungs=rungs,
            ),
        )

    rungs = [RungOutcome(rung=1, reason=RungReason.NO_SUPPORTED_WIDENING)]

    writer = next((w for w in registry if _writer_fits(w, key)), None)
    if writer is None:
        rungs.append(RungOutcome(rung=2, reason=RungReason.NO_REGISTERED_WRITER))
        rungs.append(
            RungOutcome(
                rung=3,
                reason=RungReason.WRITER_AUTHORING_REQUIRED
                if authorable(key)
                else RungReason.NO_AUTHORABLE_CONTRACT,
            )
        )
        return GenerationResult(key=key, rungs=tuple(rungs))

    action_id = writer_action_id(key)
    if action_id in catalog:
        rungs.append(RungOutcome(rung=2, reason=RungReason.ID_TAKEN))
        return GenerationResult(key=key, rungs=tuple(rungs))

    rungs.append(RungOutcome(rung=2, reason=RungReason.GENERATED))
    return GenerationResult(
        key=key,
        rungs=tuple(rungs),
        candidate=CatalogCandidate(
            candidate_id=candidate_id_for(key),
            gap=gap.aggregate,
            rung=2,
            writer=writer.id,
            entry=writer_entry(key, writer.id, writer.ref_params),
            cited_event_ids=cited(store, key),
            rungs=tuple(rungs),
        ),
    )


def require_eligible(gap: Gap, thresholds: MinerThresholds | None = None) -> None:
    """The eligibility verdict is recomputed from the aggregate. A `Gap` is a plain model, and
    one constructed with `eligible=True` by hand must not be how a threshold is skipped."""
    if not isinstance(gap, Gap):
        raise TypeError(f"generation consumes a mined Gap, got {type(gap).__name__}")
    [verdict] = mine([gap.aggregate], thresholds)
    if not verdict.eligible:
        reasons = ", ".join(reason.value for reason in verdict.reasons)
        raise NotEligible(f"{candidate_id_for(gap.key)} is not eligible for generation: {reasons}")


def writer_action_id(key: GapKey) -> str:
    return f"revert_{key.resource_kind.value.lower()}_{key.field_path.value}"


def writer_entry(key: GapKey, writer_id: str, ref_params: tuple[str, ...]) -> dict[str, Any]:
    """A declarative entry over a writer — rung 2's, and rung 3's once its writer exists."""
    return {
        "id": writer_action_id(key),
        "description": (
            f"Restore the recorded {key.field_path.value} of a "
            f"{key.resource_kind.value} changed out of band"
        ),
        "writer": writer_id,
        "provisional": True,
        "params": {name: {"type": "str", "required": True} for name in ref_params},
    }


def _closed(catalog: Catalog, registry: WriterRegistry, key: GapKey, widenings: tuple[Widening, ...]) -> bool:
    """Is this change class already expressible? A merged widening, or a live writer-backed
    action whose writer fits, closes it — and a closed gap generates nothing at any rung."""
    for widening in widenings:
        if widening.fits(key) and widening.action_id in catalog:
            if widening.applied_to(catalog.get(widening.action_id).params):
                return True
    for action in catalog:
        if action.retired or action.writer is None or action.writer not in registry:
            continue
        if _writer_fits(registry.get(action.writer), key):
            return True
    return False


def _writer_fits(writer: WriterSpec, key: GapKey) -> bool:
    # Update only: a revert restores values on a resource that still exists.
    return (
        key.verb is NormalizedAction.UPDATE
        and writer.source == key.source
        and writer.kind == key.resource_kind.value
        and writer.field_path == key.field_path.value
    )


def cited(store: GapSignalStore, key: GapKey) -> tuple[str, ...]:
    """The changes that motivated the gap, and the remediations that demonstrate its fix."""
    ids = {
        signal.event_id
        for signal in store.signals()
        if signal.key == key and signal.incident_id is not None and signal.kind is not SignalKind.EXECUTED
    }
    ids |= {demonstration.remediation_event_id for demonstration in store.demonstrations(key)}
    return tuple(sorted(ids))


# --------------------------------------------------------------------------------------
# The correctness gate — §7a
# --------------------------------------------------------------------------------------


class MismatchReason(str, Enum):
    ANCHOR_NOT_IN_LEDGER = "anchor_not_in_ledger"
    # W46: a demonstration is evidence only while the ledger still holds the human change it
    # describes, exactly as recorded. A line added to the corpus file by hand is not one.
    DEMONSTRATION_NOT_IN_LEDGER = "demonstration_not_in_ledger"
    NOT_REVERTIBLE_BY_CANDIDATE = "not_revertible_by_candidate"
    DIFFERENT_RESOURCE = "different_resource"
    CHANGES_MORE_THAN_THE_HUMAN = "changes_more_than_the_human"
    CHANGES_LESS_THAN_THE_HUMAN = "changes_less_than_the_human"
    DIFFERENT_VALUE = "different_value"
    DRY_RUN_INCONSISTENT = "dry_run_inconsistent"


class ReplayResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    demonstration_id: str
    agreed: bool
    reason: MismatchReason | None = None


class Corroboration(BaseModel):
    """The gap recounted from signals the ledger vouches for (W46).

    The signal store is a file, and `generate` recomputes eligibility from the counts a `Gap`
    carries. Neither is evidence on its own: a forged line in the store, or a `Gap` built with
    inflated counts, would clear the thresholds without a single change behind it. So replay
    counts again, keeping only signals whose change the ledger holds with the same structure and
    actor, and the thresholds must still clear.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    signals: int
    uncorroborated: int
    eligible: bool
    reasons: tuple[IneligibleReason, ...] = ()


class ReplayReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: str
    results: tuple[ReplayResult, ...]
    corroboration: Corroboration | None = None

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def agreed(self) -> int:
        return sum(result.agreed for result in self.results)

    @property
    def passed(self) -> bool:
        """No corpus is not a pass: an argument from zero cases is not one. Nor is a gap the
        ledger does not vouch for, however well the candidate agrees with its corpus."""
        corroborated = self.corroboration is not None and self.corroboration.eligible
        return corroborated and self.total > 0 and self.agreed == self.total


class CorpusDisagreement(RuntimeError):
    def __init__(self, report: ReplayReport) -> None:
        corroboration = report.corroboration
        if corroboration is None or not corroboration.eligible:
            reasons = ", ".join(reason.value for reason in (corroboration.reasons if corroboration else ()))
            detail = f"the ledger does not vouch for this gap ({reasons or 'not checked'})"
        elif report.total == 0:
            detail = "there is no recorded human remediation to replay against"
        else:
            reasons = ", ".join(sorted({r.reason.value for r in report.results if r.reason is not None}))
            detail = f"{report.total - report.agreed} of {report.total} disagreed ({reasons})"
        super().__init__(f"{report.candidate_id}: corpus replay blocks this PR — {detail}")
        self.report = report


def corroborate(
    key: GapKey, store: GapSignalStore, ledger: LedgerStore, thresholds: MinerThresholds | None = None
) -> Corroboration:
    from .miner import aggregate
    from .signals import signal_for

    signals = [signal for signal in store.signals() if signal.key == key]
    vouched = []
    for signal in signals:
        event = ledger.get(signal.event_id)
        if event is None:
            continue
        recomputed = signal_for(
            signal.kind,
            event,
            observed_at=signal.observed_at,
            incident_id=signal.incident_id,
            action_id=signal.action_id,
        )
        if recomputed == signal:
            vouched.append(signal)

    rows = [row for row in aggregate(vouched) if row.key == key]
    if not rows:
        verdict = Gap(aggregate=GapAggregate(**key.model_dump()), eligible=False)
        reasons = tuple(mine([verdict.aggregate], thresholds)[0].reasons)
        return Corroboration(signals=0, uncorroborated=len(signals), eligible=False, reasons=reasons)
    [gap] = mine(rows, thresholds)
    return Corroboration(
        signals=len(vouched),
        uncorroborated=len(signals) - len(vouched),
        eligible=gap.eligible,
        reasons=gap.reasons,
    )


def _demonstration_holds(demonstration: Any, anchor: Any, ledger: LedgerStore) -> bool:
    """The remediation is in the ledger, by a human, on the anchor's resource, with exactly the
    before and after the corpus claims — `find_remediations`' own rules, re-applied."""
    from .signals import prior_value_recorded

    later = ledger.get(demonstration.remediation_event_id)
    if later is None or later.id == anchor.id or later.diff is None:
        return False
    if later.actor.kind != "human" or not prior_value_recorded(later):
        return False
    if later.resource.blast_radius_key() != anchor.resource.blast_radius_key():
        return False
    if later.resource != demonstration.resource:
        return False
    fields = later.diff.fields_changed
    before = {name: (later.diff.before or {}).get(name) for name in fields}
    after = {name: (later.diff.after or {}).get(name) for name in fields}
    return before == demonstration.before and after == demonstration.after


def evaluation_catalog(candidate: CatalogCandidate, catalog: Catalog | None = None) -> Catalog:
    """The shipped catalog with the candidate applied. In memory only."""
    from ..catalog import ActionSpec, Catalog, ParamSpec, default_catalog

    base = catalog if catalog is not None else default_catalog()
    if candidate.rung == 1:
        widened = base.get(candidate.action_id).model_copy(
            update={
                "params": {
                    name: ParamSpec.model_validate(spec) for name, spec in candidate.entry["params"].items()
                }
            }
        )
        return Catalog([widened if a.id == widened.id else a for a in base], base.thresholds)

    spec = ActionSpec.model_validate({**candidate.entry, **_EVALUATION_TIER})
    return Catalog([*base, spec], base.thresholds)


def replay_corpus(
    candidate: CatalogCandidate,
    store: GapSignalStore,
    ledger: LedgerStore,
    *,
    catalog: Catalog | None = None,
    registry: WriterRegistry | None = None,
    thresholds: MinerThresholds | None = None,
) -> ReplayReport:
    """Replay the candidate in dry run against every recorded remediation of its gap.

    Agreement is strict: the candidate must write **exactly** the fields the human changed, to
    **exactly** the values the human set, on the same resource.

    Rung 3's generated writer is never loaded here. A dry run and an inverse never call a
    writer, so replay evaluates against a stand-in spec from `writers/k8s_support.py` whose
    `read` and `write` refuse to run.
    """
    from ..catalog import UnknownAction, ValidationRejected
    from ..inverse import ActionRequest, request_from_hint, writes
    from ..writers.registry import hint_for, registry_override

    evaluation = evaluation_catalog(candidate, catalog)
    spec = evaluation.get(candidate.action_id)
    override = (
        registry_override(evaluation_registry(candidate, registry))
        if candidate.rung == 3
        else nullcontext()
    )
    results: list[ReplayResult] = []

    with override:
        for demonstration in store.demonstrations(candidate.key):
            def verdict(reason: MismatchReason | None) -> ReplayResult:
                return ReplayResult(
                    demonstration_id=demonstration.id, agreed=reason is None, reason=reason
                )

            anchor = ledger.get(demonstration.anchor_event_id)
            if anchor is None:
                results.append(verdict(MismatchReason.ANCHOR_NOT_IN_LEDGER))
                continue
            if not _demonstration_holds(demonstration, anchor, ledger):
                results.append(verdict(MismatchReason.DEMONSTRATION_NOT_IN_LEDGER))
                continue

            request = None
            if candidate.rung == 1:
                request = request_from_hint(anchor.inverse_hint, catalog=evaluation)
                if request is not None and request.action_id != spec.id:
                    request = None
            else:
                hint = hint_for(anchor, spec)
                if hint is not None:
                    try:
                        request = ActionRequest.for_action(
                            spec.id, hint["ref"], inverse_hint=hint, catalog=evaluation
                        )
                    except (UnknownAction, ValidationRejected):
                        request = None

            written = None if request is None else writes(request, catalog=evaluation)
            if written is None or request.inverse(catalog=evaluation) is None:
                results.append(verdict(MismatchReason.NOT_REVERTIBLE_BY_CANDIDATE))
                continue

            target, proposed = written
            if target.blast_radius_key() != demonstration.resource.blast_radius_key():
                results.append(verdict(MismatchReason.DIFFERENT_RESOURCE))
                continue

            # The card an approver would read, compared on its field list: the renderer masks
            # sensitive values, and a masked comparison would pass for any two secrets.
            dry = request.dry_run(catalog=evaluation)
            if [line.field for line in dry.lines] != sorted(proposed):
                results.append(verdict(MismatchReason.DRY_RUN_INCONSISTENT))
                continue

            performed = demonstration.after
            if set(proposed) - set(performed):
                results.append(verdict(MismatchReason.CHANGES_MORE_THAN_THE_HUMAN))
            elif set(performed) - set(proposed):
                results.append(verdict(MismatchReason.CHANGES_LESS_THAN_THE_HUMAN))
            elif any(not _same(proposed[f], performed[f]) for f in proposed):
                results.append(verdict(MismatchReason.DIFFERENT_VALUE))
            else:
                results.append(verdict(None))

    return ReplayReport(
        candidate_id=candidate.candidate_id,
        results=tuple(results),
        corroboration=corroborate(candidate.key, store, ledger, thresholds),
    )


def evaluation_registry(candidate: CatalogCandidate, registry: WriterRegistry | None = None) -> WriterRegistry:
    from ..writers.k8s_support import stand_in_writer
    from ..writers.registry import WriterRegistry, default_registry

    base = registry if registry is not None else default_registry()
    stand_in = stand_in_writer(candidate.gap.resource_kind.value, candidate.gap.field_path.value)
    return WriterRegistry([*(w for w in base if w.id != candidate.writer), stand_in])


def _same(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is None and b is None  # an absent key restored is a deleted key
    return str(a) == str(b)


# --------------------------------------------------------------------------------------
# The PR bundle
# --------------------------------------------------------------------------------------


def render_entry(candidate: CatalogCandidate) -> str:
    """The catalog text a bundle carries, indented to sit under `actions:`."""
    offending = set(candidate.entry) & AGENT_MAY_NOT_AUTHOR
    if offending:
        raise ValueError(f"a generated entry may not carry {sorted(offending)} (§7.7)")

    body = yaml.safe_dump([candidate.entry], sort_keys=False, default_flow_style=False)
    if candidate.rung == 1:
        header = [
            f"# Widening of {candidate.action_id} (W42 rung 1) from {candidate.candidate_id}.",
            "# Replaces this entry's `params:` block. Nothing else in the entry changes.",
        ]
    else:
        header = [
            f"# Generated by FazerOps catalog growth (W42, rung {candidate.rung}) from {candidate.candidate_id}.",
            "# tier: <the reviewer declares this — generation never authors a tier (§7.7).",
            "#        This entry does not load until it is set.>",
        ]
    return "\n".join(f"  {line}" for line in [*header, *body.rstrip("\n").splitlines()]) + "\n"


_RUNG_NAMES = {1: "widen an existing parameter", 2: "declarative catalog entry", 3: "generated writer"}


def _what(candidate: CatalogCandidate) -> str:
    if candidate.rung == 1:
        params = candidate.entry["params"]
        return (
            f"**Rung 1** — widens `{candidate.action_id}`. Its `params:` block becomes:\n\n"
            + "\n".join(f"- `{name}`: `{_flow(spec)}`" for name, spec in params.items())
            + "\n\nThe executor, inverse, dry run and preconditions already support the widened "
            "form (human-written); this PR changes only what the catalog declares. No code was "
            "generated."
        )
    if candidate.rung == 2:
        return (
            f"**Rung 2** — a declarative entry over the human-authored `{candidate.writer}` "
            "writer. No code was generated."
        )
    return (
        f"**Rung 3** — a declarative entry over a **generated** `{candidate.writer}` writer, "
        f"written by `{candidate.authored_by_model}` into `{candidate.module_path}`. It passed "
        "the AST allowlist and the sandboxed probe; **read it** — the inverse, the dry run and "
        "the credential gate are human-written and it touches none of them.\n\n"
        f"```python\n{candidate.module_source}```"
    )


def _reviewer_must_set(candidate: CatalogCandidate) -> list[str]:
    if candidate.rung == 1:
        return []
    must = ["tier", "requires_approval_from", "credentials._ACTIONS_FOR"]
    if candidate.rung == 3:
        must.append("writers.registry.WRITER_MODULES")
    return must


def render_pr_body(
    candidate: CatalogCandidate, report: ReplayReport, containment: Mapping[str, Any] | None = None
) -> str:
    """Counts, enums, ledger ids and our own text only — never a value or key name from the
    ledger, both attacker-writable (§7.1, §10a). A rung-3 body shows the generated module,
    whose only input was enum-derived contract data."""
    gap = candidate.gap
    rungs = "\n".join(
        f"{outcome.rung}. {_RUNG_NAMES[outcome.rung]} — `{outcome.reason.value}`"
        for outcome in candidate.rungs
    )
    evidence = ", ".join(f"`{event_id}`" for event_id in candidate.cited_event_ids)
    checklist = {
        "tier": "- [ ] `tier:` — the entry does not load until it is declared",
        "requires_approval_from": "- [ ] `requires_approval_from: manager`, if tier 2",
        "credentials._ACTIONS_FOR": (
            "- [ ] the action's AWS permissions in `credentials._ACTIONS_FOR` — omitted, it is "
            "granted nothing. CI rejects agent-authored commits that touch it."
        ),
        "writers.registry.WRITER_MODULES": (
            "- [ ] add the module to `writers.registry.WRITER_MODULES` — until then the writer is "
            "not loadable. CI rejects agent-authored commits that touch it."
        ),
    }
    must = _reviewer_must_set(candidate)
    review = (
        "\n".join(checklist[item] for item in must)
        if must
        else "Nothing to declare: the entry's tier and permissions are unchanged."
    )
    lifecycle = (
        "\nMerged, this action is **provisional**: every execution needs a manager approval and "
        "the card says it was generated, until it graduates (W45).\n"
        if candidate.rung != 1
        else ""
    )
    containment = containment or {"required": False, "why": "not checked"}
    corroborated = report.corroboration.signals if report.corroboration else 0
    if containment.get("required"):
        sandbox = (
            f"Run in a sandbox against a clone of the resource and watched through the audit log: "
            f"**{containment['verdict']}** — it mutated nothing but its declared resource and left it "
            "holding exactly the values it was given (W43). Containment, not production safety."
        )
    else:
        sandbox = f"Not run — {containment['why']}."

    return f"""# Proposed catalog change: `{candidate.action_id}`

Generated by FazerOps catalog growth (Phase G, W42) from `{candidate.candidate_id}`.

{_what(candidate)}

## Why

| | |
|---|---|
| Change class | `{gap.source}` · `{gap.resource_kind.value}` · `{gap.verb.value}` · `{gap.field_path.value}` |
| Distinct incidents | {gap.incident_count} |
| Distinct actors behind the changes | {gap.distinct_actors} |
| Declines · rejections · executions | {gap.decline_count} · {gap.rejected_count} · {gap.executed_count} |
| Human remediations observed | {gap.remediation_count} |

## Correctness gate — corpus replay

Replayed in dry run against **{report.total}** recorded human remediation(s):
**{report.agreed} agreed, {report.total - report.agreed} disagreed.** The gap was recounted from
{corroborated} signal(s) the ledger vouches for, and still clears the thresholds.

## Containment

{sandbox}

## Rungs tried, in order

{rungs}

## Evidence

CI rejects this PR if any cited ledger event does not resolve: {evidence}

## The reviewer sets these — generation never does (§7.7)

{review}
{lifecycle}"""


class ContainmentRequired(RuntimeError):
    """A generated writer with an `observed` recipe reaches a PR only after a sandbox contained it."""


def containment_status(candidate: CatalogCandidate, containment: Any | None) -> dict[str, Any]:
    """What §8's `sandbox containment check [k8s only; else straight to PR]` concluded, or raise.

    Only rung 3 generates code, so only rung 3 is checked. Where a recipe is `observed` the check
    is required and must have passed for this candidate's writer; where it is `delayed` or `none`
    the design sends the candidate straight to the PR, and the bundle says that it did.
    """
    from .sandbox import RecipeClass, recipe_for

    if candidate.rung != 3:
        return {"required": False, "why": "no code was generated"}

    recipe = recipe_for(f"k8s/{candidate.gap.resource_kind.value}")
    if recipe.recipe_class is not RecipeClass.OBSERVED:
        return {"required": False, "why": f"recipe is {recipe.recipe_class.value}: {recipe.why}"}
    if containment is None:
        raise ContainmentRequired(f"{candidate.candidate_id}: a generated writer with an observed recipe needs a containment run")
    if containment.writer_id != candidate.writer or containment.authored_by != "agent":
        raise ContainmentRequired(f"{candidate.candidate_id}: the containment report is for {containment.writer_id}, not this writer")
    if not containment.contained:
        raise ContainmentRequired(f"{candidate.candidate_id}: not contained ({containment.verdict.value}: {containment.detail})")
    return {
        "required": True,
        "verdict": containment.verdict.value,
        "recipe_class": recipe.recipe_class.value,
        "runs": containment.runs,
    }


def emit_pr_bundle(
    candidate: CatalogCandidate, report: ReplayReport, out_dir: Path | str, *, containment: Any | None = None
) -> Path:
    """Write the bundle a PR is opened from. **Refuses unless replay passed** for this candidate,
    and — for a generated writer with an observed recipe — unless a sandbox contained it (W43).
    Local files only; opening the PR on a forge is outward-facing and is not done here."""
    if report.candidate_id != candidate.candidate_id:
        raise ValueError(f"replay report is for {report.candidate_id}, not {candidate.candidate_id}")
    if not report.passed:
        raise CorpusDisagreement(report)
    contained = containment_status(candidate, containment)

    directory = Path(out_dir) / candidate.candidate_id
    directory.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "candidate_id": candidate.candidate_id,
        "authored_by": "agent",
        "rung": candidate.rung,
        "action_id": candidate.action_id,
        "writer": candidate.writer,
        "gap": json.loads(candidate.gap.model_dump_json()),
        "rungs": [json.loads(outcome.model_dump_json()) for outcome in candidate.rungs],
        "cited_event_ids": list(candidate.cited_event_ids),
        "replay": {
            "total": report.total,
            "agreed": report.agreed,
            "corroborated_signals": report.corroboration.signals if report.corroboration else 0,
        },
        "containment": contained,
        "reviewer_must_set": _reviewer_must_set(candidate),
    }
    if candidate.rung == 1:
        manifest["params"] = candidate.entry["params"]
    if candidate.rung == 3:
        manifest["module_path"] = candidate.module_path
        manifest["authored_by_model"] = candidate.authored_by_model
        (directory / "writer.py").write_text(candidate.module_source or "", encoding="utf-8")

    (directory / "catalog_entry.yaml").write_text(render_entry(candidate), encoding="utf-8")
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (directory / "PR.md").write_text(render_pr_body(candidate, report, contained), encoding="utf-8")
    return directory
