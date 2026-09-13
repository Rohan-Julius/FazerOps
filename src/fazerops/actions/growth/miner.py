"""W40 — the gap miner. `docs/catalog_self_extension.md` §2 and §7.1.

**This is the injection surface of Phase G**, and the design answers it with a type rather
than a filter. The ledger is built from attacker-influenceable data; a gap becomes a PR, and a
PR becomes a catalog entry. So:

* **`mine()` accepts `GapAggregate` and nothing else** — a frozen model of enums, integers and
  one boolean, with no string field for narrative to travel in. It refuses any other type at
  runtime, so the guarantee does not rest on a type checker nobody runs.
  `tests/security/test_miner_takes_no_free_text.py` asserts it against the model's JSON
  **schema**, not against a substring search.
* **A gap is eligible only across N distinct incidents and M distinct actors**, and neither
  threshold may be configured below two. One compromised identity writing one ConfigMap
  repeatedly produces a gap with one actor, however many incidents it drives.

`aggregate()` is the one place signals become counts. It reads identities in order to count
them — distinct incidents, distinct actors — and emits only the counts.

**Off the incident path.** `mine_history` is the continuous job: it scans the ledger per
service radius, pairs declines and rejections with the human remediation that followed,
persists both, and mines the result. Nothing here runs while an incident is open, and nothing
here calls a model.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ...models import ChangeSource, NormalizedAction, TimeWindow
from .signals import (
    ANCHOR_KINDS,
    FieldPath,
    GapKey,
    GapSignal,
    GapSignalStore,
    ResourceKind,
    SignalKind,
    find_remediations,
    ledger_signals,
    remediation_signal,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...ledger.store import LedgerStore
    from ...radius import ServiceManifest

__all__ = [
    "DEFAULT_CONFIG",
    "Gap",
    "GapAggregate",
    "IneligibleReason",
    "MinerThresholds",
    "aggregate",
    "load_thresholds",
    "mine",
    "mine_history",
]

DEFAULT_CONFIG = Path(__file__).resolve().parents[4] / "config" / "catalog_growth.yaml"


class MinerThresholds(BaseModel):
    """`config/catalog_growth.yaml`'s `miner:` block.

    The floor of two is in the schema rather than in the file's comments. A threshold of one
    is not a stricter or looser setting of the same control — it is the control switched off,
    and switching it off should be a code change someone reviews, not a YAML edit.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    min_incidents: int = Field(default=2, ge=2)
    min_distinct_actors: int = Field(default=2, ge=2)
    remediation_window_minutes: int = Field(default=60, ge=1, le=24 * 60)


def load_thresholds(path: Path | str | None = None) -> MinerThresholds:
    raw = yaml.safe_load(Path(path or DEFAULT_CONFIG).read_text(encoding="utf-8")) or {}
    return MinerThresholds.model_validate(raw.get("miner") or {})


class GapAggregate(BaseModel):
    """The miner's entire input: one change class, counted. §7.1's typed structural aggregate.

    **Add a field here only if its schema is an integer, a boolean or an enum.** The security
    test reads the JSON schema and fails on anything else, including an optional string.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: ChangeSource
    resource_kind: ResourceKind
    verb: NormalizedAction
    field_path: FieldPath

    decline_count: int = Field(default=0, ge=0)
    inverse_missing_count: int = Field(default=0, ge=0)
    unactionable_count: int = Field(default=0, ge=0)
    rejected_count: int = Field(default=0, ge=0)
    executed_count: int = Field(default=0, ge=0)
    remediation_count: int = Field(default=0, ge=0)
    incident_count: int = Field(default=0, ge=0)
    distinct_actors: int = Field(default=0, ge=0)
    prior_value_recorded: bool = False

    @property
    def key(self) -> GapKey:
        return GapKey(
            source=self.source,
            resource_kind=self.resource_kind,
            verb=self.verb,
            field_path=self.field_path,
        )


class IneligibleReason(str, Enum):
    UNKNOWN_RESOURCE_KIND = "unknown_resource_kind"
    UNKNOWN_FIELD_PATH = "unknown_field_path"
    NOT_REVERT_SHAPED = "not_revert_shaped"
    NO_GAP_SIGNAL = "no_gap_signal"
    BELOW_INCIDENT_THRESHOLD = "below_incident_threshold"
    BELOW_ACTOR_THRESHOLD = "below_actor_threshold"


class Gap(BaseModel):
    """A mined change class and the verdict on it. Reasons are enums for the same reason the
    aggregate's fields are: a gap report is what W42 reads, and it must carry no text."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    aggregate: GapAggregate
    eligible: bool
    reasons: tuple[IneligibleReason, ...] = ()

    @property
    def key(self) -> GapKey:
        return self.aggregate.key


def aggregate(signals: Iterable[GapSignal]) -> list[GapAggregate]:
    """Signals → one count row per change class."""
    groups: dict[GapKey, list[GapSignal]] = {}
    for signal in signals:
        groups.setdefault(signal.key, []).append(signal)

    rows: list[GapAggregate] = []
    for key, group in groups.items():
        counts = Counter(signal.kind for signal in group)
        # An execution is a use of the catalog, not evidence of a gap, so it cannot count
        # towards either threshold. Nor can a signal with no incident: history alone is a
        # change class, not an incident someone was paged for.
        attributed = [
            s for s in group if s.incident_id is not None and s.kind is not SignalKind.EXECUTED
        ]
        rows.append(
            GapAggregate(
                **key.model_dump(),
                decline_count=counts[SignalKind.DECLINE],
                inverse_missing_count=counts[SignalKind.INVERSE_MISSING],
                unactionable_count=counts[SignalKind.UNACTIONABLE],
                rejected_count=counts[SignalKind.REJECTED],
                executed_count=counts[SignalKind.EXECUTED],
                remediation_count=counts[SignalKind.HUMAN_REMEDIATION],
                incident_count=len({s.incident_id for s in attributed}),
                distinct_actors=len({s.actor for s in attributed}),
                prior_value_recorded=any(s.prior_value_recorded for s in group),
            )
        )

    rows.sort(key=_order)
    return rows


def mine(
    aggregates: Iterable[GapAggregate], thresholds: MinerThresholds | None = None
) -> list[Gap]:
    """Decide which change classes are gaps worth generating for. Eligible first."""
    thresholds = thresholds if thresholds is not None else load_thresholds()

    gaps: list[Gap] = []
    for row in aggregates:
        if not isinstance(row, GapAggregate):
            raise TypeError(
                f"the gap miner consumes GapAggregate only, got {type(row).__name__}; "
                "anything carrying text is an injection path into the catalog (§7.1)"
            )
        reasons = _ineligibility(row, thresholds)
        gaps.append(Gap(aggregate=row, eligible=not reasons, reasons=tuple(reasons)))

    gaps.sort(key=lambda gap: (not gap.eligible, -gap.aggregate.incident_count, _order(gap.aggregate)))
    return gaps


def mine_history(
    ledger: LedgerStore,
    store: GapSignalStore,
    window: TimeWindow,
    *,
    manifest: ServiceManifest | None = None,
    thresholds: MinerThresholds | None = None,
) -> list[Gap]:
    """The continuous job, over one window of history. Idempotent: re-running it records
    nothing new and returns the same gaps."""
    from ...radius import default_manifest

    manifest = manifest if manifest is not None else default_manifest()
    thresholds = thresholds if thresholds is not None else load_thresholds()

    for service in manifest.service_names:
        for signal in ledger_signals(ledger, manifest.resolve(service), window):
            store.record(signal)

    anchors = [s for s in store.signals() if s.kind in ANCHOR_KINDS]
    for anchor, demonstration in find_remediations(
        ledger, anchors, window_minutes=thresholds.remediation_window_minutes
    ):
        store.record_demonstration(demonstration)
        store.record(remediation_signal(anchor, demonstration))

    return mine(aggregate(store.signals()), thresholds)


def _ineligibility(row: GapAggregate, thresholds: MinerThresholds) -> list[IneligibleReason]:
    reasons: list[IneligibleReason] = []

    if row.resource_kind is ResourceKind.OTHER:
        reasons.append(IneligibleReason.UNKNOWN_RESOURCE_KIND)
    if row.field_path is FieldPath.UNKNOWN:
        reasons.append(IneligibleReason.UNKNOWN_FIELD_PATH)
    if not row.prior_value_recorded:
        # §1: revert-shaped only. With no observed prior state the inverse would have to be
        # authored, and an authored inverse from a generated component is refused outright.
        reasons.append(IneligibleReason.NOT_REVERT_SHAPED)

    # A rejection only indicates a gap when rejections outnumber executions — a catalog
    # action that is sometimes rejected and usually run is an action working as intended.
    indicated = (
        row.decline_count
        + row.inverse_missing_count
        + row.unactionable_count
        + row.remediation_count
        + max(0, row.rejected_count - row.executed_count)
    )
    if indicated == 0:
        reasons.append(IneligibleReason.NO_GAP_SIGNAL)

    if row.incident_count < thresholds.min_incidents:
        reasons.append(IneligibleReason.BELOW_INCIDENT_THRESHOLD)
    if row.distinct_actors < thresholds.min_distinct_actors:
        reasons.append(IneligibleReason.BELOW_ACTOR_THRESHOLD)

    return reasons


def _order(row: GapAggregate) -> tuple[str, str, str, str]:
    return (row.source, row.resource_kind.value, row.verb.value, row.field_path.value)
