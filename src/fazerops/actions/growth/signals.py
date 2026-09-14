"""W40 — gap signals and the demonstration corpus. `docs/catalog_self_extension.md` §2.

The catalog already knows, at five points, that it could not act on a change, and until W40
it threw every one of those facts away:

| Signal | Fires when |
|---|---|
| `decline` | the proposer answered `"none"` and the ranked #1 change has no catalog revert |
| `inverse_missing` | a change carries a hint, but no inverse can be built from it |
| `unactionable` | a change carries no hint at all — nothing in the catalog maps to it |
| `human_remediation` | a named human changed the same resource after a decline or rejection |
| `rejected` | a human clicked Reject on a catalog-valid proposal |

`executed` is recorded beside them as the denominator. A resource type with a high rejection
rate and a low execution rate is a gap the model papered over rather than declined (§2), and
a rate needs both halves. W45's graduation reads the same count.

**Every signal is typed, and none carries narrative.** A signal names a change by ledger id
and describes it by enums — source, resource kind, verb, field path. The alert summary, the
diff values and the proposal's rationale never enter it, so nothing a writable ConfigMap says
can reach the miner (§7.1). The one semi-structural field is the field path, and it names the
*map* (`data`), never a ConfigMap key: a key name is a string somebody wrote (§10a).

**The demonstration corpus is persisted, not counted.** W42's correctness gate replays a
candidate against what the human actually did, so `Demonstration` stores the resource and the
before and after values. A count would record that a remediation happened and leave nothing
to compare a candidate against.

**Nothing here decides from model output.** A decline is observed by Python after the
proposer's validator has already returned `None`, and it is read off the `Brief` — the
model's vocabulary is exactly as narrow as it was before W40 (§4).
"""

from __future__ import annotations

import fcntl
import json
import logging
from collections.abc import Callable, Iterable, Iterator
from datetime import timedelta
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from ...collectors.k8s_audit import REDACTED
from ...ledger.chain import truncate_torn_line
from ...ledger.normalize import FAZEROPS_CANONICAL
from ...models import (
    BlastRadius,
    Brief,
    ChangeEvent,
    ChangeSource,
    NormalizedAction,
    ResourceRef,
    TimeWindow,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...ledger.store import LedgerStore
    from ..approval import Outcome, PendingApproval

__all__ = [
    "ANCHOR_KINDS",
    "DEFAULT_SIGNALS_PATH",
    "Demonstration",
    "FieldPath",
    "GapKey",
    "GapSignal",
    "GapSignalStore",
    "ResourceKind",
    "SignalKind",
    "catalog_can_revert",
    "classify",
    "decline_signal",
    "field_path_of",
    "find_contesting_changes",
    "find_remediations",
    "ledger_signals",
    "outcome_observer",
    "prior_value_recorded",
    "record_decline",
    "remediation_signal",
    "signal_for",
]

logger = logging.getLogger(__name__)

DEFAULT_SIGNALS_PATH = Path(".fazerops") / "gap_signals.jsonl"


class SignalKind(str, Enum):
    DECLINE = "decline"
    INVERSE_MISSING = "inverse_missing"
    UNACTIONABLE = "unactionable"
    HUMAN_REMEDIATION = "human_remediation"
    REJECTED = "rejected"
    EXECUTED = "executed"


# What a human's later change is measured against. An execution is not an anchor here: a
# change after an execution is W45's negative graduation signal, not a demonstration of a gap.
ANCHOR_KINDS = frozenset({SignalKind.DECLINE, SignalKind.REJECTED})


class ResourceKind(str, Enum):
    """`ResourceRef.kind` as an enum, so the aggregate carries no string.

    Values are the exact spellings the collectors and `keys.py` produce. Anything else —
    a CRD whose plural the audit collector title-cased, an ARN's service segment — is
    `OTHER`, which the miner never makes eligible: a writer cannot be generated for a
    resource type nobody has named.
    """

    CONFIGMAP = "ConfigMap"
    SECRET = "Secret"
    DEPLOYMENT = "Deployment"
    STATEFULSET = "StatefulSet"
    DAEMONSET = "DaemonSet"
    CRONJOB = "CronJob"
    JOB = "Job"
    SERVICE = "Service"
    INGRESS = "Ingress"
    HELM_RELEASE = "HelmRelease"
    SECURITY_GROUP = "SecurityGroup"
    IAM_ROLE = "IAMRole"
    IAM_POLICY = "IAMPolicy"
    IAM_USER = "IAMUser"
    DB_PARAMETER_GROUP = "DBParameterGroup"
    DB_INSTANCE = "DBInstance"
    PARAMETER = "Parameter"
    FUNCTION = "Function"
    REPO = "Repo"
    OTHER = "other"

    @classmethod
    def of(cls, kind: str) -> ResourceKind:
        try:
            return cls(kind)
        except ValueError:
            return cls.OTHER


class FieldPath(str, Enum):
    """Which part of a resource changed, derived from the collector — never from a value.

    `DATA` is a ConfigMap's or Secret's free-form map, and it stops at the map. The key that
    changed inside it is attacker-controlled text (§10a), so a writer is generated for the
    map and the key reaches generation only as an opaque parameter. `BINARY_DATA` is a
    ConfigMap's second map, recorded with its prior value by the same collector.
    """

    DATA = "data"
    BINARY_DATA = "binaryData"
    REVISION = "revision"
    REQUEST = "request"
    UNKNOWN = "unknown"


class GapKey(BaseModel):
    """What a gap is *about*: one change class. Hashable, so it groups signals."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: ChangeSource
    resource_kind: ResourceKind
    verb: NormalizedAction
    field_path: FieldPath


class GapSignal(BaseModel):
    """One observation that the catalog could not act on a change.

    `actor` is the actor of the **change** — never of the human who later fixed it. The
    miner's actor-diversity threshold counts it, and counting remediators would let one
    compromised identity plus the on-call who cleaned up after it clear a two-actor bar.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: SignalKind
    incident_id: str | None = None
    event_id: str
    source: ChangeSource
    resource_kind: ResourceKind
    verb: NormalizedAction
    field_path: FieldPath
    actor: str
    prior_value_recorded: bool
    action_id: str | None = Field(
        default=None, description="The catalog action a rejection or execution was about."
    )
    observed_at: AwareDatetime

    @property
    def id(self) -> str:
        return "|".join(
            (self.kind.value, self.incident_id or "-", self.event_id, self.action_id or "-")
        )

    @property
    def key(self) -> GapKey:
        return GapKey(
            source=self.source,
            resource_kind=self.resource_kind,
            verb=self.verb,
            field_path=self.field_path,
        )


class Demonstration(BaseModel):
    """What a human did after we could not act. §2's fourth signal, kept whole.

    This carries values, which is exactly why the miner never reads it: it is the corpus
    W42 replays a candidate against, not an input to deciding whether a gap exists.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    key: GapKey
    incident_id: str
    anchor_event_id: str
    remediation_event_id: str
    resource: ResourceRef
    before: dict[str, object]
    after: dict[str, object]
    actor: str
    occurred_at: AwareDatetime
    lag_seconds: float = Field(ge=0)

    @property
    def id(self) -> str:
        return f"{self.incident_id}|{self.remediation_event_id}"


# --------------------------------------------------------------------------------------
# Describing a change structurally
# --------------------------------------------------------------------------------------


def field_path_of(event: ChangeEvent) -> FieldPath:
    if event.source == "helm":
        return FieldPath.REVISION
    if event.diff is None:
        return FieldPath.UNKNOWN
    if event.source == "k8s_audit":
        # The audit collector diffs one map per event: `binaryData` when it says so, else `data`.
        return FieldPath.BINARY_DATA if event.diff.field_path == "binaryData" else FieldPath.DATA
    if event.source == "cloudtrail":
        return FieldPath.REQUEST
    return FieldPath.UNKNOWN


def prior_value_recorded(event: ChangeEvent) -> bool:
    """§1's scope test: did a collector observe a state this change could be returned to?

    A redaction is not a value. The audit collector records a Secret's keys with every value
    replaced, so the diff *claims* a captured prior value that nothing could restore.
    """
    if event.source == "helm":
        return event.reversible  # the previous revision is the prior state (Handoff §5)
    diff = event.diff
    if diff is None or not diff.prior_value_captured or not diff.before:
        return False
    return REDACTED not in diff.before.values()


def catalog_can_revert(event: ChangeEvent) -> bool:
    """Does a shipped catalog action revert this change, inverse included?

    Asks through the writer registry as well as the collector's hint (W41), so a gap stops
    being mined the day a writer-backed action closing it is merged.
    """
    from ..writers.registry import request_for_event

    return request_for_event(event) is not None


def classify(event: ChangeEvent) -> SignalKind | None:
    """`unactionable`, `inverse_missing`, or `None` when the catalog can revert it."""
    if event.inverse_hint is None:
        return SignalKind.UNACTIONABLE
    if not catalog_can_revert(event):
        return SignalKind.INVERSE_MISSING
    return None


def signal_for(
    kind: SignalKind,
    event: ChangeEvent,
    *,
    observed_at,
    incident_id: str | None = None,
    action_id: str | None = None,
) -> GapSignal:
    return GapSignal(
        kind=kind,
        incident_id=incident_id,
        event_id=event.id,
        source=event.source,
        resource_kind=ResourceKind.of(event.resource.kind),
        verb=event.action,
        field_path=field_path_of(event),
        actor=event.actor.display,
        prior_value_recorded=prior_value_recorded(event),
        action_id=action_id,
        observed_at=observed_at,
    )


# --------------------------------------------------------------------------------------
# The five points a signal is emitted from
# --------------------------------------------------------------------------------------


def decline_signal(brief: Brief) -> GapSignal | None:
    """§4 step 2, in Python: the proposer declined — is that a gap?

    **Takes the brief and nothing else.** Whether the model said `"none"` is established by
    the caller from `validate_proposal` returning `None`; what the decline is *about* is read
    off the ranked #1 candidate, which deterministic code ranked. No model output decides
    anything here.

    A decline over a change the catalog *can* revert is not a gap — the model declined for
    some other reason, and recording it would mine the model's caution as missing capability.
    """
    top = brief.top
    if top is None or catalog_can_revert(top.event):
        return None
    return signal_for(
        SignalKind.DECLINE,
        top.event,
        incident_id=brief.incident_id,
        observed_at=brief.alert.fired_at,
    )


def record_decline(brief: Brief, store: GapSignalStore) -> GapSignal | None:
    signal = decline_signal(brief)
    if signal is not None:
        store.record(signal)
    return signal


def ledger_signals(
    ledger: LedgerStore, radius: BlastRadius, window: TimeWindow
) -> list[GapSignal]:
    """The unactionable and inverse-missing changes in one radius, for the continuous miner.

    Radius-scoped because the ledger has no other read (W9). These carry no incident: a change
    nobody was paged about is evidence of a change class, not of an incident, so it cannot
    count towards the miner's incident threshold.
    """
    signals: list[GapSignal] = []
    for event in ledger.query(radius, window):
        kind = classify(event)
        if kind is not None:
            signals.append(signal_for(kind, event, observed_at=event.occurred_at))
    return signals


def outcome_observer(
    store: GapSignalStore, ledger: LedgerStore
) -> Callable[[PendingApproval, Outcome], None]:
    """An `ApprovalGateway` observer that records rejections and executions.

    The change is resolved from the ledger by the evidence ids the proposal cited, not from
    anything the Slack payload carried — the same rule the gateway applies to everything
    else about a click.
    """

    def observe(pending: PendingApproval, outcome: Outcome) -> None:
        if outcome.decision == "rejected":
            kind = SignalKind.REJECTED
        elif outcome.executed:
            kind = SignalKind.EXECUTED
        else:
            return  # approved but failed: neither a verdict on the action nor a use of it

        for event_id in pending.evidence_ids:
            event = ledger.get(event_id)
            if event is None:
                continue
            store.record(
                signal_for(
                    kind,
                    event,
                    incident_id=outcome.incident_id,
                    action_id=outcome.action_id,
                    observed_at=outcome.decided_at,
                )
            )

    return observe


def find_remediations(
    ledger: LedgerStore, anchors: Iterable[GapSignal], *, window_minutes: int
) -> Iterator[tuple[GapSignal, Demonstration]]:
    """§2's fourth signal: a named human changed the same resource soon after the anchor.

    Only a change that carries a real before and after becomes a demonstration. A remediation
    with no recorded prior value — any CloudTrail change, a Helm upgrade with no diff — cannot
    be compared to a candidate's dry run, so it is not evidence W42 could use.

    **Only the first such change is the remediation.** A later human change to the same resource
    inside the window is somebody else's story — often the next incident's cause — and reading it
    as a fix of this one would put a cause into the corpus as a demonstration, which replay then
    correctly disagrees with.
    """
    span = timedelta(minutes=window_minutes)

    for anchor in anchors:
        if anchor.incident_id is None:
            continue
        caused = ledger.get(anchor.event_id)
        if caused is None:
            continue

        key = caused.resource.blast_radius_key()
        # Scoped to the one resource the anchor is about. The radius is the resource's own
        # key, so this read cannot return anything outside the incident's blast radius.
        radius = BlastRadius(service=anchor.incident_id, keys={key})
        window = TimeWindow(start=anchor.observed_at, end=anchor.observed_at + span)

        for later in ledger.query(radius, window):
            if later.id == caused.id or later.resource.blast_radius_key() != key:
                continue
            if later.actor.kind != "human" or later.diff is None:
                continue
            if not prior_value_recorded(later):
                continue

            fields = later.diff.fields_changed
            yield anchor, Demonstration(
                key=anchor.key,
                incident_id=anchor.incident_id,
                anchor_event_id=caused.id,
                remediation_event_id=later.id,
                resource=later.resource,
                before={name: (later.diff.before or {}).get(name) for name in fields},
                after={name: (later.diff.after or {}).get(name) for name in fields},
                actor=later.actor.display,
                occurred_at=later.occurred_at,
                lag_seconds=(later.occurred_at - anchor.observed_at).total_seconds(),
            )
            break


def find_contesting_changes(
    ledger: LedgerStore, anchors: Iterable[GapSignal], *, window_minutes: int
) -> Iterator[tuple[GapSignal, ChangeEvent]]:
    """W45's negative graduation signal: anyone but automation changed the resource an
    execution acted on, inside its quiet period. The first such change per anchor.

    **Deliberately looser than `find_remediations`.** That one selects demonstrations, so it
    needs a named human and a recorded before and after; a contest needs neither. An on-call
    engineer missing from `identity_map.yaml` resolves as `unknown`, and a hand-fix through a
    path that captured no prior value is still a hand-fix. Reading either as "nobody
    intervened" would let an action graduate exactly where the evidence is thinnest, so every
    actor not known to be automation counts. Only a service account is excluded — FazerOps's
    own principal among them — because a controller reconciling, or the execution's own write
    landing in the audit log, is not a human's verdict on the action.
    """
    span = timedelta(minutes=window_minutes)

    for anchor in anchors:
        if anchor.incident_id is None:
            continue
        caused = ledger.get(anchor.event_id)
        if caused is None:
            continue

        key = caused.resource.blast_radius_key()
        radius = BlastRadius(service=anchor.incident_id, keys={key})
        window = TimeWindow(start=anchor.observed_at, end=anchor.observed_at + span)

        for later in ledger.query(radius, window):
            if later.id == caused.id or later.resource.blast_radius_key() != key:
                continue
            if later.actor.kind == "service_account" or later.actor.canonical == FAZEROPS_CANONICAL:
                continue
            yield anchor, later
            break


def remediation_signal(anchor: GapSignal, demonstration: Demonstration) -> GapSignal:
    """Keyed and attributed to the anchor's change, for the reason `GapSignal` gives."""
    return anchor.model_copy(
        update={
            "kind": SignalKind.HUMAN_REMEDIATION,
            "action_id": None,
            "observed_at": demonstration.occurred_at,
        }
    )


# --------------------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------------------

_Model = TypeVar("_Model", GapSignal, Demonstration)


class GapSignalStore:
    """Signals and demonstrations, append-only, in the ledger's own shape.

    Same file discipline as `LedgerStore` and for the same reasons: a record that can be
    rewritten in place is not evidence, and a crash mid-append costs the last line rather than
    the file. **First write wins** — a signal is an observation, and re-observing it must not
    move its timestamp, which the remediation window is measured from.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._signals: dict[str, GapSignal] = {}
        self._demonstrations: dict[str, Demonstration] = {}

        if self._path is not None:
            for signal in _replay(self._path, GapSignal):
                self._signals.setdefault(signal.id, signal)
            for demonstration in _replay(self._demonstrations_path, Demonstration):
                self._demonstrations.setdefault(demonstration.id, demonstration)

    @property
    def _demonstrations_path(self) -> Path | None:
        if self._path is None:
            return None
        return self._path.with_name(f"{self._path.stem}.demonstrations.jsonl")

    def record(self, signal: GapSignal) -> bool:
        """True if this signal was new."""
        if signal.id in self._signals:
            return False
        self._signals[signal.id] = signal
        _append(self._path, signal)
        return True

    def record_demonstration(self, demonstration: Demonstration) -> bool:
        if demonstration.id in self._demonstrations:
            return False
        self._demonstrations[demonstration.id] = demonstration
        _append(self._demonstrations_path, demonstration)
        return True

    def signals(self, *, kind: SignalKind | None = None) -> list[GapSignal]:
        found = [s for s in self._signals.values() if kind is None or s.kind is kind]
        found.sort(key=lambda s: (s.observed_at, s.id))
        return found

    def demonstrations(self, key: GapKey | None = None) -> list[Demonstration]:
        found = [d for d in self._demonstrations.values() if key is None or d.key == key]
        found.sort(key=lambda d: (d.occurred_at, d.id))
        return found

    def __len__(self) -> int:
        return len(self._signals)


def _append(path: Path | None, record: BaseModel) -> None:
    """One line, under an exclusive lock, after cutting any torn final line — as `ChainedLog` does.

    `_replay` tolerating a torn line is only half of it. Appending onto the unterminated line a
    crash left fuses the new record into it, and `_replay` then drops both: a decline, rejection
    or execution the server recorded at incident time is never observed a second time. The
    automation server and the growth job both append here, and the lock is what makes the cut
    safe — another writer's half-written line is never visible to it.
    """
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            truncate_torn_line(handle)
            handle.write((record.model_dump_json() + "\n").encode("utf-8"))
            handle.flush()
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _replay(path: Path | None, model: type[_Model]) -> Iterator[_Model]:
    """Tolerates a truncated final line, as `LedgerStore._load` does."""
    if path is None or not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield model.model_validate_json(line)
            except (ValueError, json.JSONDecodeError):
                continue
