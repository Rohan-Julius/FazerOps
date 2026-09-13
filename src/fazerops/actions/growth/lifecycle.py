"""W45 — the provisional lifecycle and tombstones. `docs/catalog_self_extension.md` §7.6, §7.8, §8.

    merged PROVISIONAL  →  graduated  →  retired (tombstoned)

**Provisional is a separate axis, and this module never names the other one.** A provisional
action keeps exactly the approval level a human declared at merge; provisional adds a manager
approval on top of it, every time, and the card says `generated, n/N`. The tempting design —
born at the top level, earning its way down — is a demotion, and demotion driven by a counter
is precisely what an attacker who can influence the counter would target (§8). Graduation
removes the extra approval and nothing else. `test_provisional.py` reads this file's AST to
hold that.

**Graduation is weaker than verifying the incident resolved**, and is presented as such
(§7.8). It needs N confirmed executions — each with its quiet period fully elapsed — and **no**
human remediation of the same resource within T minutes of any execution: W40's fourth signal,
read in the negative. Approvers habituate (§10a), so the count alone would mean little. The
negative check carries the weight, which is why one contested execution blocks graduation
outright rather than being outvoted by confirmed ones.

**Nothing here writes the catalog.** Graduation and retirement are recommendations. Clearing
`provisional` or setting `retired` is a catalog edit a human commits, and `pr.py` rejects
agent-authored commits that make either change.

**Retirement is a tombstone, never a deletion** (§7.6). W28's record cites action ids, so a
retired entry stays resolvable through `Catalog.get`; it leaves only `Catalog.action_ids` — the
proposer's enum — the writer matching in `request_for_event`, and the approval gateway.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .miner import DEFAULT_CONFIG
from .signals import GapSignal, GapSignalStore, SignalKind, find_remediations

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...ledger.store import LedgerStore
    from ..catalog import Catalog

__all__ = [
    "GraduationStatus",
    "LifecycleConfig",
    "graduation_progress",
    "graduation_status",
    "load_lifecycle",
    "retirement_candidates",
]


class LifecycleConfig(BaseModel):
    """`config/catalog_growth.yaml`'s `lifecycle:` block. Graduation after a single execution
    is refused by the schema, for the same reason the miner's thresholds have a floor."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    graduation_approvals: int = Field(default=5, ge=2)
    quiet_minutes: int = Field(default=60, ge=1, le=24 * 60)
    retire_after_unused_incidents: int = Field(default=20, ge=1)


def load_lifecycle(path: Path | str | None = None) -> LifecycleConfig:
    raw = yaml.safe_load(Path(path or DEFAULT_CONFIG).read_text(encoding="utf-8")) or {}
    return LifecycleConfig.model_validate(raw.get("lifecycle") or {})


class GraduationStatus(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str
    required: int
    confirmed: int
    contested: int
    awaiting_quiet_period: int

    @property
    def graduated(self) -> bool:
        return self.contested == 0 and self.confirmed >= self.required

    @property
    def progress(self) -> tuple[int, int]:
        return (self.confirmed, self.required)


def graduation_status(
    action_id: str,
    store: GapSignalStore,
    ledger: LedgerStore,
    *,
    now: datetime,
    config: LifecycleConfig | None = None,
) -> GraduationStatus:
    """Count one action's executions, per incident, as confirmed, contested or still quiet."""
    config = config if config is not None else load_lifecycle()
    quiet = timedelta(minutes=config.quiet_minutes)

    executions: dict[str, list[GapSignal]] = {}
    for signal in store.signals(kind=SignalKind.EXECUTED):
        if signal.action_id == action_id and signal.incident_id is not None:
            executions.setdefault(signal.incident_id, []).append(signal)

    confirmed = contested = awaiting = 0
    for anchors in executions.values():
        remediated = next(
            find_remediations(ledger, anchors, window_minutes=config.quiet_minutes), None
        )
        if remediated is not None:
            # Checked before the quiet period: a human fixing it by hand ten minutes in is
            # already a verdict, and waiting out the window would only delay recording it.
            contested += 1
        elif all(now >= anchor.observed_at + quiet for anchor in anchors):
            confirmed += 1
        else:
            awaiting += 1

    return GraduationStatus(
        action_id=action_id,
        required=config.graduation_approvals,
        confirmed=confirmed,
        contested=contested,
        awaiting_quiet_period=awaiting,
    )


def graduation_progress(
    store: GapSignalStore,
    ledger: LedgerStore,
    *,
    config: LifecycleConfig | None = None,
    clock: Callable[[], datetime] | None = None,
) -> Callable[[str], tuple[int, int]]:
    """For `ApprovalGateway(graduation=...)`: the `n/N` a provisional card shows."""
    clock = clock if clock is not None else (lambda: datetime.now(timezone.utc))

    def progress(action_id: str) -> tuple[int, int]:
        return graduation_status(action_id, store, ledger, now=clock(), config=config).progress

    return progress


def retirement_candidates(
    catalog: Catalog,
    store: GapSignalStore,
    recent_incidents: Sequence[str],
    *,
    config: LifecycleConfig | None = None,
) -> list[str]:
    """Writer-backed actions nobody used across the last N incidents, oldest-first input.

    Only writer-backed actions are ever recommended. Sprawl is the failure mode of a catalog
    that grows (§7.6); Handoff §7's hand-written actions are the catalog it grew from.
    Fewer than N incidents recommends nothing — an action cannot be shown unused over a history
    too short to have needed it.
    """
    config = config if config is not None else load_lifecycle()
    window = list(dict.fromkeys(recent_incidents))[-config.retire_after_unused_incidents :]
    if len(window) < config.retire_after_unused_incidents:
        return []

    incidents = set(window)
    used = {
        signal.action_id
        for signal in store.signals()
        if signal.kind in (SignalKind.EXECUTED, SignalKind.REJECTED) and signal.incident_id in incidents
    }
    return sorted(
        action.id
        for action in catalog
        if action.writer is not None and not action.retired and action.id not in used
    )
