"""Following a coverage gap until it closes — without holding the brief.

The brief posts at alert time, because the product's promise is that the work is done before a
human arrives. CloudTrail cannot promise the same: its events reach `lookup_events` minutes after
the call (124–146 s measured on this account, 14 Sep). So the brief goes out with its gap stated,
and this module keeps asking the lagging source about the same radius and window every
`POLL_SECONDS` until the gap's full lag has passed:

* a change that arrives late is re-ranked with everything the brief already held, and yielded at
  once — so the brief a person opens a couple of minutes in is already the corrected one;
* at the end the gap is closed as `caught_up` or `unreachable`, and yielded once more.

Nothing is yielded for a poll that found nothing new, so a quiet gap costs one final update, not
forty. Read-only and model-free, which is why it lives here, in the investigation layer: posting
the updates is the automation layer's half (`actions/server.py`).

**A re-ranked brief drops its narrative.** The explanation was written without the late change;
keeping it beside a ranking it never saw would read as if it had.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .collectors.base import Collector
from .correlation.scoring import score_events
from .correlation.sensitivity import rank_stability
from .ledger.store import LedgerStore
from .models import Brief, Candidate, ChangeEvent

__all__ = ["POLL_SECONDS", "SETTLE_MARGIN_SECONDS", "CoverageUpdate", "rescore", "watch_coverage"]

POLL_SECONDS = 20.0

# Past the settle point, not onto it: a timer can wake a moment early, and the live run of 14 Sep
# re-queried 0.01 s short and still reported a sliver of the window unobserved.
SETTLE_MARGIN_SECONDS = 5.0

# A wake this close to the close time is the close, not another poll interval.
_WAKE_TOLERANCE = timedelta(seconds=1)


@dataclass(frozen=True)
class CoverageUpdate:
    brief: Brief
    late_event_ids: list[str]
    rank_one_changed: bool
    final: bool


async def watch_coverage(
    brief: Brief,
    *,
    collectors: list[Collector] | None = None,
    poll_seconds: float = POLL_SECONDS,
    sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
    now: Callable[[], datetime] | None = None,
) -> AsyncIterator[CoverageUpdate]:
    open_gaps = [gap for gap in brief.coverage_gaps if gap.status == "open"]
    if not open_gaps:
        return
    from .pipeline import build_collectors, gather_changes

    clock = now or (lambda: datetime.now(timezone.utc))
    sources = {gap.source for gap in open_gaps}
    chosen = [c for c in (collectors if collectors is not None else build_collectors()) if c.source in sources]
    closes_at = max(gap.settles_at for gap in open_gaps) + timedelta(seconds=SETTLE_MARGIN_SECONDS)
    first_top = brief.top.event.id if brief.top else None
    late_by_source: dict[str, int] = {}
    current = brief

    while True:
        final = clock() >= closes_at - _WAKE_TOLERANCE
        results = await gather_changes(chosen, brief.radius, brief.window)

        known = {candidate.event.id for candidate in current.candidates}
        late: dict[str, ChangeEvent] = {}
        for result in results:
            for event in result.events:
                if event.id not in known and event.id not in late:
                    late[event.id] = event
                    late_by_source[result.source] = late_by_source.get(result.source, 0) + 1
        failed = {result.source for result in results if not result.ok}

        if late or final:
            revised = _revise(
                current,
                list(late.values()),
                first_top=first_top,
                at=clock(),
                final=final,
                failed=failed,
                late_by_source=late_by_source,
            )
            yield CoverageUpdate(
                brief=revised,
                late_event_ids=sorted(late),
                rank_one_changed=_top(revised) != _top(current),
                final=final,
            )
            current = revised
        if final:
            return
        await sleep(max(0.0, min(poll_seconds, (closes_at - clock()).total_seconds())))


def rescore(brief: Brief, events: list[ChangeEvent]) -> list[Candidate]:
    """`events` ranked against the brief's alert, radius and window.

    In memory, as the investigation's own scoring ledger is: a durable ledger holds this alert's
    signature, and `recurrence` would then count the alert as its own precedent.
    """
    scratch = LedgerStore()
    scratch.extend(events)
    return score_events(scratch.query(brief.radius, brief.window), brief.alert, brief.radius, brief.window, scratch)


def _top(brief: Brief) -> str | None:
    return brief.top.event.id if brief.top else None


def _revise(
    brief: Brief,
    late: list[ChangeEvent],
    *,
    first_top: str | None,
    at: datetime,
    final: bool,
    failed: set[str],
    late_by_source: dict[str, int],
) -> Brief:
    changed = bool(late)
    candidates = rescore(brief, [c.event for c in brief.candidates] + late) if changed else brief.candidates

    gaps = brief.coverage_gaps
    if final:
        gaps = [
            gap
            if gap.status != "open"
            else gap.model_copy(
                update={
                    "status": "unreachable" if gap.source in failed else "caught_up",
                    "checked_at": at,
                    "late_changes": late_by_source.get(gap.source, 0),
                }
            )
            for gap in brief.coverage_gaps
        ]

    top = candidates[0].event.id if candidates else None
    return Brief(
        incident_id=brief.incident_id,
        alert=brief.alert,
        radius=brief.radius,
        window=brief.window,
        candidates=candidates,
        ci_status=brief.ci_status,
        narrative=None if changed else brief.narrative,
        evidence_ids=[] if changed else list(brief.evidence_ids),
        degraded=brief.degraded or (final and bool(failed & {gap.source for gap in brief.coverage_gaps})),
        stability=rank_stability(candidates) if changed else brief.stability,
        coverage_gaps=gaps,
        reranked_at=at if changed else brief.reranked_at,
        ranked_first_from=first_top if first_top is not None and top != first_top else None,
    )
