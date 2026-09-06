"""W6 — the integration spine. Alert in, ranked `Brief` out.

Built on day one on purpose. The classic hackathon failure is integrating last: every unit
passes in isolation and nothing works together, discovered on the evening of the rehearsal
(plan R3). This module exists so that failure surfaces now, when there is room to respond.

**This is the investigation layer, and it imports nothing from the automation layer**
(plan §3.5). No `actions`, no `slack.handlers`, no `security.credentials`. A `Brief` must
render with the whole automation layer deleted, and `tests/integration/test_layer_seam.py`
asserts exactly that by blocking those imports.

The collector fan-out uses `asyncio.gather` here. W19 replaces it with the Strands
`GraphBuilder` topology, where the same four collectors become `FunctionNode`s in one
concurrent batch. Keeping the fan-out behind one function is what makes that a swap rather
than a rewrite.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

from .collectors.base import Collector, CollectorResult
from .collectors.github import GitHubCollector, ci_status_from
from .collectors.k8s_audit import K8sAuditCollector
from .correlation.scoring import score_events
from .models import Alert, Brief, ChangeEvent, CIStatus, TimeWindow

DEFAULT_WINDOW_HOURS = 4  # Handoff Q3, bounded [1, 24] by the orchestrator's tool schema


def build_collectors() -> list[Collector]:
    """The registry. CloudTrail (W10) and Helm (W11) join this list as they land.

    A source that is not yet built is absent rather than stubbed — an empty stub would
    render as "we looked and found nothing", which is a different claim entirely.
    """
    return [K8sAuditCollector(), GitHubCollector()]


def window_for(alert: Alert, hours: int = DEFAULT_WINDOW_HOURS) -> TimeWindow:
    hours = max(1, min(int(hours), 24))
    return TimeWindow(start=alert.fired_at - timedelta(hours=hours), end=alert.fired_at)


async def gather_changes(
    collectors: list[Collector], radius, window: TimeWindow
) -> list[CollectorResult]:
    """Fan out concurrently. Failures arrive as results, never as exceptions — a single
    dead source must degrade the brief, not take it down (plan §3.2)."""
    return list(
        await asyncio.gather(*(collector.fetch(radius, window) for collector in collectors))
    )


async def investigate(
    alert: Alert,
    *,
    hours: int = DEFAULT_WINDOW_HOURS,
    collectors: list[Collector] | None = None,
) -> Brief:
    from .radius import resolve  # local import keeps the manifest off the import path

    radius = resolve(alert.service)
    window = window_for(alert, hours)
    collectors = collectors if collectors is not None else build_collectors()

    results = await gather_changes(collectors, radius, window)

    events: list[ChangeEvent] = []
    for result in results:
        events.extend(result.events)

    candidates = score_events(events, alert, radius, window)

    github = next((r for r in results if r.source == "github"), None)
    ci_status = (
        ci_status_from(github, radius) if github is not None else CIStatus(merge_count=0)
    )

    # Degraded when any source failed, or when the alert named a service the manifest does
    # not know. Both produce a thinner brief that would otherwise read as a confident
    # "nothing changed" — the one failure mode that is worse than no brief at all.
    degraded = any(not result.ok for result in results) or not radius.keys

    return Brief(
        incident_id=f"INC-{alert.id}",
        alert=alert,
        radius=radius,
        window=window,
        candidates=candidates,
        ci_status=ci_status,
        degraded=degraded,
    )
