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
from .collectors.cloudtrail import CloudTrailCollector
from .collectors.github import GitHubCollector, ci_status_from
from .collectors.helm import HelmCollector
from .collectors.k8s_audit import K8sAuditCollector
from .correlation.scoring import score_events
from .correlation.sensitivity import rank_stability
from .ledger.store import LedgerStore
from .models import Alert, Brief, CIStatus, TimeWindow, incident_id_for

DEFAULT_WINDOW_HOURS = 4  # Handoff Q3, bounded [1, 24] by the orchestrator's tool schema


def build_collectors() -> list[Collector]:
    """All four sources Handoff §5 specifies, each working in both modes.

    A source that is not built would be absent rather than stubbed — an empty stub renders
    as "we looked and found nothing", which is a different claim entirely. As of W10 there
    are none absent.
    """
    return [
        CloudTrailCollector(),
        K8sAuditCollector(),
        HelmCollector(),
        GitHubCollector(),
    ]


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
    ledger: LedgerStore | None = None,
) -> Brief:
    """Alert in, ranked `Brief` out.

    Collector output goes through the ledger (W9) rather than straight into the scorer.
    That is one extra hop for an identical candidate set today — the collectors already
    filter by radius and window — and it is deliberate for two reasons. It deduplicates
    sources that observe the same mutation, which Helm and the K8s audit log both do. And
    it makes the ledger the thing the investigation actually reads, so W14b's recurrence
    feature queries the same store the demo populates instead of a parallel one that only
    history uses.

    The default ledger is in-memory, so the fixture demo leaves no state on a judge's
    machine. A caller wanting durable history passes `LedgerStore(path)`.
    """
    from .agents.orchestrator import orchestrate

    # W19b: scope and window are the orchestrator's decision, not this function's. In
    # `stub` mode it resolves deterministically to exactly what `resolve(alert.service)`
    # and `window_for(alert, hours)` produced before — which is why the golden ranking
    # test is unchanged by this wiring.
    plan = await orchestrate(alert, hours=hours)
    radius, window = plan.radius, plan.window
    collectors = collectors if collectors is not None else build_collectors()

    results = await gather_changes(collectors, radius, window)

    ledger = ledger if ledger is not None else LedgerStore()
    for result in results:
        ledger.extend(result.events)

    candidates = score_events(ledger.query(radius, window), alert, radius, window, ledger)

    # Recorded after scoring, so this alert is never its own precedent. `prior_alerts`
    # filters on `fired_at` as well, so the order is belt-and-braces rather than load-
    # bearing — but a durable ledger accumulates signatures across incidents, and that is
    # the only thing that makes W14b's recurrence non-zero on anything but a cold start.
    ledger.record_alert(alert)

    github = next((r for r in results if r.source == "github"), None)
    ci_status = (
        ci_status_from(github, radius) if github is not None else CIStatus(merge_count=0)
    )

    # Degraded when any source failed, when the alert named a service the manifest does not
    # know, or when the orchestrator did not finish choosing scope. All three produce a
    # thinner brief that would otherwise read as a confident "nothing changed" — the one
    # failure mode that is worse than no brief at all.
    degraded = (
        any(not result.ok for result in results) or not radius.keys or plan.degraded
    )

    return Brief(
        incident_id=incident_id_for(alert),
        alert=alert,
        radius=radius,
        window=window,
        candidates=candidates,
        ci_status=ci_status,
        degraded=degraded,
        stability=rank_stability(candidates),
        coverage_gaps=coverage_gaps_from(results),
    )


def coverage_gaps_from(results: list[CollectorResult]) -> list:
    """Only from sources that answered: a failed source is `degraded`, which already says more."""
    return sorted(
        (result.coverage_gap for result in results if result.ok and result.coverage_gap is not None),
        key=lambda gap: gap.source,
    )
