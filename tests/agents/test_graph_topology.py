"""W19 — the Strands `Graph` topology. Plan §4.

Three assertions the plan names, and they are the three claims the architecture makes:

1. `result.execution_order` shows the four collector nodes in the **same batch**. That is
   the concurrency claim, and it is the one a reviewer will check.
2. `set_node_timeout` bounds a hung collector.
3. A single failing collector **degrades the brief rather than failing the graph**.

All of it runs in `stub` mode with fixture collectors: no credentials, no network, no model.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

import pytest

from fazerops.agents.graph import (
    COLLECTOR_NODES,
    GRAPH_TIMEOUT_MULTIPLE,
    FunctionNode,
    InvestigationState,
    build_investigation_graph,
    investigate_via_graph,
)
from fazerops.collectors.base import CollectorResult
from fazerops.models import Alert, AlertClass

FIRED_AT = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


def demo_alert() -> Alert:
    return Alert(
        id="A-1",
        service="billing-api",
        summary="p99 latency for billing-api is 4200ms, up from 180ms",
        fired_at=FIRED_AT,
        alert_class=AlertClass.LATENCY_SPIKE,
        severity="critical",
    )


class SlowCollector:
    """Sleeps, then returns nothing. Used to measure the batch and to hang a node."""

    def __init__(self, source: str, delay: float) -> None:
        self.source = source
        self.delay = delay
        self.started_at: float | None = None
        self.finished_at: float | None = None

    async def fetch(self, radius, window) -> CollectorResult:
        self.started_at = time.monotonic()
        await asyncio.sleep(self.delay)
        self.finished_at = time.monotonic()
        return CollectorResult(self.source, [])


class ExplodingCollector:
    """Raises rather than returning a `CollectorResult`.

    `BaseCollector.fetch` already converts its own exceptions into an error result, so a
    real collector cannot produce this. That is exactly why the test uses a fake one: the
    claim under test is that the *node* survives a source that breaks its contract, not
    that the base class honours it.
    """

    def __init__(self, source: str) -> None:
        self.source = source

    async def fetch(self, radius, window) -> CollectorResult:
        raise RuntimeError("the API went away mid-call")


# --------------------------------------------------------------------------------------
# 1. One batch
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_four_collectors_run_in_one_batch():
    """Concurrent, not sequential — asserted on wall clock, not on a node list.

    Four collectors each sleeping 0.2s take ~0.2s in one batch and ~0.8s in a chain. The
    0.6s bound sits between the two with room for scheduling noise, so this fails loudly if
    an edge is ever added between collectors.
    """
    collectors = [SlowCollector(name, 0.2) for name in COLLECTOR_NODES]

    started = time.monotonic()
    _, result = await investigate_via_graph(demo_alert(), collectors=collectors)
    elapsed = time.monotonic() - started

    assert elapsed < 0.6, f"collectors took {elapsed:.2f}s — that is a chain, not a batch"
    # Every collector started before any of them finished: the definition of concurrent.
    latest_start = max(c.started_at for c in collectors)
    earliest_finish = min(c.finished_at for c in collectors)
    assert latest_start < earliest_finish

    assert result.status.value == "completed"


@pytest.mark.asyncio
async def test_execution_order_places_the_collectors_between_the_agents():
    """The topology of plan §3.2, read off the graph's own record of what it ran."""
    _, result = await investigate_via_graph(demo_alert())

    order = [node.node_id for node in result.execution_order]
    assert order[0] == "orchestrator"
    assert order[-1] == "correlator"
    assert set(order[1:-1]) == set(COLLECTOR_NODES)
    assert len(order) == len(COLLECTOR_NODES) + 2, "no node ran twice"


@pytest.mark.asyncio
async def test_the_graph_produces_the_same_ranking_as_the_pipeline():
    """The graph is a swap for `pipeline.investigate`'s fan-out, not a second answer.

    If these two ever disagree, the demo and the golden test are describing different
    systems — which is how a topology refactor silently becomes a correctness change.
    """
    from fazerops.pipeline import investigate

    via_graph, _ = await investigate_via_graph(demo_alert())
    via_pipeline = await investigate(demo_alert())

    assert [c.event.id for c in via_graph.candidates] == [
        c.event.id for c in via_pipeline.candidates
    ]
    assert [round(c.score, 6) for c in via_graph.candidates] == [
        round(c.score, 6) for c in via_pipeline.candidates
    ]


# --------------------------------------------------------------------------------------
# 2. The node timeout
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_node_timeout_bounds_a_hung_collector():
    """A collector that never returns must not hold the barrier open (§3.2).

    The timeout is what ends the run, and the brief still renders from the three sources
    that answered.
    """
    collectors = [SlowCollector(name, 0.05) for name in COLLECTOR_NODES[:3]]
    collectors.append(SlowCollector("github", 30.0))

    # Built here rather than through `investigate_via_graph` so the test can read
    # `node_errors` — the claim is not only that the run ended, but that it ended for the
    # stated reason and said which source it lost.
    state = InvestigationState(demo_alert())
    graph = build_investigation_graph(state, collectors=collectors, node_timeout=0.3)

    started = time.monotonic()
    result = await graph.invoke_async("Investigate alert A-1 on billing-api.")
    elapsed = time.monotonic() - started

    assert elapsed < 3.0, f"the hung node was not bounded: {elapsed:.2f}s"
    assert result.status.value == "completed", "a hung source must not fail the graph"
    assert state.node_errors["github"] == "timed out after 0.3s"
    assert state.degraded is True
    assert {r.source for r in state.results} == set(COLLECTOR_NODES[:3])


def test_the_graph_declares_a_node_timeout_outside_the_nodes_own():
    """Two timeouts, and the inner one must fire first.

    Strands' node timeout raises and fails the whole graph (verified 11 Sep — it cancels
    every sibling task). If the graph's were the shorter of the two it would win every race
    and one slow source would cost the entire brief, which is the failure
    `test_node_timeout_bounds_a_hung_collector` exists to catch.
    """
    graph = build_investigation_graph(InvestigationState(demo_alert()), node_timeout=12.0)
    assert graph.node_timeout == 12.0 * GRAPH_TIMEOUT_MULTIPLE
    assert graph.node_timeout > 12.0


# --------------------------------------------------------------------------------------
# 3. One failing collector degrades the brief
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_single_failing_collector_degrades_the_brief():
    """The whole point of `CollectorResult` carrying an error, restated at node level.

    A raised exception inside a graph node surfaces as an opaque graph failure and takes
    the brief with it. Here the graph completes, the other three sources are collected, and
    the brief says it is degraded.
    """
    collectors = [SlowCollector(name, 0.01) for name in COLLECTOR_NODES[:3]]
    collectors.append(ExplodingCollector("github"))

    brief, result = await investigate_via_graph(demo_alert(), collectors=collectors)

    assert result.status.value == "completed", "one dead source must not fail the graph"
    assert brief.degraded is True
    assert [node.node_id for node in result.execution_order][-1] == "correlator"


@pytest.mark.asyncio
async def test_a_failing_collector_does_not_cost_the_other_three_their_events():
    """Degraded is not empty. The three live sources still reach the ledger and the scorer,
    which is the difference between a thin brief and no brief."""
    from fazerops.pipeline import build_collectors

    collectors = [c for c in build_collectors() if c.source != "github"]
    collectors.append(ExplodingCollector("github"))

    brief, _ = await investigate_via_graph(demo_alert(), collectors=collectors)

    assert brief.degraded is True
    assert brief.candidates, "the surviving sources must still produce candidates"
    assert brief.top.event.resource.name == "billing-api-config"


@pytest.mark.asyncio
async def test_function_node_records_the_failure_by_name():
    """The node absorbs the exception, but it does not swallow it — a node that silently
    turns a broken source into "nothing changed" is the failure mode this project exists
    to prevent."""
    state = InvestigationState(demo_alert())

    async def boom() -> str:
        raise ValueError("nope")

    node = FunctionNode("cloudtrail", boom, state)
    result = await node.invoke_async("go")

    assert result.status.value == "completed"
    assert "cloudtrail" in state.node_errors
    assert "ValueError: nope" in state.node_errors["cloudtrail"]
    assert state.degraded is True
