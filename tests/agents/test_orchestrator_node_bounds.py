"""The live orchestrator is bounded inside its graph node (14 Sep, night).

It was a bare `Agent` node: no turn cap, no fallback, no timeout of its own. A throttled Gemini
orchestrator retried past the graph's backstop, and a 429 that escaped the Agent failed the graph —
HTTP 500, no brief. The turn cap and the fallback plan are `orchestrate()`'s, already covered by
`test_orchestrator_contract.py` (`test_turn_cap_terminates_a_pathological_loop`,
`test_a_model_that_never_dispatches_still_yields_a_plan`). What is asserted here is that the graph
uses them, and that the node's own clock turns a hang or a failure into a degraded brief.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

import fazerops.agents.graph as graph
import fazerops.agents.orchestrator as orchestrator
from fazerops.agents.graph import FunctionNode, InvestigationState, build_investigation_graph, investigate_via_graph
from fazerops.ingest.alerts import normalize_alert

ALERT = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


async def test_a_hung_orchestrator_degrades_the_brief_instead_of_failing_the_graph(monkeypatch):
    async def hangs(alert, **kwargs):
        await asyncio.sleep(60)

    monkeypatch.setattr(orchestrator, "orchestrate", hangs)
    monkeypatch.setattr(graph, "ORCHESTRATOR_TIMEOUT_SECONDS", 0.2)
    state = InvestigationState(normalize_alert(ALERT))

    brief, _ = await investigate_via_graph(state.alert, state=state)

    assert state.node_errors["orchestrator"].startswith("timed out")
    assert brief.degraded is True
    assert brief.candidates[0].event.resource.name == "billing-api-config", "the fallback scope still finds it"
    assert state.plan.dispatched is False and "default scope" in (state.plan.note or "")


async def test_a_throttled_orchestrator_degrades_the_brief_instead_of_a_500(monkeypatch):
    async def throttled(alert, **kwargs):
        raise RuntimeError("429 Too Many Requests. Resource exhausted.")

    monkeypatch.setattr(orchestrator, "orchestrate", throttled)
    state = InvestigationState(normalize_alert(ALERT))

    brief, _ = await investigate_via_graph(state.alert, state=state)

    assert "429" in state.node_errors["orchestrator"]
    assert brief.degraded is True
    assert len(brief.candidates) == 3


async def test_a_live_orchestrator_node_runs_orchestrate_with_the_runs_session_and_meter(monkeypatch):
    """Gemini mode, with no network: the node is bounded and calls `orchestrate()` — so the turn cap and
    the fallback apply — rather than being a bare `Agent` the graph cannot bound."""
    monkeypatch.setenv("FAZEROPS_LLM", "gemini")
    seen = {}

    async def spy(alert, **kwargs):
        seen.update(kwargs)
        return orchestrator._fallback_plan(kwargs["session"], note=None)

    monkeypatch.setattr(orchestrator, "orchestrate", spy)
    state = InvestigationState(normalize_alert(ALERT))
    state.meter = object()
    built = build_investigation_graph(state)

    node = built.nodes["orchestrator"].executor
    assert isinstance(node, FunctionNode)
    assert node._timeout == graph.ORCHESTRATOR_TIMEOUT_SECONDS

    await node.invoke_async("investigate")
    assert seen["session"] is state.session and seen["meter"] is state.meter
    assert state.plan is not None


def test_the_orchestrators_clock_fires_before_the_graphs_backstop():
    """If the backstop fired first, a slow orchestrator would fail the graph again."""
    assert graph.ORCHESTRATOR_TIMEOUT_SECONDS < graph.NODE_TIMEOUT_SECONDS * graph.GRAPH_TIMEOUT_MULTIPLE
