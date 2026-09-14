"""Plan §5's meter reaches the model calls of every run.

Found 14 Sep: nothing outside the recording scripts passed a meter, so every live investigation ran
with no token ledger and no per-run or per-day cap.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

from fazerops.agents import budget
from fazerops.agents.budget import TokenMeter, meter_for_mode

FIXTURE_ALERTS = Path(__file__).resolve().parents[2] / "fixtures" / "alerts"


def _alert():
    from fazerops.ingest.alerts import normalize_alert

    return normalize_alert(json.loads((FIXTURE_ALERTS / "alertmanager.json").read_text(encoding="utf-8")))


def test_a_mode_that_calls_a_model_gets_a_meter_and_an_offline_mode_does_not(monkeypatch):
    import fazerops.agents.llm as llm

    monkeypatch.setattr(llm, "requires_network", lambda mode: True)
    assert isinstance(meter_for_mode(), TokenMeter)

    monkeypatch.setattr(llm, "requires_network", lambda mode: False)
    assert meter_for_mode() is None


async def test_the_graph_hands_one_meter_to_the_correlator_and_the_proposer(monkeypatch, tmp_path):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")

    import fazerops.agents.correlator as correlator
    import fazerops.agents.proposer as proposer
    from fazerops.agents.graph import investigate_via_graph

    meter = TokenMeter(ledger_path=tmp_path / "token_ledger.jsonl")
    monkeypatch.setattr(budget, "meter_for_mode", lambda: meter)
    seen: dict[str, object] = {}
    real_correlate, real_propose = correlator.correlate, proposer.propose

    async def correlate(brief, **kwargs):
        seen["correlator"] = kwargs.get("meter")
        return await real_correlate(brief)

    async def propose(brief, narrative=None, **kwargs):
        seen["proposer"] = kwargs.get("meter")
        return await real_propose(brief, narrative)

    import fazerops.agents.orchestrator as orchestrator

    real_orchestrate = orchestrator.orchestrate

    async def orchestrate(alert, **kwargs):
        seen["orchestrator"] = kwargs.get("meter")
        return await real_orchestrate(alert, session=kwargs.get("session"))

    monkeypatch.setattr(correlator, "correlate", correlate)
    monkeypatch.setattr(proposer, "propose", propose)
    monkeypatch.setattr(orchestrator, "orchestrate", orchestrate)

    await investigate_via_graph(_alert(), proposer_node=functools.partial(proposer.proposer_node))

    # The orchestrator too: as a bare Agent node it was never metered, and the ledger had no rows for it.
    assert seen["correlator"] is meter and seen["proposer"] is meter and seen["orchestrator"] is meter


async def test_the_tier_0_pipeline_meters_the_orchestrator(monkeypatch, tmp_path):
    """`pipeline.investigate` is AgentCore's path; its only model call is the orchestrator's."""
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")

    import fazerops.agents.orchestrator as orchestrator
    from fazerops.pipeline import investigate

    meter = TokenMeter(ledger_path=tmp_path / "token_ledger.jsonl")
    monkeypatch.setattr(budget, "meter_for_mode", lambda: meter)
    seen: dict[str, object] = {}
    real = orchestrator.orchestrate

    async def orchestrate(alert, **kwargs):
        seen["meter"] = kwargs.get("meter")
        return await real(alert, **kwargs)

    monkeypatch.setattr(orchestrator, "orchestrate", orchestrate)

    await investigate(_alert())

    assert seen["meter"] is meter
