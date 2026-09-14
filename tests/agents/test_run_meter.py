"""Plan §5's meter reaches the model calls of every run.

Found 14 Sep: nothing outside the recording scripts passed a meter, so every live investigation ran
with no token ledger and no per-run or per-day cap.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

import pytest

from fazerops.agents import budget
from fazerops.agents.budget import TokenMeter, meter_for_mode
from fazerops.agents.correlator import NarrativeRejected
from fazerops.agents.proposer import ProposalRejected
from fazerops.agents.writer_author import WriterAuthoringFailed

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


# --------------------------------------------------------------------------------------
# A truncated structured-output call is still metered
# --------------------------------------------------------------------------------------


def _brief():
    from datetime import timedelta

    from fazerops.models import BlastRadius, Brief, CIStatus, TimeWindow

    alert = _alert()
    return Brief(
        incident_id="INC-truncated",
        alert=alert,
        radius=BlastRadius(service=alert.service),
        window=TimeWindow(start=alert.fired_at - timedelta(hours=4), end=alert.fired_at),
        ci_status=CIStatus(merge_count=0),
    )


async def _correlate(meter):
    from fazerops.agents.correlator import correlate

    await correlate(_brief(), meter=meter)


async def _propose(meter):
    from fazerops.agents.proposer import propose

    await propose(_brief(), meter=meter)


async def _author(meter):
    from fazerops.agents.writer_author import author_writer

    await author_writer({"kind": "ConfigMap"}, meter=meter)


@pytest.mark.parametrize(
    ("agent", "call", "rejection"),
    [
        ("correlator", _correlate, NarrativeRejected),
        ("proposer", _propose, ProposalRejected),
        ("writer_author", _author, WriterAuthoringFailed),
    ],
)
async def test_a_response_truncated_at_max_output_tokens_is_metered_before_it_is_rejected(
    monkeypatch, tmp_path, agent, call, rejection
):
    """What `MeteredGeminiModel` yields when a thinking model stops at `max_output_tokens`: usage,
    and no output. Each agent rejected that before `meter.record`, so the costliest call a run can
    make — the whole cap, spent thinking — never reached the ledger or either cap."""
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "gemini")

    from fazerops.agents import correlator

    class Truncated:
        async def structured_output(self, output_model, messages, system_prompt=None, **kwargs):
            yield {"metadata": {"usage": {"inputTokens": 3000, "outputTokens": 8192}}}

    monkeypatch.setattr(correlator, "_gemini_model", lambda model: Truncated())
    meter = TokenMeter(ledger_path=tmp_path / "token_ledger.jsonl")

    with pytest.raises(rejection, match="no structured output"):
        await call(meter)

    assert [(c["agent"], c["in"], c["out"], c["estimated"]) for c in meter.calls] == [
        (agent, 3000, 8192, False)
    ]
    assert (tmp_path / "token_ledger.jsonl").read_text(encoding="utf-8").count("\n") == 1
