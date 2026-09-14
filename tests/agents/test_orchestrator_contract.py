"""W19b — the orchestrator's contract. Plan §4.

Three assertions, and the plan names all three because the orchestrator is the first node
in the graph and its failure mode is total:

1. For the demo alert it resolves `billing-api`, a 4h window, and dispatches all four
   collectors.
2. A service not in the manifest is rejected **by the tool schema, not the prompt**.
3. The iteration cap terminates a pathological loop and surfaces a partial brief.

(2) and (3) drive the real Strands agentic loop through a scripted provider — see
`scripted_model.py`. Mocking `Agent` would have asserted against the mock.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from fazerops.agents.orchestrator import (
    MAX_TURNS,
    SERVICE_NAMES,
    WINDOW_HOURS,
    OrchestrationSession,
    build_tools,
    orchestrate,
)
from fazerops.models import Alert, AlertClass

from scripted_model import ScriptedModel  # tests/agents is on sys.path under pytest rootdir insertion

FIRED_AT = datetime(2026, 9, 9, 14, 30, tzinfo=timezone.utc)


def demo_alert(summary: str = "p99 latency for billing-api is 4200ms, up from 180ms") -> Alert:
    return Alert(
        id="A-1",
        service="billing-api",
        summary=summary,
        fired_at=FIRED_AT,
        alert_class=AlertClass.LATENCY_SPIKE,
        severity="critical",
    )


@pytest.fixture
def gemini_mode(monkeypatch):
    """A model mode, so the offline guard and `model_for` stay live while the provider is
    substituted. `stub` would skip the agentic loop entirely, which is the thing under test.
    """
    monkeypatch.setenv("FAZEROPS_LLM", "gemini")
    monkeypatch.setenv("FAZEROPS_MODE", "live")


# --------------------------------------------------------------------------------------
# 1. The demo alert
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_demo_alert_resolves_billing_api_over_four_hours(gemini_mode):
    model = ScriptedModel(
        [
            ("tool", "resolve_blast_radius", {"service": "billing-api"}),
            ("tool", "compute_window", {"hours": 4}),
            ("tool", "dispatch_collectors", {"radius_id": "radius-1", "window_id": "window-1"}),
            ("text", "Resolved billing-api over the last 4 hours and dispatched collection."),
        ]
    )
    session = OrchestrationSession(demo_alert())

    plan = await orchestrate(demo_alert(), session=session, model_client=model)

    assert plan.service == "billing-api"
    assert plan.dispatched is True
    assert plan.degraded is False
    assert plan.window.hours == 4
    assert plan.window.end == FIRED_AT
    assert session.calls == ["resolve_blast_radius", "compute_window", "dispatch_collectors"]


@pytest.mark.asyncio
async def test_dispatch_names_all_four_sources(gemini_mode):
    """Handoff §5's four sources, from the tool the agent actually called.

    Asserted on the tool's own return value rather than on `build_collectors()`, because
    the claim is that the *agent* started all four — a brief built from three sources that
    says nothing changed is the failure this whole project exists to prevent.
    """
    session = OrchestrationSession(demo_alert())
    tools = {t.tool_name: t for t in build_tools(session)}

    radius = _call(tools["resolve_blast_radius"], service="billing-api")
    window = _call(tools["compute_window"], hours=4)
    result = _call(
        tools["dispatch_collectors"],
        radius_id=radius["radius_id"],
        window_id=window["window_id"],
    )

    assert result["dispatched"] is True
    assert set(result["sources"]) == {"cloudtrail", "k8s_audit", "helm", "github"}


@pytest.mark.asyncio
async def test_stub_mode_plans_deterministically_without_a_model(monkeypatch):
    """The CI default and a judge's clean machine. No model, no network, not degraded."""
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")

    plan = await orchestrate(demo_alert())

    assert plan.service == "billing-api"
    assert plan.dispatched is True
    assert plan.degraded is False, "stub is a chosen path, not a degraded one"
    assert plan.window.hours == 4
    assert plan.radius.keys, "the demo service must resolve to a non-empty radius"


# --------------------------------------------------------------------------------------
# 2. Rejected by the schema, not by the prompt
# --------------------------------------------------------------------------------------


def test_service_enum_is_the_manifest_not_a_prompt_instruction():
    """The list of services in the tool schema is the manifest's, read at import time.

    If this ever becomes a free-form string, the model can name a service that does not
    exist, `resolve()` returns an empty radius by design, and the brief reports with total
    confidence that nothing changed.
    """
    session = OrchestrationSession(demo_alert())
    tools = {t.tool_name: t for t in build_tools(session)}

    schema = tools["resolve_blast_radius"].tool_spec["inputSchema"]["json"]
    assert schema["properties"]["service"]["enum"] == list(SERVICE_NAMES)
    assert "billing-api" in SERVICE_NAMES
    assert "payments-api" not in SERVICE_NAMES


def test_window_hours_is_bounded_by_the_schema():
    """Plan §3.1 bounds `hours` to [1, 24]. Strands rejects `Annotated[int, Field(ge=...)]`,
    so the bound is the enum of permitted values — which is stricter, not weaker."""
    session = OrchestrationSession(demo_alert())
    tools = {t.tool_name: t for t in build_tools(session)}

    schema = tools["compute_window"].tool_spec["inputSchema"]["json"]
    assert schema["properties"]["hours"]["enum"] == list(WINDOW_HOURS)
    assert min(WINDOW_HOURS) == 1 and max(WINDOW_HOURS) == 24


@pytest.mark.asyncio
async def test_unknown_service_never_reaches_the_resolver(gemini_mode):
    """A model that names a service outside the enum gets a validation error back from the
    tool executor, and the run degrades rather than silently investigating nothing."""
    model = ScriptedModel(
        [("tool", "resolve_blast_radius", {"service": "payments-api"})]
    )
    session = OrchestrationSession(demo_alert())

    plan = await orchestrate(demo_alert(), session=session, model_client=model)

    assert session.radii == {}, "no radius may be minted for a service the manifest lacks"
    assert plan.dispatched is False
    assert plan.degraded is True
    # It still returns a usable plan: the alert's own service over the default window.
    assert plan.service == "billing-api"


@pytest.mark.asyncio
async def test_invented_handle_is_refused_rather_than_executed(gemini_mode):
    """Ground rule #1 at the handle level. `dispatch_collectors` takes only ids the tools
    minted; an id the model made up is an error it is told about, not a query it runs."""
    model = ScriptedModel(
        [
            ("tool", "resolve_blast_radius", {"service": "billing-api"}),
            ("tool", "dispatch_collectors", {"radius_id": "radius-1", "window_id": "window-99"}),
            ("text", "done"),
        ]
    )
    session = OrchestrationSession(demo_alert())

    plan = await orchestrate(demo_alert(), session=session, model_client=model)

    assert session.dispatched == [], "an unminted handle must not count as a dispatch"
    assert plan.dispatched is False and plan.degraded is True


# --------------------------------------------------------------------------------------
# 3. The turn cap
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_turn_cap_terminates_a_pathological_loop(gemini_mode):
    """A model that calls the same tool forever. The cap stops it; the run still produces
    a plan.

    This is plan §5's second guardrail, and the one with **no visible symptom** — a
    runaway loop renders a perfectly correct brief and only the bill knows. The script is
    one entry long and `ScriptedModel` repeats its last turn, so the loop is genuinely
    unbounded and the only thing ending it is `Limits(turns=MAX_TURNS)`.
    """
    model = ScriptedModel([("tool", "resolve_blast_radius", {"service": "billing-api"})])
    session = OrchestrationSession(demo_alert())

    plan = await orchestrate(demo_alert(), session=session, model_client=model)

    # Equality, not `<=`. `<=` would also pass if the loop had stopped after one turn for
    # some unrelated reason, which would leave the cap untested. Raising MAX_TURNS raises
    # this count one-for-one (probed 11 Sep), so this asserts the cap is the only thing
    # ending an otherwise unbounded loop.
    assert len(session.calls) == MAX_TURNS, (
        f"the loop ran {len(session.calls)} times against a cap of {MAX_TURNS}"
    )
    assert plan.dispatched is False
    assert plan.degraded is True
    assert plan.note and "default scope" in plan.note
    # The partial brief: a real radius and a real window, so the investigation continues.
    assert plan.radius.keys and plan.window.hours == 4


@pytest.mark.asyncio
async def test_a_model_that_never_dispatches_still_yields_a_plan(gemini_mode):
    """The quieter failure: the agent answers in prose without finishing the job."""
    model = ScriptedModel([("text", "I think you should look at billing-api.")])
    session = OrchestrationSession(demo_alert())

    plan = await orchestrate(demo_alert(), session=session, model_client=model)

    assert plan.dispatched is False and plan.degraded is True
    assert plan.service == "billing-api" and plan.window.hours == 4


def test_max_turns_is_four():
    """Plan §3.1's cap, asserted as a number so a later loosening is a visible diff rather
    than a quiet one."""
    assert MAX_TURNS == 4


# --------------------------------------------------------------------------------------


def _call(tool, **params):
    """Invoke the undecorated function behind a `@tool` wrapper.

    Strands keeps it on `_tool_func`; going through `.stream()` would need a full tool-use
    event and an executor, which is what the agentic tests above already exercise.
    """
    result = tool._tool_func(**params)
    return result if isinstance(result, dict) else json.loads(result)


# --------------------------------------------------------------------------------------
# Cassette mode
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_missing_orchestrator_cassette_degrades_rather_than_raising(monkeypatch):
    """There is no orchestrator tape yet — recording one needs a `GEMINI_API_KEY`, and the
    key in `.env` is the leaked one awaiting rotation.

    The miss must behave like every other model failure: the investigation continues with
    the deterministic scope, and the brief says so. A raise here would take down the
    correlator's own cassette tests, which have nothing to do with the orchestrator.
    """
    monkeypatch.setenv("FAZEROPS_LLM", "cassette")
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")

    plan = await orchestrate(demo_alert())

    assert plan.service == "billing-api"
    assert plan.window.hours == 4
    assert plan.degraded is True, "a missing tape must never read as success"
    assert plan.note and "cassette" in plan.note


# --------------------------------------------------------------------------------------
# Spend before a failure still reaches the meter
# --------------------------------------------------------------------------------------


class _FailsOnSecondTurn(ScriptedModel):
    """One real, metered tool turn, then `failure` — an exception, or a hang."""

    def __init__(self, failure):
        super().__init__([("tool", "resolve_blast_radius", {"service": "billing-api"})])
        self._failure = failure

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs):
        if self._index >= 1:
            await self._failure()
        async for event in super().stream(messages, tool_specs, system_prompt, **kwargs):
            yield event


@pytest.mark.asyncio
async def test_turns_billed_before_an_exception_are_metered(gemini_mode, tmp_path):
    """A 429 escaping the loop after a completed turn. `result` was `None`, and the meter was
    skipped — the retrying loop `TokenMeter` exists to catch left no ledger line."""
    from fazerops.agents.budget import TokenMeter

    async def throttled():
        raise RuntimeError("429 Too Many Requests")

    meter = TokenMeter(ledger_path=tmp_path / "token_ledger.jsonl")
    session = OrchestrationSession(demo_alert())

    plan = await orchestrate(demo_alert(), session=session, meter=meter, model_client=_FailsOnSecondTurn(throttled))

    # Strands wraps the provider's error in its own `EventLoopException`, so the note names that.
    assert plan.degraded is True and "did not finish" in (plan.note or "")
    assert [(c["agent"], c["in"], c["out"]) for c in meter.calls] == [("orchestrator", 120, 30)]


@pytest.mark.asyncio
async def test_turns_billed_before_the_nodes_timeout_are_metered(gemini_mode, tmp_path):
    """The graph node cancels a slow orchestrator (`ORCHESTRATOR_TIMEOUT_SECONDS`). The turns it
    completed were billed; the cancellation still propagates, so the node still times out."""
    import asyncio

    from fazerops.agents.budget import TokenMeter

    async def hangs():
        await asyncio.sleep(60)

    meter = TokenMeter(ledger_path=tmp_path / "token_ledger.jsonl")
    session = OrchestrationSession(demo_alert())

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(
            orchestrate(demo_alert(), session=session, meter=meter, model_client=_FailsOnSecondTurn(hangs)),
            timeout=0.5,
        )

    assert [(c["agent"], c["in"], c["out"]) for c in meter.calls] == [("orchestrator", 120, 30)]
