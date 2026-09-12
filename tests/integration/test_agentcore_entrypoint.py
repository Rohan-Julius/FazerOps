"""W29 — the AgentCore entrypoint and the session state it returns. Handoff §10, plan §4.

The plan's e2e assertion — *"deployed endpoint returns a JSON-serializable brief for a
fixture alert"* — needs a deployed endpoint, which creates AWS resources and therefore
needs an explicit decision. **Everything about that response that can be checked without
deploying is checked here**, so the deploy is verifying infrastructure rather than
discovering that the handler was wrong all along.

Three of these are about failures that only surface *once deployed*, which is the
expensive place to find them:

* a `datetime` anywhere in the response makes the runtime's serialization fail;
* `BedrockAgentCoreApp` has exactly one entrypoint, so a second `@app.entrypoint` silently
  replaces the first and the endpoint quietly serves the wrong handler;
* Handoff §10 lists eight things the session must persist, and a missing one is invisible
  until someone reads a record and finds a hole in it.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

FIXTURE_ALERTS = Path(__file__).resolve().parents[2] / "fixtures" / "alerts"


@pytest.fixture(autouse=True)
def fixture_mode(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


@pytest.fixture
def entrypoint():
    pytest.importorskip("bedrock_agentcore", reason="pip install bedrock-agentcore")

    import agentcore_app

    return agentcore_app


def _alert_payload(name: str = "alertmanager.json") -> dict:
    return json.loads((FIXTURE_ALERTS / name).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------
# The response
# --------------------------------------------------------------------------------------


async def test_the_entrypoint_returns_the_demo_brief(entrypoint):
    response = await entrypoint.invoke({"alert": _alert_payload()})

    assert response["incident_id"] == "INC-7c1f9a2e4b6d8033"
    assert "billing-api-config" in response["brief"]
    assert "pool.max: 100 → 20" in response["brief"]
    assert response["stage"] == "investigated"
    assert response["degraded"] is False


async def test_a_bare_alert_payload_works_too(entrypoint):
    """Wrapping in `{"alert": ...}` is a convention only this file would know about, and a
    real caller sends one of the three payload shapes `ingest/alerts.py` normalizes."""
    response = await entrypoint.invoke(_alert_payload())

    assert response["incident_id"] == "INC-7c1f9a2e4b6d8033"


@pytest.mark.parametrize("shape", ["alertmanager.json", "cloudwatch.json", "pagerduty.json"])
async def test_all_three_payload_shapes_are_accepted(entrypoint, shape):
    response = await entrypoint.invoke(_alert_payload(shape))

    assert "error" not in response
    assert response["brief"]


async def test_the_whole_response_is_json_serializable(entrypoint):
    """AgentCore serializes the response (plan §1.1). A `datetime` left anywhere in it
    fails at the runtime boundary — after a deploy, in a log nobody is watching."""
    response = await entrypoint.invoke({"alert": _alert_payload()})

    encoded = json.dumps(response)  # raises on anything that is not JSON
    assert json.loads(encoded)["incident_id"] == "INC-7c1f9a2e4b6d8033"

    def _no_datetimes(value, path="response"):
        assert not isinstance(value, datetime), f"{path} is a datetime"
        if isinstance(value, dict):
            for key, item in value.items():
                _no_datetimes(item, f"{path}.{key}")
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                _no_datetimes(item, f"{path}[{index}]")

    _no_datetimes(response)


async def test_an_unrecognised_payload_is_refused_rather_than_guessed(entrypoint):
    """A permissively-parsed alert yields the wrong service, and the brief then
    investigates the wrong blast radius with total confidence."""
    response = await entrypoint.invoke({"alert": {"nothing": "recognisable"}})

    assert "error" in response
    assert "brief" not in response


async def test_the_response_reports_the_configuration_it_came_up_in(entrypoint, monkeypatch):
    """A container that silently defaulted to `fixture` when it was meant to be `live`
    produces a brief that looks entirely normal and is about the wrong world."""
    response = await entrypoint.invoke({"alert": _alert_payload()})

    assert response["runtime"] == {"mode": "fixture", "llm": "stub"}


def test_there_is_exactly_one_entrypoint(entrypoint):
    """`@app.entrypoint` registers under the single key `"main"`, so a second decorated
    function *replaces* the first rather than adding a route — the endpoint would then
    serve whichever was defined last, silently."""
    assert set(entrypoint.app.handlers) == {"main"}
    assert entrypoint.app.handlers["main"].__name__ == "invoke"


def test_the_entrypoint_cannot_reach_the_automation_layer(entrypoint):
    """Tier 0 only (plan §3.5). A deployed HTTP endpoint that could execute an action makes
    ground rule #5 false the moment it is public, so the assertion is about what the module
    imports, not about what it happens to call."""
    import ast

    source = Path(entrypoint.__file__).read_text(encoding="utf-8")
    imported = {
        node.module or ""
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
    } | {
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import)
        for alias in node.names
    }

    for module in imported:
        assert not module.startswith("fazerops.actions"), module
        assert not module.startswith("fazerops.slack"), module
        assert not module.startswith("fazerops.security.credentials"), module


# --------------------------------------------------------------------------------------
# Handoff §10's session state
# --------------------------------------------------------------------------------------


async def test_the_session_carries_every_field_handoff_ten_lists(entrypoint):
    """*"incident id, alert, resolved blast radius, collected events, scored candidates,
    proposal, approval decision and approver, execution result."*

    The last three are `None` on a Tier 0 run and that is correct — they are the automation
    layer's, and this endpoint is read-only. The assertion is that the *fields exist*, so
    the record has somewhere to put them.
    """
    session = (await entrypoint.invoke({"alert": _alert_payload()}))["session"]

    for field in (
        "incident_id",
        "alert",
        "radius",
        "window",
        "events",
        "candidates",
        "proposal",
        "approval",
        "execution",
    ):
        assert field in session, f"Handoff §10 requires {field}"

    assert session["radius"]["service"] == "billing-api"
    assert len(session["candidates"]) == 3
    assert session["events"], "the collected events, not only the ranked ones"
    assert session["proposal"] is None, "Tier 0 proposes nothing from a deployed endpoint"


def test_the_session_stage_is_derived_and_not_stored():
    """A stored stage is a second source of truth that goes stale the moment a field is set
    without it being updated."""
    from datetime import timezone

    from fazerops.models import Alert
    from fazerops.record.session import ApprovalRecord, ExecutionRecord, IncidentSession

    alert = Alert(
        id="a",
        service="billing-api",
        summary="latency",
        fired_at=datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc),
    )
    session = IncidentSession(incident_id="INC-a", alert=alert)
    assert session.stage == "opened"

    approved = session.with_approval(
        ApprovalRecord(
            decision="approved",
            approver="U0IC",
            approved_at=datetime(2026, 9, 6, 14, 45, tzinfo=timezone.utc),
            action_id="revert_configmap_key",
            tier=1,
        )
    )
    assert approved.stage == "approved"

    executed = approved.with_execution(
        ExecutionRecord(
            action_id="revert_configmap_key",
            succeeded=True,
            executed_at=datetime(2026, 9, 6, 14, 46, tzinfo=timezone.utc),
        )
    )
    assert executed.stage == "executed"

    failed = approved.with_execution(
        ExecutionRecord(
            action_id="revert_configmap_key",
            succeeded=False,
            executed_at=datetime(2026, 9, 6, 14, 46, tzinfo=timezone.utc),
            error="boom",
        )
    )
    assert failed.stage == "execution_failed"


async def test_the_session_is_recordable_without_the_automation_layer_having_run(entrypoint):
    """Tier 0 is the product. A session must serialize completely with every automation
    field empty, because that is the state most runs end in."""
    from fazerops.record.session import IncidentSession

    session = IncidentSession.model_validate(
        (await entrypoint.invoke({"alert": _alert_payload()}))["session"]
    )

    assert session.proposal is None
    assert session.approval is None
    assert session.execution is None
    assert session.stage == "investigated"
    assert json.loads(session.model_dump_json())["incident_id"] == "INC-7c1f9a2e4b6d8033"
