"""W29 — the automation server writes the stages only it can see into the session store (Handoff §10).

The AgentCore Runtime persists what it investigates; approval and execution happen in this process, so
this is where they are written. Driven through a real `Automation`, a real sink and the real webhook;
the store is the only fake.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import _sandbox_fakes as fakes  # noqa: E402

from fazerops.actions.roster import Roster  # noqa: E402
from fazerops.actions.runtime import Automation  # noqa: E402
from fazerops.actions.server import build_app, session_persister  # noqa: E402
from fazerops.ingest.alerts import normalize_alert  # noqa: E402
from fazerops.slack.handlers import Decision, approval_sink  # noqa: E402

ALERT = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json").read_text(encoding="utf-8"))
ROSTER = Roster(engineers=["U_IC"], managers=["U_MGR"])


class Store:
    name = "fake"

    def __init__(self):
        self.saved = []

    def save(self, session):
        self.saved.append(session)
        return str(len(self.saved))


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


@pytest.fixture
def store():
    return Store()


@pytest.fixture
def automation(tmp_path, store):
    built = Automation.assemble(
        state_dir=tmp_path, runner=lambda *a: {"action_id": "revert_configmap_key"}, sandbox=fakes.factory()
    )
    built.decided_hooks.append(session_persister(built, store, background=False))
    return built


def _decide(automation, pending, kind="approve", user="U_IC"):
    return approval_sink(automation.gateway, resolve_approver=ROSTER.resolve)(
        Decision(kind=kind, incident_id=pending.incident_id, action_id=pending.action_id, user_id=user)
    )


async def test_an_approved_and_executed_decision_is_persisted_with_its_approver(automation, store):
    response = await automation.respond(normalize_alert(ALERT))
    [pending] = response.pending

    _decide(automation, pending)

    [session] = store.saved
    assert session.incident_id == pending.incident_id
    assert session.stage == "executed"
    assert session.approval.approver == "U_IC"
    assert session.candidates, "the investigation travels with the decision"


async def test_a_rejection_is_persisted_and_a_replay_writes_nothing_more(automation, store):
    response = await automation.respond(normalize_alert(ALERT))
    [pending] = response.pending

    _decide(automation, pending, kind="reject")
    _decide(automation, pending, kind="reject", user="U_MGR")

    [session] = store.saved
    assert session.stage == "rejected"


async def test_a_failing_store_does_not_change_the_decision(tmp_path):
    class Broken(Store):
        def save(self, session):
            raise RuntimeError("AccessDenied on PutItem")

    built = Automation.assemble(
        state_dir=tmp_path, runner=lambda *a: {"action_id": "revert_configmap_key"}, sandbox=fakes.factory()
    )
    built.decided_hooks.append(session_persister(built, Broken(), background=False))
    response = await built.respond(normalize_alert(ALERT))
    [pending] = response.pending

    assert "ran once" in _decide(built, pending)


def test_the_webhook_persists_the_investigated_stage(automation, store):
    with TestClient(build_app(automation, sessions=store)) as client:
        body = client.post("/alerts", json=ALERT).json()

    [session] = store.saved
    assert session.incident_id == body["incident_id"]
    assert session.stage == "proposed"
    assert session.proposal.action_id == "revert_configmap_key"


def test_no_store_means_the_webhook_writes_nothing(automation, store):
    with TestClient(build_app(automation)) as client:
        client.post("/alerts", json=ALERT)

    assert store.saved == []
