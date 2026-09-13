"""The automation layer, assembled — an alert through to an executed approval, in one process.

Before this, every hook Phase G added was an injection nothing in production made: the gateway
never saw a proposal outside a test, the outcome observer never saw an outcome, and the one-shot
book was never offered a decline. These tests drive `Automation` and the automation server as a
deployment would, with only the cluster, the model and Slack faked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import _sandbox_fakes as fakes  # noqa: E402
from _growth_events import T0, binary_data_change, brief_for  # noqa: E402

from fazerops.actions.growth.signals import GapSignalStore, SignalKind  # noqa: E402
from fazerops.actions.roster import Roster  # noqa: E402
from fazerops.actions.runtime import Automation  # noqa: E402
from fazerops.actions.server import build_app, messages_for  # noqa: E402
from fazerops.ingest.alerts import normalize_alert  # noqa: E402
from fazerops.slack.handlers import Decision, approval_sink  # noqa: E402

ALERT = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json").read_text(encoding="utf-8"))
ROSTER = Roster(engineers=["U_IC"], managers=["U_MGR"])


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


@pytest.fixture
def executions():
    return []


@pytest.fixture
def automation(tmp_path, executions):
    def runner(request, credential, evidence):
        executions.append(request.action_id)
        return {"action_id": request.action_id}

    return Automation.assemble(state_dir=tmp_path, runner=runner, sandbox=fakes.factory())


async def test_an_alert_reaches_the_gateway_and_one_approval_executes_once(automation, executions, tmp_path):
    response = await automation.respond(normalize_alert(ALERT))

    [pending] = response.pending
    assert response.proposal.action_id == "revert_configmap_key" and pending.action_id == "revert_configmap_key"
    assert (tmp_path / "ledger.jsonl").is_file(), "the durable ledger holds what the investigation saw"

    sink = approval_sink(automation.gateway, resolve_approver=ROSTER.resolve)
    click = Decision(kind="approve", incident_id=pending.incident_id, action_id=pending.action_id, user_id="U_IC")
    sink(click)
    assert "Nothing was re-run" in sink(click)
    assert executions == ["revert_configmap_key"]


async def test_the_outcome_observer_is_wired_and_persists(automation, tmp_path):
    response = await automation.respond(normalize_alert(ALERT))
    [pending] = response.pending
    approval_sink(automation.gateway, resolve_approver=ROSTER.resolve)(
        Decision(kind="approve", incident_id=pending.incident_id, action_id=pending.action_id, user_id="U_IC")
    )

    reloaded = GapSignalStore(tmp_path / "gap_signals.jsonl")
    assert [s.kind for s in reloaded.signals()] == [SignalKind.EXECUTED]


async def test_a_decline_is_recorded_and_its_one_shot_reaches_a_card(automation, monkeypatch, tmp_path, executions):
    import fazerops.agents.graph as graph_module
    import fazerops.agents.proposer as proposer_module

    brief = brief_for("INC-9", binary_data_change("evt-binary", at=T0))
    monkeypatch.setattr(graph_module, "_brief_from", lambda state, narrative: brief)

    async def declines(*args, **kwargs):
        return None

    monkeypatch.setattr(proposer_module, "propose", declines)
    response = await automation.respond(normalize_alert(ALERT))

    assert response.proposal is None and response.one_shot.offered
    [pending] = response.pending
    assert pending.one_shot is not None
    assert [s.kind for s in GapSignalStore(tmp_path / "gap_signals.jsonl").signals()] == [SignalKind.DECLINE]

    card = json.dumps(messages_for(response)[1][0])
    assert "One-shot" in card

    sink = approval_sink(automation.gateway, resolve_approver=ROSTER.resolve)
    click = dict(incident_id=pending.incident_id, action_id=pending.action_id)
    assert ":lock:" in sink(Decision(kind="approve", user_id="U_IC", **click)), "an engineer cannot approve a one-shot"
    sink(Decision(kind="approve", user_id="U_MGR", **click))
    sink(Decision(kind="approve", user_id="U_MGR", **click))
    assert executions == [pending.action_id]


def test_the_server_posts_the_brief_and_every_card(automation):
    posted: list[str] = []
    client = TestClient(build_app(automation, post=lambda blocks, text: posted.append(text)))

    body = client.post("/alerts", json=ALERT).json()

    assert body["proposal"] == "revert_configmap_key" and body["pending"] == ["revert_configmap_key"]
    assert body["posted"] == 2 and len(posted) == 2
    assert posted[1].startswith("Approval required")


def test_a_refired_alert_says_why_no_second_card_opened(automation):
    client = TestClient(build_app(automation))
    first = client.post("/alerts", json=ALERT).json()
    approval_sink(automation.gateway, resolve_approver=ROSTER.resolve)(
        Decision(kind="approve", incident_id=first["incident_id"], action_id="revert_configmap_key", user_id="U_IC")
    )

    again = client.post("/alerts", json=ALERT).json()
    assert again["pending"] == [] and "already approved" in again["refused"][0]


def test_the_server_schedules_catalog_growth_hourly_unless_told_otherwise(automation, monkeypatch):
    from fazerops.actions.server import GROWTH_EVERY_ENV, GROWTH_REPO_ENV, growth_schedule_from_env

    monkeypatch.delenv(GROWTH_EVERY_ENV, raising=False)
    monkeypatch.delenv(GROWTH_REPO_ENV, raising=False)
    schedule = growth_schedule_from_env(automation)
    assert schedule["every_minutes"] == 60 and schedule["repo"] is None
    assert schedule["state_dir"] == automation.state_dir, "the job mines what the incident path writes"

    monkeypatch.setenv(GROWTH_EVERY_ENV, "0")
    assert growth_schedule_from_env(automation) is None


def test_opening_prs_needs_a_repository_and_targets_main(automation, monkeypatch):
    from fazerops.actions.server import GROWTH_EVERY_ENV, GROWTH_OPEN_PR_ENV, GROWTH_REPO_ENV, growth_schedule_from_env

    monkeypatch.setenv(GROWTH_EVERY_ENV, "1")
    monkeypatch.setenv(GROWTH_OPEN_PR_ENV, "1")
    monkeypatch.delenv(GROWTH_REPO_ENV, raising=False)
    with pytest.raises(ValueError, match=GROWTH_REPO_ENV):
        growth_schedule_from_env(automation)

    monkeypatch.setenv(GROWTH_REPO_ENV, "/tmp/demo")
    schedule = growth_schedule_from_env(automation)
    assert schedule["open_prs"] is True and schedule["base"] == "main"


def test_an_unrecognised_payload_is_refused(automation):
    assert TestClient(build_app(automation)).post("/alerts", json={"hello": "world"}).status_code == 400


def test_the_tier_zero_entrypoints_still_import_nothing_from_the_automation_layer():
    """Read from the AST: both files discuss the automation layer in prose, at length."""
    import ast

    root = Path(__file__).resolve().parents[2]
    for path in (root / "src" / "fazerops" / "main.py", root / "agentcore_app.py"):
        imported = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                imported.add(("." * node.level) + (node.module or ""))
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        automation = {name for name in imported if name.lstrip(".").startswith(("actions", "slack", "fazerops.actions", "fazerops.slack"))}
        assert automation == set(), (path.name, automation)
        assert imported, "the walk found the imports at all"
