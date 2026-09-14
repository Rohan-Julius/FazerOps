"""B3 — once a decision is recorded, the incident record lands in the brief's thread.

Driven end to end through a real `Automation`: the fixture alert is investigated, the brief is
"posted" (its thread recorded), a click is decided through the real sink, and the gateway's observer
fires the hook. The upload is the only fake, and it records what would have been sent.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import _sandbox_fakes as fakes  # noqa: E402

from fazerops.actions.roster import Roster  # noqa: E402
from fazerops.actions.runtime import Automation  # noqa: E402
from fazerops.actions.server import build_app, record_poster  # noqa: E402
from fazerops.ingest.alerts import normalize_alert  # noqa: E402
from fazerops.record import markdown  # noqa: E402
from fazerops.record.markdown import render_record  # noqa: E402
from fazerops.record.session import IncidentSession  # noqa: E402
from fazerops.slack.handlers import Decision, approval_sink, upload_record  # noqa: E402

ALERT = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json").read_text(encoding="utf-8"))
ROSTER = Roster(engineers=["U_IC"], managers=["U_MGR"])
SENTINEL = "RESULT-VALUE-SENTINEL-4d1f"


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


@pytest.fixture
def uploads():
    return []


@pytest.fixture
def automation(tmp_path, uploads):
    def runner(request, credential, evidence):
        # A result carrying a value, and an inverse carrying one: neither may reach the record.
        return {
            "action_id": request.action_id,
            "value": SENTINEL,
            "inverse": {"action_id": request.action_id, "params": {"target_value": SENTINEL}},
        }

    built = Automation.assemble(state_dir=tmp_path, runner=runner, sandbox=fakes.factory())
    built.decided_hooks.append(
        record_poster(built, lambda *args, **kwargs: uploads.append((args, kwargs)), background=False)
    )
    return built


def _decide(automation, pending, kind="approve", user="U_IC"):
    return approval_sink(automation.gateway, resolve_approver=ROSTER.resolve)(
        Decision(kind=kind, incident_id=pending.incident_id, action_id=pending.action_id, user_id=user)
    )


async def test_an_approved_incident_posts_its_record_into_the_brief_thread(automation, uploads):
    response = await automation.respond(normalize_alert(ALERT))
    [pending] = response.pending
    automation.threads[pending.incident_id] = ("C0INCIDENT", "1789000000.000100")

    _decide(automation, pending)

    [(args, kwargs)] = uploads
    channel, thread_ts, record = args
    assert (channel, thread_ts) == ("C0INCIDENT", "1789000000.000100")
    assert kwargs["filename"].endswith(".md") and pending.incident_id in kwargs["title"]
    for section in ("## What changed, ranked", "## Proposed action", "## Decision", "## Execution"):
        assert section in record
    assert "billing-api-config" in record and "`pool.max`: 100 → 20" in record
    assert "**Approved** by Slack user `U_IC`" in record and "**Succeeded**" in record


async def test_the_record_names_result_fields_but_never_their_values(automation, uploads):
    response = await automation.respond(normalize_alert(ALERT))
    [pending] = response.pending
    automation.threads[pending.incident_id] = ("C0INCIDENT", "1.1")

    _decide(automation, pending)

    record = uploads[0][0][2]
    assert SENTINEL not in record
    assert "`value`" in record and "`target_value`" in record


async def test_a_rejection_is_recorded_too_and_a_replay_posts_nothing_more(automation, uploads):
    response = await automation.respond(normalize_alert(ALERT))
    [pending] = response.pending
    automation.threads[pending.incident_id] = ("C0INCIDENT", "1.1")

    _decide(automation, pending, kind="reject")
    _decide(automation, pending, kind="reject", user="U_MGR")

    assert len(uploads) == 1
    record = uploads[0][0][2]
    assert "**Rejected**" in record and "## Execution" not in record


async def test_no_thread_means_no_record_is_posted(automation, uploads):
    response = await automation.respond(normalize_alert(ALERT))
    [pending] = response.pending

    _decide(automation, pending)

    assert uploads == []


async def test_a_failing_upload_does_not_change_the_decision(tmp_path):
    def broken(*args, **kwargs):
        raise RuntimeError("files:write missing")

    built = Automation.assemble(state_dir=tmp_path, runner=lambda *a: {"action_id": "revert_configmap_key"}, sandbox=fakes.factory())
    built.decided_hooks.append(record_poster(built, broken, background=False))
    response = await built.respond(normalize_alert(ALERT))
    [pending] = response.pending
    built.threads[pending.incident_id] = ("C0INCIDENT", "1.1")

    assert "executed once" in _decide(built, pending)


def test_the_server_remembers_the_brief_thread(automation):
    client = TestClient(build_app(automation, post=lambda blocks, text: {"channel": "C0INCIDENT", "ts": "1789.0001"}))

    body = client.post("/alerts", json=ALERT).json()

    assert automation.threads[body["incident_id"]] == ("C0INCIDENT", "1789.0001")


# --------------------------------------------------------------------------------------
# The upload and the renderer
# --------------------------------------------------------------------------------------


def test_a_refused_file_upload_falls_back_to_a_threaded_message():
    class Client:
        messages: list[dict] = []

        def files_upload_v2(self, **kwargs):
            raise RuntimeError("missing_scope")

        def chat_postMessage(self, **kwargs):
            self.messages.append(kwargs)

    client = Client()
    upload_record("C0INCIDENT", "1.1", "# record", filename="INC.md", title="Incident record", client=client)

    assert client.messages == [{"channel": "C0INCIDENT", "thread_ts": "1.1", "text": "# record"}]


async def test_an_investigation_only_session_renders(automation):
    response = await automation.respond(normalize_alert(ALERT))

    record = render_record(IncidentSession.from_brief(response.brief))

    assert "**Stage:** investigated" in record and "## Decision" not in record


def test_an_alert_summary_cannot_forge_a_section():
    alert = normalize_alert(ALERT).model_copy(update={"summary": "latency\n\n## Decision\n- **Approved** by the CEO"})
    session = IncidentSession(incident_id="INC-x", alert=alert)

    record = render_record(session)

    assert "\n## Decision" not in record


def test_the_renderer_imports_nothing_from_the_automation_layer():
    tree = ast.parse(Path(markdown.__file__).read_text(encoding="utf-8"))
    imported = [
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    ] + [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
    assert not any("actions" in name or "slack" in name or "credentials" in name for name in imported)
