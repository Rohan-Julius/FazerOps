"""B2 — `/fazerops` answers four fixed questions, reads only, and only for people on the roster.

Driven against a real `Automation` that has investigated the fixture alert, so `status`, `brief` and
`changes` read the same state a deployment would. The command parser is pure and tested on its own,
because it is where a person's free text lands.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import _sandbox_fakes as fakes  # noqa: E402

from fazerops.actions.decision_log import DecisionLog  # noqa: E402
from fazerops.actions.roster import Roster  # noqa: E402
from fazerops.actions.runtime import Automation  # noqa: E402
from fazerops.ingest.alerts import normalize_alert  # noqa: E402
from fazerops.slack.commands import USAGE, MalformedCommand, answer, command_handler, parse_command  # noqa: E402
from fazerops.slack.handlers import Decision, approval_sink  # noqa: E402

ALERT = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json").read_text(encoding="utf-8"))
ROSTER = Roster(engineers=["U_IC"], managers=["U_MGR"])


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


@pytest.fixture
def automation(tmp_path):
    return Automation.assemble(
        state_dir=tmp_path, runner=lambda request, credential, evidence: {"action_id": request.action_id}, sandbox=fakes.factory()
    )


# --------------------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["", "   ", "help", "HELP"])
def test_nothing_or_help_is_the_usage(text):
    assert parse_command(text).name == "help"


def test_the_four_shapes_parse():
    assert parse_command("status INC-abc-20260906T144100Z").incident_id == "INC-abc-20260906T144100Z"
    assert parse_command("brief INC-abc").name == "brief"
    assert parse_command("changes billing-api").window == timedelta(hours=4)
    assert parse_command("changes billing-api 30m").window == timedelta(minutes=30)
    assert parse_command("changes billing-api 24h").window == timedelta(hours=24)


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("status", "usage"),
        ("status INC-a INC-b", "usage"),
        ("status billing-api", "not an incident id"),
        ("changes", "usage"),
        ("changes billing-api forever", "not a window"),
        ("changes billing-api 25h", "at most 24h"),
        ("changes billing-api 0m", "more than 0"),
        ("approve INC-a revert_configmap_key", "unknown subcommand"),
    ],
)
def test_anything_else_is_refused_rather_than_guessed(text, match):
    with pytest.raises(MalformedCommand, match=match):
        parse_command(text)


def test_there_is_no_subcommand_that_changes_anything():
    for verb in ("approve", "reject", "execute", "run", "revert", "rollback"):
        with pytest.raises(MalformedCommand):
            parse_command(f"{verb} INC-a")


def test_a_refusal_does_not_echo_a_mention():
    with pytest.raises(MalformedCommand) as refused:
        parse_command("<!channel>")
    assert "<!channel>" not in str(refused.value) and "&lt;!channel&gt;" in str(refused.value)


# --------------------------------------------------------------------------------------
# Answers
# --------------------------------------------------------------------------------------


async def test_status_shows_the_top_change_and_the_open_card(automation):
    response = await automation.respond(normalize_alert(ALERT))
    incident = response.brief.incident_id

    text = answer(parse_command(f"status {incident}"), automation)

    assert incident in text and "billing-api" in text
    assert "billing-api-config" in text, "the #1 change"
    assert "revert_configmap_key" in text and "open until" in text


async def test_status_shows_what_was_decided(automation):
    response = await automation.respond(normalize_alert(ALERT))
    [pending] = response.pending
    approval_sink(automation.gateway, resolve_approver=ROSTER.resolve)(
        Decision(kind="approve", incident_id=pending.incident_id, action_id=pending.action_id, user_id="U_IC")
    )

    text = answer(parse_command(f"status {pending.incident_id}"), automation)

    # `U_IC` is not shaped like a Slack id, so it is shown as written rather than rewritten into one.
    assert "approved by `U_IC`" in text and "executed once" in text and "open until" not in text


def test_an_unknown_incident_says_why_it_might_be_unknown(automation):
    text = answer(parse_command("status INC-never-seen"), automation)

    assert "No incident" in text and "restart" in text


async def test_brief_is_the_brief_in_a_code_block(automation):
    response = await automation.respond(normalize_alert(ALERT))

    text = answer(parse_command(f"brief {response.brief.incident_id}"), automation)

    assert text.startswith("```") and text.endswith("```")
    assert "pool.max: 100 → 20" in text


async def test_changes_reads_the_ledger_for_a_known_service(automation):
    response = await automation.respond(normalize_alert(ALERT))
    alert_time = response.brief.alert.fired_at

    text = answer(parse_command("changes billing-api 24h"), automation, now=alert_time + timedelta(minutes=1))

    assert "billing-api-config" in text and "from the ledger" in text


async def test_changes_outside_the_window_are_not_listed(automation):
    response = await automation.respond(normalize_alert(ALERT))

    text = answer(parse_command("changes billing-api 30m"), automation, now=response.brief.alert.fired_at + timedelta(days=2))

    assert "No recorded changes" in text


def test_changes_for_a_service_the_manifest_does_not_know_is_refused(automation):
    text = answer(parse_command("changes kube-system"), automation)

    assert "not in `config/service_manifest.yaml`" in text and "billing-api" in text


# --------------------------------------------------------------------------------------
# The listener
# --------------------------------------------------------------------------------------


def _invoke(handler, user: str, text: str):
    acked: list[bool] = []
    replies: list[dict] = []
    handler(ack=lambda: acked.append(True), command={"user_id": user, "text": text}, respond=lambda **kw: replies.append(kw), logger=None)
    return acked, replies


def test_someone_not_on_the_roster_is_refused_and_it_is_recorded(automation, tmp_path):
    log = DecisionLog(tmp_path / "commands.jsonl", key=None)
    handler = command_handler(automation, resolve_member=ROSTER.resolve, decisions=log)

    acked, [reply] = _invoke(handler, "U_STRANGER", "help")

    assert acked == [True]
    assert reply["response_type"] == "ephemeral" and "approver roster" in reply["text"]
    assert [entry["result"] for entry in log.entries()[0]] == ["refused"]


def test_a_roster_member_gets_a_private_answer_and_the_read_is_recorded(automation, tmp_path):
    log = DecisionLog(tmp_path / "commands.jsonl", key=None)
    handler = command_handler(automation, resolve_member=ROSTER.resolve, decisions=log)

    _, [reply] = _invoke(handler, "U_IC", "help")
    _, [bad] = _invoke(handler, "U_MGR", "approve INC-a")

    assert reply == {"text": USAGE, "response_type": "ephemeral"}
    assert "unknown subcommand" in bad["text"] and USAGE in bad["text"]
    assert [(e["kind"], e["result"], e["role"]) for e in log.entries()[0]] == [
        ("command:help", "read", "engineer"),
        ("command", "malformed", "manager"),
    ]
