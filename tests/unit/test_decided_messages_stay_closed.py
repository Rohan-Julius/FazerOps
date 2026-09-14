"""Gaps 1 and 2 (14 Sep) — once an action is decided, no message offers it again.

An action is offered twice, on its approval card and on the brief. Two ways a decided action got its
buttons back: the coverage follow-up re-rendered the card and the brief from scratch whenever late
CloudTrail changes arrived, and a decision made on one message left the other untouched.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import _sandbox_fakes as fakes  # noqa: E402

from fazerops.actions.roster import Roster  # noqa: E402
from fazerops.actions.runtime import Automation  # noqa: E402
from fazerops.actions.server import _follow_coverage, decision_closer, messages_for  # noqa: E402
from fazerops.ingest.alerts import normalize_alert  # noqa: E402
from fazerops.slack.handlers import Decision, approval_sink  # noqa: E402

ALERT = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json").read_text(encoding="utf-8"))
ROSTER = Roster(engineers=["U_IC"], managers=["U_MGR"])
BRIEF_HANDLE = ("C0INCIDENT", "1789000000.000100")
CARD_HANDLE = ("C0INCIDENT", "1789000000.000200")


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


@pytest.fixture
def automation(tmp_path):
    return Automation.assemble(state_dir=tmp_path, runner=lambda *args: {"action_id": "revert_configmap_key"}, sandbox=fakes.factory())


def _buttons(blocks: list[dict]) -> set[str]:
    return {
        element.get("action_id")
        for block in blocks
        if block.get("type") == "actions"
        for element in block.get("elements") or []
    }


def _decide(automation, pending, kind: str = "approve"):
    approval_sink(automation.gateway, resolve_approver=ROSTER.resolve)(
        Decision(kind=kind, incident_id=pending.incident_id, action_id=pending.action_id, user_id="U_IC")
    )


async def _posted(automation):
    """Investigate, and record where the brief and its card were posted, as the server does."""
    response = await automation.respond(normalize_alert(ALERT))
    [pending] = response.pending
    automation.threads[pending.incident_id] = BRIEF_HANDLE
    automation.cards[pending.key] = CARD_HANDLE
    return response, pending


async def test_only_the_card_offers_the_decision_before_it_is_made(automation):
    """Plan §9.2 (14 Sep): one decision, one place to make it."""
    response, _ = await _posted(automation)
    (brief_blocks, _), (card_blocks, _) = messages_for(response)

    assert not {"approve", "reject"} & _buttons(brief_blocks)
    assert {"approve", "reject"} <= _buttons(card_blocks)


async def test_a_decision_closes_both_the_card_and_the_brief(automation):
    _, pending = await _posted(automation)
    edits: list[tuple] = []
    automation.decided_hooks.append(
        decision_closer(automation, lambda channel, ts, blocks, text: edits.append(((channel, ts), blocks)), background=False)
    )

    _decide(automation, pending)

    assert {handle for handle, _ in edits} == {BRIEF_HANDLE, CARD_HANDLE}
    for _, blocks in edits:
        assert not {"approve", "reject"} & _buttons(blocks), "a decided action is offered nowhere"
        assert "<@U_IC> approved" in json.dumps(blocks)


async def test_a_rejection_closes_them_too(automation):
    _, pending = await _posted(automation)
    edits: list[tuple] = []
    automation.decided_hooks.append(decision_closer(automation, lambda *args, **kwargs: edits.append(args), background=False))

    _decide(automation, pending, kind="reject")

    assert len(edits) == 2 and all("rejected" in json.dumps(blocks) for *_, blocks in edits)


async def test_the_brief_keeps_show_all_when_it_closes(automation):
    _, pending = await _posted(automation)
    edits: list[tuple] = []
    automation.decided_hooks.append(
        decision_closer(automation, lambda channel, ts, blocks, text: edits.append(((channel, ts), blocks)), background=False)
    )
    _decide(automation, pending)

    [brief_blocks] = [blocks for handle, blocks in edits if handle == BRIEF_HANDLE]
    if "show_all" in _buttons(messages_for((await automation.respond(normalize_alert(ALERT))))[0][0]):
        assert "show_all" in _buttons(brief_blocks)


async def test_the_coverage_follow_up_never_restores_buttons_on_a_decided_action(automation, monkeypatch):
    response, pending = await _posted(automation)
    _decide(automation, pending)

    # Make the follow-up's coverage note change, which is what triggers a card re-render.
    import fazerops.render.text as render_text

    notes = iter([None, "late changes may still arrive"])
    monkeypatch.setattr(render_text, "approval_card_note", lambda brief: next(notes))

    async def one_update(brief, on_update, *, sleep=None, **kwargs):
        on_update(SimpleNamespace(brief=brief, late_event_ids=()))
        return brief

    monkeypatch.setattr(automation, "follow_coverage", one_update)
    edits: list[tuple] = []

    await _follow_coverage(
        automation,
        response,
        [BRIEF_HANDLE, CARD_HANDLE],
        lambda channel, ts, blocks, text: edits.append(((channel, ts), blocks)),
        sleep=None,
    )

    assert CARD_HANDLE not in {handle for handle, _ in edits}, "a decided card is not re-rendered"
    [(_, brief_blocks)] = [edit for edit in edits if edit[0] == BRIEF_HANDLE]
    assert not {"approve", "reject"} & _buttons(brief_blocks)


async def test_the_follow_up_still_updates_an_open_card(automation, monkeypatch):
    """The fix must not freeze the card it is meant to keep current."""
    response, _ = await _posted(automation)

    import fazerops.render.text as render_text

    notes = iter([None, "late changes may still arrive"])
    monkeypatch.setattr(render_text, "approval_card_note", lambda brief: next(notes))

    async def one_update(brief, on_update, *, sleep=None, **kwargs):
        on_update(SimpleNamespace(brief=brief, late_event_ids=()))
        return brief

    monkeypatch.setattr(automation, "follow_coverage", one_update)
    edits: list[tuple] = []

    await _follow_coverage(
        automation, response, [BRIEF_HANDLE, CARD_HANDLE], lambda channel, ts, blocks, text: edits.append(((channel, ts), blocks)), sleep=None
    )

    [(_, card_blocks)] = [edit for edit in edits if edit[0] == CARD_HANDLE]
    assert {"approve", "reject"} <= _buttons(card_blocks)
    assert "late changes may still arrive" in json.dumps(card_blocks)


def test_the_server_remembers_each_cards_message(automation):
    from fastapi.testclient import TestClient

    from fazerops.actions.server import build_app

    posts = iter([{"channel": "C0INCIDENT", "ts": "1.1"}, {"channel": "C0INCIDENT", "ts": "1.2"}])
    client = TestClient(build_app(automation, post=lambda blocks, text: next(posts)))

    body = client.post("/alerts", json=ALERT).json()

    assert automation.threads[body["incident_id"]] == ("C0INCIDENT", "1.1")
    assert automation.cards[(body["incident_id"], "revert_configmap_key")] == ("C0INCIDENT", "1.2")
