"""W25 — Block Kit rendering. Handoff §9, plan §4.

The plan's assertions: three ranked candidates, a collapsed diff, the CI-status line,
Approve/Reject, and valid Block Kit JSON under the 50-block limit.

Two more are here because they are the ways this surface fails *silently*. A message over
50 blocks is rejected whole by Slack, so an over-long brief does not arrive truncated — it
does not arrive, during an incident, with no error anyone sees. And an unescaped alert
summary lets attacker-influenceable text forge system UI: ground rule #2 treats that text
as hostile everywhere it is displayed, not only where it enters a model.

Runs in the CI default. No token, no workspace, no socket — `blocks.py` performs no I/O,
which is the property that makes that true.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fazerops.actions.dry_run import render
from fazerops.actions.inverse import request_from_hint
from fazerops.ingest.alerts import normalize_alert
from fazerops.models import (
    Actor,
    Alert,
    AlertClass,
    BlastRadius,
    Brief,
    Candidate,
    ChangeEvent,
    CIStatus,
    Diff,
    NormalizedAction,
    ResourceRef,
    Tier,
    TimeWindow,
)
from fazerops.pipeline import investigate
from fazerops.slack.blocks import BLOCK_LIMIT, TOP_CANDIDATES, approval_card, change_brief

FIXTURE_ALERTS = Path(__file__).resolve().parents[2] / "fixtures" / "alerts"

CONFIGMAP_HINT = {
    "action_id": "revert_configmap_key",
    "namespace": "billing",
    "name": "billing-api-config",
    "key": "pool.max",
    "prior_value": "100",
    "current_value": "20",
}

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)


@pytest.fixture
async def demo_brief(monkeypatch):
    """The real demo brief, through the real pipeline — not a hand-built stand-in.

    A renderer test against a synthetic `Brief` proves the renderer handles the shape the
    test author imagined. This one renders what the demo will actually put on screen.
    """
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    payload = json.loads((FIXTURE_ALERTS / "alertmanager.json").read_text(encoding="utf-8"))
    return await investigate(normalize_alert(payload))


def _synthetic_brief(*, candidates: int, summary: str = "Latency high") -> Brief:
    """A brief with an arbitrary number of candidates, for the bounds tests."""
    alert = Alert(
        id="synthetic",
        service="billing-api",
        summary=summary,
        fired_at=ALERT_TIME,
        alert_class=AlertClass.LATENCY_SPIKE,
    )
    events = [
        Candidate(
            event=ChangeEvent(
                id=f"evt-{index}",
                source="k8s_audit",
                occurred_at=ALERT_TIME - timedelta(minutes=index + 1),
                actor=Actor(raw=f"user-{index}"),
                action=NormalizedAction.UPDATE,
                resource=ResourceRef(kind="ConfigMap", name=f"cm-{index}", namespace="billing"),
                diff=Diff(before={"a": "1"}, after={"a": "2"}),
                in_band=False,
                raw_ref=f"ref-{index}",
            ),
            score=0.5,
            rank=index + 1,
        )
        for index in range(candidates)
    ]
    return Brief(
        incident_id="INC-synthetic",
        alert=alert,
        radius=BlastRadius(service="billing-api", keys={"k8s:billing/configmap/cm-0"}),
        window=TimeWindow(start=ALERT_TIME - timedelta(hours=4), end=ALERT_TIME),
        candidates=events,
        ci_status=CIStatus(merge_count=0),
    )


def _texts(blocks: list[dict]) -> str:
    """Every renderable string in the message, flattened — what a human actually sees.

    `ensure_ascii=False` because the default escapes `→` to `\\u2192`, and a test asserting
    on the rendered arrow would fail against a renderer that is working perfectly.
    """
    return json.dumps(blocks, ensure_ascii=False)


def _buttons(blocks: list[dict]) -> list[dict]:
    return [
        element
        for block in blocks
        if block["type"] == "actions"
        for element in block["elements"]
    ]


# --------------------------------------------------------------------------------------
# The plan's assertions
# --------------------------------------------------------------------------------------


async def test_the_brief_renders_three_ranked_candidates(demo_brief):
    blocks = change_brief(demo_brief, proposal_summary="Revert pool.max", action_id="revert_configmap_key")
    rendered = _texts(blocks)

    assert len(demo_brief.candidates) == 3, "the demo scenario ships three candidates"
    for candidate in demo_brief.candidates:
        assert f"#{candidate.rank}" in rendered
        assert candidate.event.resource.name in rendered
        assert candidate.event.id in rendered, "every candidate cites its evidence id"

    # Rank 1 is the ConfigMap — the finding the whole demo turns on.
    assert "#1  ConfigMap billing-api-config" in rendered


async def test_the_brief_renders_a_collapsed_diff(demo_brief):
    blocks = change_brief(demo_brief)
    rendered = _texts(blocks)

    assert "pool.max: 100 → 20" in rendered
    assert "```" in rendered, "the diff renders as a code block, not as prose"


async def test_the_brief_carries_an_explicit_ci_status_line(demo_brief):
    """W11a's punchline, and it is rendered from `merge_count` rather than hardcoded."""
    blocks = change_brief(demo_brief)
    assert "Nothing shipped through CI in this window." in _texts(blocks)


async def test_the_brief_offers_approve_and_reject(demo_brief):
    blocks = change_brief(
        demo_brief, proposal_summary="Revert pool.max", action_id="revert_configmap_key"
    )
    buttons = _buttons(blocks)

    assert {button["action_id"] for button in buttons} >= {"approve", "reject"}
    for button in buttons:
        if button["action_id"] in ("approve", "reject"):
            value = json.loads(button["value"])
            assert value == {
                "incident_id": demo_brief.incident_id,
                "action_id": "revert_configmap_key",
            }


async def test_every_block_is_valid_block_kit_json(demo_brief):
    """Structural validity, checked against Block Kit's actual rules rather than by eye.

    Slack rejects the whole message on any of these, so each one is a demo that posts
    nothing at the moment it is needed.
    """
    blocks = change_brief(
        demo_brief, proposal_summary="Revert pool.max", action_id="revert_configmap_key"
    )

    json.dumps(blocks)  # serializable at all
    assert len(blocks) <= BLOCK_LIMIT

    for block in blocks:
        assert block["type"] in {"header", "section", "context", "divider", "actions"}

        if block["type"] == "header":
            # Block Kit forbids mrkdwn in a header and truncates at 150 characters.
            assert block["text"]["type"] == "plain_text"
            assert len(block["text"]["text"]) <= 150
        if block["type"] == "section":
            assert len(block["text"]["text"]) <= 3000
        if block["type"] == "context":
            assert 1 <= len(block["elements"]) <= 10
        if block["type"] == "actions":
            assert 1 <= len(block["elements"]) <= 25
            for element in block["elements"]:
                assert element["type"] == "button"
                assert len(element["value"]) <= 2000
                assert len(element["text"]["text"]) <= 75


# --------------------------------------------------------------------------------------
# The silent failures
# --------------------------------------------------------------------------------------


def test_a_brief_with_many_candidates_stays_under_the_block_limit():
    """Slack rejects a message over 50 blocks **whole**. Trimming is the difference
    between a shortened brief and no brief."""
    blocks = change_brief(_synthetic_brief(candidates=40), action_id="revert_configmap_key")

    assert len(blocks) <= BLOCK_LIMIT
    # Only the top three are rendered in the first place, so this brief is nowhere near
    # the limit — which is the point: the bound holds by construction, not by trimming.
    assert "#4" not in _texts(blocks)


def test_the_trim_keeps_the_actions_row():
    """When trimming does fire, it drops findings and keeps the buttons. A card nobody can
    act on is worse than a shorter one."""
    from fazerops.slack.blocks import _bounded

    over = [{"type": "divider"} for _ in range(60)]
    over.append({"type": "actions", "elements": [{"type": "button"}]})

    trimmed = _bounded(over)
    assert len(trimmed) <= BLOCK_LIMIT
    assert trimmed[-1]["type"] == "actions"
    assert "omitted to stay under Slack's 50-block limit" in _texts(trimmed)


def test_only_the_top_three_candidates_render_and_the_rest_are_offered():
    brief = _synthetic_brief(candidates=9)
    blocks = change_brief(brief)
    rendered = _texts(blocks)

    assert f"#{TOP_CANDIDATES}" in rendered
    assert f"#{TOP_CANDIDATES + 1}" not in rendered

    show_all = [b for b in _buttons(blocks) if b["action_id"] == "show_all"]
    assert show_all, "Handoff §9 requires a Show all changes control"
    assert "6 more" in show_all[0]["text"]["text"]


def test_untrusted_alert_text_cannot_forge_slack_ui():
    """Ground rule #2, on the display surface.

    `<!channel>` in an alert summary pings the workspace; a `<url|label>` renders as a
    link an operator clicks. Neither is code execution, and both are the alert payload
    speaking in the system's voice.
    """
    hostile = "latency high <!channel> <https://evil.example/approve|Approve here>"
    blocks = change_brief(_synthetic_brief(candidates=1, summary=hostile))
    rendered = _texts(blocks)

    assert "<!channel>" not in rendered
    assert "&lt;!channel&gt;" in rendered
    assert "<https://evil.example/approve|" not in rendered


def test_a_diff_value_cannot_escape_its_code_block():
    """A ConfigMap value containing a fence would otherwise close the block early and
    render everything after it as message text — including text that looks like ours."""
    from fazerops.slack.blocks import _code

    fenced = _code("pool.max: ``` *approved by SRE* ")
    assert fenced.count("```") == 2, "exactly the opening and closing fences"


def test_a_brief_with_no_proposal_offers_no_approve_button(demo_brief):
    """Ground rule #5 is about a human deciding something real. An Approve with nothing
    behind it is a button whose only outcome is an error."""
    blocks = change_brief(demo_brief)

    assert {b["action_id"] for b in _buttons(blocks)} == set()
    assert "nothing will run" in _texts(blocks)


def test_an_unresolvable_service_says_so_rather_than_rendering_an_empty_list():
    """"We did not know where to look" is not "nothing changed", and an empty candidate
    list on a card reads as the second."""
    brief = _synthetic_brief(candidates=0)
    brief = brief.model_copy(
        update={"radius": BlastRadius(service="unknown-service", keys=set())}
    )

    rendered = _texts(change_brief(brief))
    assert "Could not resolve" in rendered
    assert "no changes were searched for" in rendered


# --------------------------------------------------------------------------------------
# The approval card — Handoff §9's second message type
# --------------------------------------------------------------------------------------


def test_a_coverage_note_sits_above_the_diff_where_it_is_read_before_deciding():
    note = "CloudTrail changes after 14:26 UTC may still arrive until 14:56 UTC. This card was drafted before they could be seen."
    card = approval_card(_demo_dry_run(), incident_id="INC-1", tier=Tier.ENGINEER_APPROVAL, coverage_note=note)
    texts = [json.dumps(block) for block in card]
    note_at = next(i for i, text in enumerate(texts) if "may still arrive until" in text)
    diff_at = next(i for i, text in enumerate(texts) if "```" in text)
    assert note_at < diff_at
    assert "may still arrive" not in json.dumps(approval_card(_demo_dry_run(), incident_id="INC-1", tier=Tier.ENGINEER_APPROVAL))


def _demo_dry_run():
    request = request_from_hint(CONFIGMAP_HINT)
    assert request is not None
    return render(request, evidence=_evidence())


def _evidence():
    """The collected evidence preconditions are answered from — never a live cluster.

    The key comes from `keys.py` rather than being spelled out, for the reason
    `_configmap_exists` gives: evidence written in its own key format stops matching the
    moment the format changes, and the test keeps passing while the action refuses.
    """
    from fazerops import keys
    from fazerops.actions.preconditions import Evidence

    return Evidence(
        resource_keys=frozenset(
            {keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}
        ),
        complete=True,
    )


def test_the_approval_card_states_the_action_the_diff_and_the_inverse():
    """Handoff §9's four required elements, in its order."""
    card = approval_card(_demo_dry_run(), incident_id="INC-1", tier=Tier.ENGINEER_APPROVAL)
    rendered = _texts(card)

    assert "Revert pool.max in ConfigMap billing-api-config" in rendered
    assert "billing/configmap/billing-api-config" in rendered
    assert "pool.max: 20 → 100" in rendered
    assert "revert_configmap_key(" in rendered, "the inverse is stated explicitly"
    assert "Tier 1" in rendered


def test_a_tier_two_card_states_why_it_escalated():
    card = approval_card(
        _demo_dry_run(),
        incident_id="INC-1",
        tier=Tier.MANAGER_APPROVAL,
        escalation_reason="crosses a namespace boundary",
    )
    rendered = _texts(card)

    assert "Tier 2" in rendered
    assert "manager approval required" in rendered
    assert "crosses a namespace boundary" in rendered


def test_an_action_with_no_inverse_shows_no_approve_button():
    """Ground rule #4 where an operator reads it. Approving something that is about to
    refuse is the same defect as approving something irreversible."""
    from fazerops.actions.inverse import ActionRequest

    request = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
    )  # no inverse_hint, so no inverse can be computed
    dry = render(request, evidence=_evidence())
    assert dry.reversible is False

    card = approval_card(dry, incident_id="INC-1", tier=Tier.ENGINEER_APPROVAL)
    assert "No inverse could be computed" in _texts(card)
    assert _buttons(card) == []


def test_an_unmet_precondition_reaches_the_card_and_removes_the_button():
    """`execute()` would refuse; the card must say so before someone approves it."""
    request = request_from_hint(CONFIGMAP_HINT)
    from fazerops.actions.preconditions import Evidence

    dry = render(request, evidence=Evidence())  # nobody collected anything
    assert dry.unmet_preconditions

    card = approval_card(dry, incident_id="INC-1", tier=Tier.ENGINEER_APPROVAL)
    assert "precondition not met" in _texts(card)
    assert _buttons(card) == []
