"""A3 — a decided card closes in place, and a refusal goes to the person who clicked.

Driven through `_make_handler` with the real `approval_sink` and a real gateway, because the
behaviour lives in the join: the sink decides what to say and to whom, and the handler turns that
into `chat_update`, `chat_postEphemeral` or `say`. The client is a recorder — the handler does not
type-check it, and every call it makes is the assertion.
"""

from __future__ import annotations

import json

import pytest

from fazerops import keys
from fazerops.actions.approval import ApprovalGateway, Approver, ApproverRole
from fazerops.actions.inverse import ActionRequest
from fazerops.actions.preconditions import Evidence
from fazerops.slack.blocks import approval_card, close_decision
from fazerops.slack.handlers import MalformedCallback, _make_handler, approval_card_for, approval_sink, parse_decision

INCIDENT = "INC-7c1f9a2e4b6d8033-20260906T144100Z"
ACTION = "revert_configmap_key"
EVIDENCE = Evidence(
    resource_keys=frozenset({keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}),
    complete=True,
)
ROSTER = {
    "U0IC": Approver(user_id="U0IC", role=ApproverRole.ENGINEER),
    "U0MGR": Approver(user_id="U0MGR", role=ApproverRole.MANAGER),
}


def a_request(current_value: str = "20") -> ActionRequest:
    return ActionRequest.for_action(
        ACTION,
        {"namespace": "billing", "name": "billing-api-config", "key": "pool.max", "target_value": "100"},
        inverse_hint={
            "action_id": ACTION,
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "prior_value": "100",
            "current_value": current_value,
        },
    )


class Recorder:
    def __init__(self) -> None:
        self.updates: list[dict] = []
        self.ephemeral: list[dict] = []

    def chat_update(self, **kwargs):
        self.updates.append(kwargs)

    def chat_postEphemeral(self, **kwargs):
        self.ephemeral.append(kwargs)


def _click(card: list[dict], kind: str, user: str) -> dict:
    """The `block_actions` payload Slack sends for a click on `card`'s own button."""
    [actions] = [block for block in card if block["type"] == "actions"]
    [button] = [element for element in actions["elements"] if element["action_id"] == kind]
    return {
        "type": "block_actions",
        "user": {"id": user},
        "channel": {"id": "C0INCIDENT"},
        "message": {"ts": "1789000000.000100", "blocks": card},
        "actions": [{**button, "block_id": actions["block_id"]}],
    }


@pytest.fixture
def world():
    executed: list[str] = []
    gateway = ApprovalGateway(runner=lambda request, credential, evidence: executed.append(request.action_id) or {})
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    handler = _make_handler(approval_sink(gateway, resolve_approver=lambda user: ROSTER[user]))
    return gateway, pending, handler, executed


def _run(handler, payload):
    said: list[str] = []
    client = Recorder()
    handler(ack=lambda: None, body=payload, say=said.append, logger=None, client=client)
    return said, client


def test_an_approved_card_loses_its_buttons_and_says_so_once(world):
    gateway, pending, handler, executed = world

    said, client = _run(handler, _click(approval_card_for(pending), "approve", "U0IC"))

    assert executed == [ACTION]
    [update] = client.updates
    assert update["ts"] == "1789000000.000100" and update["channel"] == "C0INCIDENT"
    assert not any(block["type"] == "actions" for block in update["blocks"]), "no decision left to make"
    assert "approved" in json.dumps(update["blocks"]) and "<@U0IC>" in json.dumps(update["blocks"])
    assert said == [], "the closed card already announces it; saying it again posts it twice"


def test_a_rejected_card_closes_too(world):
    _, pending, handler, executed = world

    _, client = _run(handler, _click(approval_card_for(pending), "reject", "U0IC"))

    assert executed == []
    assert "rejected" in json.dumps(client.updates[0]["blocks"])


def test_a_replay_is_told_privately(world):
    _, pending, handler, executed = world
    card = approval_card_for(pending)
    _run(handler, _click(card, "approve", "U0IC"))

    said, client = _run(handler, _click(card, "approve", "U0MGR"))

    assert executed == [ACTION]
    assert said == []
    [private] = client.ephemeral
    assert private["user"] == "U0MGR" and "already approved" in private["text"]


def test_a_stale_card_is_refused_privately_and_closed(world):
    gateway, first, handler, executed = world
    old_card = approval_card_for(first)
    gateway.register(INCIDENT, a_request("35"), evidence=EVIDENCE)

    said, client = _run(handler, _click(old_card, "approve", "U0IC"))

    assert executed == [] and gateway.outcome(INCIDENT, ACTION) is None
    assert said == [], "a refusal about one click is not announced to the incident channel"
    assert client.ephemeral[0]["user"] == "U0IC" and "older dry run" in client.ephemeral[0]["text"]
    assert "Replaced by a newer card" in json.dumps(client.updates[0]["blocks"])


def test_an_engineer_refused_a_tier2_card_is_told_privately_and_the_card_stays_open():
    from fazerops.actions.catalog import default_catalog, promote  # noqa: F401 - the tier source

    gateway = ApprovalGateway(runner=lambda *a: {})
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE, crosses_namespace_boundary=True)
    handler = _make_handler(approval_sink(gateway, resolve_approver=lambda user: ROSTER[user]))

    said, client = _run(handler, _click(approval_card_for(pending), "approve", "U0IC"))

    assert said == [] and client.updates == [], "still waiting for a manager"
    assert "manager" in client.ephemeral[0]["text"]


def test_a_reply_that_cannot_be_sent_privately_is_still_sent():
    class Broken(Recorder):
        def chat_postEphemeral(self, **kwargs):
            raise RuntimeError("channel_not_found")

    said: list[str] = []
    handler = _make_handler(lambda decision: "unused")
    handler(ack=lambda: None, body={"actions": [{"action_id": "approve", "value": "not json"}]}, say=said.append, logger=None, client=Broken())

    assert said and "valid incident reference" in said[0]


# --------------------------------------------------------------------------------------
# The payload and the pure close
# --------------------------------------------------------------------------------------


def test_an_approve_without_a_digest_is_refused():
    payload = {"actions": [{"action_id": "approve", "value": json.dumps({"incident_id": INCIDENT, "action_id": ACTION})}]}

    with pytest.raises(MalformedCallback, match="dry-run digest"):
        parse_decision(payload)


def test_the_card_carries_its_dry_runs_digest_and_its_expiry(world):
    _, pending, _, _ = world
    card = approval_card_for(pending)

    assert parse_decision(_click(card, "approve", "U0IC")).dry_run_digest == pending.digest
    assert "Expires" in json.dumps(card)


def test_closing_keeps_show_all_on_the_brief():
    brief_row = {
        "type": "actions",
        "block_id": f"fazerops:{INCIDENT}",
        "elements": [
            {"action_id": "approve", "value": json.dumps({"incident_id": INCIDENT, "action_id": ACTION, "dry_run": "d"})},
            {"action_id": "reject", "value": json.dumps({"incident_id": INCIDENT, "action_id": ACTION, "dry_run": "d"})},
            {"action_id": "show_all", "value": json.dumps({"incident_id": INCIDENT, "action_id": None})},
        ],
    }

    closed = close_decision([brief_row], action_id=ACTION, line="decided")

    assert [element["action_id"] for element in closed[0]["elements"]] == ["show_all"]
    assert closed[1]["type"] == "context"


def test_a_message_with_no_buttons_for_this_action_is_not_edited():
    card = approval_card(a_request().dry_run(evidence=EVIDENCE), incident_id=INCIDENT, tier=1)

    assert close_decision(card, action_id="helm_rollback", line="decided") is None
