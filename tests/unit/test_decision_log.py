"""B1 — every click is written down, refusals included, and writing it down never changes the answer.

The refusals are the point: before this, an unlisted clicker, an engineer on a Tier 2 card, a stale
card and a forged payload each reached a `logger.warning` at most, and nothing an incident review
could read. Driven through the real `approval_sink` and gateway, because the log is only as complete
as the path that feeds it.
"""

from __future__ import annotations

import json

import pytest

from fazerops import keys
from fazerops.actions.approval import ApprovalGateway
from fazerops.actions.decision_log import DecisionLog
from fazerops.actions.inverse import ActionRequest
from fazerops.actions.preconditions import Evidence
from fazerops.actions.roster import Roster
from fazerops.ledger.chain import Integrity
from fazerops.slack.handlers import Decision, _make_handler, approval_sink

INCIDENT = "INC-7c1f9a2e4b6d8033-20260906T144100Z"
ACTION = "revert_configmap_key"
ROSTER = Roster(engineers=["U0IC"], managers=["U0MGR"])
EVIDENCE = Evidence(
    resource_keys=frozenset({keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}),
    complete=True,
)


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


@pytest.fixture
def world(tmp_path):
    executed: list[str] = []
    gateway = ApprovalGateway(runner=lambda request, credential, evidence: executed.append(request.action_id) or {})
    log = DecisionLog(tmp_path / "decisions.jsonl", key=None)
    return gateway, log, approval_sink(gateway, resolve_approver=ROSTER.resolve, decisions=log), executed


def click(pending, kind: str = "approve", user: str = "U0IC", digest: str | None = None) -> Decision:
    return Decision(
        kind=kind,
        incident_id=pending.incident_id,
        action_id=pending.action_id,
        user_id=user,
        dry_run_digest=digest or pending.digest,
    )


def results(log: DecisionLog) -> list[str]:
    return [entry["result"] for entry in log.entries()[0]]


def test_an_approval_and_its_replay_are_both_recorded(world):
    gateway, log, sink, executed = world
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    sink(click(pending))
    sink(click(pending, user="U0MGR"))

    first, replay = log.entries()[0]
    assert (first["result"], first["user_id"], first["role"], first["tier"]) == ("executed", "U0IC", "engineer", 1)
    assert first["dry_run_digest"] == pending.digest and first["incident_id"] == INCIDENT
    assert (replay["result"], replay["role"]) == ("replay", "manager")
    assert executed == [ACTION]


def test_a_clicker_not_on_the_roster_is_recorded_as_refused(world):
    gateway, log, sink, executed = world
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    sink(click(pending, user="U0STRANGER"))

    [entry] = log.entries()[0]
    assert entry["result"] == "refused" and entry["role"] is None
    assert entry["reason"].startswith("UnknownApprover")
    assert executed == []


def test_an_engineer_on_a_tier2_card_is_recorded_with_the_reason(world):
    gateway, log, sink, _ = world
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE, crosses_namespace_boundary=True)

    sink(click(pending))

    [entry] = log.entries()[0]
    assert entry["result"] == "refused" and entry["role"] == "engineer"
    assert entry["reason"].startswith("ApproverNotPermitted")


def test_a_failure_before_the_decision_is_told_to_the_clicker_and_leaves_the_card_open(world, monkeypatch):
    gateway, log, sink, executed = world
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    def unreachable(*args, **kwargs):
        raise RuntimeError("credentials attempted to construct a network client")

    monkeypatch.setattr("fazerops.actions.approval.mint_actor_credential", unreachable)
    reply = sink(click(pending))

    assert reply is not None and reply.private and "No decision was recorded" in reply
    assert reply.card_line is None, "nothing was decided, so the card must keep its buttons"
    [entry] = log.entries()[0]
    assert entry["result"] == "failed" and entry["reason"].startswith("RuntimeError")
    assert executed == [] and gateway.outcome(INCIDENT, ACTION) is None

    monkeypatch.undo()
    sink(click(pending))
    assert executed == [ACTION], "the same card still executes once the failure is gone"


def test_a_stale_card_is_recorded_as_refused(world):
    gateway, log, sink, _ = world
    first = gateway.register(INCIDENT, a_request("20"), evidence=EVIDENCE)
    gateway.register(INCIDENT, a_request("35"), evidence=EVIDENCE)

    sink(click(first))

    [entry] = log.entries()[0]
    assert entry["result"] == "refused" and entry["reason"].startswith("StaleCard")
    assert entry["dry_run_digest"] == first.digest, "the digest the clicker saw, which is what went wrong"


def test_rejections_and_show_all_are_recorded(world):
    gateway, log, sink, _ = world
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    sink(Decision(kind="show_all", incident_id=INCIDENT, user_id="U0IC"))
    sink(click(pending, kind="reject"))

    assert results(log) == ["read", "rejected"]


def test_a_forged_payload_is_recorded_without_its_value(world):
    _, log, sink, _ = world
    handler = _make_handler(sink, on_malformed=log.record_malformed)
    forged = {
        "user": {"id": "U0IC"},
        "actions": [{"action_id": "approve", "value": json.dumps({"incident_id": INCIDENT, "action_id": ACTION, "namespace": "kube-system"})}],
    }

    handler(ack=lambda: None, body=forged, say=lambda text: None, logger=None, client=None)

    [entry] = log.entries()[0]
    assert (entry["result"], entry["user_id"], entry["kind"]) == ("malformed", "U0IC", "approve")
    assert "kube-system" not in json.dumps(entry), "the forger's value is not kept"


def test_a_signed_log_detects_an_edit(tmp_path, world):
    gateway, _, _, _ = world
    path = tmp_path / "signed.jsonl"
    log = DecisionLog(path, key=b"synthetic-evidence-key")
    sink = approval_sink(gateway, resolve_approver=ROSTER.resolve, decisions=log)
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    sink(click(pending, user="U0STRANGER"))
    sink(click(pending))

    assert log.entries()[1] is Integrity.VERIFIED

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["record"]["result"] = "executed"  # rewrite a refusal into an approval
    path.write_text("\n".join([json.dumps(tampered), *lines[1:]]) + "\n", encoding="utf-8")

    assert DecisionLog(path, key=b"synthetic-evidence-key").entries()[1] is Integrity.BROKEN


def test_a_failing_log_changes_nothing_about_the_decision(world):
    gateway, _, _, executed = world

    class Broken:
        def record(self, **kwargs):
            raise OSError("disk full")

    sink = approval_sink(gateway, resolve_approver=ROSTER.resolve, decisions=Broken())
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    reply = sink(click(pending))

    assert "executed once" in reply and executed == [ACTION]
