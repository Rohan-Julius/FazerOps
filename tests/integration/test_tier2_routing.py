"""W26b — Tier 2 manager-approval routing. Handoff §1, §7 and §9, Idea §3 and §4, plan §4.

Before W26b, Tier 2 was *classified but not routed*: the catalog declared it, the card
could print it, and nothing refused an IC approval — which made the Tier 2 branch of
Handoff §1's architecture diagram decorative.

The plan's assertions: a Tier 2 action is **not** executable on an IC approval; the card
states **why** it escalated; a manager approval executes it; and **promotion never
demotes**. Idea §3's warning runs the other way too — managers approve risk and spend, not
pod restarts — so the roster is asserted to refuse a person holding both roles rather than
quietly promoting them.

Both routes into Tier 2 are covered, because they fail differently: an action **declared**
Tier 2 in the catalog, and a Tier 1 action **promoted** by `thresholds.yaml`.
"""

from __future__ import annotations

import pytest

from fazerops import keys
from fazerops.actions.approval import (
    ApprovalGateway,
    Approver,
    ApproverNotPermitted,
    ApproverRole,
)
from fazerops.actions.catalog import default_catalog
from fazerops.actions.inverse import ActionRequest
from fazerops.actions.preconditions import Evidence
from fazerops.actions.roster import Roster, UnknownApprover
from fazerops.models import Tier
from fazerops.slack.handlers import Decision, approval_card_for, approval_sink

INCIDENT = "INC-2026-09-12-T2"

IC = Approver(user_id="U0IC", role=ApproverRole.ENGINEER)
MANAGER = Approver(user_id="U0MGR", role=ApproverRole.MANAGER)
ROSTER = Roster(engineers=["U0IC"], managers=["U0MGR"])

CONFIGMAP_EVIDENCE = Evidence(
    resource_keys=frozenset(
        {keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}
    ),
    complete=True,
)
RDS_EVIDENCE = Evidence(
    resource_keys=frozenset(
        {keys.db_parameter_group("billing-primary-params").blast_radius_key()}
    ),
    complete=True,
)


class Runner:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, request, credential, evidence):
        self.calls.append(request.action_id)
        return {"action_id": request.action_id}


def tier1_request() -> ActionRequest:
    return ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
        inverse_hint={
            "action_id": "revert_configmap_key",
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "prior_value": "100",
            "current_value": "20",
        },
    )


def tier2_request() -> ActionRequest:
    """`restore_db_parameter` — declared Tier 2 because it touches a managed database."""
    return ActionRequest.for_action(
        "restore_db_parameter",
        {
            "parameter_group": "billing-primary-params",
            "parameter": "max_connections",
            "target_value": "200",
        },
        inverse_hint={
            "action_id": "restore_db_parameter",
            "parameter_group": "billing-primary-params",
            "parameter": "max_connections",
            "prior_value": "200",
            "current_value": "50",
        },
    )


# --------------------------------------------------------------------------------------
# A declared Tier 2 action refuses an IC approval
# --------------------------------------------------------------------------------------


def test_the_catalog_declares_a_tier_2_action_with_a_manager_approver():
    spec = default_catalog().get("restore_db_parameter")
    assert spec.tier is Tier.MANAGER_APPROVAL
    assert spec.requires_approval_from == "manager"


def test_a_declared_tier_2_action_is_not_executable_on_an_ic_approval():
    runner = Runner()
    gateway = ApprovalGateway(runner=runner)
    gateway.register(INCIDENT, tier2_request(), evidence=RDS_EVIDENCE)

    with pytest.raises(ApproverNotPermitted):
        gateway.decide(
            incident_id=INCIDENT,
            action_id="restore_db_parameter",
            approver=IC,
            kind="approve",
        )

    assert runner.calls == [], "an IC approval executed a Tier 2 mutation"
    assert gateway.outcome(INCIDENT, "restore_db_parameter") is None


def test_a_manager_approval_executes_the_declared_tier_2_action():
    runner = Runner()
    gateway = ApprovalGateway(runner=runner)
    gateway.register(INCIDENT, tier2_request(), evidence=RDS_EVIDENCE)

    outcome = gateway.decide(
        incident_id=INCIDENT,
        action_id="restore_db_parameter",
        approver=MANAGER,
        kind="approve",
    )

    assert runner.calls == ["restore_db_parameter"]
    assert outcome.executed is True
    assert outcome.tier is Tier.MANAGER_APPROVAL
    assert outcome.approval_record().tier == 2


def test_a_refused_ic_click_leaves_the_card_open_for_the_manager():
    """The refusal must not consume the incident. One wrong click closing an approval
    nobody ever gave is a worse failure than the click itself."""
    runner = Runner()
    gateway = ApprovalGateway(runner=runner)
    gateway.register(INCIDENT, tier2_request(), evidence=RDS_EVIDENCE)

    with pytest.raises(ApproverNotPermitted):
        gateway.decide(
            incident_id=INCIDENT, action_id="restore_db_parameter", approver=IC, kind="approve"
        )

    assert gateway.pending(INCIDENT, "restore_db_parameter") is not None
    outcome = gateway.decide(
        incident_id=INCIDENT,
        action_id="restore_db_parameter",
        approver=MANAGER,
        kind="approve",
    )
    assert outcome.executed is True


# --------------------------------------------------------------------------------------
# A promoted Tier 1 action routes to the manager path, not the IC one
# --------------------------------------------------------------------------------------


def test_a_promoted_tier_1_action_routes_to_the_manager_path():
    runner = Runner()
    gateway = ApprovalGateway(runner=runner)
    pending = gateway.register(
        INCIDENT, tier1_request(), evidence=CONFIGMAP_EVIDENCE, crosses_namespace_boundary=True
    )

    assert pending.declared_tier is Tier.ENGINEER_APPROVAL
    assert pending.tier is Tier.MANAGER_APPROVAL
    assert pending.escalated is True

    with pytest.raises(ApproverNotPermitted):
        gateway.decide(
            incident_id=INCIDENT,
            action_id="revert_configmap_key",
            approver=IC,
            kind="approve",
        )
    assert runner.calls == []

    outcome = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=MANAGER, kind="approve"
    )
    assert runner.calls == ["revert_configmap_key"]
    assert outcome.tier is Tier.MANAGER_APPROVAL


def test_promotion_never_demotes_a_declared_tier_2():
    """No promotion input, and no *absence* of one, lowers a declared Tier 2 to an IC
    decision. `test_tier_promotion.py` sweeps this exhaustively; this asserts the
    consequence that matters — the routing."""
    runner = Runner()
    gateway = ApprovalGateway(runner=runner)
    gateway.register(
        INCIDENT,
        tier2_request(),
        evidence=RDS_EVIDENCE,
        estimated_cost_delta_usd=0.0,
        resource_count=0,
        crosses_namespace_boundary=False,
    )

    with pytest.raises(ApproverNotPermitted):
        gateway.decide(
            incident_id=INCIDENT, action_id="restore_db_parameter", approver=IC, kind="approve"
        )
    assert runner.calls == []


# --------------------------------------------------------------------------------------
# The card states why it escalated
# --------------------------------------------------------------------------------------


def test_the_card_states_the_promotion_reason():
    gateway = ApprovalGateway(runner=Runner())
    pending = gateway.register(
        INCIDENT, tier1_request(), evidence=CONFIGMAP_EVIDENCE, crosses_namespace_boundary=True
    )

    text = repr(approval_card_for(pending))
    assert "Tier 2" in text
    assert "a manager" in text
    assert "namespace boundary" in text, "the card does not say why it escalated"


def test_the_card_for_a_declared_tier_2_says_it_was_declared():
    """There is no promotion reason to state, and inventing one would teach an operator to
    read "escalated" as decoration."""
    gateway = ApprovalGateway(runner=Runner())
    pending = gateway.register(INCIDENT, tier2_request(), evidence=RDS_EVIDENCE)

    text = repr(approval_card_for(pending))
    assert "Tier 2" in text
    assert "always needs a manager" in text


def test_the_card_shows_the_effective_tier_not_the_declared_one():
    """The defect this guards is understating an escalation on exactly the action that
    escalated."""
    gateway = ApprovalGateway(runner=Runner())
    promoted = gateway.register(
        INCIDENT, tier1_request(), evidence=CONFIGMAP_EVIDENCE, resource_count=5_000
    )
    plain = ApprovalGateway(runner=Runner()).register(
        "INC-OTHER", tier1_request(), evidence=CONFIGMAP_EVIDENCE
    )

    assert "Tier 2" in repr(approval_card_for(promoted))
    assert "Tier 1" in repr(approval_card_for(plain))


# --------------------------------------------------------------------------------------
# The approver principals are actually separate — Idea §3, both directions
# --------------------------------------------------------------------------------------


def test_the_roster_refuses_a_person_listed_as_both_roles():
    """A person quietly holding both roles makes the split decorative while still looking
    configured."""
    with pytest.raises(ValueError, match="both engineer and manager"):
        Roster(engineers=["U0BOTH"], managers=["U0BOTH"])


def test_an_unlisted_user_is_refused_rather_than_defaulted_to_engineer():
    with pytest.raises(UnknownApprover):
        ROSTER.resolve("U0STRANGER")


def test_an_empty_roster_refuses_everyone():
    """The shipped default. A misconfigured deployment approves nothing rather than
    approving everything."""
    empty = Roster()
    assert empty.empty
    with pytest.raises(UnknownApprover, match="roster is empty"):
        empty.resolve("U0MGR")


def test_a_manager_clears_tier_1_but_an_engineer_never_clears_tier_2():
    assert ApproverRole.MANAGER.clears(Tier.ENGINEER_APPROVAL)
    assert ApproverRole.MANAGER.clears(Tier.MANAGER_APPROVAL)
    assert ApproverRole.ENGINEER.clears(Tier.ENGINEER_APPROVAL)
    assert not ApproverRole.ENGINEER.clears(Tier.MANAGER_APPROVAL)


# --------------------------------------------------------------------------------------
# End to end through the Slack sink
# --------------------------------------------------------------------------------------


def test_an_ic_click_on_a_tier_2_card_is_told_it_needs_a_manager():
    runner = Runner()
    gateway = ApprovalGateway(runner=runner)
    gateway.register(INCIDENT, tier2_request(), evidence=RDS_EVIDENCE)
    sink = approval_sink(gateway, resolve_approver=ROSTER.resolve)

    reply = sink(
        Decision(
            kind="approve",
            incident_id=INCIDENT,
            action_id="restore_db_parameter",
            user_id="U0IC",
        )
    )

    assert runner.calls == []
    assert "manager" in reply

    assert "ran once" in sink(
        Decision(
            kind="approve",
            incident_id=INCIDENT,
            action_id="restore_db_parameter",
            user_id="U0MGR",
        )
    )
    assert runner.calls == ["restore_db_parameter"]


def test_a_click_from_someone_not_on_the_roster_runs_nothing():
    runner = Runner()
    gateway = ApprovalGateway(runner=runner)
    gateway.register(INCIDENT, tier2_request(), evidence=RDS_EVIDENCE)
    sink = approval_sink(gateway, resolve_approver=ROSTER.resolve)

    reply = sink(
        Decision(
            kind="approve",
            incident_id=INCIDENT,
            action_id="restore_db_parameter",
            user_id="U0STRANGER",
        )
    )

    assert runner.calls == []
    assert "roster" in reply and "Nothing has run" in reply
