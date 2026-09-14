"""W26 — approval routing, idempotency and the dry-run ordering. Handoff §7 and §8, plan §4.

> *Replaying the same `(incident_id, action_id)` executes **once**; the second call is
> refused and returns the first result.*

A double-executed mutation during a live demo is unrecoverable, so the assertions here
count *executor calls*, not return values. A gateway that returned the right answer twice
while patching the cluster twice would pass a value-only test.

The runner is injected throughout — nothing in this file touches a cluster, AWS or Slack —
but the credential is the real one, minted through the real frame-checked gate. Faking the
credential would test a mock of the property the unit exists to provide.
"""

from __future__ import annotations

import pytest

from fazerops import keys
from fazerops.actions.approval import (
    AlreadyDecided,
    ApprovalGateway,
    Approver,
    ApproverNotPermitted,
    ApproverRole,
    NotAwaitingApproval,
    scope_of,
)
from fazerops.actions.catalog import default_catalog
from fazerops.actions.inverse import ActionRequest
from fazerops.actions.preconditions import Evidence
from fazerops.models import Tier
from fazerops.security.credentials import ActorCredential, CredentialRefused

INCIDENT = "INC-2026-09-12-001"

CONFIGMAP_HINT = {
    "action_id": "revert_configmap_key",
    "namespace": "billing",
    "name": "billing-api-config",
    "key": "pool.max",
    "prior_value": "100",
    "current_value": "20",
}

EVIDENCE = Evidence(
    resource_keys=frozenset(
        {keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}
    ),
    complete=True,
)

IC = Approver(user_id="U_IC_01", role=ApproverRole.ENGINEER)
MANAGER = Approver(user_id="U_MGR_01", role=ApproverRole.MANAGER)


def a_request() -> ActionRequest:
    """The demo's action: restore `pool.max` to the value it held before the out-of-band
    edit. Built from the recorded hint so the inverse is computable and ground rule #4 does
    not refuse before the approval logic is reached."""
    return ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
        inverse_hint=CONFIGMAP_HINT,
    )


class Runner:
    """Stands in for the executor, and counts. The count is the assertion."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[tuple[str, ActorCredential]] = []
        self.fail = fail

    def __call__(self, request, credential, evidence):
        self.calls.append((request.action_id, credential))
        if self.fail:
            raise RuntimeError("the cluster rejected the patch")
        return {"action_id": request.action_id, "value": request.params["target_value"]}

    @property
    def count(self) -> int:
        return len(self.calls)


@pytest.fixture
def gateway_and_runner():
    runner = Runner()
    return ApprovalGateway(runner=runner), runner


# --------------------------------------------------------------------------------------
# Idempotency — the assertion the plan names
# --------------------------------------------------------------------------------------


def test_replaying_the_same_incident_and_action_executes_exactly_once(gateway_and_runner):
    gateway, runner = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    first = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )
    second = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )

    assert runner.count == 1, "the replay executed a second mutation"
    assert first.executed is True
    assert first.replay is False
    assert second.replay is True, "the second call was not marked as a replay"


def test_the_replay_returns_the_first_result_rather_than_a_fresh_one(gateway_and_runner):
    gateway, runner = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    first = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )
    second = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )

    assert second.result == first.result
    assert second.decided_at == first.decided_at, "the replay re-stamped the decision time"
    assert second.approver == first.approver


def test_a_replay_by_a_different_approver_still_returns_the_first_decision(gateway_and_runner):
    """Idempotency is keyed on the action, not on who clicked. A second human clicking a
    stale card must not re-run the mutation under their own name — and the record must keep
    naming whoever actually authorized it."""
    gateway, runner = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    first = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )
    replay = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=MANAGER, kind="approve"
    )

    assert runner.count == 1
    assert replay.approver == IC.user_id == first.approver


def test_a_rejection_is_also_idempotent_and_executes_nothing(gateway_and_runner):
    gateway, runner = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    first = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="reject"
    )
    second = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )

    assert runner.count == 0, "an approval after a rejection executed the action"
    assert first.decision == "rejected"
    assert first.executed is False
    assert second.decision == "rejected" and second.replay is True


def test_a_failed_execution_is_recorded_so_a_retry_does_not_re_run_it():
    """A mutation that raised may have partially landed. A retry that re-runs it is the
    unrecoverable case; a retry refused, leaving a human to look, is the recoverable one."""
    runner = Runner(fail=True)
    gateway = ApprovalGateway(runner=runner)
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    first = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )
    second = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )

    assert runner.count == 1
    assert first.executed is False
    assert "the cluster rejected the patch" in first.error
    assert second.replay is True and second.error == first.error


def test_re_registering_a_decided_action_is_refused(gateway_and_runner):
    """Otherwise a fresh card is posted for a mutation that already ran, and the next click
    is a human approving something they have no way of knowing is done."""
    gateway, runner = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )

    with pytest.raises(AlreadyDecided) as caught:
        gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    assert caught.value.outcome.executed is True
    assert runner.count == 1


def test_two_different_incidents_are_independent(gateway_and_runner):
    """The key is the pair. The same action on a second incident is a second mutation and
    must not be swallowed by the first incident's outcome."""
    gateway, runner = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    gateway.register("INC-2026-09-12-002", a_request(), evidence=EVIDENCE)

    gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )
    gateway.decide(
        incident_id="INC-2026-09-12-002",
        action_id="revert_configmap_key",
        approver=IC,
        kind="approve",
    )

    assert runner.count == 2


# --------------------------------------------------------------------------------------
# The dry run is shown first — structurally, not by flow
# --------------------------------------------------------------------------------------


def test_a_decision_for_an_unregistered_action_is_refused(gateway_and_runner):
    """The structural half of "dry-run first": `register()` is the only way to open an
    approval and it renders the dry run as it does, so there is no path from a callback to
    `execute()` that skipped one."""
    gateway, runner = gateway_and_runner

    with pytest.raises(NotAwaitingApproval):
        gateway.decide(
            incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
        )

    assert runner.count == 0


def test_registering_renders_the_dry_run(gateway_and_runner):
    gateway, _ = gateway_and_runner
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    assert pending.dry_run.action_id == "revert_configmap_key"
    assert pending.dry_run.reversible is True
    assert pending.dry_run.unmet_preconditions == []
    assert pending.dry_run.lines, "the card would show an empty diff"


def test_the_pending_card_is_closed_once_decided(gateway_and_runner):
    gateway, _ = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )

    with pytest.raises(NotAwaitingApproval):
        gateway.pending(INCIDENT, "revert_configmap_key")


# --------------------------------------------------------------------------------------
# The credential — minted here, bound here, spent once
# --------------------------------------------------------------------------------------


def test_the_executor_is_handed_a_credential_bound_to_this_incident_and_action(
    gateway_and_runner,
):
    gateway, runner = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )

    _, credential = runner.calls[0]
    assert isinstance(credential, ActorCredential)
    assert credential.incident_id == INCIDENT
    assert credential.action_id == "revert_configmap_key"
    assert credential.namespace == "billing"
    assert credential.expired is False


def test_a_replay_mints_no_second_credential(gateway_and_runner):
    """Idempotency is checked *before* the mint, so a replayed approval cannot even produce
    a credential — let alone use one."""
    gateway, runner = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )
    gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )

    assert len(runner.calls) == 1


def test_the_credential_the_gateway_mints_survives_the_real_gate():
    """End to end through the *real* executor guard rather than the injected runner: the
    credential this module mints is one `require_actor_credential` accepts, and it is spent
    by that call."""
    from fazerops.security.credentials import require_actor_credential

    runner = Runner()
    gateway = ApprovalGateway(runner=runner)
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
    )
    _, credential = runner.calls[0]

    accepted = require_actor_credential(
        credential,
        incident_id=INCIDENT,
        action_id="revert_configmap_key",
        namespace="billing",
    )
    assert accepted is credential

    with pytest.raises(CredentialRefused):
        require_actor_credential(
            credential, action_id="revert_configmap_key", namespace="billing"
        )


def test_two_concurrent_approvals_execute_once_and_the_second_is_the_replay():
    """Regression: the replay check read the outcome table, and nothing wrote to it until the
    mutation finished — so two deliveries of one click on two Socket Mode pool threads both
    passed the check, both minted, and both ran. The runner holds the first call inside the
    mutation until the second has had every chance to overtake it."""
    import threading

    started, release = threading.Event(), threading.Event()

    class SlowRunner(Runner):
        def __call__(self, request, credential, evidence):
            started.set()
            release.wait(timeout=5)
            return super().__call__(request, credential, evidence)

    runner = SlowRunner()
    gateway = ApprovalGateway(runner=runner)
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    outcomes = []

    def click():
        outcomes.append(
            gateway.decide(
                incident_id=INCIDENT, action_id=pending.action_id, approver=IC, kind="approve", dry_run_digest=pending.digest
            )
        )

    first = threading.Thread(target=click)
    first.start()
    assert started.wait(timeout=5)
    second = threading.Thread(target=click)
    second.start()
    second.join(timeout=0.3)
    assert second.is_alive(), "the second click did not wait for the first to finish"
    release.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert runner.count == 1, "two concurrent clicks executed two mutations"
    assert sorted(outcome.replay for outcome in outcomes) == [False, True]
    assert outcomes[0].decided_at == outcomes[1].decided_at


def test_a_call_that_records_nothing_releases_its_claim(gateway_and_runner, monkeypatch):
    """A mint that raised ran nothing and recorded nothing; the claim must not outlive it, or
    every retry of an STS blip would wait forever."""
    from fazerops.actions import approval

    gateway, runner = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    real_mint = approval.mint_actor_credential

    def flaky(**kwargs):
        monkeypatch.setattr(approval, "mint_actor_credential", real_mint)
        raise RuntimeError("sts unreachable")

    monkeypatch.setattr(approval, "mint_actor_credential", flaky)
    with pytest.raises(RuntimeError, match="sts unreachable"):
        gateway.decide(incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve")
    assert gateway.outcome(INCIDENT, "revert_configmap_key") is None

    outcome = gateway.decide(incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve")
    assert outcome.executed is True and outcome.replay is False and runner.count == 1


def test_the_scope_is_derived_from_the_action_not_supplied_by_the_caller():
    """A caller that could name the scope could widen the credential past the action it was
    approved for."""
    assert scope_of(a_request()) == "billing"

    rds = ActionRequest.for_action(
        "restore_db_parameter",
        {
            "parameter_group": "billing-primary-params",
            "parameter": "max_connections",
            "target_value": "200",
        },
        inverse_hint={"current_value": "50"},
    )
    assert scope_of(rds) == "billing-primary-params"


# --------------------------------------------------------------------------------------
# Tier routing reaches the gateway (W26b extends this)
# --------------------------------------------------------------------------------------


def test_a_promoted_action_refuses_an_ic_approval_and_stays_open(gateway_and_runner):
    """Promotion is not advisory. An IC clicking a promoted card is refused, nothing runs,
    and the card stays open so the manager it escalated to can still act on it."""
    gateway, runner = gateway_and_runner
    pending = gateway.register(
        INCIDENT, a_request(), evidence=EVIDENCE, crosses_namespace_boundary=True
    )
    assert pending.tier is Tier.MANAGER_APPROVAL
    assert pending.escalated is True
    assert "namespace" in pending.escalation_reason

    with pytest.raises(ApproverNotPermitted):
        gateway.decide(
            incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="approve"
        )

    assert runner.count == 0
    assert gateway.outcome(INCIDENT, "revert_configmap_key") is None

    outcome = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=MANAGER, kind="approve"
    )
    assert runner.count == 1
    assert outcome.executed is True
    assert outcome.tier is Tier.MANAGER_APPROVAL


def test_a_manager_may_approve_a_tier_1_action(gateway_and_runner):
    """The tiers are a floor on seniority, not a routing table that excludes the senior."""
    gateway, runner = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    outcome = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=MANAGER, kind="approve"
    )
    assert outcome.executed is True and runner.count == 1


# --------------------------------------------------------------------------------------
# The outcome is the incident record's input (Handoff §10)
# --------------------------------------------------------------------------------------


def test_the_outcome_converts_to_the_records_handoff_10_persists(gateway_and_runner):
    gateway, _ = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE, crosses_namespace_boundary=True)
    outcome = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=MANAGER, kind="approve"
    )

    approval = outcome.approval_record()
    assert approval.decision == "approved"
    assert approval.approver == MANAGER.user_id
    assert approval.tier == 2
    assert "namespace" in approval.escalation_reason

    execution = outcome.execution_record()
    assert execution is not None and execution.succeeded is True


def test_a_rejection_produces_no_execution_record(gateway_and_runner):
    """`IncidentSession.stage` reads the presence of the record. An empty one would report
    an execution that never happened."""
    gateway, _ = gateway_and_runner
    gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    outcome = gateway.decide(
        incident_id=INCIDENT, action_id="revert_configmap_key", approver=IC, kind="reject"
    )

    assert outcome.execution_record() is None
    assert outcome.approval_record().decision == "rejected"
