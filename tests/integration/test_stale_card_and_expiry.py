"""D1 and A2 (drift log, 14 Sep) — a click approves the dry run it was shown, while it is still fresh.

**D1.** A re-fired alert re-registered the same `(incident, action)` and silently replaced the
pending entry, so a click on the first card executed the second card's dry run. The card now
carries the dry run's digest and `decide()` refuses a mismatch.

**A2.** `registered_at` was recorded and never read. Preconditions check collected evidence, not
the live cluster, so an approval clicked hours later acted on hours-old evidence.

Both refusals record nothing: the counts below are executor calls and recorded outcomes, because a
refusal that quietly recorded a decision would block the fresh card it is meant to send people to.
"""

from __future__ import annotations

import pytest

from fazerops import keys
from fazerops.actions.approval import (
    ApprovalExpired,
    ApprovalGateway,
    Approver,
    ApproverRole,
    StaleCard,
)
from fazerops.actions.catalog import ApprovalPolicy, Catalog, default_catalog
from fazerops.actions.inverse import ActionRequest
from fazerops.actions.preconditions import Evidence

INCIDENT = "INC-7c1f9a2e4b6d8033-20260906T144100Z"
ACTION = "revert_configmap_key"
IC = Approver(user_id="U_IC_01", role=ApproverRole.ENGINEER)
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


class Runner:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, request, credential, evidence):
        self.calls += 1
        return {"action_id": request.action_id}


class Clock:
    def __init__(self) -> None:
        self.now = 1_789_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def runner() -> Runner:
    return Runner()


@pytest.fixture
def gateway(runner, clock) -> ApprovalGateway:
    return ApprovalGateway(runner=runner, clock=clock)


# --------------------------------------------------------------------------------------
# D1 — the digest
# --------------------------------------------------------------------------------------


def test_a_card_from_before_a_re_registration_executes_nothing(gateway, runner):
    first = gateway.register(INCIDENT, a_request("20"), evidence=EVIDENCE)
    second = gateway.register(INCIDENT, a_request("35"), evidence=EVIDENCE)
    assert first.digest != second.digest, "the re-fired investigation saw a different current value"

    with pytest.raises(StaleCard):
        gateway.decide(incident_id=INCIDENT, action_id=ACTION, approver=IC, kind="approve", dry_run_digest=first.digest)

    assert runner.calls == 0
    assert gateway.outcome(INCIDENT, ACTION) is None, "a stale click must not decide the fresh card"


def test_the_newest_card_still_executes_exactly_once(gateway, runner):
    gateway.register(INCIDENT, a_request("20"), evidence=EVIDENCE)
    second = gateway.register(INCIDENT, a_request("35"), evidence=EVIDENCE)

    outcome = gateway.decide(
        incident_id=INCIDENT, action_id=ACTION, approver=IC, kind="approve", dry_run_digest=second.digest
    )

    assert outcome.executed and runner.calls == 1


def test_a_stale_reject_does_not_reject_the_fresh_card(gateway, runner):
    first = gateway.register(INCIDENT, a_request("20"), evidence=EVIDENCE)
    gateway.register(INCIDENT, a_request("35"), evidence=EVIDENCE)

    with pytest.raises(StaleCard):
        gateway.decide(incident_id=INCIDENT, action_id=ACTION, approver=IC, kind="reject", dry_run_digest=first.digest)

    assert gateway.outcome(INCIDENT, ACTION) is None


def test_an_identical_re_registration_is_the_same_card(gateway):
    first = gateway.register(INCIDENT, a_request("20"), evidence=EVIDENCE)
    again = gateway.register(INCIDENT, a_request("20"), evidence=EVIDENCE)

    assert again is first, "the same dry run must not restart the card's expiry or change its digest"


def test_a_replay_is_answered_with_the_first_outcome_whatever_card_it_came_from(gateway, runner):
    """`decide()` checks idempotency first. A replay from the older card is still the first click's
    answer, not a `StaleCard` — and still no second execution."""
    first = gateway.register(INCIDENT, a_request("20"), evidence=EVIDENCE)
    gateway.decide(incident_id=INCIDENT, action_id=ACTION, approver=IC, kind="approve", dry_run_digest=first.digest)

    replay = gateway.decide(
        incident_id=INCIDENT, action_id=ACTION, approver=IC, kind="approve", dry_run_digest="0000000000000000"
    )

    assert replay.replay and runner.calls == 1


def test_the_digest_covers_what_the_card_shows():
    """Every field a human reads moves the digest, including a value that renders `<redacted>`."""
    base = default_catalog()
    one = a_request("20").dry_run(evidence=EVIDENCE, catalog=base)
    other = a_request("21").dry_run(evidence=EVIDENCE, catalog=base)

    assert one.digest == a_request("20").dry_run(evidence=EVIDENCE, catalog=base).digest
    assert one.digest != other.digest


# --------------------------------------------------------------------------------------
# A2 — expiry
# --------------------------------------------------------------------------------------


def test_an_expired_card_refuses_and_records_nothing(gateway, runner, clock):
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    clock.now = pending.expires_at + 1

    with pytest.raises(ApprovalExpired):
        gateway.decide(incident_id=INCIDENT, action_id=ACTION, approver=IC, kind="approve", dry_run_digest=pending.digest)

    assert runner.calls == 0
    assert gateway.outcome(INCIDENT, ACTION) is None


def test_re_investigating_after_expiry_opens_a_fresh_card(gateway, runner, clock):
    stale = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    clock.now = stale.expires_at + 1

    fresh = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    assert fresh is not stale and fresh.expires_at > clock.now
    assert gateway.decide(
        incident_id=INCIDENT, action_id=ACTION, approver=IC, kind="approve", dry_run_digest=fresh.digest
    ).executed
    assert runner.calls == 1


def test_a_card_is_approvable_until_its_expiry(gateway, runner, clock):
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    clock.now = pending.expires_at - 1

    assert gateway.decide(
        incident_id=INCIDENT, action_id=ACTION, approver=IC, kind="approve", dry_run_digest=pending.digest
    ).executed


def test_the_shipped_expiry_is_read_from_thresholds_yaml(gateway, clock):
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)

    assert default_catalog().approval.expires_after_seconds == 1800
    assert pending.expires_at == clock.now + 1800


def test_an_unset_expiry_never_expires(runner, clock):
    base = default_catalog()
    catalog = Catalog(list(base), base.thresholds, ApprovalPolicy(expires_after_seconds=None))
    gateway = ApprovalGateway(catalog=catalog, runner=runner, clock=clock)
    pending = gateway.register(INCIDENT, a_request(), evidence=EVIDENCE)
    clock.now += 10**9

    assert pending.expires_at is None
    assert gateway.decide(
        incident_id=INCIDENT, action_id=ACTION, approver=IC, kind="approve", dry_run_digest=pending.digest
    ).executed
