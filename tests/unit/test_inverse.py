"""W21 — inverse computation. Ground rule #4, Handoff §7.

> *Every mutating action computes its inverse before executing and refuses to run if it
> cannot.*

The plan names three assertions, and they are the three halves of that sentence:

* `inverse(revert_configmap_key: pool.max→100)` returns a **fully-parameterized** action
  restoring `20`;
* an unknown prior value yields `None`;
* **`execute()` raises when `inverse()` is `None`.**

The third is the one that matters. The first two are correctness; the third is the promise.
"""

from __future__ import annotations

import pytest

from fazerops.actions.catalog import UnknownAction
from fazerops.actions.inverse import (
    ActionRequest,
    InverseUnavailable,
    inverse,
    request_from_hint,
)

# The demo's own event: `pool.max` went 100 → 20 out of band. Reverting it means setting the
# key back to 100, and the inverse of *that* is setting it back to 20.
CONFIGMAP_HINT = {
    "action_id": "revert_configmap_key",
    "namespace": "billing",
    "name": "billing-api-config",
    "key": "pool.max",
    "prior_value": "100",
    "current_value": "20",
}

HELM_HINT = {
    "action_id": "helm_rollback",
    "release": "billing-api",
    "namespace": "billing",
    "target_revision": 2,
    "current_revision": 3,
}

RDS_HINT = {
    "action_id": "restore_db_parameter",
    "parameter_group": "billing-primary-params",
    "parameter": "max_connections",
    "prior_value": "200",
    "current_value": "50",
}


# --------------------------------------------------------------------------------------
# The plan's first assertion
# --------------------------------------------------------------------------------------


def test_inverse_of_reverting_pool_max_to_100_restores_20():
    forward = request_from_hint(CONFIGMAP_HINT)

    assert forward is not None
    assert forward.action_id == "revert_configmap_key"
    assert forward.params["target_value"] == "100", "the forward action restores the prior value"

    undo = inverse(forward)

    assert undo is not None
    assert undo.action_id == "revert_configmap_key", "the action is its own inverse (Handoff §7)"
    assert undo.params == {
        "namespace": "billing",
        "name": "billing-api-config",
        "key": "pool.max",
        "target_value": "20",
    }


def test_the_inverse_is_fully_parameterized():
    """Every required parameter present, not just the one that changed.

    A partially-parameterized inverse is indistinguishable at the call site from a complete
    one and fails at execution — with the original change already applied, which is the
    worst possible moment to discover it.
    """
    undo = inverse(request_from_hint(CONFIGMAP_HINT))
    spec = undo.spec()

    assert set(undo.params) >= set(spec.required_params)
    assert all(undo.params[name] is not None for name in spec.required_params)


def test_inverse_of_a_helm_rollback_targets_the_currently_deployed_revision():
    """Handoff §5: revision N−1 gives the inverse for free."""
    forward = request_from_hint(HELM_HINT)

    assert forward.params["target_revision"] == 2
    undo = inverse(forward)

    assert undo is not None
    assert undo.params["target_revision"] == 3
    assert undo.params["release"] == "billing-api"
    assert undo.params["namespace"] == "billing"


def test_inverse_of_a_db_parameter_restores_the_current_value():
    forward = request_from_hint(RDS_HINT)

    assert forward.params["target_value"] == "200"
    undo = inverse(forward)

    assert undo is not None
    assert undo.params["target_value"] == "50"
    assert undo.params["parameter_group"] == "billing-primary-params"


def test_inversion_is_relative_to_the_recorded_snapshot_and_does_not_compose():
    """**Inversion here is not involutive, and it must not be assumed to be.**

    Written as an involutivity assertion first, and it failed — correctly. A hint is one
    snapshot: `prior_value` and `current_value` as they stood when the collector observed
    the change. `inverse()` answers "what restores the recorded state", so it returns
    `current_value` no matter how many times it is applied. Composing it is meaningless,
    because the second application would need a *second* snapshot taken after the first
    action ran, and no such snapshot exists.

    Nothing in the product composes inverses — an approval card shows one action and its
    one inverse. This test exists so the next reader does not mistake the fixed point below
    for a bug, and does not add a caller that depends on composition.
    """
    forward = request_from_hint(CONFIGMAP_HINT)
    undo = inverse(forward)

    assert forward.params["target_value"] == "100"
    assert undo.params["target_value"] == "20", "restores the state the collector recorded"
    assert inverse(undo).params["target_value"] == "20", "a fixed point, not a round trip"


# --------------------------------------------------------------------------------------
# The plan's second assertion — unknown prior value → None
# --------------------------------------------------------------------------------------


def test_unknown_prior_value_yields_no_forward_action():
    """CloudTrail's normal case. `lookup_events` returns no prior value, so ground rule #4
    forbids the reversible claim — and nothing may reconstruct one."""
    hint = dict(CONFIGMAP_HINT, prior_value=None)
    assert request_from_hint(hint) is None


def test_unknown_current_value_yields_no_inverse():
    forward = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
        inverse_hint=dict(CONFIGMAP_HINT, current_value=None),
    )
    assert inverse(forward) is None


def test_no_hint_at_all_yields_no_inverse():
    forward = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
    )
    assert forward.inverse() is None


def test_a_hint_naming_an_action_outside_the_catalog_is_refused():
    """An `inverse_hint` is data recorded by a collector from source payloads, so it is as
    untrusted as anything else in the ledger. It cannot name an action the catalog lacks."""
    assert request_from_hint({"action_id": "delete_namespace", "namespace": "billing"}) is None


def test_an_empty_hint_is_not_an_error():
    """An event with no recorded prior value is the normal case, not a fault. Raising here
    would make every CloudTrail event an exception to handle."""
    assert request_from_hint(None) is None
    assert request_from_hint({}) is None


# --------------------------------------------------------------------------------------
# The plan's third assertion — the refusal
# --------------------------------------------------------------------------------------


def test_execute_refuses_when_the_inverse_is_none():
    """Ground rule #4, and the only assertion in this file that is about a *promise* rather
    than about arithmetic."""
    forward = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
    )
    assert forward.inverse() is None

    with pytest.raises(InverseUnavailable, match="ground rule #4"):
        forward.execute()


def test_execute_computes_the_inverse_itself_rather_than_trusting_the_caller():
    """The guard must not be bypassable by a caller who forgot to check — that caller is
    the entire reason the guard exists.

    Asserted by reaching the executor only when an inverse exists: with a good hint *and*
    satisfied preconditions the call gets past both guards and into `configmap:revert_key`,
    whose mutating body is W24.
    """
    from fazerops.actions.executors._pending import ExecutorNotYetImplemented
    from fazerops.actions.preconditions import Evidence

    forward = request_from_hint(CONFIGMAP_HINT)
    evidence = Evidence(
        resource_keys=frozenset({"k8s:billing/configmap/billing-api-config"}), complete=True
    )
    with pytest.raises(ExecutorNotYetImplemented):
        forward.execute(evidence=evidence)


def test_execute_reaches_no_executor_when_the_inverse_is_missing(monkeypatch):
    """The refusal happens *before* the executor is resolved, so a missing inverse can
    never reach code that mutates."""
    called: list[str] = []

    def spy(*args, **kwargs):
        called.append("resolved")
        raise AssertionError("resolve_executor must not be reached")

    monkeypatch.setattr("fazerops.actions.catalog.resolve_executor", spy)

    forward = ActionRequest.for_action(
        "helm_rollback",
        {"release": "billing-api", "namespace": "billing", "target_revision": 2},
    )
    with pytest.raises(InverseUnavailable):
        forward.execute()
    assert called == []


# --------------------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------------------


def test_an_action_request_cannot_be_built_for_an_unknown_action():
    with pytest.raises(UnknownAction):
        ActionRequest.for_action("delete_namespace", {"namespace": "billing"})


def test_an_action_request_validates_its_params_on_construction():
    from fazerops.actions.catalog import ValidationRejected

    with pytest.raises(ValidationRejected):
        ActionRequest.for_action("revert_configmap_key", {"namespace": "billing"})
