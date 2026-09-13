"""W27 — a hand-forged `action_id` is rejected pre-dispatch. Handoff §0 rule #1, plan §4.

The sibling suites assume the *model* is compromised. This one assumes the **payload** is:
a Slack button value edited in transit, a replayed callback, a direct call into the
automation layer by something that skipped the proposer entirely.

"Pre-dispatch" is the whole assertion, and it is checked by counting constructions rather
than by catching an exception. A version that resolved the executor, built a client, and
*then* noticed the action was unknown would raise the same exception while having already
opened a connection to a cluster.

Every layer an id can enter through is covered, because an allowlist enforced at four of
five entry points is an allowlist with one way in.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _injection import FORBIDDEN_ACTION_PREFIXES  # noqa: E402

from fazerops.actions.approval import (  # noqa: E402
    ApprovalGateway,
    Approver,
    ApproverRole,
)
from fazerops.actions.catalog import (  # noqa: E402
    UnknownAction,
    ValidationRejected,
    default_catalog,
)
from fazerops.actions.inverse import ActionRequest  # noqa: E402
from fazerops.agents.proposer import ACTION_IDS  # noqa: E402

FORGED = [
    "delete_namespace",
    "revert_configmap_key ",          # trailing space
    "REVERT_CONFIGMAP_KEY",           # case
    "revert_configmap_key; kubectl delete ns billing",
    "../../etc/passwd",
    "fazerops.actions.executors.configmap:revert_key",   # an import path, not an id
    "os:system",
    "",
    "revert_configmap_key\nhelm_rollback",
]

IC = Approver(user_id="U0IC", role=ApproverRole.ENGINEER)


@pytest.fixture
def watched(monkeypatch):
    """Counts every executor resolution. The count is the assertion."""
    from fazerops.actions import catalog as catalog_module

    resolved: list[str] = []
    real = catalog_module.resolve_executor

    def watch(action):
        resolved.append(action.id)
        return real(action)

    monkeypatch.setattr(catalog_module, "resolve_executor", watch)
    monkeypatch.setattr("fazerops.actions.inverse.resolve_executor", watch, raising=False)
    return resolved


# --------------------------------------------------------------------------------------
# The catalog itself
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("action_id", FORGED)
def test_the_catalog_refuses_a_forged_id(action_id):
    with pytest.raises(UnknownAction):
        default_catalog().get(action_id)


@pytest.mark.parametrize("action_id", FORGED)
def test_an_action_request_cannot_be_built_from_a_forged_id(action_id, watched):
    """`ActionRequest.for_action` is the only constructor, so an id that fails here has no
    other route to an executor."""
    with pytest.raises(UnknownAction):
        ActionRequest.for_action(action_id, {"namespace": "billing"})

    assert watched == [], "an executor was resolved for a forged action id"


def test_there_is_no_fallback_or_default_action():
    """A default action is how an unknown id becomes a mutation instead of a refusal."""
    catalog = default_catalog()

    assert len(catalog) == 3
    for action_id in catalog.action_ids:
        assert not action_id.startswith(FORBIDDEN_ACTION_PREFIXES)
    assert "default" not in catalog and "fallback" not in catalog


# --------------------------------------------------------------------------------------
# The proposer's schema
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("action_id", FORGED)
def test_a_forged_id_is_not_expressible_in_the_proposer_schema(action_id):
    """The enum is built from the catalog at import, so this is a schema failure rather
    than a lookup that someone could forget to write."""
    assert action_id not in ACTION_IDS


def test_the_proposer_enum_is_exactly_the_catalog():
    assert set(ACTION_IDS) == set(default_catalog().action_ids)


# --------------------------------------------------------------------------------------
# The approval gateway — the last door before a credential exists
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("action_id", FORGED)
def test_the_gateway_refuses_to_register_a_forged_id(action_id, watched):
    gateway = ApprovalGateway(runner=lambda *a, **k: pytest.fail("an executor ran"))

    with pytest.raises((UnknownAction, ValidationRejected)):
        gateway.register(
            "INC-FORGED",
            ActionRequest.for_action(action_id, {"namespace": "billing"}),
            evidence=None,
        )

    assert watched == []


@pytest.mark.parametrize("action_id", FORGED)
def test_a_decision_naming_a_forged_id_mints_no_credential(action_id, watched):
    """The Slack path's shape: a button value edited in transit names an action nobody
    registered. It must not reconstruct one."""
    from fazerops.actions.approval import NotAwaitingApproval

    gateway = ApprovalGateway(runner=lambda *a, **k: pytest.fail("an executor ran"))

    with pytest.raises(NotAwaitingApproval):
        gateway.decide(
            incident_id="INC-FORGED", action_id=action_id, approver=IC, kind="approve"
        )

    assert watched == []


def test_a_forged_id_cannot_ride_in_on_a_real_incident(watched):
    """A registered incident plus a swapped action id — the replay-with-substitution shape.
    The idempotency key is the pair, so the real action's outcome must not authorize the
    forged one."""
    from fazerops import keys
    from fazerops.actions.approval import NotAwaitingApproval
    from fazerops.actions.preconditions import Evidence

    ran: list[str] = []
    gateway = ApprovalGateway(runner=lambda req, cred, ev: (ran.append(req.action_id), {})[1])
    real = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
        inverse_hint={"current_value": "20"},
    )
    gateway.register(
        "INC-REAL",
        real,
        evidence=Evidence(
            resource_keys=frozenset(
                {keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}
            ),
            complete=True,
        ),
    )

    with pytest.raises(NotAwaitingApproval):
        gateway.decide(
            incident_id="INC-REAL", action_id="delete_namespace", approver=IC, kind="approve"
        )

    assert ran == []


# --------------------------------------------------------------------------------------
# Parameters, not just ids
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "params",
    [
        {"namespace": "billing"},  # missing required
        {"namespace": "billing", "name": "c", "key": "k", "target_value": 1},  # wrong type
        {
            "namespace": "billing",
            "name": "c",
            "key": "k",
            "target_value": "1",
            "command": "kubectl delete ns billing",
        },  # unknown parameter
    ],
)
def test_bad_parameters_are_rejected_before_any_executor_is_resolved(params, watched):
    with pytest.raises(ValidationRejected):
        ActionRequest.for_action("revert_configmap_key", params)

    assert watched == []
