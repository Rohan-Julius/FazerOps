"""W20c — `restore_db_parameter`. Handoff §7, plan §4. **Tier 2.**

The plan's assertions: `tier: 2` is **declared** in the catalog and never inferred at
runtime; `inverse()` restores the prior parameter value; and `execute()` refuses without a
manager approval (W26b).

The third is asserted through the real `ApprovalGateway` rather than by checking a flag —
the property is that an IC approval cannot produce a credential this executor accepts, and
that is a claim about two modules agreeing, not about one field.

**Nothing here touches AWS.** Creating a parameter group is resource creation, which this
build does not do without asking. The boto3 call shapes carry `# UNVERIFIED (W20c)` in the
executor until a live test proves them; what *is* proven here is the argument construction,
the ordering of the guards, and that no client is built before the credential is checked.
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
from fazerops.actions.executors.rds import DEFAULT_APPLY_METHOD, restore_parameter
from fazerops.actions.inverse import ActionRequest, InverseUnavailable, request_from_hint
from fazerops.actions.preconditions import Evidence, PreconditionFailed
from fazerops.models import Tier
from fazerops.security.credentials import CredentialRefused, ReaderCredential

GROUP = "billing-primary-params"
PARAMETER = "max_connections"

HINT = {
    "action_id": "restore_db_parameter",
    "parameter_group": GROUP,
    "parameter": PARAMETER,
    "prior_value": "200",
    "current_value": "50",
}

EVIDENCE = Evidence(
    resource_keys=frozenset({keys.db_parameter_group(GROUP).blast_radius_key()}), complete=True
)

IC = Approver(user_id="U0IC", role=ApproverRole.ENGINEER)
MANAGER = Approver(user_id="U0MGR", role=ApproverRole.MANAGER)


class FakeRds:
    """Records calls instead of making them."""

    def __init__(self, *, value_after: str | None = "200") -> None:
        self.modified: list[dict] = []
        self.value_after = value_after

    def modify_db_parameter_group(self, **kwargs):
        self.modified.append(kwargs)
        return {"DBParameterGroupName": kwargs["DBParameterGroupName"]}

    def get_paginator(self, name):
        assert name == "describe_db_parameters"
        outer = self

        class Paginator:
            def paginate(self, **_):
                return [
                    {
                        "Parameters": [
                            {"ParameterName": "other", "ParameterValue": "x"},
                            {"ParameterName": PARAMETER, "ParameterValue": outer.value_after},
                        ]
                    }
                ]

        return Paginator()

    @property
    def count(self) -> int:
        return len(self.modified)


def a_request(**overrides) -> ActionRequest:
    params = {"parameter_group": GROUP, "parameter": PARAMETER, "target_value": "200"}
    params.update(overrides)
    return ActionRequest.for_action("restore_db_parameter", params, inverse_hint=HINT)


# --------------------------------------------------------------------------------------
# Tier is declared, never inferred
# --------------------------------------------------------------------------------------


def test_the_catalog_declares_tier_2_and_a_manager_approver():
    spec = default_catalog().get("restore_db_parameter")
    assert spec.tier is Tier.MANAGER_APPROVAL
    assert spec.requires_approval_from == "manager"


def test_the_request_reports_the_catalogs_tier():
    assert a_request().tier() is Tier.MANAGER_APPROVAL


def test_the_executor_contains_no_tier_check_of_its_own():
    """Structural. A second, local tier check would be a second source of truth, and the
    first time the two disagreed the one nobody audited would win."""
    import inspect

    from fazerops.actions.executors import rds

    body = inspect.getsource(rds.restore_parameter)
    assert "tier" not in body.lower().split('"""')[-1], "the executor inspects tier itself"


# --------------------------------------------------------------------------------------
# The inverse restores the prior value
# --------------------------------------------------------------------------------------


def test_the_inverse_restores_the_value_that_is_current_now():
    undo = a_request().inverse()

    assert undo is not None
    assert undo.action_id == "restore_db_parameter"
    assert undo.params["target_value"] == "50", "the inverse does not restore what was replaced"
    assert undo.params["parameter_group"] == GROUP
    assert undo.params["parameter"] == PARAMETER


def test_the_forward_action_is_built_from_the_hint():
    request = request_from_hint(HINT)

    assert request is not None
    assert request.params["target_value"] == "200"


def test_a_hint_with_no_current_value_yields_no_inverse_and_execute_refuses():
    request = ActionRequest.for_action(
        "restore_db_parameter",
        {"parameter_group": GROUP, "parameter": PARAMETER, "target_value": "200"},
        inverse_hint={k: v for k, v in HINT.items() if k != "current_value"},
    )

    assert request.inverse() is None
    with pytest.raises(InverseUnavailable):
        request.execute(credential=None, evidence=EVIDENCE)


def test_the_inverse_carries_an_explicit_apply_method_through():
    undo = a_request(apply_method="immediate").inverse()
    assert undo.params["apply_method"] == "immediate"


# --------------------------------------------------------------------------------------
# execute() refuses without a manager approval — W26b
# --------------------------------------------------------------------------------------


def test_an_ic_approval_cannot_produce_a_credential_this_executor_accepts():
    calls = []
    gateway = ApprovalGateway(runner=lambda req, cred, ev: calls.append(cred) or {})
    gateway.register("INC-RDS", a_request(), evidence=EVIDENCE)

    with pytest.raises(ApproverNotPermitted):
        gateway.decide(
            incident_id="INC-RDS",
            action_id="restore_db_parameter",
            approver=IC,
            kind="approve",
        )

    assert calls == [], "an IC approval reached the executor"


def test_a_manager_approval_mints_a_credential_the_executor_accepts():
    client = FakeRds()
    gateway = ApprovalGateway(
        runner=lambda req, cred, ev: restore_parameter(
            req.params, credential=cred, undo=req.inverse(), client=client
        )
    )
    gateway.register("INC-RDS", a_request(), evidence=EVIDENCE)

    outcome = gateway.decide(
        incident_id="INC-RDS",
        action_id="restore_db_parameter",
        approver=MANAGER,
        kind="approve",
    )

    assert outcome.error is None, outcome.error
    assert client.count == 1
    assert outcome.result["parameter"] == PARAMETER


def test_the_credential_is_scoped_to_the_parameter_group_not_a_namespace():
    """`restore_db_parameter` has no namespace; `approval.scope_of` binds it to the group,
    which is the resource `session_policy`'s tag condition names."""
    minted = {}
    gateway = ApprovalGateway(runner=lambda req, cred, ev: (minted.setdefault("c", cred), {})[1])
    gateway.register("INC-RDS", a_request(), evidence=EVIDENCE)
    gateway.decide(
        incident_id="INC-RDS",
        action_id="restore_db_parameter",
        approver=MANAGER,
        kind="approve",
    )

    assert minted["c"].namespace == GROUP


def test_the_session_policy_grants_only_the_two_rds_calls():
    from fazerops.security.credentials import session_policy

    statement = session_policy(GROUP, "restore_db_parameter")["Statement"][0]
    assert set(statement["Action"]) == {
        "rds:ModifyDBParameterGroup",
        "rds:DescribeDBParameters",
    }


# --------------------------------------------------------------------------------------
# The credential gate runs before any client
# --------------------------------------------------------------------------------------


def test_the_executor_refuses_without_a_credential_and_builds_no_client():
    client = FakeRds()

    with pytest.raises(CredentialRefused):
        restore_parameter(
            {"parameter_group": GROUP, "parameter": PARAMETER, "target_value": "200"},
            credential=None,
            client=client,
        )

    assert client.count == 0


def test_the_executor_refuses_the_reader_principal():
    client = FakeRds()

    with pytest.raises(CredentialRefused):
        restore_parameter(
            {"parameter_group": GROUP, "parameter": PARAMETER, "target_value": "200"},
            credential=ReaderCredential(),
            client=client,
        )

    assert client.count == 0


def test_an_uncollected_parameter_group_fails_closed():
    with pytest.raises(PreconditionFailed):
        a_request().execute(credential=None, evidence=Evidence(complete=True))


# --------------------------------------------------------------------------------------
# The call it actually builds
# --------------------------------------------------------------------------------------


@pytest.fixture
def approved():
    minted = {}
    gateway = ApprovalGateway(runner=lambda req, cred, ev: (minted.setdefault("c", cred), {})[1])
    gateway.register("INC-RDS", a_request(), evidence=EVIDENCE)
    gateway.decide(
        incident_id="INC-RDS",
        action_id="restore_db_parameter",
        approver=MANAGER,
        kind="approve",
    )
    return minted["c"]


def test_one_parameter_per_call(approved):
    """A partially-valid batch would apply some parameters and reject others, leaving a
    state no computed inverse describes."""
    client = FakeRds()
    restore_parameter(
        {"parameter_group": GROUP, "parameter": PARAMETER, "target_value": "200"},
        credential=approved,
        client=client,
    )

    sent = client.modified[0]
    assert sent["DBParameterGroupName"] == GROUP
    assert len(sent["Parameters"]) == 1
    assert sent["Parameters"][0] == {
        "ParameterName": PARAMETER,
        "ParameterValue": "200",
        "ApplyMethod": DEFAULT_APPLY_METHOD,
    }


def test_the_default_apply_method_is_pending_reboot():
    """RDS rejects `immediate` for a static parameter, and that failure arrives mid-mutation
    after the approval has already been spent. `pending-reboot` is valid for every
    parameter, so the default cannot fail on a property nobody looked up."""
    assert DEFAULT_APPLY_METHOD == "pending-reboot"


def test_an_explicit_apply_method_is_honoured(approved):
    client = FakeRds()
    restore_parameter(
        {
            "parameter_group": GROUP,
            "parameter": PARAMETER,
            "target_value": "200",
            "apply_method": "immediate",
        },
        credential=approved,
        client=client,
    )

    assert client.modified[0]["Parameters"][0]["ApplyMethod"] == "immediate"


def test_the_catalog_rejects_an_apply_method_outside_the_enum():
    from fazerops.actions.catalog import ValidationRejected

    with pytest.raises(ValidationRejected):
        ActionRequest.for_action(
            "restore_db_parameter",
            {
                "parameter_group": GROUP,
                "parameter": PARAMETER,
                "target_value": "200",
                "apply_method": "whenever",
            },
            inverse_hint=HINT,
        )


def test_the_result_reports_the_value_read_back(approved):
    client = FakeRds(value_after="200")
    result = restore_parameter(
        {"parameter_group": GROUP, "parameter": PARAMETER, "target_value": "200"},
        credential=approved,
        undo=a_request().inverse(),
        client=client,
    )

    assert result["value"] == "200"
    assert result["inverse"]["params"]["target_value"] == "50"


def test_an_unreadable_value_does_not_report_a_completed_change_as_a_failure(approved):
    class Unreadable(FakeRds):
        def get_paginator(self, name):
            raise RuntimeError("describe_db_parameters exploded")

    client = Unreadable()
    result = restore_parameter(
        {"parameter_group": GROUP, "parameter": PARAMETER, "target_value": "200"},
        credential=approved,
        client=client,
    )

    assert result["value"] is None
    assert client.count == 1, "the modify did not happen"


def test_the_executor_is_no_longer_pending():
    from fazerops.actions.executors._pending import ExecutorNotYetImplemented

    try:
        restore_parameter(
            {"parameter_group": GROUP, "parameter": PARAMETER, "target_value": "200"}
        )
    except ExecutorNotYetImplemented:  # pragma: no cover
        pytest.fail("restore_db_parameter still raises ExecutorNotYetImplemented")
    except CredentialRefused:
        pass
