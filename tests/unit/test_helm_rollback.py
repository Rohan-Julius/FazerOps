"""W20b — `helm_rollback`. Handoff §5 and §7, plan §4.

The plan's two assertions: `inverse(rollback to N−1)` returns a rollback to the **current**
revision, and a target revision absent from `helm history` fails the precondition **before
any client is constructed**.

The second is the one with teeth, and it is asserted by counting invocations of an injected
runner rather than by catching an exception — a version that built its argv, shelled out,
and *then* noticed the precondition would raise the same exception while having already
touched the cluster.

Nothing here runs `helm`. The e2e half is `tests/e2e/test_helm_rollback.py`, marked
`cluster`.
"""

from __future__ import annotations

import json

import pytest

from fazerops.actions.catalog import default_catalog
from fazerops.actions.executors.helm import rollback
from fazerops.actions.inverse import ActionRequest, request_from_hint
from fazerops.actions.preconditions import Evidence, PreconditionFailed
from fazerops.models import Tier
from fazerops.security.credentials import CredentialRefused, ReaderCredential

RELEASE = "billing-api"
NAMESPACE = "billing"

# Revision 3 is deployed; the change under investigation was the upgrade to 3, so the
# action rolls back to 2 and its inverse rolls forward to 3.
HINT = {
    "action_id": "helm_rollback",
    "release": RELEASE,
    "namespace": NAMESPACE,
    "target_revision": 2,
    "current_revision": 3,
}

EVIDENCE = Evidence(helm_revisions={f"{NAMESPACE}/{RELEASE}": frozenset({1, 2, 3})}, complete=True)


class FakeRunner:
    """Captures argv instead of running it. The captured list is the assertion."""

    def __init__(self, *, version: int | None = 4) -> None:
        self.argv: list[list[str]] = []
        self.version = version

    def __call__(self, argv):
        self.argv.append(list(argv))
        if "status" in argv:
            return json.dumps({"version": self.version})
        return ""

    @property
    def count(self) -> int:
        return len(self.argv)


def a_request() -> ActionRequest:
    return ActionRequest.for_action(
        "helm_rollback",
        {"release": RELEASE, "namespace": NAMESPACE, "target_revision": 2},
        inverse_hint=HINT,
    )


# --------------------------------------------------------------------------------------
# The inverse — Handoff §5's "revision N-1 is the inverse for free"
# --------------------------------------------------------------------------------------


def test_the_inverse_of_a_rollback_to_n_minus_1_is_a_rollback_to_the_current_revision():
    undo = a_request().inverse()

    assert undo is not None
    assert undo.action_id == "helm_rollback"
    assert undo.params["target_revision"] == 3, "the inverse does not restore what was replaced"
    assert undo.params["release"] == RELEASE
    assert undo.params["namespace"] == NAMESPACE


def test_the_forward_action_is_built_from_the_collectors_hint():
    """The Helm collector attaches `previous_revision` for exactly this — it is the only
    source that knows what N−1 was."""
    request = request_from_hint(HINT)

    assert request is not None
    assert request.action_id == "helm_rollback"
    assert request.params["target_revision"] == 2


def test_a_hint_with_no_current_revision_yields_no_inverse():
    """Ground rule #4: `None` is the answer, and `execute()` then refuses. A rollback whose
    undo target is unknown is an irreversible mutation dressed as a reversible one."""
    request = ActionRequest.for_action(
        "helm_rollback",
        {"release": RELEASE, "namespace": NAMESPACE, "target_revision": 2},
        inverse_hint={k: v for k, v in HINT.items() if k != "current_revision"},
    )

    assert request.inverse() is None


def test_execute_refuses_when_no_inverse_can_be_computed():
    from fazerops.actions.inverse import InverseUnavailable

    request = ActionRequest.for_action(
        "helm_rollback",
        {"release": RELEASE, "namespace": NAMESPACE, "target_revision": 2},
        inverse_hint=None,
    )

    with pytest.raises(InverseUnavailable):
        request.execute(credential=None, evidence=EVIDENCE)


# --------------------------------------------------------------------------------------
# Preconditions fail before anything is constructed
# --------------------------------------------------------------------------------------


def test_a_target_revision_absent_from_history_fails_before_any_client_is_constructed():
    runner = FakeRunner()
    request = ActionRequest.for_action(
        "helm_rollback",
        {"release": RELEASE, "namespace": NAMESPACE, "target_revision": 99},
        inverse_hint={**HINT, "target_revision": 99},
    )

    with pytest.raises(PreconditionFailed):
        request.execute(credential=None, evidence=EVIDENCE)

    assert runner.count == 0, "helm was invoked despite an unsatisfied precondition"


def test_an_uncollected_release_fails_closed():
    """An empty inventory means "nobody looked", not "it is fine" — `preconditions.py`."""
    with pytest.raises(PreconditionFailed):
        a_request().execute(credential=None, evidence=Evidence(complete=True))


# --------------------------------------------------------------------------------------
# The credential gate runs before the binary
# --------------------------------------------------------------------------------------


def test_the_executor_refuses_without_a_credential_and_runs_nothing():
    runner = FakeRunner()

    with pytest.raises(CredentialRefused):
        rollback(
            {"release": RELEASE, "namespace": NAMESPACE, "target_revision": 2},
            credential=None,
            runner=runner,
        )

    assert runner.count == 0


def test_the_executor_refuses_the_reader_principal():
    """Read and write are different principals (Handoff §8), checked by type on every call
    rather than remembered by whoever wrote the executor."""
    runner = FakeRunner()

    with pytest.raises(CredentialRefused):
        rollback(
            {"release": RELEASE, "namespace": NAMESPACE, "target_revision": 2},
            credential=ReaderCredential(),
            runner=runner,
        )

    assert runner.count == 0


# --------------------------------------------------------------------------------------
# The command it actually builds
# --------------------------------------------------------------------------------------


@pytest.fixture
def approved():
    """A credential minted through the real gateway, as a real approval would."""
    from fazerops.actions.approval import ApprovalGateway, Approver, ApproverRole

    minted = {}

    def capture(request, credential, evidence):
        minted["credential"] = credential
        return {}

    gateway = ApprovalGateway(runner=capture)
    gateway.register("INC-HELM", a_request(), evidence=EVIDENCE)
    gateway.decide(
        incident_id="INC-HELM",
        action_id="helm_rollback",
        approver=Approver(user_id="U0IC", role=ApproverRole.ENGINEER),
        kind="approve",
    )
    return minted["credential"]


def test_the_rollback_names_an_explicit_revision():
    """`helm rollback <release>` with no revision rolls back one step from wherever the
    release is *now*, which is not necessarily where it was when the dry run was rendered.
    The revision a human read must be the revision that executes."""
    from fazerops.actions.approval import ApprovalGateway, Approver, ApproverRole

    runner = FakeRunner()
    gateway = ApprovalGateway(
        runner=lambda req, cred, ev: rollback(req.params, credential=cred, undo=req.inverse(), runner=runner)
    )
    gateway.register("INC-HELM", a_request(), evidence=EVIDENCE)
    gateway.decide(
        incident_id="INC-HELM",
        action_id="helm_rollback",
        approver=Approver(user_id="U0IC", role=ApproverRole.ENGINEER),
        kind="approve",
    )

    command = runner.argv[0]
    assert command[:3] == ["helm", "rollback", RELEASE]
    assert "2" in command, "the rollback did not name the target revision"
    assert "--namespace" in command and NAMESPACE in command
    assert "--wait" not in command, "a blocking rollback hangs the demo — see the module docstring"


def test_every_argv_element_is_a_string(approved):
    """A revision is an int everywhere else in this build and argv is not. An int reaching
    subprocess is a TypeError mid-mutation."""
    runner = FakeRunner()
    rollback(
        {"release": RELEASE, "namespace": NAMESPACE, "target_revision": 2},
        credential=approved,
        runner=runner,
    )

    for command in runner.argv:
        assert all(isinstance(part, str) for part in command), command


def test_the_result_distinguishes_the_requested_revision_from_the_one_helm_landed_on(approved):
    """Helm creates a *new* revision restoring the target's manifest, so the release
    reports N+1 after a rollback. Conflating the two would make the incident record claim
    the release sits on a revision it does not."""
    runner = FakeRunner(version=4)

    result = rollback(
        {"release": RELEASE, "namespace": NAMESPACE, "target_revision": 2},
        credential=approved,
        undo=a_request().inverse(),
        runner=runner,
    )

    assert result["requested_revision"] == 2
    assert result["revision"] == 4
    assert result["inverse"]["params"]["target_revision"] == 3


def test_an_unreadable_status_does_not_report_a_completed_rollback_as_a_failure(approved):
    """The mutation has already happened by then. Raising would invite a retry of something
    that already ran."""

    class StatusFails(FakeRunner):
        def __call__(self, argv):
            self.argv.append(list(argv))
            if "status" in argv:
                raise RuntimeError("helm status exploded")
            return ""

    runner = StatusFails()
    result = rollback(
        {"release": RELEASE, "namespace": NAMESPACE, "target_revision": 2},
        credential=approved,
        runner=runner,
    )

    assert result["revision"] is None
    assert result["requested_revision"] == 2


# --------------------------------------------------------------------------------------
# Catalog agreement
# --------------------------------------------------------------------------------------


def test_helm_rollback_is_tier_1_and_declared_not_inferred():
    spec = default_catalog().get("helm_rollback")
    assert spec.tier is Tier.ENGINEER_APPROVAL
    assert spec.requires_approval_from != "manager"


def test_the_executor_is_no_longer_pending():
    from fazerops.actions.executors._pending import ExecutorNotYetImplemented

    runner = FakeRunner()
    try:
        rollback({"release": RELEASE, "namespace": NAMESPACE, "target_revision": 2}, runner=runner)
    except ExecutorNotYetImplemented:  # pragma: no cover - the assertion below is the point
        pytest.fail("helm_rollback still raises ExecutorNotYetImplemented")
    except CredentialRefused:
        pass
