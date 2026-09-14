"""D3 and A4 (drift log, 14 Sep) — a mutation FazerOps executes names the human who approved it.

Found on the live k3d cluster before this change: every ConfigMap revert FazerOps had executed was
recorded in the Kubernetes audit log as `system:admin`, the kubeconfig's principal. The collector
read that back as an unresolved actor making an out-of-band change, so FazerOps's own approved
revert became a candidate cause in the next incident, attributed to nobody.

Asserted at each hop without a cluster: the approver on the minted credential, on the STS call, on
the Kubernetes client's impersonation headers and Helm's argv, and the collector attributing an
impersonated event to FazerOps. `tests/e2e/test_actor_attribution_live.py` asserts the same chain
against the real API server.
"""

from __future__ import annotations

import pytest

from fazerops import keys
from fazerops.actions.approval import ApprovalGateway, Approver, ApproverRole
from fazerops.actions.inverse import ActionRequest
from fazerops.actions.preconditions import Evidence
from fazerops.collectors.k8s_audit import K8sAuditCollector
from fazerops.ledger.normalize import FAZEROPS_ACTOR_PREFIX, normalize_actor
from fazerops.security.credentials import KUBERNETES_ACTOR_GROUP, kubernetes_identity

INCIDENT = "INC-7c1f9a2e4b6d8033-20260906T144100Z"
IC = Approver(user_id="U0IC", role=ApproverRole.ENGINEER)
EVIDENCE = Evidence(
    resource_keys=frozenset({keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}),
    complete=True,
)
HINT = {
    "action_id": "revert_configmap_key",
    "namespace": "billing",
    "name": "billing-api-config",
    "key": "pool.max",
    "prior_value": "100",
    "current_value": "20",
}


def _request() -> ActionRequest:
    return ActionRequest.for_action(
        "revert_configmap_key",
        {"namespace": "billing", "name": "billing-api-config", "key": "pool.max", "target_value": "100"},
        inverse_hint=HINT,
    )


def _approve(gateway: ApprovalGateway) -> None:
    pending = gateway.register(INCIDENT, _request(), evidence=EVIDENCE)
    gateway.decide(incident_id=INCIDENT, action_id=pending.action_id, approver=IC, kind="approve", dry_run_digest=pending.digest)


# --------------------------------------------------------------------------------------
# The credential
# --------------------------------------------------------------------------------------


def test_the_minted_credential_carries_the_approver():
    seen = []
    _approve(ApprovalGateway(runner=lambda request, credential, evidence: seen.append(credential) or {}))

    [credential] = seen
    assert credential.approver == "U0IC"
    assert kubernetes_identity(credential) == (f"{FAZEROPS_ACTOR_PREFIX}U0IC", [KUBERNETES_ACTOR_GROUP])


RDS_GROUP = "billing-primary-params"
RDS_EVIDENCE = Evidence(resource_keys=frozenset({keys.db_parameter_group(RDS_GROUP).blast_radius_key()}), complete=True)
MANAGER = Approver(user_id="U0MGR", role=ApproverRole.MANAGER)
ROLE = "arn:aws:iam::111122223333:role/fazerops-actor"


def _rds_request() -> ActionRequest:
    return ActionRequest.for_action(
        "restore_db_parameter",
        {"parameter_group": RDS_GROUP, "parameter": "max_connections", "target_value": "200"},
        inverse_hint={
            "action_id": "restore_db_parameter",
            "parameter_group": RDS_GROUP,
            "parameter": "max_connections",
            "prior_value": "200",
            "current_value": "50",
        },
    )


def _approve_rds(gateway: ApprovalGateway) -> None:
    pending = gateway.register(INCIDENT, _rds_request(), evidence=RDS_EVIDENCE)
    gateway.decide(
        incident_id=INCIDENT, action_id="restore_db_parameter", approver=MANAGER, kind="approve", dry_run_digest=pending.digest
    )


class RecordingSTS:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def assume_role(self, **kwargs):
        self.calls.append(kwargs)
        return {"Credentials": {"AccessKeyId": "ASIA-SYNTHETIC", "SecretAccessKey": "synthetic", "SessionToken": "synthetic"}}


def test_the_sts_session_names_the_approver(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    sts = RecordingSTS()

    _approve_rds(ApprovalGateway(runner=lambda *args: {}, sts_client=sts, role_arn=ROLE))

    [call] = sts.calls
    assert call["SourceIdentity"] == "slack-U0MGR"
    assert {"Key": "fazerops:approver", "Value": "U0MGR"} in call["Tags"]
    assert {"Key": "fazerops:incident", "Value": INCIDENT} in call["Tags"]


def test_a_kubernetes_action_never_assumes_the_aws_role(monkeypatch):
    """The trap gap 3 closed: its session policy grants no AWS call, and STS rejects a policy with an
    empty action list — so assuming for it would break every revert once a role was configured."""
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    sts = RecordingSTS()
    seen = []

    _approve(ApprovalGateway(runner=lambda request, credential, evidence: seen.append(credential) or {}, sts_client=sts, role_arn=ROLE))

    assert sts.calls == []
    assert seen[0].approver == "U0IC", "the Kubernetes identity still carries the approver"


def test_the_sts_call_is_valid_against_the_real_api_model(monkeypatch):
    """Offline: botocore validates parameter names and types against STS's own service model before a
    stubbed response is returned. This retires the parameter-name half of `UNVERIFIED`; that the
    account's trust policy accepts the call still needs the role to exist. (botocore does not enforce
    string lengths client-side, so `SourceIdentity`'s 2–64 bound is `credentials._assume`'s to keep.)"""
    boto3 = pytest.importorskip("boto3")
    from botocore.exceptions import ParamValidationError
    from botocore.stub import Stubber

    monkeypatch.setenv("FAZEROPS_MODE", "live")
    client = boto3.client("sts", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    from datetime import datetime, timezone

    response = {
        "Credentials": {
            # Deliberately not key-shaped: `test_no_secrets` fails the build on anything that is.
            "AccessKeyId": "synthetic-access-key-id",
            "SecretAccessKey": "testing-secret-access-key",
            "SessionToken": "testing-session-token",
            "Expiration": datetime(2026, 9, 14, tzinfo=timezone.utc),
        }
    }
    with Stubber(client) as stub:
        stub.add_response("assume_role", response)
        seen = []
        _approve_rds(
            ApprovalGateway(
                runner=lambda request, credential, evidence: seen.append(credential) or {}, sts_client=client, role_arn=ROLE
            )
        )
        stub.assert_no_pending_responses()

    assert seen[0].access_key_id == "synthetic-access-key-id"

    # The negative control: a parameter name STS does not have is rejected, so the call above passing
    # means every name FazerOps sends exists in the real API.
    # A response is queued so the stubber gets past its own "unexpected call" check and botocore's
    # parameter validation is what decides.
    with Stubber(client) as stub, pytest.raises(ParamValidationError, match="Unknown parameter"):
        stub.add_response("assume_role", response)
        client.assume_role(RoleArn=ROLE, RoleSessionName="fazerops-x", SourceIdentityy="slack-U0MGR")


def test_no_card_opens_for_an_aws_action_without_a_role():
    from fazerops.actions.approval import ApprovalRefused

    with pytest.raises(ApprovalRefused, match="FAZEROPS_ACTOR_ROLE_ARN"):
        ApprovalGateway().register(INCIDENT, _rds_request(), evidence=RDS_EVIDENCE)

    assert ApprovalGateway(role_arn=ROLE).register(INCIDENT, _rds_request(), evidence=RDS_EVIDENCE).action_id == "restore_db_parameter"


def test_the_rds_executor_refuses_to_run_as_the_hosts_own_identity():
    """The second barrier: a credential with no STS keys never reaches boto3."""
    from fazerops.actions.executors.rds import restore_parameter
    from fazerops.security.credentials import CredentialRefused

    seen = []
    _approve_rds(ApprovalGateway(runner=lambda request, credential, evidence: seen.append(credential) or {}))

    with pytest.raises(CredentialRefused, match="own AWS identity"):
        restore_parameter(_rds_request().params, credential=seen[0])


def test_the_server_reads_the_actor_role_from_the_environment(monkeypatch, tmp_path):
    from fazerops.actions import server

    monkeypatch.setenv("FAZEROPS_STATE_DIR", str(tmp_path))
    monkeypatch.setenv(server.ACTOR_ROLE_ENV, ROLE)
    assert server.assemble_from_env().gateway._role_arn == ROLE

    monkeypatch.delenv(server.ACTOR_ROLE_ENV)
    assert server.assemble_from_env().gateway._role_arn is None


def test_an_approver_id_cannot_break_out_of_the_identity_it_is_placed_in():
    """Slack ids are alphanumeric, but the value crosses into HTTP headers and STS fields; a newline
    or a colon must not become a second header or a different prefix."""
    seen = []
    gateway = ApprovalGateway(runner=lambda request, credential, evidence: seen.append(credential) or {})
    pending = gateway.register(INCIDENT, _request(), evidence=EVIDENCE)
    gateway.decide(
        incident_id=INCIDENT,
        action_id=pending.action_id,
        approver=Approver(user_id="U0IC\r\nImpersonate-Group: system:masters", role=ApproverRole.ENGINEER),
        kind="approve",
        dry_run_digest=pending.digest,
    )

    user, groups = kubernetes_identity(seen[0])
    assert "\n" not in user and "\r" not in user and ":" not in user.removeprefix(FAZEROPS_ACTOR_PREFIX)
    assert groups == [KUBERNETES_ACTOR_GROUP]


# --------------------------------------------------------------------------------------
# The clients
# --------------------------------------------------------------------------------------


def test_the_kubernetes_client_impersonates_the_approver(monkeypatch):
    kubernetes = pytest.importorskip("kubernetes", reason="pip install 'fazerops[cluster]'")
    monkeypatch.setattr(kubernetes.config, "load_kube_config", lambda *a, **k: None)
    seen = []
    _approve(ApprovalGateway(runner=lambda request, credential, evidence: seen.append(credential) or {}))

    from fazerops.actions.k8s_client import api_client

    headers = api_client(seen[0]).default_headers
    assert headers["Impersonate-User"] == f"{FAZEROPS_ACTOR_PREFIX}U0IC"
    assert headers["Impersonate-Group"] == KUBERNETES_ACTOR_GROUP


def test_helm_rollback_runs_as_the_approver():
    from fazerops.actions.executors import helm

    seen = []
    gateway = ApprovalGateway(runner=lambda request, credential, evidence: seen.append(credential) or {})
    request = ActionRequest.for_action(
        "helm_rollback",
        {"release": "billing-api", "namespace": "billing", "target_revision": 2},
        inverse_hint={"action_id": "helm_rollback", "release": "billing-api", "namespace": "billing", "target_revision": 2, "current_revision": 3},
    )
    evidence = Evidence(helm_revisions={"billing/billing-api": frozenset({2, 3})}, complete=True)
    pending = gateway.register(INCIDENT, request, evidence=evidence)
    gateway.decide(incident_id=INCIDENT, action_id="helm_rollback", approver=IC, kind="approve", dry_run_digest=pending.digest)

    argv: list[list[str]] = []
    helm.rollback(request.params, credential=seen[0], runner=lambda command: argv.append(command) or "{}")

    for command in argv:
        assert command[command.index("--kube-as-user") + 1] == f"{FAZEROPS_ACTOR_PREFIX}U0IC"
        assert command[command.index("--kube-as-group") + 1] == KUBERNETES_ACTOR_GROUP


# --------------------------------------------------------------------------------------
# The ledger reads it back
# --------------------------------------------------------------------------------------


def _patch_event(**overrides) -> dict:
    event = {
        "auditID": "a3-attribution-0001",
        "stage": "ResponseComplete",
        "verb": "patch",
        "requestReceivedTimestamp": "2026-09-14T10:00:00.000000Z",
        "user": {"username": "system:admin", "groups": ["system:masters"]},
        "objectRef": {"resource": "configmaps", "namespace": "billing", "name": "billing-api-config"},
        "responseStatus": {"code": 200},
    }
    event.update(overrides)
    return event


def test_an_impersonated_change_is_attributed_to_fazerops_and_its_approver():
    event = K8sAuditCollector()._normalize(
        _patch_event(impersonatedUser={"username": f"{FAZEROPS_ACTOR_PREFIX}U0IC", "groups": [KUBERNETES_ACTOR_GROUP]})
    )

    assert event is not None
    assert event.actor.canonical == "fazerops" and event.actor.resolved
    assert event.actor.raw == f"{FAZEROPS_ACTOR_PREFIX}U0IC"
    assert event.in_band, "an approved execution arrived through the approval path, not around it"


def test_the_same_change_without_impersonation_names_nobody():
    """What the audit log recorded for every FazerOps revert before this change."""
    event = K8sAuditCollector()._normalize(_patch_event())

    assert event is not None and not event.actor.resolved and not event.in_band


def test_a_fazerops_sts_session_is_recognised_in_cloudtrail():
    actor = normalize_actor(f"fazerops-{INCIDENT}-restore_db_parameter"[:64], "cloudtrail")

    assert actor.canonical == "fazerops"


def test_a_kubernetes_name_that_merely_starts_with_fazerops_is_not():
    assert not normalize_actor("fazerops-INC-lookalike", "k8s_audit").resolved
    assert not normalize_actor("system:serviceaccount:fazerops-sandbox-1:writer", "k8s_audit").resolved
