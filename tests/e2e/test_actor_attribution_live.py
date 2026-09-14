"""D3 against the real API server — an approved revert is attributed to its approver in the audit log.

Before the fix, the same revert through the same gateway was recorded as `system:admin` (checked on
the live cluster, 14 Sep). Runs the mutation through `ApprovalGateway` with the real executor, then
reads the event back through the real collector.

Marked `cluster`. Free — one local patch, restored in teardown pass or fail. Needs the RBAC binding
`./scripts/setup_k3d.sh` applies (`config/k8s/fazerops-actor-rbac.yaml`).
"""

from __future__ import annotations

import json
import time

import pytest

from fazerops import keys
from fazerops.actions.approval import ApprovalGateway, Approver, ApproverRole
from fazerops.actions.inverse import ActionRequest
from fazerops.actions.preconditions import Evidence
from fazerops.collectors.k8s_audit import K8sAuditCollector, audit_log_path
from fazerops.ledger.normalize import FAZEROPS_ACTOR_PREFIX

pytestmark = pytest.mark.cluster

NAMESPACE, CONFIGMAP, KEY = "billing", "billing-api-config", "pool.max"
APPROVER = f"U0E2E{int(time.time())}"


@pytest.fixture(autouse=True)
def live_mode(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


@pytest.fixture
def core_v1():
    kubernetes = pytest.importorskip("kubernetes", reason="pip install 'fazerops[cluster]'")
    try:
        kubernetes.config.load_kube_config()
        client = kubernetes.client.CoreV1Api()
        original = (client.read_namespaced_config_map(CONFIGMAP, NAMESPACE).data or {}).get(KEY)
    except Exception as exc:  # noqa: BLE001 - any cluster failure is the same skip
        pytest.skip(f"{NAMESPACE}/{CONFIGMAP} unreachable — run ./scripts/setup_k3d.sh ({exc})")
    client.patch_namespaced_config_map(CONFIGMAP, NAMESPACE, {"data": {KEY: "20"}})
    yield client
    client.patch_namespaced_config_map(CONFIGMAP, NAMESPACE, {"data": {KEY: original}})


def _impersonated_patches(since: str) -> list[dict]:
    found = []
    for line in audit_log_path().read_text(encoding="utf-8").splitlines():
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            raw.get("stage") == "ResponseComplete"
            and raw.get("requestReceivedTimestamp", "") >= since
            and (raw.get("objectRef") or {}).get("name") == CONFIGMAP
            and (raw.get("impersonatedUser") or {}).get("username") == f"{FAZEROPS_ACTOR_PREFIX}{APPROVER}"
        ):
            found.append(raw)
    return found


def test_an_approved_revert_is_attributed_to_its_approver(core_v1):
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 5))
    gateway = ApprovalGateway()
    request = ActionRequest.for_action(
        "revert_configmap_key",
        {"namespace": NAMESPACE, "name": CONFIGMAP, "key": KEY, "target_value": "100"},
        inverse_hint={"action_id": "revert_configmap_key", "namespace": NAMESPACE, "name": CONFIGMAP, "key": KEY, "prior_value": "100", "current_value": "20"},
    )
    evidence = Evidence(resource_keys=frozenset({keys.k8s_configmap(NAMESPACE, CONFIGMAP).blast_radius_key()}), complete=True)
    pending = gateway.register("INC-E2E-ATTRIBUTION", request, evidence=evidence)

    outcome = gateway.decide(
        incident_id="INC-E2E-ATTRIBUTION",
        action_id=pending.action_id,
        approver=Approver(user_id=APPROVER, role=ApproverRole.ENGINEER),
        kind="approve",
        dry_run_digest=pending.digest,
    )
    assert outcome.executed, outcome.error
    assert (core_v1.read_namespaced_config_map(CONFIGMAP, NAMESPACE).data or {})[KEY] == "100"

    deadline = time.time() + 15  # the API server flushes the audit log asynchronously
    while not (events := _impersonated_patches(since)) and time.time() < deadline:
        time.sleep(0.5)
    assert events, "no audit event impersonating the approver — is the RBAC binding applied?"

    event = K8sAuditCollector()._normalize(events[-1])
    assert event is not None
    assert event.actor.canonical == "fazerops" and event.actor.raw.endswith(APPROVER)
    assert event.in_band
