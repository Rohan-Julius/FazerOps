"""W20b — `helm_rollback` against the live k3d cluster. Handoff §5 and §7, plan §4.

The plan's assertion: the rollback executes against k3d and the release reports the target
revision's state.

**It runs against a throwaway release, never against `billing-api`.** The demo's release
sits at revision 3 with all three revisions dated before the incident window, which is what
makes `fixtures/helm/` show three candidates. A rollback creates a *new* revision stamped
now, and Helm cannot delete revisions — so one run of this test against `billing-api` would
silently poison the next `scripts/capture_helm_fixture.py`. The test installs its own
release in its own namespace and uninstalls both, pass or fail.

It runs the mutation through `ActionRequest.execute()` rather than calling the executor
directly, so the four guards in front of it are exercised rather than bypassed: the inverse
is computed, the preconditions are checked against collected evidence, the credential is
minted by a real approval and demanded by the executor, and only then does `helm` run.

Marked `cluster`, excluded from the CI default suite. Free — one local install, one local
rollback, one local uninstall.

    ./scripts/setup_k3d.sh && pytest -m cluster

Named `..._e2e` rather than `test_helm_rollback.py`, which is what plan §4 calls it: pytest
imports test modules by basename when the directories are not packages, so two files of the
same name in `tests/unit/` and `tests/e2e/` collide at collection and take the *whole* run
down — including the default suite, which deselects these tests but still collects them.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from fazerops.actions.approval import ApprovalGateway, Approver, ApproverRole
from fazerops.actions.inverse import ActionRequest
from fazerops.actions.preconditions import Evidence
from fazerops.security.credentials import CredentialRefused

pytestmark = pytest.mark.cluster

RELEASE = "fazerops-e2e-rollback"
NAMESPACE = "fazerops-e2e"
CHART = Path(__file__).resolve().parents[2] / "charts" / "billing-api"

IC = Approver(user_id="U0E2E", role=ApproverRole.ENGINEER)


@pytest.fixture(autouse=True)
def live_mode(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


def _helm(*args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["helm", *args], capture_output=True, text=True, timeout=180, check=False
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"helm {' '.join(args[:2])} failed: {result.stderr.strip()}")
    return result.stdout


def _replicas(release: str = RELEASE) -> int:
    """What the release currently declares, read back from Helm's own stored values."""
    values = json.loads(_helm("get", "values", release, "-n", NAMESPACE, "-o", "json") or "{}")
    return int(values.get("replicaCount", 1))


@pytest.fixture
def release():
    """Install at replicaCount=1, upgrade to 3, and tear the whole thing down afterwards.

    `replicaCount` is the marker because it is stored in Helm's own release values, so
    reading it back proves the *release* rolled back rather than proving that some pod
    happened to restart.
    """
    if not _helm("version", "--short", check=False):
        pytest.skip("helm is not on PATH")
    if subprocess.run(["kubectl", "cluster-info"], capture_output=True).returncode != 0:
        pytest.skip("no reachable cluster — run ./scripts/setup_k3d.sh")

    _helm("uninstall", RELEASE, "-n", NAMESPACE, check=False)  # a leftover from a crash
    _helm(
        "install", RELEASE, str(CHART),
        "-n", NAMESPACE, "--create-namespace",
        "--set", "replicaCount=1",
    )
    _helm("upgrade", RELEASE, str(CHART), "-n", NAMESPACE, "--set", "replicaCount=3")

    assert _replicas() == 3, "fixture setup did not reach the state the test rolls back from"

    try:
        yield
    finally:
        # Unconditional. A leftover release in a leftover namespace is the kind of debris
        # that shows up as an unrelated failure in a later rehearsal.
        _helm("uninstall", RELEASE, "-n", NAMESPACE, check=False)
        subprocess.run(
            ["kubectl", "delete", "namespace", NAMESPACE, "--ignore-not-found"],
            capture_output=True,
        )


def _request() -> ActionRequest:
    return ActionRequest.for_action(
        "helm_rollback",
        {"release": RELEASE, "namespace": NAMESPACE, "target_revision": 1},
        inverse_hint={
            "action_id": "helm_rollback",
            "release": RELEASE,
            "namespace": NAMESPACE,
            "target_revision": 1,
            "current_revision": 2,
        },
    )


def _evidence() -> Evidence:
    return Evidence(helm_revisions={f"{NAMESPACE}/{RELEASE}": frozenset({1, 2})}, complete=True)


def _approve_and_execute(request: ActionRequest, incident: str) -> dict:
    """Through the gateway, so the credential is one a real approval minted."""
    gateway = ApprovalGateway()
    gateway.register(incident, request, evidence=_evidence())
    outcome = gateway.decide(
        incident_id=incident, action_id="helm_rollback", approver=IC, kind="approve"
    )
    assert outcome.error is None, outcome.error
    return outcome.result


def test_the_rollback_executes_and_the_release_reports_the_target_state(release):
    result = _approve_and_execute(_request(), "INC-E2E-HELM-1")

    assert _replicas() == 1, "the release did not roll back to revision 1's state"
    assert result["requested_revision"] == 1
    # Helm creates a new revision restoring revision 1's manifest — it does not move the
    # pointer back to 1. The record says so rather than claiming the release sits on 1.
    assert result["revision"] == 3


def test_the_returned_inverse_rolls_the_release_forward_again(release):
    result = _approve_and_execute(_request(), "INC-E2E-HELM-2")
    assert _replicas() == 1

    undo = result["inverse"]
    assert undo["action_id"] == "helm_rollback"
    assert undo["params"]["target_revision"] == 2

    forward = ActionRequest.for_action(
        "helm_rollback",
        undo["params"],
        inverse_hint={
            "action_id": "helm_rollback",
            "release": RELEASE,
            "namespace": NAMESPACE,
            "target_revision": 2,
            "current_revision": 3,
        },
    )
    gateway = ApprovalGateway()
    gateway.register("INC-E2E-HELM-3", forward, evidence=Evidence(
        helm_revisions={f"{NAMESPACE}/{RELEASE}": frozenset({1, 2, 3})}, complete=True
    ))
    gateway.decide(
        incident_id="INC-E2E-HELM-3", action_id="helm_rollback", approver=IC, kind="approve"
    )

    assert _replicas() == 3, "the computed inverse did not restore what the rollback replaced"


def test_an_unapproved_rollback_touches_the_cluster_not_at_all(release):
    """The guard that matters most on a live cluster: no credential, no mutation."""
    with pytest.raises(CredentialRefused):
        _request().execute(credential=None, evidence=_evidence())

    assert _replicas() == 3, "the release moved without an approval"


def test_the_demo_release_is_untouched_by_this_module(release):
    """Explicit, because the cost of getting it wrong is silent and lands a day later in
    `scripts/capture_helm_fixture.py`."""
    history = json.loads(_helm("history", "billing-api", "-n", "billing", "-o", "json") or "[]")

    assert [entry["revision"] for entry in history] == [1, 2, 3]
