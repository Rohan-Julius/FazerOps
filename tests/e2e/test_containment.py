"""W43 — containment verification against the live k3d cluster. Plan §4 Phase G.

The plan's assertions against a real API server and the real audit log, with the collector as
the instrument:

* a writer that mutates outside its declared ref is rejected — a neighbour it patched, and a
  namespace RBAC stopped it reaching;
* a declared ref outside the incident's blast radius is rejected **before** the sandbox runs, and
  no sandbox namespace comes into existence.

And the two writers `tests/cassettes/writer_author.json` holds — written by Gemini on Vertex — are
contained for real, for both contracts. `tests/unit/test_containment_verdicts.py` holds the same verdicts
against an in-memory sandbox; this file is what keeps that fake honest.

Marked `cluster`. Free: every object is created inside a fresh namespace, which is deleted after.

    ./scripts/setup_k3d.sh && pytest -m cluster tests/e2e/test_containment.py
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fazerops.actions.growth.sandbox import Verdict, generated_subject, human_subject, verify_containment
from fazerops.actions.writers import k8s_configmap
from fazerops.models import BlastRadius, ResourceRef

pytestmark = pytest.mark.cluster

REPO_ROOT = Path(__file__).resolve().parents[2]
DECLARED = ResourceRef(kind="ConfigMap", name="billing-api-config", namespace="billing")
RADIUS = BlastRadius(service="billing-api", keys={DECLARED.blast_radius_key()})
PRIOR = {"pool.max": "100", "added.by.change": None}
CURRENT = {"pool.max": "20", "added.by.change": "x"}


@pytest.fixture(autouse=True)
def live(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    monkeypatch.setenv("FAZEROPS_SANDBOX_CONTEXT", "k3d-fazerops")


@pytest.fixture
def admin():
    kubernetes = pytest.importorskip("kubernetes", reason="pip install 'fazerops[cluster]'")
    from fazerops.collectors.k8s_audit import audit_log_path

    try:
        kubernetes.config.load_kube_config()
        core = kubernetes.client.CoreV1Api()
        core.list_namespace(limit=1)
    except Exception as exc:  # noqa: BLE001 - any kubeconfig or connection failure is the same skip
        pytest.skip(f"no reachable cluster: {exc}")
    if not audit_log_path().is_file():
        pytest.skip("no audit log — run ./scripts/setup_k3d.sh")
    return core


def _sandboxes(core) -> set[str]:
    return {
        ns.metadata.name
        for ns in core.list_namespace(label_selector="fazerops.io/sandbox=containment").items
        if ns.status.phase != "Terminating"
    }


def _recorded(field: str) -> dict:
    """The Vertex-recorded writer for `field`, straight off the tape."""
    tape = json.loads((REPO_ROOT / "tests" / "cassettes" / "writer_author.json").read_text(encoding="utf-8"))
    [response] = [
        entry["response"]
        for entry in tape.values()
        if ('"binaryData"' in entry["response"]["write_source"]) == (field == "binaryData")
    ]
    return response


def _verify(subject, **overrides):
    arguments = {"declared": DECLARED, "radius": RADIUS, "prior": PRIOR, "current": CURRENT, **overrides}
    return verify_containment(subject, **arguments)


def test_the_human_written_writer_is_contained(admin):
    before = admin.read_namespaced_config_map("billing-api-config", "billing").data
    report = _verify(human_subject(k8s_configmap.WRITER))

    assert report.contained, report
    assert admin.read_namespaced_config_map("billing-api-config", "billing").data == before, "production untouched"


@pytest.mark.parametrize("field", ["data", "binaryData"])
def test_the_recorded_generated_writers_are_contained(admin, field):
    recorded = _recorded(field)
    subject = generated_subject("ConfigMap", field, recorded["read_source"], recorded["write_source"])
    overrides = {} if field == "data" else {"prior": {"logo.png": "bmV3"}, "current": {"logo.png": "b2xk"}}

    report = _verify(subject, **overrides)
    assert report.contained, report


def test_a_writer_that_mutates_outside_its_declared_ref_is_rejected(admin):
    recorded = _recorded("data")
    liar = recorded["write_source"].replace('name=params["name"]', 'name="neighbour"')
    report = _verify(generated_subject("ConfigMap", "data", recorded["read_source"], liar))

    assert report.verdict is Verdict.MUTATED_OUTSIDE_DECLARED_REF
    [outside] = report.observed_outside
    assert outside.startswith("k8s:fazerops-sandbox-") and outside.endswith("/configmap/neighbour")


def test_a_writer_that_tried_another_namespace_is_rejected_though_rbac_stopped_it(admin):
    recorded = _recorded("data")
    far = recorded["write_source"].replace('namespace=params["namespace"]', 'namespace="fazerops-elsewhere"')
    report = _verify(generated_subject("ConfigMap", "data", recorded["read_source"], far))

    assert report.verdict is Verdict.MUTATED_OUTSIDE_DECLARED_REF
    assert report.observed_outside == ("k8s:fazerops-elsewhere/configmap/billing-api-config",)


def test_a_declared_ref_outside_the_radius_is_rejected_before_any_sandbox_exists(admin):
    before = _sandboxes(admin)
    elsewhere = BlastRadius(service="auth-service", keys={"k8s:auth/configmap/auth-service-config"})
    report = _verify(human_subject(k8s_configmap.WRITER), radius=elsewhere)

    assert report.verdict is Verdict.DECLARED_REF_OUTSIDE_RADIUS
    assert report.sandbox_ran is False
    assert _sandboxes(admin) == before


def test_the_sandbox_leaves_nothing_behind(admin):
    before = _sandboxes(admin)
    _verify(human_subject(k8s_configmap.WRITER))
    assert _sandboxes(admin) == before, "the sandbox namespace is deleted (it may still be terminating)"
