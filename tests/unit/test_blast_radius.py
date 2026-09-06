"""W4 — tier A. If the ConfigMap is not in the radius the demo has no candidate, and the
failure is a silent empty list rather than an exception.
"""

import pytest

from faberops.radius import ServiceManifest, default_manifest

CONFIGMAP_KEY = "k8s:billing/configmap/billing-api-config"
RDS_KEY = "aws:arn:aws:rds:us-east-1:111122223333:db:billing-primary"


@pytest.fixture
def manifest() -> ServiceManifest:
    return default_manifest()


def test_the_demo_configmap_is_in_billing_api_radius(manifest):
    """This one assertion is the difference between a demo and a blank brief."""
    assert CONFIGMAP_KEY in manifest.resolve("billing-api").keys


def test_aws_resources_are_in_radius_alongside_kubernetes_ones(manifest):
    """The multi-source claim is the defensibility argument — the radius has to span
    both coordinate systems or the ledger only ever answers about one."""
    radius = manifest.resolve("billing-api")
    assert RDS_KEY in radius.keys
    assert CONFIGMAP_KEY in radius.keys


def test_one_hop_pulls_in_direct_dependencies(manifest):
    radius = manifest.resolve("billing-api")
    assert "k8s:auth/configmap/auth-service-config" in radius.keys
    assert "aws:arn:aws:rds:us-east-1:111122223333:db:billing-replica" in radius.keys


def test_two_hops_are_excluded(manifest):
    """Handoff §4. session-store is reachable only via auth-service; including it would
    make every radius eventually contain the whole estate."""
    radius = manifest.resolve("billing-api")
    assert "k8s:auth/configmap/session-store-config" not in radius.keys


def test_direct_keys_exclude_the_dependency_hop(manifest):
    """W14's radius_overlap scores a direct hit above a one-hop neighbour, which requires
    the two to stay distinguishable after resolution."""
    radius = manifest.resolve("billing-api")
    assert CONFIGMAP_KEY in radius.direct_keys
    assert "k8s:auth/configmap/auth-service-config" not in radius.direct_keys
    assert radius.direct_keys < radius.keys


def test_workload_kind_prefix_is_honoured(manifest):
    """Handoff §4 writes workloads as `deployment/billing-api` — the kind is part of the
    entry. An earlier revision dropped the prefix and hardcoded Deployment, which meant a
    StatefulSet in a radius was recorded as the wrong resource type and could never match
    the audit collector's key for it."""
    billing = {ref.kind: ref for ref in manifest.refs_for("billing-api")}
    assert "Deployment" in billing
    assert billing["Deployment"].name == "billing-api"

    session = {ref.kind: ref for ref in manifest.refs_for("session-store")}
    assert "StatefulSet" in session, "the statefulset/ prefix must not be read as Deployment"
    assert "k8s:auth/statefulset/session-store" in manifest.keys_for("session-store")


def test_a_bare_workload_name_is_read_as_a_deployment():
    """Tolerated because it is the common case, and rejecting it would turn a manifest
    typo into a stack trace at import time."""
    from faberops.keys import k8s_workload

    assert k8s_workload("billing", "billing-api").kind == "Deployment"
    assert k8s_workload("auth", "statefulset/session-store").kind == "StatefulSet"
    assert k8s_workload("ops", "daemonset/node-agent").kind == "DaemonSet"


def test_unknown_service_returns_empty_not_everything(manifest):
    """A resolver that falls back to the whole manifest turns a typo into a 40-candidate
    brief — worse than nothing, because it looks like it worked."""
    radius = manifest.resolve("billing-apiii")
    assert radius.keys == set()
    assert radius.direct_keys == set()
    assert radius.service == "billing-apiii"


def test_service_names_are_sorted_and_complete(manifest):
    """The orchestrator's tool enum is built from this (plan §3.1)."""
    assert manifest.service_names == (
        "auth-service",
        "billing-api",
        "billing-db",
        "session-store",
    )


def test_a_service_key_is_included_so_release_events_land_in_radius(manifest):
    """Helm releases and GitHub merges name a service, not a namespaced resource."""
    assert "service:billing-api" in manifest.resolve("billing-api").keys


def test_zero_hops_is_the_service_alone(manifest):
    radius = manifest.resolve("billing-api", hops=0)
    assert radius.keys == radius.direct_keys
    assert "k8s:auth/configmap/auth-service-config" not in radius.keys


def test_reverse_lookup_attributes_a_key_to_its_service(manifest):
    """Used at normalization time to stamp blast_radius_keys onto the event."""
    assert manifest.owning_services(CONFIGMAP_KEY) == {"billing-api"}
    assert manifest.owning_services("k8s:nowhere/configmap/nope") == set()


def test_dependency_cycles_terminate(tmp_path):
    """Nothing in the checked-in manifest cycles today, but a hand-edit during the build
    would otherwise hang the collector fan-out rather than fail visibly."""
    path = tmp_path / "cyclic.yaml"
    path.write_text(
        "services:\n"
        "  a:\n    kubernetes:\n      namespace: x\n      configmaps: [a-cfg]\n"
        "    depends_on: [b]\n"
        "  b:\n    kubernetes:\n      namespace: x\n      configmaps: [b-cfg]\n"
        "    depends_on: [a]\n",
        encoding="utf-8",
    )
    radius = ServiceManifest.load(path).resolve("a", hops=5)
    assert "k8s:x/configmap/b-cfg" in radius.keys
