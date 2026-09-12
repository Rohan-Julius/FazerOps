"""W24 — `revert_configmap_key` against the live k3d cluster. Handoff §7, plan §4.

The plan's two assertions: after execute the live ConfigMap reads `pool.max: "100"`, and
the returned inverse restores `20`.

**This is the only test in the repo that mutates anything**, so it is the only one that has
to leave the world as it found it. Every test below records the key's real value first and
restores it in a fixture teardown that runs even when the assertion fails — a test that
leaves the demo ConfigMap at the wrong value breaks the *next* rehearsal, and the symptom
shows up nowhere near here.

It runs the mutation through `ActionRequest.execute()` rather than calling the executor
directly. Calling the executor would prove the patch works and prove nothing about the four
guards standing in front of it, which is the part of this that is the product: the inverse
is computed, the preconditions are checked, the credential is demanded and spent, and only
then does anything touch the cluster.

Marked `cluster`, excluded from the CI default suite. Free — one local patch and one local
patch back.

    ./scripts/setup_k3d.sh && pytest -m cluster
"""

from __future__ import annotations

import pytest

from fazerops.actions.inverse import ActionRequest, request_from_hint
from fazerops.actions.preconditions import Evidence
from fazerops.security.credentials import CredentialRefused

pytestmark = pytest.mark.cluster

NAMESPACE = "billing"
CONFIGMAP = "billing-api-config"
KEY = "pool.max"

# The demo's change: a human dropped the pool size from 100 to 20 out of band, and the
# action restores 100. `current_value` is what the collector recorded at the moment of
# observation — reading it back at execution time would race the very change being
# reverted (`actions/inverse.py`).
PRIOR_VALUE = "100"
CHANGED_VALUE = "20"


@pytest.fixture(autouse=True)
def live_mode(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


@pytest.fixture
def core_v1():
    """A client for the test's own reads and its cleanup, separate from the executor's.

    Separate on purpose: if the executor's client construction is broken, a test sharing
    one client would fail in setup and never reach the assertion that says so.
    """
    kubernetes = pytest.importorskip("kubernetes", reason="pip install 'fazerops[cluster]'")

    try:
        kubernetes.config.load_kube_config()
    except Exception as exc:  # noqa: BLE001 - any kubeconfig failure is the same skip
        pytest.skip(f"no usable kubeconfig: {exc}")

    client = kubernetes.client.CoreV1Api()
    try:
        client.read_namespaced_config_map(name=CONFIGMAP, namespace=NAMESPACE)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"{NAMESPACE}/{CONFIGMAP} unreachable — run ./scripts/setup_k3d.sh ({exc})")

    return client


@pytest.fixture
def restore_key(core_v1):
    """Record the key's real value and put it back afterwards, pass or fail.

    Yields a setter so each test can stage the state it needs. The teardown is
    unconditional because the failure mode it guards against is a *later* rehearsal
    reading a value this test left behind.
    """
    original = _read(core_v1)

    def _set(value: str) -> None:
        core_v1.patch_namespaced_config_map(
            name=CONFIGMAP, namespace=NAMESPACE, body={"data": {KEY: value}}
        )

    yield _set

    if original is not None:
        _set(original)


def _read(client) -> str | None:
    configmap = client.read_namespaced_config_map(name=CONFIGMAP, namespace=NAMESPACE)
    return (configmap.data or {}).get(KEY)


def _hint(prior: str = PRIOR_VALUE, current: str = CHANGED_VALUE) -> dict:
    return {
        "action_id": "revert_configmap_key",
        "namespace": NAMESPACE,
        "name": CONFIGMAP,
        "key": KEY,
        "prior_value": prior,
        "current_value": current,
    }


def _evidence() -> Evidence:
    from fazerops import keys

    return Evidence(
        resource_keys=frozenset({keys.k8s_configmap(NAMESPACE, CONFIGMAP).blast_radius_key()}),
        complete=True,
    )


def _approved_credential():
    """A credential as the approval handler would mint it.

    Built through the same frame-checked gate the handler uses rather than by constructing
    an `ActorCredential` — which is refused, and correctly so. A test that bypassed the
    gate would be testing a different executor from the one that ships.
    """
    source = compile(
        "def caller(mint, kwargs):\n    return mint(**kwargs)\n", "<synthetic>", "exec"
    )
    namespace: dict = {"__name__": "fazerops.slack.handlers"}
    exec(source, namespace)  # noqa: S102 - the gate reads the calling frame; see above

    from fazerops.security.credentials import mint_actor_credential

    return namespace["caller"](
        mint_actor_credential,
        {
            "incident_id": "INC-e2e",
            "action_id": "revert_configmap_key",
            "namespace": NAMESPACE,
        },
    )


# --------------------------------------------------------------------------------------
# The plan's two assertions
# --------------------------------------------------------------------------------------


def test_execute_restores_the_prior_value_on_the_live_configmap(core_v1, restore_key):
    """After execute the live ConfigMap reads `pool.max: "100"`.

    Read back off the cluster, not off the executor's return value — the return value is
    what the executor believes happened, and the point of an e2e test is to check that
    belief against the API server.
    """
    restore_key(CHANGED_VALUE)
    assert _read(core_v1) == CHANGED_VALUE, "staging failed; the rest of this proves nothing"

    request = request_from_hint(_hint())
    assert request is not None
    assert request.params["target_value"] == PRIOR_VALUE

    result = request.execute(credential=_approved_credential(), evidence=_evidence())

    assert _read(core_v1) == PRIOR_VALUE
    assert result["value"] == PRIOR_VALUE


def test_the_returned_inverse_restores_twenty(core_v1, restore_key):
    """The inverse is a real, executable action — not a description of one.

    So it is executed. Ground rule #4 promises the change can be undone; a test that only
    inspected the inverse's parameters would leave the promise untested at the one point
    it is actually redeemed.
    """
    restore_key(CHANGED_VALUE)

    request = request_from_hint(_hint())
    undo = request.inverse()

    assert undo is not None
    assert undo.params["target_value"] == CHANGED_VALUE

    request.execute(credential=_approved_credential(), evidence=_evidence())
    assert _read(core_v1) == PRIOR_VALUE

    undo.execute(credential=_approved_credential(), evidence=_evidence())
    assert _read(core_v1) == CHANGED_VALUE


# --------------------------------------------------------------------------------------
# The guards, against a real cluster — each must stop before the API server is touched
# --------------------------------------------------------------------------------------


def test_no_credential_means_no_mutation(core_v1, restore_key):
    """Ground rule #5 against a live cluster: the refusal is not merely an exception, it is
    an exception with the ConfigMap unchanged behind it."""
    restore_key(CHANGED_VALUE)

    request = request_from_hint(_hint())
    with pytest.raises(CredentialRefused):
        request.execute(evidence=_evidence())

    assert _read(core_v1) == CHANGED_VALUE


def test_a_credential_for_another_namespace_means_no_mutation(core_v1, restore_key):
    """A credential someone approved for something else is exactly as wrong as none."""
    restore_key(CHANGED_VALUE)

    request = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": NAMESPACE,
            "name": CONFIGMAP,
            "key": KEY,
            "target_value": PRIOR_VALUE,
        },
        inverse_hint=_hint(),
    )

    source = compile("def c(m, k):\n    return m(**k)\n", "<synthetic>", "exec")
    ns: dict = {"__name__": "fazerops.slack.handlers"}
    exec(source, ns)  # noqa: S102
    from fazerops.security.credentials import mint_actor_credential

    wrong_scope = ns["c"](
        mint_actor_credential,
        {
            "incident_id": "INC-e2e",
            "action_id": "revert_configmap_key",
            "namespace": "kube-system",
        },
    )

    with pytest.raises(CredentialRefused, match="scoped to namespace"):
        request.execute(credential=wrong_scope, evidence=_evidence())

    assert _read(core_v1) == CHANGED_VALUE


def test_an_uncomputable_inverse_means_no_mutation(core_v1, restore_key):
    """Ground rule #4 against a live cluster. The hint carries no `current_value`, so no
    inverse exists and `execute()` refuses before resolving an executor."""
    from fazerops.actions.inverse import InverseUnavailable

    restore_key(CHANGED_VALUE)

    request = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": NAMESPACE,
            "name": CONFIGMAP,
            "key": KEY,
            "target_value": PRIOR_VALUE,
        },
    )

    with pytest.raises(InverseUnavailable):
        request.execute(credential=_approved_credential(), evidence=_evidence())

    assert _read(core_v1) == CHANGED_VALUE


def test_an_unmet_precondition_means_no_mutation(core_v1, restore_key):
    """Preconditions fail closed: an empty inventory means "nobody looked", not "it is
    fine". Asserted here because the cluster is reachable — so the refusal is provably
    about the evidence and not about the connection."""
    from fazerops.actions.preconditions import PreconditionFailed

    restore_key(CHANGED_VALUE)

    request = request_from_hint(_hint())
    with pytest.raises(PreconditionFailed):
        request.execute(credential=_approved_credential(), evidence=Evidence())

    assert _read(core_v1) == CHANGED_VALUE


def test_the_patch_leaves_the_other_keys_alone(core_v1, restore_key):
    """A strategic merge of one key, never a replace.

    A read-modify-write would race any other writer and could silently discard a concurrent
    change — during an incident, which is when concurrent changes happen.
    """
    restore_key(CHANGED_VALUE)
    before = core_v1.read_namespaced_config_map(name=CONFIGMAP, namespace=NAMESPACE).data or {}

    request_from_hint(_hint()).execute(
        credential=_approved_credential(), evidence=_evidence()
    )

    after = core_v1.read_namespaced_config_map(name=CONFIGMAP, namespace=NAMESPACE).data or {}

    assert set(after) == set(before), "no key was added or removed"
    for key, value in before.items():
        if key != KEY:
            assert after[key] == value, f"{key} was modified by a single-key revert"


def test_a_credential_is_spent_by_one_execution(core_v1, restore_key):
    """Handoff §8: one action per session. The second execute refuses, so a double-click
    that reaches this far still mutates once."""
    restore_key(CHANGED_VALUE)

    credential = _approved_credential()
    request = request_from_hint(_hint())

    request.execute(credential=credential, evidence=_evidence())
    assert _read(core_v1) == PRIOR_VALUE

    with pytest.raises(CredentialRefused, match="already been used"):
        request.execute(credential=credential, evidence=_evidence())
