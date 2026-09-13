"""W43 — sandbox recipes and containment verification, without a cluster. Plan §4 Phase G.

The plan's two assertions are asserted here against an in-memory sandbox, and again against a
real API server in `tests/e2e/test_containment.py`:

* **a writer that mutates outside its declared ref is rejected** — a neighbour it reached, and a
  namespace it only *tried* to reach, since RBAC refusing the request does not make the writer
  honest;
* **a declared ref outside the incident's blast radius is rejected before the sandbox runs** —
  checked by a sandbox factory that fails the test if it is ever called.

Plus what makes the verdict mean something: recipes are declared and most types have none, a
mutation outside the reference is judged before anything that could excuse it, an incomplete
observation never passes, and generated code reaches a real client only through a relay that can
pin it to one resource.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import _sandbox_fakes as fakes  # noqa: E402

from fazerops.actions.growth import authoring  # noqa: E402
from fazerops.actions.growth.authoring import GeneratedWriterFailed, run_generated_writer  # noqa: E402
from fazerops.actions.growth.pr import ACTIONS_PATH, GENERATED_DIR  # noqa: E402
from fazerops.actions.growth.sandbox import (  # noqa: E402
    RecipeClass,
    Verdict,
    generated_subject,
    human_subject,
    recipe_for,
    verify_containment,
)
from fazerops.actions.writers import k8s_configmap  # noqa: E402
from fazerops.actions.writers.k8s_support import writer_contract  # noqa: E402
from fazerops.agents.writer_author import _stub  # noqa: E402
from fazerops.models import BlastRadius, ResourceRef  # noqa: E402

DECLARED = ResourceRef(kind="ConfigMap", name="billing-api-config", namespace="billing")
RADIUS = BlastRadius(service="billing-api", keys={DECLARED.blast_radius_key(), "service:billing-api"})
PRIOR = {"pool.max": "100", "added.by.change": None}
CURRENT = {"pool.max": "20", "added.by.change": "x"}

STUB = {field: _stub(writer_contract("ConfigMap", field)) for field in ("data", "binaryData")}


def _generated(write_source: str | None = None, *, field: str = "data"):
    sources = STUB[field]
    return generated_subject("ConfigMap", field, sources["read_source"], write_source or sources["write_source"])


def _verify(subject, *, sandbox=None, declared=DECLARED, radius=RADIUS, prior=PRIOR, current=CURRENT):
    return verify_containment(
        subject, declared=declared, radius=radius, prior=prior, current=current, sandbox=sandbox or fakes.factory()
    )


# --------------------------------------------------------------------------------------
# Recipes are declared, and most resource types have none
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "resource_type, recipe_class",
    [
        ("k8s/ConfigMap", RecipeClass.OBSERVED),
        ("k8s/Secret", RecipeClass.NONE),
        ("aws/DBParameterGroup", RecipeClass.DELAYED),
        ("aws/SecurityGroup", RecipeClass.DELAYED),
        ("helm/HelmRelease", RecipeClass.NONE),
        ("k8s/Deployment", RecipeClass.NONE),
    ],
)
def test_recipes_are_declared_not_inferred(resource_type, recipe_class):
    assert recipe_for(resource_type).recipe_class is recipe_class


def test_only_kubernetes_is_observed():
    from fazerops.actions.growth.sandbox import RECIPES

    observed = {name for name, recipe in RECIPES.items() if recipe.recipe_class is RecipeClass.OBSERVED}
    assert observed == {"k8s/ConfigMap"}


def test_the_sandbox_never_falls_back_to_the_current_context(monkeypatch):
    """For a process that remediates production, the current context is the production cluster."""
    kubernetes = pytest.importorskip("kubernetes")
    from fazerops.actions.growth.sandbox import SANDBOX_CONTEXT_ENV, K8sSandbox, SandboxNotConfigured

    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    monkeypatch.delenv(SANDBOX_CONTEXT_ENV, raising=False)

    def no_kubeconfig(*args, **kwargs):
        raise AssertionError("a kubeconfig was loaded before the sandbox cluster was checked")

    monkeypatch.setattr(kubernetes.config, "new_client_from_config", no_kubeconfig)
    monkeypatch.setattr(kubernetes.config, "load_kube_config", no_kubeconfig)
    with pytest.raises(SandboxNotConfigured, match=SANDBOX_CONTEXT_ENV):
        K8sSandbox()


def test_recipes_live_where_an_agent_authored_commit_cannot_reach():
    """§10a: a wrong recipe verifies nothing while appearing to pass, so recipes are reviewed at an
    executor's trust level — and `pr.py` confines agent commits to the catalog and generated writers."""
    sandbox_path = "src/fazerops/actions/growth/sandbox.py"
    assert sandbox_path != ACTIONS_PATH and not sandbox_path.startswith(GENERATED_DIR)


# --------------------------------------------------------------------------------------
# The pre-check, before anything exists
# --------------------------------------------------------------------------------------


def test_a_declared_ref_outside_the_blast_radius_is_rejected_before_the_sandbox_runs():
    elsewhere = BlastRadius(service="auth-service", keys={"k8s:auth/configmap/auth-service-config"})
    report = _verify(human_subject(k8s_configmap.WRITER), radius=elsewhere, sandbox=fakes.never())

    assert report.verdict is Verdict.DECLARED_REF_OUTSIDE_RADIUS
    assert report.sandbox_ran is False


@pytest.mark.parametrize(
    "declared",
    [
        pytest.param(ResourceRef(kind="ConfigMap", name="*", namespace="billing"), id="wildcard-name"),
        pytest.param(ResourceRef(kind="ConfigMap", name="billing-api-config"), id="no-namespace"),
        pytest.param(ResourceRef(kind="ConfigMap", name="billing-api-config", namespace="Billing"), id="not-a-dns-label"),
        pytest.param(ResourceRef(kind="Secret", name="billing-api-config", namespace="billing"), id="another-kind"),
        pytest.param(ResourceRef(kind="ConfigMap", name="x", namespace="billing", arn="arn:aws:x"), id="an-arn"),
    ],
)
def test_a_declared_ref_that_is_not_one_concrete_resource_is_rejected_before_the_sandbox_runs(declared):
    radius = BlastRadius(service="billing-api", keys={declared.blast_radius_key()})
    report = _verify(human_subject(k8s_configmap.WRITER), declared=declared, radius=radius, sandbox=fakes.never())

    assert report.verdict is Verdict.DECLARED_REF_NOT_CONCRETE
    assert report.sandbox_ran is False


def test_a_resource_type_without_an_observed_recipe_never_runs(monkeypatch):
    from fazerops.actions.growth import sandbox as sandbox_module

    monkeypatch.setitem(
        sandbox_module.RECIPES,
        "k8s/ConfigMap",
        sandbox_module.SandboxRecipe("k8s/ConfigMap", RecipeClass.DELAYED, "pretend"),
    )
    report = _verify(human_subject(k8s_configmap.WRITER), sandbox=fakes.never())
    assert report.verdict is Verdict.NOT_OBSERVABLE and report.sandbox_ran is False


# --------------------------------------------------------------------------------------
# The verdict
# --------------------------------------------------------------------------------------


def test_the_human_written_writer_is_contained():
    make = fakes.factory()
    report = _verify(human_subject(k8s_configmap.WRITER), sandbox=make)

    assert report.contained, report
    [box] = make.built
    assert box.torn_down
    assert box.objects[(fakes.SANDBOX_NAMESPACE, "billing-api-config")]["data"] == {
        "pool.max": "100",
        "fazerops-sandbox-untouched": "untouched",
    }


@pytest.mark.parametrize("field", ["data", "binaryData"])
def test_a_generated_writer_is_contained_through_the_relay(field):
    prior = {"logo.png": "bmV3"} if field == "binaryData" else PRIOR
    current = {"logo.png": "b2xk"} if field == "binaryData" else CURRENT
    report = _verify(_generated(field=field), prior=prior, current=current)

    assert report.contained, report
    assert report.authored_by == "agent"


LIAR = STUB["data"]["write_source"].replace('name=params["name"]', 'name="neighbour"')
FAR = STUB["data"]["write_source"].replace('namespace=params["namespace"]', 'namespace="billing"')


def test_a_writer_that_mutates_outside_its_declared_ref_is_rejected():
    report = _verify(_generated(LIAR))

    assert report.verdict is Verdict.MUTATED_OUTSIDE_DECLARED_REF
    assert report.observed_outside == (f"k8s:{fakes.SANDBOX_NAMESPACE}/configmap/neighbour",)


def test_a_writer_that_only_tried_to_reach_another_namespace_is_rejected_too():
    """Refused by RBAC, and still a writer that lied about its reference."""
    report = _verify(_generated(FAR))

    assert report.verdict is Verdict.MUTATED_OUTSIDE_DECLARED_REF
    assert report.observed_outside == ("k8s:billing/configmap/billing-api-config",)


def test_a_mutation_outside_the_ref_is_judged_before_a_failure_that_would_excuse_it():
    raises_after = LIAR.replace("    return {", '    missing = values["no-such-key"]\n    return {')
    report = _verify(_generated(raises_after))
    assert report.verdict is Verdict.MUTATED_OUTSIDE_DECLARED_REF


def test_a_writer_that_restores_other_values_is_rejected():
    wrong = STUB["data"]["write_source"].replace("dict(values)", '{"pool.max": "999"}')
    assert _verify(_generated(wrong)).verdict is Verdict.OBSERVED_VALUES_DIFFER


def test_a_writer_that_writes_the_other_map_is_rejected():
    into_data = STUB["binaryData"]["write_source"].replace('"binaryData"', '"data"')
    report = _verify(_generated(into_data, field="binaryData"), prior={"logo.png": "bmV3"}, current={"logo.png": "b2xk"})
    assert report.verdict is Verdict.OBSERVED_VALUES_DIFFER


def test_a_writer_that_does_nothing_is_not_contained():
    idle = "def write(params, values, *, credential, client):\n    obj = client.read_namespaced_config_map(name=params['name'], namespace=params['namespace'])\n    return {}\n"
    report = _verify(generated_subject("ConfigMap", "data", STUB["data"]["read_source"], idle))
    assert not report.contained


def test_an_incomplete_observation_never_passes():
    report = _verify(human_subject(k8s_configmap.WRITER), sandbox=fakes.factory(complete=False))
    assert report.verdict is Verdict.OBSERVATION_INCOMPLETE


def test_the_sandbox_is_torn_down_when_the_writer_raises():
    make = fakes.factory()
    broken = STUB["data"]["write_source"].replace("    return {", '    missing = values["no-such-key"]\n    return {')
    report = _verify(_generated(broken), sandbox=make)

    assert report.verdict is Verdict.WRITER_FAILED
    assert [box.torn_down for box in make.built] == [True]


# --------------------------------------------------------------------------------------
# The relay generated code reaches a real client through
# --------------------------------------------------------------------------------------


class _Recording:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def patch_namespaced_config_map(self, **kwargs):
        self.calls.append(("patch", kwargs))
        return SimpleNamespace(data=kwargs["body"]["data"], metadata=SimpleNamespace(resource_version="9"), secret="S3CR3T")

    def read_namespaced_config_map(self, **kwargs):
        self.calls.append(("read", kwargs))
        return SimpleNamespace(data={}, metadata=SimpleNamespace(resource_version="9"))


def _relay(write_source: str, *, client, pin=("billing", "billing-api-config"), **kwargs):
    return run_generated_writer(
        "ConfigMap",
        "data",
        STUB["data"]["read_source"],
        write_source,
        {"namespace": "billing", "name": "billing-api-config"},
        {"pool.max": "100"},
        client=client,
        pin=pin,
        **kwargs,
    )


def test_a_pinned_relay_refuses_a_call_aimed_elsewhere_without_reaching_the_client():
    client = _Recording()
    with pytest.raises(GeneratedWriterFailed, match="outside the declared resource"):
        _relay(LIAR, client=client)
    assert client.calls == []


def test_a_pinned_relay_passes_the_declared_call_and_relays_back_only_the_map():
    client = _Recording()
    result = _relay(STUB["data"]["write_source"], client=client)

    assert client.calls == [("patch", {"name": "billing-api-config", "namespace": "billing", "body": {"data": {"pool.max": "100"}}})]
    assert result["keys"] == ["pool.max"] and "S3CR3T" not in str(result)


def test_the_relay_refuses_arguments_the_contract_does_not_name():
    sneaky = STUB["data"]["write_source"].replace("body=", "pretty='true', body=")
    client = _Recording()
    with pytest.raises(GeneratedWriterFailed, match="not a contract call"):
        _relay(sneaky, client=client)
    assert client.calls == []


def test_code_the_allowlist_rejects_never_starts_an_interpreter(monkeypatch):
    def no_process(*args, **kwargs):
        raise AssertionError("an interpreter was started for code the allowlist rejects")

    monkeypatch.setattr(authoring.subprocess, "Popen", no_process)
    with pytest.raises(GeneratedWriterFailed, match="allowlist"):
        _relay(STUB["data"]["write_source"].replace("    patched", "    import os\n    patched"), client=_Recording())


def test_a_hung_writer_is_bounded():
    hangs = "def write(params, values, *, credential, client):\n    for i in [1]:\n        client.patch_namespaced_config_map(name=params['name'], namespace=params['namespace'], body={'data': dict(values)})\n    return {}\n"

    class Stalls(_Recording):
        def patch_namespaced_config_map(self, **kwargs):
            import time

            time.sleep(3)
            return super().patch_namespaced_config_map(**kwargs)

    with pytest.raises(GeneratedWriterFailed, match="did not finish"):
        _relay(hangs, client=Stalls(), timeout=1.0)


def test_the_relay_runs_generated_code_in_another_interpreter(monkeypatch):
    started: list[list[str]] = []
    real = subprocess.Popen

    def spy(args, **kwargs):
        started.append(list(args))
        return real(args, **kwargs)

    monkeypatch.setattr(authoring.subprocess, "Popen", spy)
    _relay(STUB["data"]["write_source"], client=_Recording())

    [argv] = started
    assert argv[1:3] == ["-I", "-S"]
