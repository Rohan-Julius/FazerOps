"""W41 — the writer registry and the generic revert substrate. Plan §4 Phase G.

The plan's two assertions, and the properties they rest on:

* **A writer cannot supply its own inverse or dry-run renderer** — not by a field on the spec,
  not by a line in a catalog entry. The inverse and the diff are what an approver's decision
  rests on, and both stay human-written.
* **Writers inherit the credential guarantee** — `test_every_executor_calls_the_gate` now covers
  the one executor every writer runs behind, and this file asserts the gate is called *before*
  the writer is, and that writers never call it themselves (the credential is single-use).

The catalog used here is the shipped one plus one declarative entry, written to a temp file.
The shipped catalog gains nothing in W41 — `test_catalog_schema.py` still asserts exactly
Handoff §7's three.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _growth_events import MULTI_AFTER, MULTI_BEFORE, T0, configmap_change, multi_key_change  # noqa: E402

from fazerops import keys  # noqa: E402
from fazerops.actions.approval import ApprovalGateway, Approver, ApproverRole  # noqa: E402
from fazerops.actions.catalog import (  # noqa: E402
    DEFAULT_ACTIONS,
    WRITER_DRY_RUN,
    WRITER_EXECUTOR,
    WRITER_PRECONDITIONS,
    ActionSpec,
    Catalog,
    default_catalog,
)
from fazerops.actions.inverse import InverseUnavailable  # noqa: E402
from fazerops.actions.preconditions import Evidence  # noqa: E402
from fazerops.actions.writers import k8s_configmap  # noqa: E402
from fazerops.actions.writers.registry import (  # noqa: E402
    WRITER_MODULES,
    UnknownWriter,
    WriterRegistry,
    WriterSpec,
    default_registry,
    request_for_event,
)
from fazerops.security.credentials import CredentialRefused  # noqa: E402

SRC = Path(__file__).resolve().parents[2] / "src" / "fazerops"

DECLARATIVE = """
  - id: revert_configmap_data
    tier: 1
    description: Restore every recorded key of a ConfigMap changed out of band
    writer: k8s/ConfigMap:data
    params:
      namespace: {type: str, required: true}
      name: {type: str, required: true}
"""

EVIDENCE = Evidence(
    resource_keys=frozenset({keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}),
    complete=True,
)


@pytest.fixture
def catalog(tmp_path) -> Catalog:
    path = tmp_path / "actions.yaml"
    path.write_text(DEFAULT_ACTIONS.read_text(encoding="utf-8") + DECLARATIVE, encoding="utf-8")
    return Catalog.load(path)


@pytest.fixture
def cluster(monkeypatch):
    """Stands in for the Kubernetes API. Its patch list is the assertion."""

    class FakeCoreV1:
        def __init__(self) -> None:
            self.patches: list[tuple[str, str, dict]] = []

        def patch_namespaced_config_map(self, *, name, namespace, body):
            self.patches.append((namespace, name, body))
            return SimpleNamespace(data=body["data"], metadata=SimpleNamespace(resource_version="7"))

    fake = FakeCoreV1()
    monkeypatch.setattr(k8s_configmap, "_core_v1", lambda: fake)
    return fake


def _request(catalog, event=None):
    return request_for_event(event or multi_key_change("evt-1", at=T0), catalog=catalog)


def _entry(**overrides) -> dict:
    return {
        "id": "revert_configmap_data",
        "tier": 1,
        "description": "d",
        "writer": "k8s/ConfigMap:data",
        "params": {"namespace": {"type": "str"}, "name": {"type": "str"}},
        **overrides,
    }


def _writer_kwargs(**overrides) -> dict:
    spec = k8s_configmap.WRITER
    kwargs = {field.name: getattr(spec, field.name) for field in dataclasses.fields(WriterSpec)}
    return {**kwargs, **overrides}


# --------------------------------------------------------------------------------------
# A writer cannot supply its own inverse or dry run
# --------------------------------------------------------------------------------------


def test_a_writer_spec_has_no_field_for_an_inverse_a_dry_run_or_a_gate():
    names = {field.name for field in dataclasses.fields(WriterSpec)}
    assert not names & {"inverse", "undo", "dry_run", "render", "renderer", "diff", "executor", "credential"}


def test_a_writer_spec_cannot_be_given_one_at_construction_or_after():
    with pytest.raises(TypeError):
        WriterSpec(**_writer_kwargs(), inverse=lambda request: None)

    with pytest.raises(dataclasses.FrozenInstanceError):
        k8s_configmap.WRITER.write = lambda *args, **kwargs: {}
    with pytest.raises((AttributeError, TypeError)):
        k8s_configmap.WRITER.dry_run = lambda request: None  # slots: no such attribute exists


@pytest.mark.parametrize(
    "field, value",
    [
        ("executor", "fazerops.actions.executors.configmap:revert_key"),
        ("dry_run", "kubectl_diff"),
        ("inverse", "revert_configmap_key"),
    ],
)
def test_a_writer_backed_entry_cannot_declare_its_own(field, value):
    with pytest.raises(ValidationError, match="cannot declare its own"):
        ActionSpec.model_validate(_entry(**{field: value}))


def test_a_writer_backed_entry_is_filled_from_the_generic_layer(catalog):
    action = catalog.get("revert_configmap_data")

    assert action.executor == WRITER_EXECUTOR
    assert action.dry_run == WRITER_DRY_RUN
    assert action.inverse == action.id
    assert set(WRITER_PRECONDITIONS) <= set(action.preconditions)


def test_an_entry_naming_an_unregistered_writer_fails_at_load(tmp_path):
    path = tmp_path / "actions.yaml"
    path.write_text(
        DEFAULT_ACTIONS.read_text(encoding="utf-8") + DECLARATIVE.replace("k8s/ConfigMap:data", "k8s/Deployment:data"),
        encoding="utf-8",
    )
    with pytest.raises(UnknownWriter):
        Catalog.load(path)


def test_the_shipped_catalog_is_unchanged_by_w41():
    assert all(action.writer is None for action in default_catalog())


# --------------------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------------------


def test_the_scope_field_must_name_a_reference_parameter():
    with pytest.raises(ValueError, match="scope_field"):
        WriterSpec(**_writer_kwargs(scope_field="cluster"))


def test_a_field_path_with_no_recorded_prior_value_is_refused():
    with pytest.raises(ValueError, match="no recorded prior"):
        WriterSpec(**_writer_kwargs(field_path="request"))


def test_the_registry_refuses_duplicates_and_anything_that_is_not_a_spec():
    with pytest.raises(ValueError, match="two writers"):
        WriterRegistry([k8s_configmap.WRITER, k8s_configmap.WRITER])
    with pytest.raises(TypeError):
        WriterRegistry([{"resource_type": "k8s/ConfigMap"}])


def test_every_writer_registered_today_is_human_authored():
    """W41 generates nothing. The first agent-authored writer is W42's third rung."""
    assert len(default_registry()) == len(WRITER_MODULES)
    assert {writer.authored_by for writer in default_registry()} == {"human"}


# --------------------------------------------------------------------------------------
# The generic inverse and dry run
# --------------------------------------------------------------------------------------


def test_the_recorded_gap_becomes_revertible_once_a_writer_backed_action_exists(catalog):
    change = multi_key_change("evt-1", at=T0)

    assert request_for_event(change) is None, "the shipped catalog cannot revert a two-key patch"

    request = request_for_event(change, catalog=catalog)
    assert request.action_id == "revert_configmap_data"
    assert request.params == {"namespace": "billing", "name": "billing-api-config"}


def test_a_collector_hint_still_wins_for_the_change_it_describes(catalog):
    single = configmap_change("evt-1", at=T0, before={"pool.max": "100"}, after={"pool.max": "20"})
    assert request_for_event(single, catalog=catalog).action_id == "revert_configmap_key"


def test_the_inverse_restores_exactly_what_the_collector_saw(catalog):
    request = _request(catalog)
    undo = request.inverse(catalog=catalog)

    assert undo.action_id == request.action_id
    assert undo.inverse_hint["prior"] == MULTI_AFTER
    assert undo.inverse_hint["current"] == MULTI_BEFORE

    redo = undo.inverse(catalog=catalog)
    assert redo.params == request.params
    assert redo.inverse_hint == request.inverse_hint


def test_the_dry_run_renders_every_recorded_key_and_performs_no_io(catalog, monkeypatch):
    def no_cluster():
        raise AssertionError("a dry run must not construct a client")

    monkeypatch.setattr(k8s_configmap, "_core_v1", no_cluster)
    dry = _request(catalog).dry_run(evidence=EVIDENCE, catalog=catalog)

    assert [line.field for line in dry.lines] == sorted(MULTI_BEFORE)
    for line in dry.lines:
        assert (line.before, line.after) == (MULTI_AFTER[line.field], MULTI_BEFORE[line.field])
    assert dry.reversible is True
    assert dry.unmet_preconditions == []
    assert dry.target == "k8s:billing/configmap/billing-api-config"


def test_a_sensitive_key_is_masked_on_the_card(catalog):
    change = configmap_change(
        "evt-1", at=T0, before={"db.password": "old", "pool.max": "1"}, after={"db.password": "new", "pool.max": "2"}
    )
    dry = _request(catalog, change).dry_run(evidence=EVIDENCE, catalog=catalog)

    rendered = dry.render()
    assert "old" not in rendered and "new" not in rendered
    assert next(line for line in dry.lines if line.field == "db.password").changed is True


def test_values_recorded_on_one_resource_are_never_applied_to_another(catalog):
    """The check that matters most in the substrate: without it, values observed on one
    ConfigMap could be written to another, under a dry run that faithfully renders it."""
    request = _request(catalog)
    retargeted = request.model_copy(update={"params": {**request.params, "name": "payments-config"}})

    assert retargeted.inverse(catalog=catalog) is None
    dry = retargeted.dry_run(evidence=EVIDENCE, catalog=catalog)
    assert dry.lines == [] and dry.reversible is False
    with pytest.raises(InverseUnavailable):
        retargeted.execute(None, evidence=EVIDENCE, catalog=catalog)


# --------------------------------------------------------------------------------------
# Execution — the gate before the writer
# --------------------------------------------------------------------------------------


def test_execution_without_an_approval_never_reaches_the_writer(catalog, cluster):
    with pytest.raises(CredentialRefused):
        _request(catalog).execute(None, evidence=EVIDENCE, catalog=catalog)

    assert cluster.patches == []


def test_an_approved_action_patches_exactly_the_recorded_keys(catalog, cluster):
    gateway = ApprovalGateway(
        catalog=catalog,
        runner=lambda request, credential, evidence: request.execute(
            credential, evidence=evidence, catalog=catalog
        ),
    )
    gateway.register("INC-1", _request(catalog), evidence=EVIDENCE)
    outcome = gateway.decide(
        incident_id="INC-1",
        action_id="revert_configmap_data",
        approver=Approver(user_id="U_IC", role=ApproverRole.ENGINEER),
        kind="approve",
    )

    assert outcome.executed, outcome.error
    assert cluster.patches == [("billing", "billing-api-config", {"data": MULTI_BEFORE})]
    assert outcome.result["authored_by"] == "human"
    assert "auth.faber-demo.io" not in json.dumps(outcome.result), "results carry key names, never values"


def test_the_gate_is_called_before_the_writer():
    tree = ast.parse((SRC / "actions" / "executors" / "writer.py").read_text(encoding="utf-8"))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]

    gate = [c.lineno for c in calls if isinstance(c.func, ast.Name) and c.func.id == "require_actor_credential"]
    write = [c.lineno for c in calls if isinstance(c.func, ast.Attribute) and c.func.attr == "write"]

    assert gate and write
    assert max(gate) < min(write)


@pytest.mark.parametrize("module_path", WRITER_MODULES)
def test_writers_never_call_the_gate_themselves(module_path):
    """The credential is spent by the check, so a writer that also checked would refuse every
    approved mutation — and one that 'fixed' that by skipping the executor's check would be
    the bypass. Writers take the credential and never check it."""
    relative = Path(*module_path.split(".")[1:]).with_suffix(".py")
    tree = ast.parse((SRC / relative).read_text(encoding="utf-8"))
    called = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "require_actor_credential" not in called

    writer = __import__(module_path, fromlist=["WRITER"]).WRITER
    assert "credential" in inspect.signature(writer.write).parameters
