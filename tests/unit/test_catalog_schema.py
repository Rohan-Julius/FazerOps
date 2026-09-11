"""W20 — the action catalog's schema. Plan §4, Handoff §7.

The catalog is the structural barrier between model output and the cluster (ground rule
#1), so these assertions are about what the catalog *cannot* express, not about what it
happens to contain today:

* every declared action has a tier, a param schema, a **resolvable executor import path**,
  a `dry_run` and an `inverse`;
* **no declared-but-unimplemented entries**;
* an unknown `action_id` is rejected;
* params failing the schema are rejected **before any client is constructed**.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from fazerops.actions.catalog import (
    ActionSpec,
    Catalog,
    ParamSpec,
    UnknownAction,
    ValidationRejected,
    default_catalog,
    effective_tier,
    resolve_executor,
    validate_params,
)
from fazerops.models import Tier

HANDOFF_ACTIONS = {"revert_configmap_key", "helm_rollback", "restore_db_parameter"}
SRC = Path(__file__).resolve().parents[2] / "src" / "fazerops"


@pytest.fixture
def catalog() -> Catalog:
    return default_catalog()


# --------------------------------------------------------------------------------------
# Completeness
# --------------------------------------------------------------------------------------


def test_the_catalog_ships_all_three_handoff_actions(catalog):
    """§3.5 was reversed on 6 Sep to build Handoff §7 in full. "Classified but not routed"
    left the Tier 2 branch of Handoff §1's diagram decorative."""
    assert set(catalog.action_ids) == HANDOFF_ACTIONS


@pytest.mark.parametrize("action_id", sorted(HANDOFF_ACTIONS))
def test_every_action_declares_the_full_schema(catalog, action_id):
    action = catalog.get(action_id)

    assert isinstance(action.tier, Tier)
    assert action.params, "an action with no parameters cannot be targeted"
    assert all(isinstance(spec, ParamSpec) for spec in action.params.values())
    assert action.dry_run, "Handoff §7: every action implements dry_run()"
    assert action.inverse, "Handoff §7: every action implements inverse()"
    assert ":" in action.executor


@pytest.mark.parametrize("action_id", sorted(HANDOFF_ACTIONS))
def test_every_executor_import_path_resolves_to_a_callable(catalog, action_id):
    """The rule plan §4 states: a catalog entry with no executor is a live path to an
    `ImportError` mid-demo. Resolution happens at *load* time, so this is a restatement of
    what `Catalog.load` already enforced — asserted separately because the load-time check
    is the thing most likely to be removed for being "redundant"."""
    assert callable(resolve_executor(catalog.get(action_id)))


@pytest.mark.parametrize("action_id", sorted(HANDOFF_ACTIONS))
def test_every_dry_run_renderer_named_by_the_catalog_exists(catalog, action_id):
    from fazerops.actions.dry_run import _RENDERERS

    assert catalog.get(action_id).dry_run in _RENDERERS


@pytest.mark.parametrize("action_id", sorted(HANDOFF_ACTIONS))
def test_every_inverse_named_by_the_catalog_has_a_builder(catalog, action_id):
    from fazerops.actions.inverse import _INVERSE_BUILDERS

    assert catalog.get(action_id).inverse in _INVERSE_BUILDERS


def test_a_catalog_entry_with_an_unresolvable_executor_fails_at_load(tmp_path):
    """The failure must land at startup, not at execution with a human already waiting on
    an approval card."""
    bad = tmp_path / "actions.yaml"
    bad.write_text(
        "actions:\n"
        "  - id: ghost\n"
        "    tier: 1\n"
        "    description: an action with no executor\n"
        "    params: {x: {type: str, required: true}}\n"
        "    dry_run: kubectl_diff\n"
        "    inverse: revert_configmap_key\n"
        "    executor: fazerops.actions.executors.nowhere:missing\n",
        encoding="utf-8",
    )
    with pytest.raises((ModuleNotFoundError, ValueError)):
        Catalog.load(bad)


# --------------------------------------------------------------------------------------
# Unknown actions
# --------------------------------------------------------------------------------------


def test_an_unknown_action_id_is_rejected_with_no_fallback(catalog):
    with pytest.raises(UnknownAction) as excinfo:
        catalog.get("delete_namespace")
    # The message names what *is* available, so an operator reading a failed proposal can
    # see the catalog is closed rather than assume a typo in their own request.
    assert "delete_namespace" in str(excinfo.value)
    assert "revert_configmap_key" in str(excinfo.value)


def test_membership_is_how_the_proposers_enum_is_built(catalog):
    """W22 draws `action_id`'s enum from `action_ids`, the same pattern as W19b's service
    enum — so the model cannot name an action that does not exist."""
    assert catalog.action_ids == tuple(sorted(HANDOFF_ACTIONS))
    assert "revert_configmap_key" in catalog
    assert "rm_-rf" not in catalog


# --------------------------------------------------------------------------------------
# Parameter validation, before any client
# --------------------------------------------------------------------------------------


def test_missing_required_param_is_rejected(catalog):
    action = catalog.get("revert_configmap_key")
    with pytest.raises(ValidationRejected, match="namespace"):
        validate_params(action, {"name": "billing-api-config", "key": "pool.max", "target_value": "100"})


def test_unknown_param_is_rejected(catalog):
    action = catalog.get("revert_configmap_key")
    with pytest.raises(ValidationRejected, match="kubeconfig"):
        validate_params(
            action,
            {
                "namespace": "billing",
                "name": "billing-api-config",
                "key": "pool.max",
                "target_value": "100",
                "kubeconfig": "/tmp/evil",
            },
        )


def test_wrong_type_is_rejected(catalog):
    action = catalog.get("helm_rollback")
    with pytest.raises(ValidationRejected, match="target_revision"):
        validate_params(
            action, {"release": "billing-api", "namespace": "billing", "target_revision": "two"}
        )


def test_bool_is_not_accepted_for_an_int_param(catalog):
    """`bool` subclasses `int` in Python, so an unguarded isinstance check accepts `True`
    for `target_revision` — and `True` resolves to revision 1, which is a real revision."""
    action = catalog.get("helm_rollback")
    with pytest.raises(ValidationRejected, match="bool"):
        validate_params(
            action, {"release": "billing-api", "namespace": "billing", "target_revision": True}
        )


def test_enum_param_is_bounded(catalog):
    action = catalog.get("restore_db_parameter")
    with pytest.raises(ValidationRejected, match="apply_method"):
        validate_params(
            action,
            {
                "parameter_group": "billing-primary-params",
                "parameter": "max_connections",
                "target_value": "100",
                "apply_method": "right-now-please",
            },
        )


def test_validation_happens_before_any_client_is_constructed():
    """Asserted on the source, not on behaviour.

    A behavioural test would need a client to fail to construct, which means writing the
    thing the rule forbids. Reading the AST proves `validate_params` imports nothing that
    could open a socket and touches no module-level client — the property has to hold for
    every call, not just the one a test makes.
    """
    tree = ast.parse((SRC / "actions" / "catalog.py").read_text(encoding="utf-8"))
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "validate_params"
    )
    imported = [
        node for node in ast.walk(function) if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    assert imported == [], "validate_params must not import anything — it runs before clients"

    module_level = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert not module_level & {"boto3", "botocore", "kubernetes", "subprocess"}


# --------------------------------------------------------------------------------------
# Tier
# --------------------------------------------------------------------------------------


def test_tier_is_declared_not_inferred(catalog):
    assert catalog.get("revert_configmap_key").tier is Tier.ENGINEER_APPROVAL
    assert catalog.get("helm_rollback").tier is Tier.ENGINEER_APPROVAL
    assert catalog.get("restore_db_parameter").tier is Tier.MANAGER_APPROVAL


def test_tier_two_must_name_a_manager():
    """A Tier 2 action with nobody to escalate to accepts an IC approval, which is worse
    than having no tier system at all."""
    with pytest.raises(ValueError, match="manager"):
        ActionSpec.model_validate(
            {
                "id": "x",
                "tier": 2,
                "description": "d",
                "params": {"a": {"type": "str"}},
                "dry_run": "kubectl_diff",
                "inverse": "revert_configmap_key",
                "executor": "fazerops.actions.executors.configmap:revert_key",
            }
        )


def test_thresholds_only_promote(catalog):
    action = catalog.get("revert_configmap_key")

    assert effective_tier(action) is Tier.ENGINEER_APPROVAL
    assert effective_tier(action, resource_count=100) is Tier.MANAGER_APPROVAL
    assert effective_tier(action, crosses_namespace_boundary=True) is Tier.MANAGER_APPROVAL
    assert effective_tier(action, estimated_cost_delta_usd=5000.0) is Tier.MANAGER_APPROVAL


def test_nothing_demotes_a_tier_two_action(catalog):
    """The one-way property, asserted against every combination of "nothing triggered a
    promotion" — a Tier 2 action must come out Tier 2 whatever the inputs say."""
    action = catalog.get("restore_db_parameter")

    for kwargs in (
        {},
        {"resource_count": 0},
        {"estimated_cost_delta_usd": 0.0},
        {"crosses_namespace_boundary": False},
        {"resource_count": 0, "estimated_cost_delta_usd": 0.0},
    ):
        assert effective_tier(action, **kwargs) is Tier.MANAGER_APPROVAL, kwargs


def test_the_thresholds_file_has_no_demotion_field():
    """`Thresholds` is `extra="forbid"` over a promotion-only shape, so a `demote_to_tier_1`
    key added to the YAML is a load error rather than a silently ignored one — and a
    silently ignored security control is the worse of the two."""
    from fazerops.actions.catalog import Thresholds

    with pytest.raises(Exception):
        Thresholds.model_validate({"demote_to_tier_1": {"resource_count": 1}})
