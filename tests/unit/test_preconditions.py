"""W20 — the catalog's declared preconditions, evaluated. Handoff §7.

`config/actions.yaml` declares `preconditions:` on every action. This file asserts they
*mean* something: that each declared name resolves to a real check, that the checks gate
`execute()`, and — the property that matters most — that a check which cannot be evaluated
**fails closed**.

An unevaluated precondition that returns True is a precondition that does nothing, and the
first time anyone notices is when an action runs against a resource that was never there.
"""

from __future__ import annotations

import pytest

from fazerops import keys
from fazerops.actions.catalog import default_catalog
from fazerops.actions.inverse import ActionRequest, request_from_hint
from fazerops.actions.preconditions import (
    CHECKS,
    Evidence,
    PreconditionFailed,
    check,
    failures,
)

CONFIGMAP_HINT = {
    "action_id": "revert_configmap_key",
    "namespace": "billing",
    "name": "billing-api-config",
    "key": "pool.max",
    "prior_value": "100",
    "current_value": "20",
}

HELM_HINT = {
    "action_id": "helm_rollback",
    "release": "billing-api",
    "namespace": "billing",
    "target_revision": 2,
    "current_revision": 3,
}

RDS_HINT = {
    "action_id": "restore_db_parameter",
    "parameter_group": "billing-primary-params",
    "parameter": "max_connections",
    "prior_value": "200",
    "current_value": "50",
}

# **Keys come from `keys.py`, never hand-spelled.** Writing them out by hand is how the
# first version of `_parameter_group_exists` passed its own test while matching nothing a
# collector ever produces (12 Sep) — the test agreed with the bug because both were written
# from the same wrong guess.
CONFIGMAP_EVIDENCE = Evidence(
    resource_keys=frozenset(
        {keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}
    ),
    complete=True,
)
HELM_EVIDENCE = Evidence(
    helm_revisions={"billing/billing-api": frozenset({1, 2, 3})}, complete=True
)
RDS_EVIDENCE = Evidence(
    resource_keys=frozenset(
        {keys.db_parameter_group("billing-primary-params").blast_radius_key()}
    ),
    complete=True,
)


# --------------------------------------------------------------------------------------
# Every declared name is a real check
# --------------------------------------------------------------------------------------


def test_every_declared_precondition_resolves_to_a_check():
    """A typo in `actions.yaml` must not silently disable a safety check.

    `test_catalog_schema.py` would still pass with a misspelled name — the entry *has* a
    precondition list — so this is the assertion that catches it.
    """
    declared = {name for action in default_catalog() for name in action.preconditions}

    assert declared, "the catalog declares no preconditions at all"
    assert declared <= set(CHECKS), f"unregistered: {sorted(declared - set(CHECKS))}"


def test_an_unregistered_precondition_name_is_itself_a_failure(tmp_path):
    """Not skipped. Skipping unknown names is how a renamed check quietly stops running."""
    path = tmp_path / "actions.yaml"
    path.write_text(
        "actions:\n"
        "  - id: revert_configmap_key\n"
        "    tier: 1\n"
        "    description: d\n"
        "    params:\n"
        "      namespace: {type: str, required: true}\n"
        "      name: {type: str, required: true}\n"
        "      key: {type: str, required: true}\n"
        "      target_value: {type: str, required: true}\n"
        "    preconditions: [configmap_exsits]\n"  # deliberate typo
        "    dry_run: kubectl_diff\n"
        "    inverse: revert_configmap_key\n"
        "    executor: fazerops.actions.executors.configmap:revert_key\n",
        encoding="utf-8",
    )

    from fazerops.actions.catalog import Catalog

    catalog = Catalog.load(path)
    request = request_from_hint(CONFIGMAP_HINT, catalog=catalog)

    reasons = failures(request, CONFIGMAP_EVIDENCE, catalog=catalog)
    assert any("no such precondition check is registered" in reason for reason in reasons)


# --------------------------------------------------------------------------------------
# Satisfied
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hint,evidence",
    [(CONFIGMAP_HINT, CONFIGMAP_EVIDENCE), (HELM_HINT, HELM_EVIDENCE), (RDS_HINT, RDS_EVIDENCE)],
)
def test_collected_evidence_satisfies_the_preconditions(hint, evidence):
    assert failures(request_from_hint(hint), evidence) == []
    check(request_from_hint(hint), evidence)  # does not raise


# --------------------------------------------------------------------------------------
# Fail closed
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("hint", [CONFIGMAP_HINT, HELM_HINT, RDS_HINT])
def test_no_evidence_fails_closed_rather_than_passing(hint):
    """**The property this module exists for.**

    Nothing collected means nothing confirmed. An existence check with an empty inventory
    must refuse — "we did not look" is not "it is there".
    """
    reasons = failures(request_from_hint(hint), Evidence())
    assert reasons, "an action must not run because nobody looked"


def test_an_empty_inventory_is_distinguished_from_a_collected_one():
    """`complete` is what separates "we looked and saw nothing" from "we never looked", and
    both must fail — but for different, stated reasons."""
    request = request_from_hint(CONFIGMAP_HINT)

    never_looked = failures(request, Evidence(complete=False))
    looked_and_empty = failures(request, Evidence(complete=True))

    assert any("no resource inventory was collected" in r for r in never_looked)
    assert any("no collected change touched" in r for r in looked_and_empty)


def test_a_configmap_nobody_collected_is_refused():
    request = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "some-other-config",
            "key": "pool.max",
            "target_value": "100",
        },
        inverse_hint=CONFIGMAP_HINT,
    )
    reasons = failures(request, CONFIGMAP_EVIDENCE)
    assert any("some-other-config" in reason for reason in reasons)


def test_a_helm_revision_absent_from_the_collected_history_is_refused():
    """W20b's assertion, and it is answered **before any client is constructed** — from the
    revisions the Helm collector already read, not from a live `helm history` call."""
    request = ActionRequest.for_action(
        "helm_rollback",
        {"release": "billing-api", "namespace": "billing", "target_revision": 99},
        inverse_hint=HELM_HINT,
    )
    reasons = failures(request, HELM_EVIDENCE)

    assert any("revision 99 is not in the collected history" in reason for reason in reasons)


def test_prior_value_known_fails_when_no_prior_value_was_captured():
    """CloudTrail's normal case: `lookup_events` returns no prior value."""
    request = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
        inverse_hint=dict(CONFIGMAP_HINT, current_value=None),
    )
    reasons = failures(request, CONFIGMAP_EVIDENCE)
    assert any("no prior value was captured" in reason for reason in reasons)


# --------------------------------------------------------------------------------------
# They actually gate execution
# --------------------------------------------------------------------------------------


def test_execute_refuses_on_an_unmet_precondition():
    """The guard is evaluated inside `execute()`, not asserted by the caller — the same
    reason ground rule #4's inverse check lives there."""
    request = ActionRequest.for_action(
        "helm_rollback",
        {"release": "billing-api", "namespace": "billing", "target_revision": 99},
        inverse_hint=HELM_HINT,
    )
    assert request.inverse() is not None, "isolate the precondition, not the inverse"

    with pytest.raises(PreconditionFailed, match="revision 99"):
        request.execute(evidence=HELM_EVIDENCE)


def test_no_executor_is_resolved_when_a_precondition_fails(monkeypatch):
    def spy(*args, **kwargs):
        raise AssertionError("resolve_executor must not be reached")

    monkeypatch.setattr("fazerops.actions.catalog.resolve_executor", spy)

    request = request_from_hint(CONFIGMAP_HINT)
    with pytest.raises(PreconditionFailed):
        request.execute(evidence=Evidence())


def test_ground_rule_four_is_not_shadowed_by_a_precondition():
    """`prior_value_known` and "the inverse is None" are the **same condition** for
    `revert_configmap_key`, so whichever guard runs first decides the exception.

    Ground rule #4 is the named, non-negotiable rule and the one the plan asserts by name.
    It must not be shadowed by a check that happens to notice the same thing.
    """
    from fazerops.actions.inverse import InverseUnavailable

    request = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
    )
    with pytest.raises(InverseUnavailable):
        request.execute(evidence=CONFIGMAP_EVIDENCE)


# --------------------------------------------------------------------------------------
# The card says so
# --------------------------------------------------------------------------------------


def test_the_dry_run_card_states_an_unmet_precondition():
    """Approving something that is about to refuse is the same defect as approving
    something irreversible — so the card carries it, not only the exception."""
    request = ActionRequest.for_action(
        "helm_rollback",
        {"release": "billing-api", "namespace": "billing", "target_revision": 99},
        inverse_hint=HELM_HINT,
    )
    dry = request.dry_run(evidence=HELM_EVIDENCE)

    assert dry.unmet_preconditions
    assert "precondition not met" in dry.render()
    assert "revision 99" in dry.render()


def test_a_satisfied_card_carries_no_precondition_warning():
    dry = request_from_hint(CONFIGMAP_HINT).dry_run(evidence=CONFIGMAP_EVIDENCE)

    assert dry.unmet_preconditions == []
    assert "precondition not met" not in dry.render()


# --------------------------------------------------------------------------------------
# Evidence from a real brief
# --------------------------------------------------------------------------------------


async def test_evidence_from_the_demo_brief_satisfies_the_demo_action(monkeypatch):
    """End to end: the brief the investigation actually produces carries enough evidence to
    satisfy the preconditions of the action the demo proposes.

    If this goes red the demo's Tier 1 path refuses on camera, which is the failure the
    whole unit exists to make impossible.
    """
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")

    import json
    from pathlib import Path

    from fazerops.ingest.alerts import normalize_alert
    from fazerops.pipeline import investigate

    root = Path(__file__).resolve().parents[2]
    payload = json.loads((root / "fixtures" / "alerts" / "alertmanager.json").read_text())
    brief = await investigate(normalize_alert(payload))

    evidence = Evidence.from_brief(brief)
    request = request_from_hint(brief.top.event.inverse_hint)

    assert request is not None, "the demo's rank 1 event must yield a proposable action"
    assert failures(request, evidence) == []


def test_the_checks_use_the_same_key_builder_the_collectors_do():
    """The keys a precondition looks for must be the keys the manifest and collectors write.

    Asserted against `radius.resolve` — the resolver reads the *manifest*, and the collectors
    stamp events with `keys.py`, so agreeing with the resolver is agreeing with both. This is
    the test that would have caught `_parameter_group_exists` matching `:pg:<name>`.
    """
    from fazerops.radius import resolve

    radius = resolve("billing-api")

    assert keys.k8s_configmap("billing", "billing-api-config").blast_radius_key() in radius.keys
    assert keys.db_parameter_group("billing-primary-params").blast_radius_key() in radius.keys


def test_a_parameter_group_in_the_real_radius_satisfies_its_precondition():
    """The RDS check against evidence built from the manifest rather than by hand."""
    from fazerops.radius import resolve

    evidence = Evidence(resource_keys=frozenset(resolve("billing-api").keys), complete=True)

    assert failures(request_from_hint(RDS_HINT), evidence) == []
