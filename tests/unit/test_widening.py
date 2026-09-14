"""W42 rung 1 — the human-written support a declared widening relies on. Plan §4 Phase G.

A widening is only "no new trust surface" if everything that executes already handles the
widened form before the catalog declares it. So this file asserts the support directly, against
a catalog with `WIDENINGS[0]` applied exactly as a merged PR would apply it:

* the shipped catalog **rejects** the widened form, so none of this is reachable until a human
  merges the widening;
* the audit collector records every changed key and value, and still claims `reversible` only
  for what the shipped action can do;
* the `keys` form takes its targets **only** from recorded values, and refuses a different
  ConfigMap, a different key set, or both forms at once — in the inverse, the dry run, the
  precondition and the executor alike, because all four share `inverse.recorded_keys`;
* the single-key demo action behaves identically before and after the widening.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _growth_events import MULTI_AFTER, MULTI_BEFORE, T0, configmap_change, multi_key_change  # noqa: E402

from fazerops import keys  # noqa: E402
from fazerops.actions.approval import ApprovalGateway, Approver, ApproverRole  # noqa: E402
from fazerops.actions.catalog import (  # noqa: E402
    DEFAULT_ACTIONS,
    Catalog,
    ValidationRejected,
    default_catalog,
    validate_params,
)
from fazerops.actions.executors import configmap as configmap_executor  # noqa: E402
from fazerops.actions.growth.generate import WIDENINGS, apply_params, params_of  # noqa: E402
from fazerops.actions.inverse import ActionRequest, InverseUnavailable, request_from_hint, writes  # noqa: E402
from fazerops.actions.preconditions import Evidence  # noqa: E402
from fazerops.collectors.k8s_audit import K8sAuditCollector  # noqa: E402
from fazerops.security.envelope import project_event_for_llm  # noqa: E402

ACTION = "revert_configmap_key"
EVIDENCE = Evidence(
    resource_keys=frozenset({keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}),
    complete=True,
)
DEMO_HINT = {
    "action_id": ACTION,
    "namespace": "billing",
    "name": "billing-api-config",
    "key": "pool.max",
    "prior_value": "100",
    "current_value": "20",
}


@pytest.fixture
def widened(tmp_path) -> Catalog:
    """The shipped catalog with the declared widening applied through the same text rewrite a
    rung-1 PR commits."""
    shipped = default_catalog().get(ACTION)
    path = tmp_path / "actions.yaml"
    path.write_text(
        apply_params(DEFAULT_ACTIONS.read_text(encoding="utf-8"), ACTION, WIDENINGS[0].apply(params_of(shipped))),
        encoding="utf-8",
    )
    return Catalog.load(path)


@pytest.fixture
def cluster(monkeypatch):
    patches: list[tuple[str, str, dict]] = []

    class FakeCoreV1:
        def patch_namespaced_config_map(self, *, name, namespace, body):
            patches.append((namespace, name, body))
            return SimpleNamespace(data=body["data"], metadata=SimpleNamespace(resource_version="9"))

    monkeypatch.setattr(configmap_executor, "_core_v1", lambda credential=None: FakeCoreV1())
    return patches


def _multi_request(catalog, **param_overrides):
    change = multi_key_change("evt-1", at=T0)
    request = request_from_hint(change.inverse_hint, catalog=catalog)
    if param_overrides:
        request = request.model_copy(update={"params": {**request.params, **param_overrides}})
    return request


# --------------------------------------------------------------------------------------
# Unreachable until merged
# --------------------------------------------------------------------------------------


def test_the_shipped_catalog_rejects_the_widened_form():
    change = multi_key_change("evt-1", at=T0)

    assert "keys" not in default_catalog().get(ACTION).params
    assert request_from_hint(change.inverse_hint) is None, "an unusable hint is None, never an exception"
    with pytest.raises(ValidationRejected, match="keys"):
        validate_params(default_catalog().get(ACTION), {"namespace": "billing", "name": "x", "keys": ["a"]})


def test_the_declared_widening_changes_only_params(widened):
    shipped, after = default_catalog().get(ACTION), widened.get(ACTION)

    assert after.model_dump(exclude={"params"}) == shipped.model_dump(exclude={"params"})
    assert after.params["keys"].type == "list[str]"
    assert after.params["key"].required is False and after.params["target_value"].required is False
    assert {n: s for n, s in after.params.items() if n not in {"keys", "key", "target_value"}} == {
        n: s for n, s in shipped.params.items() if n not in {"key", "target_value"}
    }


@pytest.mark.parametrize("value", [[], "pool.max", ["a", "a"], ["a", ""], ["a", 3]])
def test_a_list_parameter_is_validated(widened, value):
    with pytest.raises(ValidationRejected):
        validate_params(widened.get(ACTION), {"namespace": "billing", "name": "x", "keys": value})


# --------------------------------------------------------------------------------------
# The collector
# --------------------------------------------------------------------------------------


def _audit(audit_id: str, timestamp: str, data: dict) -> dict:
    return {
        "auditID": audit_id,
        "stage": "ResponseComplete",
        "verb": "update",
        "user": {"username": "dinesh@faber-demo.io"},
        "requestReceivedTimestamp": timestamp,
        "objectRef": {"resource": "configmaps", "namespace": "billing", "name": "billing-api-config"},
        "responseStatus": {"code": 200},
        "responseObject": {"data": data},
    }


def test_the_collector_records_every_key_of_a_multi_key_edit_without_claiming_reversible():
    collector = K8sAuditCollector()
    ordered = collector._prepare(
        [_audit("a", "2026-09-06T13:00:00Z", MULTI_BEFORE), _audit("b", "2026-09-06T14:00:00Z", MULTI_AFTER)]
    )
    event = collector._normalize(ordered[1])

    assert event.reversible is False, "reversible reaches the model and the brief; it stays narrow"
    assert event.inverse_hint == {
        "action_id": ACTION,
        "namespace": "billing",
        "name": "billing-api-config",
        "keys": sorted(MULTI_BEFORE),
        "prior_values": MULTI_BEFORE,
        "current_values": MULTI_AFTER,
    }
    assert "inverse_hint" not in project_event_for_llm(event), "and the hint never reaches a model"


# --------------------------------------------------------------------------------------
# The keys form, once widened
# --------------------------------------------------------------------------------------


def test_the_multi_key_hint_becomes_a_keys_request(widened):
    request = _multi_request(widened)
    assert request.params == {"namespace": "billing", "name": "billing-api-config", "keys": sorted(MULTI_BEFORE)}


def test_the_inverse_swaps_the_recorded_values_and_round_trips(widened):
    request = _multi_request(widened)
    undo = request.inverse(catalog=widened)

    assert undo.inverse_hint["prior_values"] == MULTI_AFTER
    assert undo.inverse_hint["current_values"] == MULTI_BEFORE
    redo = undo.inverse(catalog=widened)
    assert (redo.params, redo.inverse_hint) == (request.params, request.inverse_hint)


def test_the_dry_run_shows_every_key_from_recorded_values(widened):
    dry = _multi_request(widened).dry_run(evidence=EVIDENCE, catalog=widened)

    assert [(l.field, l.before, l.after) for l in dry.lines] == [
        (k, MULTI_AFTER[k], MULTI_BEFORE[k]) for k in sorted(MULTI_BEFORE)
    ]
    assert dry.reversible and dry.unmet_preconditions == []


def test_a_sensitive_key_is_masked_in_the_widened_dry_run(widened):
    change = configmap_change(
        "evt-1", at=T0, before={"db.password": "old-secret", "pool.max": "1"}, after={"db.password": "new-secret", "pool.max": "2"}
    )
    rendered = request_from_hint(change.inverse_hint, catalog=widened).dry_run(evidence=EVIDENCE, catalog=widened).render()
    assert "old-secret" not in rendered and "new-secret" not in rendered


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": "payments-config"},
        {"keys": ["issuer"]},
        {"keys": ["issuer", "session.ttl", "extra"]},
        {"key": "issuer"},
    ],
    ids=["another-configmap", "subset", "superset", "both-forms"],
)
def test_the_keys_form_refuses_anything_but_exactly_what_was_recorded(widened, overrides, cluster):
    request = _multi_request(widened, **overrides)

    assert request.inverse(catalog=widened) is None
    assert writes(request, catalog=widened) is None
    assert request.dry_run(evidence=EVIDENCE, catalog=widened).reversible is False
    with pytest.raises(InverseUnavailable):
        request.execute(None, evidence=EVIDENCE, catalog=widened)
    assert cluster == []


def test_an_approved_keys_request_patches_exactly_the_recorded_prior_values(widened, cluster):
    gateway = ApprovalGateway(
        catalog=widened,
        runner=lambda request, credential, evidence: request.execute(credential, evidence=evidence, catalog=widened),
    )
    gateway.register("INC-1", _multi_request(widened), evidence=EVIDENCE)
    outcome = gateway.decide(
        incident_id="INC-1", action_id=ACTION, approver=Approver(user_id="U_IC", role=ApproverRole.ENGINEER), kind="approve"
    )

    assert outcome.executed, outcome.error
    assert cluster == [("billing", "billing-api-config", {"data": MULTI_BEFORE})]
    assert outcome.result["keys"] == sorted(MULTI_BEFORE)
    assert "auth.faber-demo.io" not in str(outcome.result), "results carry key names, never values"


def test_the_executor_refuses_mismatched_recorded_values_before_spending_a_credential(cluster):
    params = {"namespace": "billing", "name": "payments-config", "keys": sorted(MULTI_BEFORE)}
    with pytest.raises(ValueError, match="refusing"):
        configmap_executor.revert_key(params, credential=None, recorded=multi_key_change("e", at=T0).inverse_hint)
    assert cluster == []


# --------------------------------------------------------------------------------------
# The demo action is untouched
# --------------------------------------------------------------------------------------


def test_the_single_key_demo_action_is_identical_before_and_after_the_widening(widened):
    before = request_from_hint(DEMO_HINT)
    after = request_from_hint(DEMO_HINT, catalog=widened)

    assert before.params == after.params
    assert before.inverse().params == after.inverse(catalog=widened).params
    assert before.dry_run(evidence=EVIDENCE).render() == after.dry_run(evidence=EVIDENCE, catalog=widened).render()
    assert writes(before) == writes(after, catalog=widened)


def test_a_widened_request_naming_neither_form_refuses(widened):
    request = ActionRequest.for_action(ACTION, {"namespace": "billing", "name": "billing-api-config"}, catalog=widened)

    assert request.inverse(catalog=widened) is None
    assert request.dry_run(evidence=EVIDENCE, catalog=widened).reversible is False
