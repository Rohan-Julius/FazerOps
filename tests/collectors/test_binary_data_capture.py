"""W42's second writer contract — a ConfigMap's `binaryData` — against what Kubernetes wrote.

`tests/fixtures/k8s_audit_binary_data.json` is two audit entries captured from the k3d API server
by `scripts/capture_binary_data_fixture.py`, untouched: a ConfigMap created with a text and a
binary map, then one binary key patched. It lives outside `fixtures/` because the demo's
collectors read everything there, and this change belongs to no incident.

What it establishes is that rung 3 has a target in production shape: the audit log records the
binary map with its prior value, the collector diffs it as its own field path without disturbing
the `data` diff every hint and the demo rely on, and no shipped action or registered writer can
restore it — so generation reaches rung 3.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from fazerops.actions.growth.generate import RungReason, generate
from fazerops.actions.growth.miner import Gap, GapAggregate
from fazerops.actions.growth.signals import FieldPath, GapSignalStore, ResourceKind, SignalKind, classify, field_path_of, prior_value_recorded
from fazerops.collectors.k8s_audit import K8sAuditCollector
from fazerops.security.envelope import render_candidate_for_llm

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "k8s_audit_binary_data.json"


@pytest.fixture
def entries() -> list[dict]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _events(entries):
    return [event for _, event in K8sAuditCollector().normalize_entries(copy.deepcopy(entries))]


def test_the_capture_is_a_real_create_then_patch_of_one_binary_key(entries):
    create, patch = entries
    assert (create["verb"], patch["verb"]) == ("create", "patch")
    assert create["responseObject"]["data"] == patch["responseObject"]["data"], "the text map did not change"
    assert create["responseObject"]["binaryData"] != patch["responseObject"]["binaryData"]


def test_the_collector_diffs_the_binary_map_with_its_prior_value(entries):
    _, patch = _events(entries)
    diff = patch.diff

    assert diff.field_path == "binaryData"
    assert diff.prior_value_captured is True
    assert diff.before == entries[0]["responseObject"]["binaryData"]
    assert diff.after == entries[1]["responseObject"]["binaryData"]
    assert diff.fields_changed == ["favicon.ico"]


def test_no_shipped_action_claims_it(entries):
    _, patch = _events(entries)
    assert patch.reversible is False and patch.inverse_hint is None


def test_first_sight_of_a_configmap_is_reported_exactly_as_before(entries):
    create, _ = _events(entries)
    assert create.diff.field_path is None
    assert create.diff.prior_value_captured is False


def test_a_change_to_the_text_map_keeps_the_data_diff_it_always_had(entries):
    changed = copy.deepcopy(entries)
    changed[1]["responseObject"]["binaryData"] = changed[0]["responseObject"]["binaryData"]
    changed[1]["responseObject"]["data"] = {"cache.ttl": "900"}

    _, patch = _events(changed)
    assert patch.diff.field_path is None
    assert patch.diff.fields_changed == ["cache.ttl"]
    assert patch.reversible is True, "the single-key revert still applies to a data edit"


def test_when_both_maps_change_the_data_diff_wins(entries):
    both = copy.deepcopy(entries)
    both[1]["responseObject"]["data"] = {"cache.ttl": "900"}

    _, patch = _events(both)
    assert patch.diff.field_path is None and patch.diff.fields_changed == ["cache.ttl"]


def test_the_field_path_never_reaches_model_context(entries):
    from fazerops.models import Candidate

    _, patch = _events(entries)
    assert "binaryData" not in render_candidate_for_llm(Candidate(event=patch, score=0.5, rank=1))


def test_it_is_a_gap_the_miner_can_describe(entries):
    _, patch = _events(entries)

    assert field_path_of(patch) is FieldPath.BINARY_DATA
    assert prior_value_recorded(patch)
    assert classify(patch) is SignalKind.UNACTIONABLE


def test_generation_reaches_rung_three_for_it():
    aggregate = GapAggregate(
        source="k8s_audit",
        resource_kind=ResourceKind.CONFIGMAP,
        verb="update",
        field_path=FieldPath.BINARY_DATA,
        unactionable_count=2,
        incident_count=2,
        distinct_actors=2,
        prior_value_recorded=True,
    )
    result = generate(Gap(aggregate=aggregate, eligible=True), GapSignalStore())

    assert [(r.rung, r.reason) for r in result.rungs] == [
        (1, RungReason.NO_SUPPORTED_WIDENING),
        (2, RungReason.NO_REGISTERED_WRITER),
        (3, RungReason.WRITER_AUTHORING_REQUIRED),
    ]
