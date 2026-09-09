"""W14 — the hand-authored `type_prior` table.

Two things are asserted, and the second matters more than it looks. That the five rows
Handoff §6 gives actually resolve to a high/medium prior — otherwise the table is
decorative. And that **every** cell of `(action, resource_type) × alert_class` resolves to
a number: an unlisted cell must fall back to the declared default, never raise. A KeyError
here surfaces at correlation time on demo day, in a code path nothing else exercises.
"""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

from fazerops.correlation.features import load_weights, type_prior
from fazerops.correlation.priors import default_priors, normalize_type
from fazerops.models import (
    Actor,
    Alert,
    AlertClass,
    ChangeEvent,
    Diff,
    NormalizedAction,
    ResourceRef,
)

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)
DEFAULT = float(load_weights()["type_prior_default"])
MEDIUM = default_priors().level("medium")


def alert(alert_class: AlertClass) -> Alert:
    return Alert(
        id="a-1",
        service="billing-api",
        summary="something is wrong",
        fired_at=ALERT_TIME,
        alert_class=alert_class,
    )


def event(action: str, kind: str, *, changed: dict | None = None) -> ChangeEvent:
    diff = None
    if changed is not None:
        diff = Diff(before={key: "old" for key in changed}, after=changed)
    return ChangeEvent(
        id=f"e-{action}-{kind}",
        source="k8s_audit",
        occurred_at=ALERT_TIME - timedelta(minutes=38),
        actor=Actor(raw="dinesh@faber-demo.io"),
        action=action,
        resource=ResourceRef(kind=kind, name="thing", namespace="billing"),
        blast_radius_keys={"service:billing-api"},
        in_band=False,
        diff=diff,
        raw_ref="fixture#e",
    )


# --------------------------------------------------------------------------------------
# Handoff §6's five rows
# --------------------------------------------------------------------------------------


def test_a_connection_pool_configmap_edit_is_a_high_prior_for_a_latency_spike():
    """Handoff §6 row 1, and the demo's own causal change."""
    candidate = event("update", "ConfigMap", changed={"pool.max": "20"})
    assert type_prior(candidate, alert(AlertClass.LATENCY_SPIKE)) > MEDIUM


def test_the_other_four_rows_resolve_above_the_default():
    rows = [
        (event("update", "DBParameterGroup"), AlertClass.LATENCY_SPIKE),
        (event("revoke", "SecurityGroupIngress"), AlertClass.CONNECTION_REFUSED),
        (event("update", "IAMRolePolicy"), AlertClass.AUTH_FAILURE),
        (event("rollout", "Deployment"), AlertClass.ERROR_RATE_SPIKE),
    ]
    for candidate, alert_class in rows:
        assert type_prior(candidate, alert(alert_class)) > DEFAULT, candidate.resource.kind


def test_an_unqualified_configmap_edit_does_not_inherit_the_qualified_row():
    """The qualifier is what stops every ConfigMap edit in the radius reading as a likely
    cause of a latency spike. The demo's rank 3 is exactly this event."""
    unrelated = event("update", "ConfigMap", changed={"session.ttl": "7200"})
    assert type_prior(unrelated, alert(AlertClass.LATENCY_SPIKE)) == DEFAULT


def test_the_qualifier_reads_field_names_and_not_field_values():
    """A value is whatever someone typed into a ConfigMap — attacker-influenceable in a way
    a key name is not. A prior that could be raised by writing "pool" into a value would
    put a scoring input under the control of the person being investigated."""
    smuggled = event("update", "ConfigMap", changed={"greeting": "pool max connections"})
    assert type_prior(smuggled, alert(AlertClass.LATENCY_SPIKE)) == DEFAULT


def test_the_right_change_against_the_wrong_alert_class_gets_no_boost():
    """A row is a cell, not a property of the change. The pool edit is only a high prior
    for the alert class it plausibly causes."""
    pool_edit = event("update", "ConfigMap", changed={"pool.max": "20"})
    assert type_prior(pool_edit, alert(AlertClass.DISK_PRESSURE)) == DEFAULT


# --------------------------------------------------------------------------------------
# Total coverage — no KeyError path
# --------------------------------------------------------------------------------------


def test_every_cell_resolves_to_a_number():
    """Every combination of the normalized verb vocabulary, the resource kinds these
    collectors emit, and the alert classes — present in the table or falling back to the
    declared default. None raises."""
    kinds = [
        "ConfigMap",
        "Secret",
        "Deployment",
        "StatefulSet",
        "Repo",
        "Release",
        "DBParameterGroup",
        "SecurityGroupIngress",
        "IAMRolePolicy",
        "Function",
        "Parameter",
    ]
    combinations = itertools.product(NormalizedAction, kinds, AlertClass)

    for action, kind, alert_class in combinations:
        score = type_prior(event(action.value, kind), alert(alert_class))
        assert 0.0 <= score <= 1.0


def test_an_unclassified_alert_takes_the_declared_default():
    """`unclassified` is a real classification outcome (W13), not an error state. It has no
    row anywhere, so it must land on the default rather than on a KeyError."""
    pool_edit = event("update", "ConfigMap", changed={"pool.max": "20"})
    assert type_prior(pool_edit, alert(AlertClass.UNCLASSIFIED)) == DEFAULT


def test_resource_types_match_across_naming_conventions():
    """Handoff §6 writes `db_parameter_group`; CloudTrail emits `DBParameterGroup`. If
    these stop being the same type, the row silently never fires."""
    assert normalize_type("DBParameterGroup") == normalize_type("db_parameter_group")
    assert normalize_type("ConfigMap") == normalize_type("configmaps".rstrip("s"))
