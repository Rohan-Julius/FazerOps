"""W8 — the collector that produces the demo's single causal event.

If the diff is wrong there is nothing to rank, nothing to revert, and no demo.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from faberops.collectors.k8s_audit import K8sAuditCollector
from faberops.models import NormalizedAction, TimeWindow
from faberops.radius import ServiceManifest

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)
WINDOW = TimeWindow(start=ALERT_TIME - timedelta(hours=4), end=ALERT_TIME)


@pytest.fixture
def radius():
    return ServiceManifest.load().resolve("billing-api")


@pytest.fixture
async def events(radius, monkeypatch):
    monkeypatch.setenv("FABEROPS_MODE", "fixture")
    result = await K8sAuditCollector().fetch(radius, WINDOW)
    assert result.ok, result.error
    return result.events


def _by_resource(events, name):
    return next(e for e in events if e.resource.name == name)


async def test_the_causal_configmap_edit_is_collected(events):
    edit = _by_resource(events, "billing-api-config")
    assert edit.action is NormalizedAction.UPDATE
    assert edit.actor.canonical == "dinesh"

    # Asserted as a property of the scenario, not as a literal timestamp. W7b replaces
    # this fixture with payloads captured from a real cluster; an exact microsecond
    # equality would then fail for a reason that has nothing to do with the collector,
    # and a test that has to be edited to accept real data never tested the collector at
    # all. Idea §7's narrative is "38 minutes before the alert" — that is the assertion.
    minutes_before = (ALERT_TIME - edit.occurred_at).total_seconds() / 60
    assert 37 <= minutes_before <= 39
    assert WINDOW.contains(edit.occurred_at)


async def test_the_diff_reconstructs_the_prior_value_from_an_earlier_entry(events):
    """The audit entry for an update carries only the new object. `before` comes from the
    same object's previous entry — which sits outside the window, so this only works
    because prior-state indexing runs before window filtering."""
    diff = _by_resource(events, "billing-api-config").diff
    assert diff is not None
    assert diff.before == {"pool.max": "100", "pool.min": "5", "timeout": "30s"}
    assert diff.after == {"pool.max": "20", "pool.min": "5", "timeout": "30s"}
    assert diff.prior_value_captured is True


async def test_only_the_changed_field_is_reported(events):
    """`pool.min` and `timeout` are unchanged. A diff that lists all three fields makes
    the on-camera evidence look like a whole-file rewrite instead of one edit."""
    assert _by_resource(events, "billing-api-config").diff.fields_changed == ["pool.max"]


async def test_the_prior_state_anchor_is_not_itself_a_candidate(events):
    """The 09:12 entry is outside the 4h window. It informs the diff; it must not appear
    in the brief, or the timeline shows a change that predates the incident."""
    assert all(e.occurred_at >= WINDOW.start for e in events)
    assert len(events) == 3


async def test_read_verbs_are_excluded(events):
    """A ledger that records reads is a log. The fixture contains a `get` on the very
    ConfigMap in question, which is the most tempting one to leak through.

    Asserted by counting rather than by naming an audit id: a leaked read would produce a
    *second* `billing-api-config` event inside the window. Naming the id would couple this
    to the hand-authored fixture and break the moment W7b captures real UUIDs.
    """
    assert all(e.action is not NormalizedAction.UNKNOWN for e in events)

    configmap_events = [e for e in events if e.resource.name == "billing-api-config"]
    assert len(configmap_events) == 1, "the 14:20 `get` on this ConfigMap leaked through"


async def test_control_plane_principals_are_excluded(events):
    """kube-system mutates constantly. Left in, it dominates every brief."""
    assert not any(
        e.actor.raw.startswith("system:serviceaccount:kube-system:") for e in events
    )
    assert not any(e.resource.name == "billing-api" for e in events)


async def test_secret_values_are_redacted_but_the_rotation_is_still_reported(events):
    """The fact a key rotated is the evidence. The value must never reach Slack, the
    markdown record, or a model prompt."""
    secret = _by_resource(events, "billing-api-db")
    assert secret.diff.after == {"password": "<redacted>"}
    assert "c3VwZXJzZWNyZXQtcm90YXRlZA==" not in str(secret.model_dump())


async def test_in_band_is_reported_for_pipeline_principals(events):
    """Handoff §3: reported to the user, never fed to the scorer."""
    assert _by_resource(events, "billing-api-db").in_band is True
    assert _by_resource(events, "billing-api-config").in_band is False


async def test_the_one_hop_dependency_change_is_collected(events):
    """auth-service is one hop out. It is a real candidate, and the one the ConfigMap
    edit has to out-rank by a clear margin (W15)."""
    hop = _by_resource(events, "auth-service-config")
    assert hop.actor.canonical == "priya"
    assert hop.resource.namespace == "auth"


async def test_events_are_retrievable_by_their_blast_radius_key(events, radius):
    """Both sides of the index derive keys from the same ResourceRef (keys.py). If they
    disagreed, this returns nothing and the brief says nothing changed."""
    edit = _by_resource(events, "billing-api-config")
    assert "k8s:billing/configmap/billing-api-config" in edit.blast_radius_keys
    assert radius.overlaps(edit.blast_radius_keys)


# --- reversibility --------------------------------------------------------------------


async def test_the_configmap_edit_carries_an_inverse_hint(events):
    """Ground rule #4. Reversibility is claimed only when the undo can be constructed."""
    edit = _by_resource(events, "billing-api-config")
    assert edit.reversible is True
    assert edit.inverse_hint == {
        "action_id": "revert_configmap_key",
        "namespace": "billing",
        "name": "billing-api-config",
        "key": "pool.max",
        "prior_value": "100",
        "current_value": "20",
    }


async def test_changes_with_no_captured_prior_value_are_not_claimed_reversible(events):
    """The auth-service patch has no earlier entry in the log, so there is no prior value
    to restore. Claiming reversibility here fails at the executor, mid-demo."""
    hop = _by_resource(events, "auth-service-config")
    assert hop.reversible is False
    assert hop.inverse_hint is None
    assert hop.diff.prior_value_captured is False


async def test_secret_changes_are_never_claimed_reversible(events):
    """The prior value is redacted, so the inverse cannot be built — and an action that
    writes `<redacted>` into a live Secret is worse than no action at all."""
    assert _by_resource(events, "billing-api-db").reversible is False


# --- resilience -----------------------------------------------------------------------


async def test_a_metadata_level_entry_yields_no_diff_rather_than_a_wrong_one(radius):
    """If the audit policy is misconfigured to Metadata level (R2), the collector still
    produces events — it just cannot show a diff. Degrading beats inventing."""
    collector = K8sAuditCollector()
    collector._prepare([])
    event = collector._normalize(
        {
            "auditID": "meta-1",
            "stage": "ResponseComplete",
            "verb": "update",
            "user": {"username": "dinesh@faber-demo.io"},
            "requestReceivedTimestamp": "2026-09-06T14:03:11Z",
            "objectRef": {
                "resource": "configmaps",
                "namespace": "billing",
                "name": "billing-api-config",
            },
            "responseStatus": {"code": 200},
        }
    )
    assert event is not None
    assert event.diff is None
    assert event.reversible is False


async def test_denied_requests_are_not_recorded_as_changes(radius):
    """A 403 changed nothing. Recording it puts a change in the ledger that never
    happened, and the revert would have nothing to revert."""
    collector = K8sAuditCollector()
    collector._prepare([])
    assert (
        collector._normalize(
            {
                "auditID": "denied-1",
                "stage": "ResponseComplete",
                "verb": "delete",
                "user": {"username": "dinesh@faber-demo.io"},
                "requestReceivedTimestamp": "2026-09-06T14:03:11Z",
                "objectRef": {
                    "resource": "configmaps",
                    "namespace": "billing",
                    "name": "billing-api-config",
                },
                "responseStatus": {"code": 403},
            }
        )
        is None
    )
