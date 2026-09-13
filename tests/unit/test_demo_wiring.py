"""The settings a demo deployment needs.

A deployment points FazerOps at the company's own application repositories
(`FAZEROPS_SERVICE_REPOS`), so the GitHub collector watches real pushes and merges. Asserted here to
do exactly that, to refuse the typo that would silently watch nothing, and to leave the checked-in
manifest alone when unset — which is what every other test relies on. Plus the two pieces of the
recorded story that are not settings: the staged alert, and which human change counts as a fix.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from _growth_events import T0, configmap_change, multi_key_change  # noqa: E402

from fazerops.actions.growth.signals import SignalKind, find_remediations, signal_for  # noqa: E402
from fazerops.ledger.store import LedgerStore  # noqa: E402
from fazerops.radius import SERVICE_REPOS_ENV, ServiceManifest  # noqa: E402


def test_a_service_can_watch_the_companys_own_repository(monkeypatch):
    monkeypatch.setenv(SERVICE_REPOS_ENV, "auth-service=acme/app")
    manifest = ServiceManifest.load()

    assert "repo:acme/app" in manifest.keys_for("auth-service")
    assert "repo:faber-demo/auth-service" not in manifest.keys_for("auth-service"), "replaced, not added to"
    assert "repo:faber-demo/billing-api" in manifest.keys_for("billing-api"), "other services untouched"


@pytest.mark.parametrize("value", ["auth-servce=acme/app", "auth-service", "auth-service=app"])
def test_a_mistyped_repository_setting_refuses_rather_than_watching_nothing(monkeypatch, value):
    monkeypatch.setenv(SERVICE_REPOS_ENV, value)
    with pytest.raises(ValueError, match=SERVICE_REPOS_ENV):
        ServiceManifest.load()


def test_unset_the_manifest_is_the_checked_in_one(monkeypatch):
    monkeypatch.delenv(SERVICE_REPOS_ENV, raising=False)
    assert "repo:faber-demo/auth-service" in ServiceManifest.load().keys_for("auth-service")


def test_only_the_first_human_change_after_an_incident_is_its_remediation():
    """The next incident's cause, by another person inside the window, is not this one's fix."""
    ledger = LedgerStore()
    cause = multi_key_change("evt-1", at=T0 - timedelta(minutes=5), actor="priya")
    fix = configmap_change("fix-1", at=T0 + timedelta(minutes=5), actor="dinesh", before={"issuer": "b"}, after={"issuer": "a"})
    next_cause = configmap_change("evt-2", at=T0 + timedelta(minutes=20), actor="arun", before={"issuer": "a"}, after={"issuer": "c"})
    for event in (cause, fix, next_cause):
        ledger.record(event)
    anchor = signal_for(SignalKind.DECLINE, cause, observed_at=T0, incident_id="INC-1")

    assert [d.remediation_event_id for _, d in find_remediations(ledger, [anchor], window_minutes=60)] == ["fix-1"]


def test_the_demo_alert_names_a_service_the_manifest_knows():
    from demo_world import alert_payload

    from fazerops.ingest.alerts import normalize_alert

    first, second = normalize_alert(alert_payload()), normalize_alert(alert_payload())
    assert first.service == "auth-service"
    assert first.id != second.id, "each staged incident is its own incident"
    json.dumps(alert_payload())
