"""The audit log rotates — 64MB, one backup, per `scripts/setup_k3d.sh`.

Found live 14 Sep: the collector read only `audit.log`, so after a rotation the first edit to a
ConfigMap carried no prior value, and no revert was offered for a change the cluster had recorded
in full.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from fazerops.collectors.k8s_audit import AUDIT_LOG_ENV, K8sAuditCollector, rotated_logs
from fazerops.models import TimeWindow
from fazerops.radius import ServiceManifest

ALERT = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)
WINDOW = TimeWindow(start=ALERT - timedelta(hours=4), end=ALERT)
BACKUP = "audit-2026-09-14T10-16-40.162.log"


def _write(audit_id: str, at: datetime, data: dict[str, str]) -> dict:
    return {
        "auditID": audit_id,
        "stage": "ResponseComplete",
        "verb": "update",
        "user": {"username": "dinesh@faber-demo.io"},
        "requestReceivedTimestamp": at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "objectRef": {"resource": "configmaps", "namespace": "billing", "name": "billing-api-config"},
        "responseStatus": {"code": 200},
        "responseObject": {"kind": "ConfigMap", "data": data},
    }


def _log(path, *entries) -> None:
    path.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")


@pytest.fixture
def radius():
    return ServiceManifest.load().resolve("billing-api")


async def _fetch(monkeypatch, directory, radius):
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv(AUDIT_LOG_ENV, str(directory / "audit.log"))
    result = await K8sAuditCollector().fetch(radius, WINDOW)
    assert result.ok, result.error
    return sorted(result.events, key=lambda event: event.occurred_at)


async def test_the_prior_value_is_recovered_from_the_rotated_backup(tmp_path, monkeypatch, radius):
    _log(tmp_path / BACKUP, _write("before-rotation", ALERT - timedelta(hours=6), {"pool.max": "100"}))
    _log(tmp_path / "audit.log", _write("edit", ALERT - timedelta(minutes=5), {"pool.max": "20"}))

    [event] = await _fetch(monkeypatch, tmp_path, radius)

    assert event.diff.prior_value_captured
    assert event.diff.before == {"pool.max": "100"}
    assert event.inverse_hint["prior_value"] == "100"


async def test_a_change_made_before_the_rotation_is_still_collected(tmp_path, monkeypatch, radius):
    _log(
        tmp_path / BACKUP,
        _write("anchor", ALERT - timedelta(hours=6), {"pool.max": "100"}),
        _write("early", ALERT - timedelta(hours=2), {"pool.max": "50"}),
    )
    _log(tmp_path / "audit.log", _write("late", ALERT - timedelta(minutes=5), {"pool.max": "20"}))

    early, late = await _fetch(monkeypatch, tmp_path, radius)

    assert (early.diff.before, early.diff.after) == ({"pool.max": "100"}, {"pool.max": "50"})
    assert (late.diff.before, late.diff.after) == ({"pool.max": "50"}, {"pool.max": "20"})


def test_backups_are_read_oldest_first_and_nothing_else_is(tmp_path):
    for name in (BACKUP, "audit-2026-09-13T08-00-00.000.log", "audit.log", "other.log"):
        (tmp_path / name).write_text("", encoding="utf-8")

    assert [path.name for path in rotated_logs(tmp_path / "audit.log")] == [
        "audit-2026-09-13T08-00-00.000.log",
        BACKUP,
    ]
