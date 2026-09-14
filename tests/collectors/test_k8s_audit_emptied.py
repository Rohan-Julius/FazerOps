"""A ConfigMap whose map was emptied — and the stale prior value that used to outlive it.

Kubernetes serializes `data` and `binaryData` with `omitempty`, so an update that removes every
key stores an object with no `data` field at all. The prior-state index used to skip such an
entry, so the *next* edit diffed against the map from before the emptying, and its revert hint
offered to restore a value someone had deleted on purpose.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from fazerops.collectors.k8s_audit import AUDIT_LOG_ENV, K8sAuditCollector
from fazerops.models import TimeWindow
from fazerops.radius import ServiceManifest

ALERT = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)
WINDOW = TimeWindow(start=ALERT - timedelta(hours=4), end=ALERT)


def _update(
    audit_id: str,
    at: datetime,
    data: dict[str, str] | None,
    *,
    binary: dict[str, str] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"kind": "ConfigMap", "metadata": {"name": "billing-api-config"}}
    if data is not None:
        body["data"] = data
    if binary is not None:
        body["binaryData"] = binary
    return {
        "auditID": audit_id,
        "stage": "ResponseComplete",
        "verb": "update",
        "user": {"username": "dinesh@faber-demo.io"},
        "requestReceivedTimestamp": at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "objectRef": {"resource": "configmaps", "namespace": "billing", "name": "billing-api-config"},
        "responseStatus": {"code": 200},
        "responseObject": body,
    }


def _events(entries):
    return [event for _, event in K8sAuditCollector().normalize_entries(entries)]


def test_an_edit_after_the_data_was_emptied_diffs_against_the_empty_map():
    _, emptied, readded = _events(
        [
            _update("1", ALERT - timedelta(hours=3), {"pool.max": "50"}),
            _update("2", ALERT - timedelta(hours=2), None),
            _update("3", ALERT - timedelta(hours=1), {"pool.max": "5"}),
        ]
    )

    assert emptied.diff.before == {"pool.max": "50"} and emptied.diff.after is None
    assert readded.diff.before == {}
    assert (readded.inverse_hint or {}).get("prior_value") != "50"


def test_an_edit_after_the_binary_map_was_emptied_diffs_against_the_empty_map():
    text = {"app.properties": "pool.max=50"}
    _, _, readded = _events(
        [
            _update("1", ALERT - timedelta(hours=3), text, binary={"favicon.ico": "AAAA"}),
            _update("2", ALERT - timedelta(hours=2), text),
            _update("3", ALERT - timedelta(hours=1), text, binary={"favicon.ico": "BBBB"}),
        ]
    )

    assert readded.diff.field_path == "binaryData"
    assert readded.diff.before == {}


def test_an_object_never_seen_with_data_still_carries_no_diff():
    """A Deployment has no `data`; the fix must not start diffing every body against `{}`."""
    entries = [_update("1", ALERT - timedelta(hours=2), None), _update("2", ALERT - timedelta(hours=1), None)]
    assert [event.diff for event in _events(entries)] == [None, None]


@pytest.fixture
def radius():
    return ServiceManifest.load().resolve("billing-api")


async def test_an_emptying_before_the_window_replaces_the_stale_anchor(tmp_path, monkeypatch, radius):
    """Live mode keeps one pre-window anchor per object. The emptying is that object's latest
    state, so it must be the anchor — not the older entry that still had a value."""
    entries = [
        _update("before", WINDOW.start - timedelta(hours=2), {"pool.max": "50"}),
        _update("emptied", WINDOW.start - timedelta(hours=1), None),
        _update("edit", WINDOW.start + timedelta(hours=1), {"pool.max": "5"}),
    ]
    (tmp_path / "audit.log").write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv(AUDIT_LOG_ENV, str(tmp_path / "audit.log"))

    result = await K8sAuditCollector().fetch(radius, WINDOW)

    assert result.ok, result.error
    [edit] = result.events
    assert edit.diff.before != {"pool.max": "50"}
    assert (edit.inverse_hint or {}).get("prior_value") != "50"
