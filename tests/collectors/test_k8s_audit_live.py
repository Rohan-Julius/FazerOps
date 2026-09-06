"""W8's live path — reading the API server's audit log off disk.

These run without a cluster: the live path's input is a JSON-lines file, so a temp file is
a faithful stand-in for the API server's output. `tests/e2e/test_k3d_audit.py` covers the
half that a temp file cannot — that a real cluster actually produces this shape.

The behaviour under test is mostly about what the reader is allowed to *discard*. It skips
almost everything in a 64MB log, and each thing it skips is a way the demo could silently
report "nothing changed".
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from faberops.collectors.k8s_audit import AUDIT_LOG_ENV, K8sAuditCollector
from faberops.radius import ServiceManifest

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)
WINDOW_START = ALERT_TIME - timedelta(hours=4)


def entry(when: datetime, *, name: str = "billing-api-config", verb: str = "update",
          user: str = "dinesh@faber-demo.io", data: dict | None = None,
          namespace: str = "billing", resource: str = "configmaps") -> dict:
    payload = {
        "auditID": f"{name}-{when.isoformat()}",
        "stage": "ResponseComplete",
        "level": "RequestResponse",
        "verb": verb,
        "user": {"username": user},
        "requestReceivedTimestamp": when.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "objectRef": {"resource": resource, "namespace": namespace, "name": name},
        "responseStatus": {"code": 200},
    }
    if data is not None:
        payload["responseObject"] = {"kind": "ConfigMap", "data": data}
    return payload


@pytest.fixture
def audit_log(tmp_path, monkeypatch):
    """Point the live path at a log this test controls, in live mode."""
    path = tmp_path / "audit.log"
    monkeypatch.setenv("FABEROPS_MODE", "live")
    monkeypatch.setenv(AUDIT_LOG_ENV, str(path))

    def write(entries: list[dict], trailing: str = "") -> None:
        path.write_text("\n".join(json.dumps(e) for e in entries) + "\n" + trailing,
                        encoding="utf-8")

    write.path = path
    return write


@pytest.fixture
def window():
    from faberops.models import TimeWindow

    return TimeWindow(start=WINDOW_START, end=ALERT_TIME)


@pytest.fixture
def radius():
    return ServiceManifest.load().resolve("billing-api")


async def test_the_live_path_reads_the_log_and_produces_the_same_events(
    audit_log, radius, window
):
    """Parity with fixture mode: the file is the only thing that differs."""
    audit_log([
        entry(WINDOW_START - timedelta(hours=2), data={"pool.max": "100"}),
        entry(ALERT_TIME - timedelta(minutes=38), data={"pool.max": "20"}),
    ])

    result = await K8sAuditCollector().fetch(radius, window)

    assert result.ok, result.error
    assert len(result.events) == 1
    edit = result.events[0]
    assert edit.diff.before == {"pool.max": "100"}
    assert edit.diff.after == {"pool.max": "20"}


async def test_the_prior_state_anchor_is_read_from_outside_the_window(
    audit_log, radius, window
):
    """The reader discards nearly everything before the window — but not the entry that
    makes the diff possible. Losing it turns the demo's central evidence into "the value
    is now 20", which is a claim rather than a before/after."""
    audit_log([
        entry(WINDOW_START - timedelta(days=3), data={"pool.max": "999"}),   # superseded
        entry(WINDOW_START - timedelta(hours=1), data={"pool.max": "100"}),  # the anchor
        entry(ALERT_TIME - timedelta(minutes=38), data={"pool.max": "20"}),
    ])

    result = await K8sAuditCollector().fetch(radius, window)

    assert result.events[0].diff.before == {"pool.max": "100"}


async def test_entries_after_the_alert_are_never_read(audit_log, radius, window):
    """The log keeps growing while the brief is being assembled. A change made *after* the
    page cannot have caused it, and showing one implies a causal claim that is backwards."""
    audit_log([
        entry(WINDOW_START - timedelta(hours=1), data={"pool.max": "100"}),
        entry(ALERT_TIME - timedelta(minutes=38), data={"pool.max": "20"}),
        entry(ALERT_TIME + timedelta(minutes=5), data={"pool.max": "50"}),
    ])

    result = await K8sAuditCollector().fetch(radius, window)

    assert len(result.events) == 1
    assert result.events[0].diff.after == {"pool.max": "20"}


async def test_a_torn_final_line_does_not_kill_the_brief(audit_log, radius, window):
    """The API server appends as it goes, so the last line can be half written at the
    moment the alert fires. That is normal, not corruption."""
    audit_log(
        [
            entry(WINDOW_START - timedelta(hours=1), data={"pool.max": "100"}),
            entry(ALERT_TIME - timedelta(minutes=38), data={"pool.max": "20"}),
        ],
        trailing='{"auditID":"half-writ',
    )

    result = await K8sAuditCollector().fetch(radius, window)

    assert result.ok, result.error
    assert len(result.events) == 1


async def test_a_missing_log_degrades_the_brief_rather_than_reporting_no_changes(
    radius, window, monkeypatch, tmp_path
):
    """The one wrong answer this product can give is "nothing changed" when it simply
    could not look. A degraded brief names the source; an empty one lies."""
    monkeypatch.setenv("FABEROPS_MODE", "live")
    monkeypatch.setenv(AUDIT_LOG_ENV, str(tmp_path / "nope.log"))

    result = await K8sAuditCollector().fetch(radius, window)

    assert result.ok is False
    assert "FileNotFoundError" in result.error
    assert result.events == []


async def test_the_live_path_applies_the_same_exclusions_as_fixture_mode(
    audit_log, radius, window
):
    """Reads, control-plane principals and out-of-radius objects are dropped by the shared
    normalizer, not by anything the reader does. If that ever stops being true, fixture
    mode and live mode have diverged."""
    audit_log([
        entry(ALERT_TIME - timedelta(minutes=38), data={"pool.max": "20"}),
        entry(ALERT_TIME - timedelta(minutes=30), verb="get", data={"pool.max": "20"}),
        entry(ALERT_TIME - timedelta(minutes=20), name="billing-api",
              resource="deployments",
              user="system:serviceaccount:kube-system:generic-garbage-collector"),
        entry(ALERT_TIME - timedelta(minutes=10), name="unrelated-config",
              namespace="marketing", data={"x": "1"}),
    ])

    result = await K8sAuditCollector().fetch(radius, window)

    assert [e.resource.name for e in result.events] == ["billing-api-config"]
