"""W7 — proof that the cluster's audit policy actually produces the demo's evidence.

The load-bearing assertion is `requestObject` *and* `responseObject` on a ConfigMap update.
Only `RequestResponse` yields those, and without them `collectors/k8s_audit.py` cannot
reconstruct a before/after — the diff degrades into "the value is now 20", which is a claim
rather than a screenshot. Handoff §5 asks for the real before/after; this is the test that
says the cluster can supply it.

Requires the cluster from `scripts/setup_k3d.sh`. Excluded from the CI default suite by the
`cluster` marker, which is why the whole file is allowed to shell out to kubectl.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from fazerops.collectors.k8s_audit import K8sAuditCollector

pytestmark = pytest.mark.cluster

REPO_ROOT = Path(__file__).resolve().parents[2]
CLUSTER = os.environ.get("FAZEROPS_CLUSTER", "fazerops")
CONTEXT = f"k3d-{CLUSTER}"
AUDIT_LOG = Path(
    os.environ.get("FAZEROPS_AUDIT_DIR", str(REPO_ROOT / ".k3d" / "audit"))
) / "audit.log"

NAMESPACE = "billing"
CONFIGMAP = "billing-api-config"

# The API server buffers audit writes, so an entry is not on disk the instant kubectl
# returns. Polling beats a fixed sleep: normally one pass, and a slow machine does not
# turn a passing assertion into a flake.
POLL_TIMEOUT_S = 30.0
POLL_INTERVAL_S = 0.5


def kubectl(*args: str) -> str:
    return subprocess.run(
        ["kubectl", "--context", CONTEXT, *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def audit_entries() -> list[dict]:
    """Every entry on disk. The log is JSON lines; a partially flushed final line is
    normal and is skipped rather than treated as corruption."""
    entries = []
    with AUDIT_LOG.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def wait_for_entry(predicate) -> dict:
    deadline = time.monotonic() + POLL_TIMEOUT_S
    while time.monotonic() < deadline:
        for entry in reversed(audit_entries()):
            if predicate(entry):
                return entry
        time.sleep(POLL_INTERVAL_S)
    pytest.fail(f"no matching audit entry within {POLL_TIMEOUT_S:.0f}s of {AUDIT_LOG}")


@pytest.fixture(scope="module", autouse=True)
def cluster_available():
    if not AUDIT_LOG.exists():
        pytest.skip(f"no audit log at {AUDIT_LOG} — run scripts/setup_k3d.sh")
    try:
        kubectl("get", "configmap", CONFIGMAP, "-n", NAMESPACE, "-o", "name")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(f"cluster '{CLUSTER}' is not serving the demo workload: {exc}")


@pytest.fixture
def restored_configmap():
    """Leave the cluster where the demo expects to find it: `pool.max: "100"`."""
    yield
    kubectl(
        "patch", "configmap", CONFIGMAP, "-n", NAMESPACE,
        "--type", "merge", "-p", json.dumps({"data": {"pool.max": "100"}}),
    )


def _configmap_update(new_value: str):
    def predicate(entry: dict) -> bool:
        ref = entry.get("objectRef") or {}
        return (
            entry.get("stage") == "ResponseComplete"
            and entry.get("verb") == "patch"
            and ref.get("resource") == "configmaps"
            and ref.get("name") == CONFIGMAP
            and ((entry.get("responseObject") or {}).get("data") or {}).get("pool.max")
            == new_value
        )

    return predicate


def test_configmap_edit_records_both_request_and_response_bodies(restored_configmap):
    new_value = str(uuid.uuid4().int % 1000)
    kubectl(
        "patch", "configmap", CONFIGMAP, "-n", NAMESPACE,
        "--type", "merge", "-p", json.dumps({"data": {"pool.max": new_value}}),
    )

    entry = wait_for_entry(_configmap_update(new_value))

    assert entry["level"] == "RequestResponse"
    assert entry["requestObject"]["data"]["pool.max"] == new_value
    assert entry["responseObject"]["data"]["pool.max"] == new_value
    # Everything the collector keys on, present on a payload the API server produced
    # rather than one this repo wrote (W7b replaces the fixture with exactly these).
    for field in ("auditID", "requestReceivedTimestamp", "user", "objectRef", "responseStatus"):
        assert field in entry, f"real audit entry has no {field}"


def test_other_resources_stay_at_metadata_level():
    """`Metadata` everywhere else is the other half of the policy. If Deployments came
    back at RequestResponse the log would carry whole pod templates for every rollout, and
    the demo's fixture would be unreadable."""
    kubectl(
        "annotate", "deployment", "billing-api", "-n", NAMESPACE,
        f"fazerops.dev/probe={uuid.uuid4().hex[:8]}", "--overwrite",
    )

    entry = wait_for_entry(
        lambda e: (e.get("objectRef") or {}).get("resource") == "deployments"
        and (e.get("objectRef") or {}).get("name") == "billing-api"
        and e.get("stage") == "ResponseComplete"
        and e.get("verb") in {"patch", "update"}
    )

    assert entry["level"] == "Metadata"
    assert "requestObject" not in entry
    assert "responseObject" not in entry


def test_the_collector_reconstructs_a_diff_from_real_entries(restored_configmap):
    """The bridge to W7b: two real edits in sequence must give the collector everything it
    needs to produce a before/after. If this passes, the recorded fixture is honest."""
    first, second = str(uuid.uuid4().int % 1000), str(uuid.uuid4().int % 1000)
    for value in (first, second):
        kubectl(
            "patch", "configmap", CONFIGMAP, "-n", NAMESPACE,
            "--type", "merge", "-p", json.dumps({"data": {"pool.max": value}}),
        )
    wait_for_entry(_configmap_update(second))

    collector = K8sAuditCollector()
    raw = [e for e in audit_entries() if (e.get("objectRef") or {}).get("name") == CONFIGMAP]
    prepared = collector._prepare(raw)

    event = next(
        e
        for e in (collector._normalize(item) for item in reversed(prepared))
        if e is not None and (e.diff.after or {}).get("pool.max") == second
    )
    assert event.diff.prior_value_captured is True
    assert event.diff.before["pool.max"] == first
    assert event.diff.fields_changed == ["pool.max"]
    assert event.reversible is True
    assert event.inverse_hint["prior_value"] == first


def test_the_live_collector_reads_the_real_log_end_to_end(restored_configmap):
    """W8's live path against a real cluster, with nothing stubbed.

    The unit tests feed the reader a temp file; only this one proves the default log
    location, the API server's real output and the collector's normalizer line up. It is
    the closest thing to the demo's live mode that runs without a human at the keyboard.
    """
    from datetime import datetime, timedelta, timezone

    from fazerops.config import Mode
    from fazerops.models import TimeWindow
    from fazerops.radius import ServiceManifest

    before = str(uuid.uuid4().int % 1000)
    after = str(uuid.uuid4().int % 1000)
    started = datetime.now(timezone.utc)
    for value in (before, after):
        kubectl(
            "patch", "configmap", CONFIGMAP, "-n", NAMESPACE,
            "--type", "merge", "-p", json.dumps({"data": {"pool.max": value}}),
        )
    wait_for_entry(_configmap_update(after))

    # The window opens after the first edit, so `before` is only reachable as a
    # prior-state anchor read from outside it — exactly the demo's shape.
    window = TimeWindow(
        start=started + timedelta(milliseconds=1),
        end=datetime.now(timezone.utc) + timedelta(minutes=1),
    )

    os.environ["FAZEROPS_MODE"] = Mode.LIVE.value
    try:
        result = asyncio.run(K8sAuditCollector().fetch(
            ServiceManifest.load().resolve("billing-api"), window))
    finally:
        os.environ["FAZEROPS_MODE"] = Mode.FIXTURE.value

    assert result.ok, result.error
    edits = [e for e in result.events if (e.diff.after or {}).get("pool.max") == after]
    assert len(edits) == 1, "the live path did not return the edit it just made"
    assert edits[0].diff.before["pool.max"] == before
    assert edits[0].reversible is True
