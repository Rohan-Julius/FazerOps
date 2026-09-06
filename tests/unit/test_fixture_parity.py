"""W5 — the fixture/live switch.

The property under test is that fixture mode and live mode differ in *exactly one place*:
where raw payloads come from. Everything after that — normalization, window filtering,
radius filtering, ordering — is shared code. If the two paths ever diverge, the demo
passes on data the production path could not produce.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from fazerops.collectors.base import BaseCollector, Collector, CollectorResult
from fazerops.models import BlastRadius, ChangeEvent, ResourceRef, TimeWindow
from fazerops.ledger.normalize import blast_radius_keys, normalize_action, normalize_actor

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)
WINDOW = TimeWindow(start=ALERT_TIME - timedelta(hours=4), end=ALERT_TIME)
RADIUS = BlastRadius(
    service="billing-api",
    keys={"k8s:billing/configmap/billing-api-config", "service:billing-api"},
    direct_keys={"k8s:billing/configmap/billing-api-config"},
)


def _payload(name: str, when: str, namespace: str = "billing") -> dict[str, Any]:
    return {
        "auditID": name,
        "verb": "update",
        "user": {"username": "dinesh@faber-demo.io"},
        "requestReceivedTimestamp": when,
        "objectRef": {"resource": "configmaps", "name": name, "namespace": namespace},
    }


class _ReferenceCollector(BaseCollector):
    """Stands in for W8/W10/W11 until they land, and exercises the shared template.

    Both modes are backed by the same `_normalize`, which is the whole point.
    """

    source = "k8s_audit"
    fixture_dir = "k8s_audit"

    def __init__(self, live_payloads: list[dict[str, Any]] | None = None) -> None:
        self.live_payloads = live_payloads or []
        self.live_calls = 0

    async def _fetch_live(self, radius, window) -> list[dict[str, Any]]:
        self.live_calls += 1
        return self.live_payloads

    def _normalize(self, raw: dict[str, Any]) -> ChangeEvent | None:
        ref = ResourceRef(
            kind="ConfigMap",
            name=raw["objectRef"]["name"],
            namespace=raw["objectRef"]["namespace"],
        )
        actor = normalize_actor(raw["user"]["username"], "k8s_audit")
        return ChangeEvent(
            id=raw["auditID"],
            source="k8s_audit",
            occurred_at=raw["requestReceivedTimestamp"],
            actor=actor,
            action=normalize_action(raw["verb"], "k8s_audit"),
            resource=ref,
            in_band=False,
            raw_ref=f"fixture#{raw['auditID']}",
            blast_radius_keys=blast_radius_keys(ref),
        )


@pytest.fixture
def fixture_root(tmp_path, monkeypatch):
    monkeypatch.setattr("fazerops.collectors.base.FIXTURE_ROOT", tmp_path)
    return tmp_path


def _write_fixture(root, payloads):
    directory = root / "k8s_audit"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "events.json").write_text(json.dumps(payloads), encoding="utf-8")


async def test_both_modes_produce_identically_shaped_events(fixture_root, monkeypatch):
    """The parity assertion. Same payload in, same `ChangeEvent` out, either way."""
    payloads = [_payload("billing-api-config", "2026-09-06T14:03:11.123456Z")]
    _write_fixture(fixture_root, payloads)

    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    from_fixture = await _ReferenceCollector().fetch(RADIUS, WINDOW)

    monkeypatch.setenv("FAZEROPS_MODE", "live")
    live_collector = _ReferenceCollector(live_payloads=payloads)
    from_live = await live_collector.fetch(RADIUS, WINDOW)

    assert live_collector.live_calls == 1
    assert [e.model_dump() for e in from_fixture.events] == [
        e.model_dump() for e in from_live.events
    ]


async def test_fixture_mode_never_calls_the_live_path(fixture_root, monkeypatch):
    """The zero-credential promise depends on this being structural, not remembered."""
    _write_fixture(fixture_root, [_payload("billing-api-config", "2026-09-06T14:03:11Z")])
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")

    collector = _ReferenceCollector(live_payloads=[])
    await collector.fetch(RADIUS, WINDOW)

    assert collector.live_calls == 0


async def test_events_outside_the_window_are_dropped(fixture_root, monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    _write_fixture(
        fixture_root,
        [
            _payload("billing-api-config", "2026-09-06T14:03:11Z"),  # inside
            _payload("billing-api-config", "2026-09-06T09:00:00Z"),  # 5h before, outside
        ],
    )
    result = await _ReferenceCollector().fetch(RADIUS, WINDOW)
    assert len(result.events) == 1


async def test_the_window_end_is_exclusive(fixture_root, monkeypatch):
    """Half-open `[start, end)`. An inclusive end double-counts an event landing exactly
    on the alert timestamp."""
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    _write_fixture(fixture_root, [_payload("billing-api-config", "2026-09-06T14:41:00Z")])
    result = await _ReferenceCollector().fetch(RADIUS, WINDOW)
    assert result.events == []


async def test_events_outside_the_blast_radius_are_dropped(fixture_root, monkeypatch):
    """Project isolation: events outside the radius are never returned."""
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    _write_fixture(
        fixture_root,
        [
            _payload("billing-api-config", "2026-09-06T14:03:11Z"),
            _payload("unrelated-config", "2026-09-06T14:05:00Z", namespace="marketing"),
        ],
    )
    result = await _ReferenceCollector().fetch(RADIUS, WINDOW)
    assert [e.resource.name for e in result.events] == ["billing-api-config"]


async def test_events_are_returned_in_chronological_order(fixture_root, monkeypatch):
    """The brief renders a timeline. Unordered events make the causal story unreadable
    even when the ranking is right."""
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    _write_fixture(
        fixture_root,
        [
            _payload("billing-api-config", "2026-09-06T14:30:00Z"),
            _payload("billing-api-config", "2026-09-06T11:00:00Z"),
            _payload("billing-api-config", "2026-09-06T14:03:11Z"),
        ],
    )
    result = await _ReferenceCollector().fetch(RADIUS, WINDOW)
    assert [e.occurred_at.hour for e in result.events] == [11, 14, 14]


async def test_a_missing_fixture_directory_is_an_empty_source_not_an_error(
    fixture_root, monkeypatch
):
    """A collector whose fixtures do not exist yet must not break the three that do."""
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    result = await _ReferenceCollector().fetch(RADIUS, WINDOW)
    assert result.ok is True
    assert result.events == []


async def test_a_failing_source_degrades_the_brief_rather_than_raising(monkeypatch):
    """Collectors run as nodes in one Strands Graph batch (plan §3.2). An exception there
    surfaces as an opaque graph failure and takes the whole brief with it."""
    monkeypatch.setenv("FAZEROPS_MODE", "live")

    class _Broken(_ReferenceCollector):
        async def _fetch_live(self, radius, window):
            raise ConnectionError("CloudTrail is having a day")

    result = await _Broken().fetch(RADIUS, WINDOW)
    assert result.ok is False
    assert "ConnectionError" in result.error
    assert result.events == []


async def test_live_mode_is_not_silently_implemented_by_the_base_class(monkeypatch):
    """A collector with no live path must say so, not return an empty list that reads as
    'nothing changed'."""
    monkeypatch.setenv("FAZEROPS_MODE", "live")

    class _FixtureOnly(BaseCollector):
        source = "helm"
        fixture_dir = "helm"

        def _normalize(self, raw):  # pragma: no cover - never reached
            return None

    result = await _FixtureOnly().fetch(RADIUS, WINDOW)
    assert result.ok is False
    assert "NotImplementedError" in result.error


def test_the_reference_collector_satisfies_the_protocol():
    assert isinstance(_ReferenceCollector(), Collector)


def test_collector_result_reports_its_own_health():
    assert CollectorResult("helm", []).ok is True
    assert CollectorResult("helm", [], error="boom").ok is False
