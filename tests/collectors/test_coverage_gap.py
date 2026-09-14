"""CloudTrail delivery delay — a source that answers before its events have arrived.

The failure this guards is the quiet one: `lookup_events` at alert time returns *ok, zero events*
for the minutes `temporal_proximity` scores highest, and the brief reads as "nothing changed".
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from fazerops.collectors.base import BaseCollector
from fazerops.collectors.cloudtrail import CloudTrailCollector
from fazerops.collectors.github import GitHubCollector
from fazerops.collectors.helm import HelmCollector
from fazerops.collectors.k8s_audit import K8sAuditCollector
from fazerops.models import BlastRadius, TimeWindow
from fazerops.pipeline import coverage_gaps_from, investigate
from fazerops.render.text import render_brief

END = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)
WINDOW = TimeWindow(start=END - timedelta(hours=4), end=END)
RADIUS = BlastRadius(service="billing-api", keys={"k"}, direct_keys={"k"})
ALERTS = Path(__file__).resolve().parents[2] / "fixtures" / "alerts"


class Lagging(BaseCollector):
    source = "cloudtrail"
    fixture_dir = "cloudtrail"
    delivery_lag = timedelta(minutes=15)

    def __init__(self, now: datetime, fail: bool = False) -> None:
        self.now, self.fail = now, fail

    def _now(self) -> datetime:
        return self.now

    async def _fetch_live(self, radius: BlastRadius, window: TimeWindow) -> list[dict[str, Any]]:
        if self.fail:
            raise RuntimeError("throttled")
        return []

    def _normalize(self, raw: dict[str, Any]):
        return None


@pytest.fixture
def live(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


async def test_a_query_inside_the_lag_reports_the_unseen_tail(live):
    result = await Lagging(now=END + timedelta(minutes=5)).fetch(RADIUS, WINDOW)
    assert result.ok and result.events == []
    gap = result.coverage_gap
    assert (gap.unobserved.start, gap.unobserved.end) == (END - timedelta(minutes=10), END)
    assert gap.settles_at == END + timedelta(minutes=15)


async def test_a_query_after_the_lag_has_no_gap(live):
    assert (await Lagging(now=END + timedelta(minutes=16)).fetch(RADIUS, WINDOW)).coverage_gap is None


async def test_a_window_shorter_than_the_lag_is_unobserved_from_its_start(live):
    short = TimeWindow(start=END - timedelta(minutes=5), end=END)
    gap = (await Lagging(now=END).fetch(RADIUS, short)).coverage_gap
    assert gap.unobserved.start == short.start


async def test_a_fixture_is_a_finished_recording(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    assert (await Lagging(now=END).fetch(RADIUS, WINDOW)).coverage_gap is None


async def test_a_failed_source_is_degraded_not_gapped(live):
    result = await Lagging(now=END, fail=True).fetch(RADIUS, WINDOW)
    assert not result.ok and result.coverage_gap is None
    assert coverage_gaps_from([result]) == []


def test_only_cloudtrail_declares_a_delivery_lag():
    assert CloudTrailCollector.delivery_lag == timedelta(minutes=15)
    for collector in (K8sAuditCollector, HelmCollector, GitHubCollector):
        assert collector.delivery_lag == timedelta(0)


async def test_the_brief_states_the_gap_and_is_not_degraded(live):
    """Degraded would fire on every live brief built at alert time, and a flag that is always on
    says nothing. The gap is a stated hole in the evidence instead."""
    from fazerops.ingest.alerts import normalize_alert

    alert = normalize_alert(json.loads((ALERTS / "alertmanager.json").read_text(encoding="utf-8")))
    brief = await investigate(alert, collectors=[Lagging(now=alert.fired_at + timedelta(minutes=2))])

    [gap] = brief.coverage_gaps
    assert gap.source == "cloudtrail" and brief.degraded is False
    text = render_brief(brief)
    assert "CloudTrail may not yet show changes after" in text and "up to 15 min late" in text


async def test_the_demo_brief_has_no_gap(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    from fazerops.ingest.alerts import normalize_alert

    alert = normalize_alert(json.loads((ALERTS / "alertmanager.json").read_text(encoding="utf-8")))
    assert (await investigate(alert)).coverage_gaps == []
