"""Following a CloudTrail coverage gap without holding the brief.

The brief posts at alert time. The lagging source is then polled every 20 s until its full lag has
passed; a late change re-ranks the brief at once, and the automation server edits the posted brief
and every card drafted from it in place.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fazerops.actions.runtime import Automation, Response
from fazerops.actions.server import build_app
from fazerops.collectors.base import CollectorResult
from fazerops.correlation.scoring import score_events
from fazerops.coverage import POLL_SECONDS, SETTLE_MARGIN_SECONDS, CoverageUpdate, rescore, watch_coverage
from fazerops.models import (
    Actor,
    Alert,
    AlertClass,
    BlastRadius,
    Brief,
    ChangeEvent,
    CIStatus,
    CoverageGap,
    NormalizedAction,
    ResourceRef,
    TimeWindow,
)
from fazerops.render.text import approval_card_note, describe_coverage_gap, render_brief
from fazerops.slack.blocks import change_brief

ALERT_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json"
T0 = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)
KEY = "k8s:billing/configmap/billing-api-config"
PG = "aws:arn:pg"
RADIUS = BlastRadius(service="billing-api", keys={KEY, PG}, direct_keys={KEY, PG})
WINDOW = TimeWindow(start=T0 - timedelta(hours=4), end=T0)
ALERT = Alert(id="a1", service="billing-api", summary="p99 latency", fired_at=T0, alert_class=AlertClass.LATENCY_SPIKE)
GAP = CoverageGap(source="cloudtrail", unobserved=TimeWindow(start=T0 - timedelta(minutes=13), end=T0), delivery_lag_minutes=15)
CLOSES = T0 + timedelta(minutes=15, seconds=SETTLE_MARGIN_SECONDS)


def _event(event_id: str, source: str, minutes_before: int, key: str) -> ChangeEvent:
    arn = key.removeprefix("aws:") if key.startswith("aws:") else None
    return ChangeEvent(
        id=event_id,
        source=source,
        occurred_at=T0 - timedelta(minutes=minutes_before),
        actor=Actor(raw="someone"),
        action=NormalizedAction.UPDATE,
        resource=ResourceRef(kind="DBParameterGroup" if arn else "ConfigMap", name=event_id, namespace=None if arn else "billing", arn=arn),
        blast_radius_keys={key},
        in_band=False,
        raw_ref=f"{source}:{event_id}",
    )


EARLY = _event("cm-edit", "k8s_audit", 38, KEY)
LATE = _event("ct-late", "cloudtrail", 4, PG)  # a DB parameter change 4 min before a latency alert: outranks EARLY
OLD = _event("ct-old", "cloudtrail", 230, PG)  # arrives late, ranks below EARLY


def _brief(*, gaps=(GAP,)) -> Brief:
    return Brief(
        incident_id="INC-a1",
        alert=ALERT,
        radius=RADIUS,
        window=WINDOW,
        candidates=score_events([EARLY], ALERT, RADIUS, WINDOW),
        ci_status=CIStatus(merge_count=0),
        narrative="written before anything arrived late",
        evidence_ids=["cm-edit"],
        coverage_gaps=list(gaps),
    )


class Clock:
    """A clock the injected sleep advances — the poll loop's timing, asserted without waiting."""

    def __init__(self, start: datetime) -> None:
        self.at, self.sleeps = start, []

    def now(self) -> datetime:
        return self.at

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.at += timedelta(seconds=seconds)


class Source:
    def __init__(self, schedule, *, fail: bool = False) -> None:
        self.source, self.schedule, self.fail, self.calls = "cloudtrail", schedule, fail, 0

    async def fetch(self, radius, window):
        events = self.schedule[min(self.calls, len(self.schedule) - 1)] if self.schedule else []
        self.calls += 1
        if self.fail:
            return CollectorResult("cloudtrail", [], error="throttled")
        return CollectorResult("cloudtrail", list(events))


async def _watch(brief, source, clock):
    return [u async for u in watch_coverage(brief, collectors=[source], sleep=clock.sleep, now=clock.now)]


async def test_a_brief_with_no_open_gap_is_not_followed():
    clock = Clock(T0)
    assert await _watch(_brief(gaps=()), Source([[]]), clock) == []


async def test_a_quiet_gap_is_polled_every_twenty_seconds_and_closes_once():
    clock, source = Clock(T0 + timedelta(minutes=2)), Source([[]])
    [update] = await _watch(_brief(), source, clock)

    assert update.final and update.late_event_ids == [] and not update.rank_one_changed
    assert all(0 <= s <= POLL_SECONDS for s in clock.sleeps)
    assert source.calls >= (13 * 60) // POLL_SECONDS, "polled through the gap, not once at its end"
    assert clock.at >= CLOSES - timedelta(seconds=1)

    [gap] = update.brief.coverage_gaps
    assert (gap.status, gap.late_changes) == ("caught_up", 0)
    assert update.brief.narrative == "written before anything arrived late", "nothing changed, so the explanation stands"
    assert "caught up at" in describe_coverage_gap(gap) and "no change arrived late" in describe_coverage_gap(gap)


async def test_a_late_change_that_takes_rank_one_is_reported_at_the_next_poll():
    clock, source = Clock(T0 + timedelta(seconds=30)), Source([[], [], [], [LATE]])
    first, final = await _watch(_brief(), source, clock)

    assert not first.final and first.late_event_ids == ["ct-late"] and first.rank_one_changed
    assert clock.sleeps[:3] == [POLL_SECONDS] * 3, "found on the fourth poll, a minute in — not at fifteen"
    assert [c.event.id for c in first.brief.candidates] == ["ct-late", "cm-edit"]
    assert first.brief.ranked_first_from == "cm-edit" and first.brief.narrative is None
    assert first.brief.coverage_gaps[0].status == "open"

    assert final.final and final.late_event_ids == [] and not final.rank_one_changed
    assert final.brief.ranked_first_from == "cm-edit"
    assert (final.brief.coverage_gaps[0].status, final.brief.coverage_gaps[0].late_changes) == ("caught_up", 1)


async def test_a_late_change_that_ranks_lower_re_ranks_without_displacing_rank_one():
    clock = Clock(T0 + timedelta(minutes=1))
    first, _ = await _watch(_brief(), Source([[OLD]]), clock)
    assert not first.rank_one_changed and first.brief.ranked_first_from is None
    assert first.brief.reranked_at is not None
    assert "#1 is unchanged" in render_brief(first.brief)


async def test_a_source_that_cannot_be_reached_at_the_close_is_reported_unreachable():
    clock = Clock(T0 + timedelta(minutes=14, seconds=50))
    [final] = await _watch(_brief(), Source([[]], fail=True), clock)
    assert final.brief.coverage_gaps[0].status == "unreachable" and final.brief.degraded
    assert "could not be re-checked" in describe_coverage_gap(final.brief.coverage_gaps[0])


async def test_follow_coverage_records_late_changes_in_the_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    monkeypatch.delenv("FAZEROPS_EVIDENCE_KEY", raising=False)
    automation = Automation.assemble(state_dir=tmp_path)
    clock, seen = Clock(T0 + timedelta(minutes=1)), []

    last = await automation.follow_coverage(
        _brief(), seen.append, collectors=[Source([[LATE]])], sleep=clock.sleep, now=clock.now
    )
    assert [u.final for u in seen] == [False, True]
    assert "ct-late" in automation.ledger and last.top.event.id == "ct-late"


def test_what_an_approval_card_must_say():
    assert "may still arrive until 14:56 UTC" in approval_card_note(_brief())
    assert approval_card_note(_brief(gaps=())) is None

    candidates = rescore(_brief(), [EARLY, LATE])
    reranked = _brief().model_copy(update={"candidates": candidates, "reranked_at": T0 + timedelta(minutes=2), "ranked_first_from": "cm-edit"})
    note = approval_card_note(reranked)
    assert "#1 is now DBParameterGroup ct-late" in note and "drafted when #1 was ConfigMap cm-edit" in note


def test_a_re_ranked_brief_warns_that_its_proposal_came_from_the_earlier_ranking():
    candidates = rescore(_brief(), [EARLY, LATE])
    reranked = _brief().model_copy(update={"candidates": candidates, "reranked_at": T0 + timedelta(minutes=2), "ranked_first_from": "cm-edit"})
    blocks = json.dumps(change_brief(reranked, proposal_summary="Restore pool.max", action_id="revert_configmap_key"))
    assert "Re-ranked at 14:43 UTC" in blocks and "drafted from the ranking before late changes arrived" in blocks


@pytest.fixture
def automation(tmp_path, monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    return Automation.assemble(state_dir=tmp_path)


def test_the_server_edits_the_posted_brief_in_place(automation, monkeypatch):
    posted, edits = [], []
    candidates = rescore(_brief(), [EARLY, LATE])
    reranked = _brief().model_copy(update={"candidates": candidates, "reranked_at": T0 + timedelta(minutes=2), "ranked_first_from": "cm-edit"})

    async def respond(alert, *, collectors=None):
        return Response(brief=_brief())

    async def follow(brief, on_update, *, sleep):
        await sleep(0)
        on_update(CoverageUpdate(brief=reranked, late_event_ids=["ct-late"], rank_one_changed=True, final=False))
        return reranked

    def post(blocks, text):
        posted.append(text)
        return {"ok": True, "channel": "C1", "ts": f"{len(posted)}.0"}

    def update(channel, ts, blocks, text):
        edits.append((channel, ts, json.dumps(blocks)))

    async def instant(seconds):
        return None

    monkeypatch.setattr(automation, "respond", respond)
    monkeypatch.setattr(automation, "follow_coverage", follow)

    with TestClient(build_app(automation, post=post, update=update, sleep=instant)) as client:
        body = client.post("/alerts", json=json.loads(ALERT_FIXTURE.read_text(encoding="utf-8"))).json()
        deadline = time.monotonic() + 5
        while not edits and time.monotonic() < deadline:
            time.sleep(0.02)

    assert body["coverage_follow_up"] is True and len(posted) == 1, "one message: the brief, later edited"
    [(channel, ts, blocks)] = edits
    assert (channel, ts) == ("C1", "1.0")
    assert "Re-ranked at 14:43 UTC" in blocks and "ct-late" in blocks


def test_without_a_way_to_edit_nothing_is_followed(automation, monkeypatch):
    async def respond(alert, *, collectors=None):
        return Response(brief=_brief())

    monkeypatch.setattr(automation, "respond", respond)
    body = TestClient(build_app(automation, post=lambda blocks, text: {"channel": "C1", "ts": "1.0"})).post(
        "/alerts", json=json.loads(ALERT_FIXTURE.read_text(encoding="utf-8"))
    ).json()
    assert body["coverage_follow_up"] is False
