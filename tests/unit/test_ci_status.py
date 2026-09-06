"""W11a — the pitch's punchline, asserted as data rather than as a string.

Idea.md §7: the scenario was chosen so the cause is invisible to GitHub, and "that single
fact is the entire pitch." The risk is not that the line is wrong on the demo fixture —
it is that the line is *hardcoded* and happens to be true for one fixture. So the same
renderer is run over a non-empty fixture and must say something different.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from faberops.collectors.github import GitHubCollector, ci_status_from, render_ci_status
from faberops.models import CIStatus, TimeWindow
from faberops.radius import ServiceManifest

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)
WINDOW = TimeWindow(start=ALERT_TIME - timedelta(hours=4), end=ALERT_TIME)

EMPTY_LINE = "Nothing shipped through CI in this window."


@pytest.fixture
def radius():
    return ServiceManifest.load().resolve("billing-api")


async def test_the_demo_window_renders_the_line_verbatim(radius, monkeypatch):
    monkeypatch.setenv("FABEROPS_MODE", "fixture")
    result = await GitHubCollector().fetch(radius, WINDOW)

    assert result.ok
    assert result.events == []
    assert render_ci_status(ci_status_from(result, radius)) == EMPTY_LINE


async def test_a_non_empty_window_renders_a_merge_count_instead(radius, monkeypatch):
    """The assertion that proves the renderer reads the data. If this said the same thing
    as the test above, the line would be a claim rather than a finding."""
    monkeypatch.setenv("FABEROPS_MODE", "fixture")

    collector = GitHubCollector()
    collector.fixture_dir = "github_nonempty"
    result = await collector.fetch(radius, WINDOW)

    status = ci_status_from(result, radius)
    assert status.merge_count == 2
    assert render_ci_status(status) == "2 merges shipped through CI in this window."
    assert EMPTY_LINE not in render_ci_status(status)


def test_singular_and_plural_both_read_correctly():
    assert render_ci_status(CIStatus(merge_count=1)) == "1 merge shipped through CI in this window."
    assert render_ci_status(CIStatus(merge_count=0)) == EMPTY_LINE


async def test_the_repos_actually_checked_are_recorded(radius, monkeypatch):
    """The claim is only as strong as its scope. A brief that says nothing shipped without
    naming where it looked is not evidence."""
    monkeypatch.setenv("FABEROPS_MODE", "fixture")
    result = await GitHubCollector().fetch(radius, WINDOW)

    status = ci_status_from(result, radius)
    assert "faber-demo/billing-api" in status.repos_checked
    assert "faber-demo/auth-service" in status.repos_checked  # the one-hop dependency


async def test_merges_outside_the_window_do_not_count(radius, monkeypatch):
    """Otherwise the strongest claim in the product is scoped to whatever the fixture
    happens to hold rather than to the incident window."""
    monkeypatch.setenv("FABEROPS_MODE", "fixture")

    collector = GitHubCollector()
    collector.fixture_dir = "github_nonempty"
    narrow = TimeWindow(start=ALERT_TIME - timedelta(minutes=30), end=ALERT_TIME)
    result = await collector.fetch(radius, narrow)

    assert render_ci_status(ci_status_from(result, radius)) == EMPTY_LINE


async def test_merges_are_reported_in_band(radius, monkeypatch):
    """A merge *is* the pipeline. Handoff §3: reported to the user, never scored."""
    monkeypatch.setenv("FABEROPS_MODE", "fixture")

    collector = GitHubCollector()
    collector.fixture_dir = "github_nonempty"
    result = await collector.fetch(radius, WINDOW)

    assert all(event.in_band for event in result.events)
    assert all(not event.reversible for event in result.events)
