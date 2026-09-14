"""A listing cut off at its bound is reported, never read as the whole window.

CloudTrail and GitHub both read a bounded listing in live mode. The failure this guards is the
quiet one: the bound is hit, the result is still `ok`, and the brief renders the unread part of
the window as "nothing changed" — for GitHub, as "Nothing shipped through CI".
"""

from __future__ import annotations

import json
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from fazerops.collectors.cloudtrail import CloudTrailCollector
from fazerops.collectors.github import MAX_PAGES, PER_PAGE, GitHubCollector, ci_status_from
from fazerops.models import TimeWindow
from fazerops.pipeline import coverage_gaps_from
from fazerops.radius import ServiceManifest

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=UTC)
WINDOW = TimeWindow(start=ALERT_TIME - timedelta(hours=4), end=ALERT_TIME)

# The recorded CloudTrail events sit on 4 September — see fixtures/cloudtrail/README.md.
CLOUDTRAIL_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "cloudtrail" / "billing_window.json"
CLOUDTRAIL_WIDE = TimeWindow(start=datetime(2026, 9, 1, tzinfo=UTC), end=ALERT_TIME)


@pytest.fixture
def radius():
    return ServiceManifest.load().resolve("billing-api")


@pytest.fixture
def live_mode(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


# --------------------------------------------------------------------------------------
# CloudTrail — `MaxItems`
# --------------------------------------------------------------------------------------


def _install_boto3(monkeypatch, events: list[dict[str, Any]], *, more: bool) -> None:
    """A `boto3` whose paginator returns `events` and, like botocore's, sets `resume_token`
    when `MaxItems` stopped it with events still unread."""

    class Pages:
        resume_token = "more" if more else None

        def __iter__(self):
            yield {"Events": events}

    paginator = types.SimpleNamespace(paginate=lambda **_: Pages())
    client = types.SimpleNamespace(get_paginator=lambda _name: paginator)
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda *_a, **_k: client))


def _recorded() -> list[dict[str, Any]]:
    return json.loads(CLOUDTRAIL_FIXTURE.read_text(encoding="utf-8"))


async def test_cloudtrail_stopped_at_max_events_is_not_ok(radius, live_mode, monkeypatch):
    _install_boto3(monkeypatch, _recorded(), more=True)

    result = await CloudTrailCollector().fetch(radius, CLOUDTRAIL_WIDE)

    assert not result.ok
    assert "truncated" in result.error
    assert result.events, "what was read is still evidence"
    assert coverage_gaps_from([result]) == []


async def test_cloudtrail_read_to_its_end_is_ok(radius, live_mode, monkeypatch):
    _install_boto3(monkeypatch, _recorded(), more=False)

    result = await CloudTrailCollector().fetch(radius, CLOUDTRAIL_WIDE)

    assert result.ok, result.error
    assert result.events


# --------------------------------------------------------------------------------------
# GitHub — pages
# --------------------------------------------------------------------------------------

REPO = "faber-demo/billing-api"


def _pull(number: int, *, updated_at: str, merged_at: str | None = None) -> dict[str, Any]:
    return {
        "number": number,
        "merged_at": merged_at,
        "merge_commit_sha": f"{number:040x}",
        "updated_at": updated_at,
        "user": {"login": "priya-s"},
        "base": {"repo": {"full_name": REPO}},
    }


def _full_page(first: int, *, updated_at: str) -> list[dict[str, Any]]:
    return [_pull(number, updated_at=updated_at) for number in range(first, first + PER_PAGE)]


class _PagedGitHub(GitHubCollector):
    """The live collector with its HTTP call replaced by pages of closed pull requests."""

    def __init__(self, pull_pages) -> None:
        self.pull_pages = pull_pages
        self.pages_read: list[int] = []

    async def _get(self, path: str, **params: str) -> Any:
        if path.removeprefix("/repos/").count("/") == 1:
            return {"default_branch": "main"}
        if path == f"/repos/{REPO}/pulls":
            page = int(params["page"])
            self.pages_read.append(page)
            return self.pull_pages(page)
        return []


async def test_a_merge_past_the_first_page_is_still_counted(radius, live_mode):
    """A busy repository's comments, labels and bots push an in-window merge off page one."""
    merged = _pull(9001, updated_at="2026-09-06T12:05:44Z", merged_at="2026-09-06T12:05:44Z")
    collector = _PagedGitHub(
        lambda page: {1: _full_page(1, updated_at="2026-09-06T14:00:00Z"), 2: [merged]}.get(page, [])
    )

    result = await collector.fetch(radius, WINDOW)

    assert result.ok, result.error
    assert collector.pages_read == [1, 2]
    assert ci_status_from(result, radius).merge_count == 1


async def test_paging_stops_once_a_page_ends_before_the_window(radius, live_mode):
    """Newest update first: nothing after a pull request last touched before the window opened
    can have merged inside it."""
    page = _full_page(1, updated_at="2026-09-06T14:00:00Z")
    page[-1] = _pull(100, updated_at="2026-09-05T09:00:00Z")
    collector = _PagedGitHub(lambda number: page if number == 1 else _full_page(1000, updated_at="2026-09-06T14:00:00Z"))

    result = await collector.fetch(radius, WINDOW)

    assert result.ok, result.error
    assert collector.pages_read == [1]


async def test_a_listing_cut_off_at_the_page_bound_is_not_nothing_shipped(radius, live_mode):
    collector = _PagedGitHub(lambda page: _full_page(page * PER_PAGE, updated_at="2026-09-06T14:00:00Z"))

    result = await collector.fetch(radius, WINDOW)

    assert collector.pages_read == list(range(1, MAX_PAGES + 1))
    assert not result.ok
    assert "truncated" in result.error and REPO in result.error
