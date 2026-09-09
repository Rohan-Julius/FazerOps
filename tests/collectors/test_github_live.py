"""W11 — the GitHub collector's live path, against the real API.

`tests/collectors/test_thin_collectors.py` covers the *logic* thoroughly, but it stubs
`_get`, so the HTTP client underneath has never run: the request headers, the API version
pin, the token lookup, the JSON decode and the `asyncio.to_thread` wrapper are all untested
by it. That is the gap this file closes.

**It cannot point at the demo manifest.** `config/service_manifest.yaml` names
`faber-demo/billing-api`, which is a fiction chosen for the scenario — the repository does
not exist and a live call against it returns 404. So the repo under test comes from the
environment, and the test skips when it is unset rather than hardcoding somebody else's
repository into this suite.

    FAZEROPS_GITHUB_TEST_REPO=owner/name pytest -m github

Free, and read-only. Unauthenticated requests to public repositories are rate-limited to 60
per hour, which is ample; `GITHUB_TOKEN` is used when present and raises that limit.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from fazerops.collectors.github import GitHubCollector, ci_status_from, render_ci_status
from fazerops.models import BlastRadius, TimeWindow

pytestmark = pytest.mark.github

TEST_REPO = os.environ.get("FAZEROPS_GITHUB_TEST_REPO")


@pytest.fixture(autouse=True)
def live_mode(monkeypatch):
    if not TEST_REPO:
        pytest.skip("set FAZEROPS_GITHUB_TEST_REPO=owner/name to exercise the live path")
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


@pytest.fixture
def radius() -> BlastRadius:
    """Built directly rather than resolved from the manifest — see the module docstring."""
    key = f"repo:{TEST_REPO}"
    return BlastRadius(service="under-test", keys={key}, direct_keys={key})


@pytest.fixture
def window() -> TimeWindow:
    now = datetime.now(timezone.utc)
    return TimeWindow(start=now - timedelta(days=90), end=now)


async def test_the_live_client_reaches_the_api(radius, window):
    """The assertion the stubbed tests structurally cannot make: that a real request is
    formed, authorised and parsed."""
    collector = GitHubCollector()
    repository = await collector._get(f"/repos/{TEST_REPO}")

    assert repository["full_name"].lower() == TEST_REPO.lower()
    assert repository["default_branch"]


async def test_a_live_fetch_produces_change_events_or_an_empty_window(radius, window):
    """Either outcome is correct — what must not happen is an exception, or a failure
    reported as an empty window. A dead source degrades the brief; it does not quietly
    become the strongest claim the product makes."""
    result = await GitHubCollector().fetch(radius, window)

    assert result.ok, result.error
    assert all(event.source == "github" for event in result.events)


async def test_merges_and_pushes_are_told_apart_on_real_data(radius, window):
    """`ci_status_from` counts merges only. A direct push to the default branch is a
    candidate change that did *not* ship through a pull request, and counting it as one
    would weaken the product's central claim on the exact case it exists to catch."""
    result = await GitHubCollector().fetch(radius, window)
    status = ci_status_from(result, radius)

    assert status.merge_count <= len(result.events)
    assert render_ci_status(status)


async def test_the_ci_status_line_names_where_it_looked(radius, window):
    """The claim is only as strong as its scope."""
    result = await GitHubCollector().fetch(radius, window)

    assert TEST_REPO in ci_status_from(result, radius).repos_checked


async def test_a_missing_repository_degrades_rather_than_raising(window):
    """A 404 on a private or renamed repo must not render as "nothing shipped through CI"
    — that would turn an auth error into the product's strongest claim."""
    key = "repo:faber-demo/definitely-not-a-real-repository"
    missing = BlastRadius(service="x", keys={key}, direct_keys={key})

    result = await GitHubCollector().fetch(missing, window)

    assert not result.ok
    assert result.events == []
