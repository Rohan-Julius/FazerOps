"""W11 — the two thin collectors: Helm history, and GitHub's live path.

Thin is not the same as untested. Each of these carries one claim the rest of the build
depends on:

* **Helm supplies revision N-1.** Handoff §5 notes that revision is `helm_rollback`'s
  inverse for free (W20b). If the collector does not carry it, ground rule #4 has to
  reconstruct the inverse from somewhere else, on camera.
* **GitHub collects direct pushes, not only merged PRs.** An out-of-band `git push` to the
  default branch is exactly the kind of change this product exists to catch, and it is
  invisible to a collector that only reads pull requests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

import urllib.error

from fazerops.collectors.github import GitHubCollector, ci_status_from, render_ci_status
from fazerops.collectors.helm import HelmCollector
from fazerops.models import NormalizedAction, TimeWindow
from fazerops.radius import ServiceManifest

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)
WINDOW = TimeWindow(start=ALERT_TIME - timedelta(hours=4), end=ALERT_TIME)

# The captured release history sits before the incident window opens — see
# fixtures/helm/README.md. Widening the window is how these tests reach it.
WIDE = TimeWindow(start=datetime(2026, 8, 25, tzinfo=timezone.utc), end=ALERT_TIME)


@pytest.fixture
def radius():
    return ServiceManifest.load().resolve("billing-api")


@pytest.fixture
def fixture_mode(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")


@pytest.fixture
def live_mode(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


# --------------------------------------------------------------------------------------
# Helm
# --------------------------------------------------------------------------------------


async def test_the_release_history_lands_in_the_blast_radius(radius, fixture_mode):
    """The silent failure this guards: a release keyed one way by the manifest and another
    by the collector returns nothing, and the brief says Helm shipped nothing."""
    result = await HelmCollector().fetch(radius, WIDE)

    assert result.ok
    assert [event.resource.name for event in result.events] == ["billing-api"] * 3


async def test_every_revision_but_the_first_carries_revision_n_minus_one(radius, fixture_mode):
    """Handoff §5: revision N-1 is the inverse for free. W20b's `helm_rollback` reads
    exactly this, and ground rule #4 refuses to execute an action without it."""
    result = await HelmCollector().fetch(radius, WIDE)
    by_revision = {event.inverse_hint["current_revision"]: event for event in result.events
                   if event.inverse_hint}

    assert by_revision[3].inverse_hint["target_revision"] == 2
    assert by_revision[2].inverse_hint["target_revision"] == 1
    assert by_revision[3].inverse_hint["action_id"] == "helm_rollback"


async def test_the_first_revision_is_not_reversible(radius, fixture_mode):
    """There is nothing to roll back to. Ground rule #4: an event that cannot compute its
    inverse must not claim to be reversible — the model validator on `ChangeEvent` would
    reject it, so this is asserting the collector is honest rather than lucky."""
    result = await HelmCollector().fetch(radius, WIDE)
    install = next(event for event in result.events if event.raw_ref.endswith("@1"))

    assert install.reversible is False
    assert install.inverse_hint is None
    assert install.action is NormalizedAction.CREATE


async def test_an_upgrade_normalizes_to_rollout(radius, fixture_mode):
    """`helm history` has no verb field — the operation only appears in `description`. A
    wrong verb here feeds a wrong type_prior and fails as what looks like a scoring bug."""
    result = await HelmCollector().fetch(radius, WIDE)
    upgrades = [event for event in result.events if event.raw_ref.endswith(("@2", "@3"))]

    assert upgrades
    assert all(event.action is NormalizedAction.ROLLOUT for event in upgrades)


async def test_the_release_history_is_outside_the_incident_window(radius, fixture_mode):
    """The demo's story, asserted rather than assumed: billing-api ships through Helm, and
    nothing shipped through Helm during the incident window either. If a revision ever
    lands inside it, the brief grows a fourth candidate and the rehearsed narrative is
    wrong before anyone notices."""
    result = await HelmCollector().fetch(radius, WINDOW)

    assert result.ok
    assert result.events == []


async def test_a_release_outside_the_radius_is_dropped(fixture_mode):
    """`helm list -A` returns every release on the cluster, traefik included. The radius
    filter is what keeps a judge's brief about billing-api free of kube-system."""
    unrelated = ServiceManifest.load().resolve("session-store")
    result = await HelmCollector().fetch(unrelated, WIDE)

    assert result.ok
    assert result.events == []


async def test_helm_carries_no_principal_and_says_so(radius, fixture_mode):
    """Helm's history has no field naming who ran the upgrade. An unresolved actor is
    honest; inventing one would attribute a change to a human who did not make it."""
    result = await HelmCollector().fetch(radius, WIDE)

    assert all(not event.actor.resolved for event in result.events)


# --------------------------------------------------------------------------------------
# GitHub — the live path
# --------------------------------------------------------------------------------------


class _FakeGitHub(GitHubCollector):
    """The live collector with only its one HTTP call replaced.

    Everything under test — which endpoints are called, how merges and pushes are told
    apart, normalization, window and radius filtering — is the real code. Stubbing
    `fetch` instead would test nothing.
    """

    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.paths: list[str] = []

    async def _get(self, path: str, **params: str) -> Any:
        self.paths.append(path)
        return self.responses.get(path, [])


MERGED_PR = {
    "number": 412,
    "merged_at": "2026-09-06T12:05:44Z",
    "merge_commit_sha": "9f3c1ad4e77b2c05a1e6f8d3b2409c7715ee0a13",
    "user": {"login": "priya-s"},
    "base": {"repo": {"full_name": "faber-demo/billing-api"}},
}

DIRECT_PUSH = {
    "sha": "ba1d90f74c9e2c1d5f8a0b3e7d24c6a91f0e5b82",
    "commit": {
        "author": {"name": "Dinesh Raman", "date": "2026-09-06T12:40:09Z"},
        "committer": {"name": "Dinesh Raman", "date": "2026-09-06T12:40:09Z"},
        "message": "hotfix: drop the retry ceiling",
    },
    "author": {"login": "dinesh-r"},
}


def _responses(pulls: list[dict], commits: list[dict]) -> dict[str, Any]:
    repos = ["faber-demo/billing-api", "faber-demo/auth-service"]
    responses: dict[str, Any] = {}
    for repo in repos:
        responses[f"/repos/{repo}"] = {"default_branch": "main"}
        responses[f"/repos/{repo}/pulls"] = pulls if repo == repos[0] else []
        responses[f"/repos/{repo}/commits"] = commits if repo == repos[0] else []
    return responses


async def test_the_live_path_returns_nothing_for_the_demo_window(radius, live_mode):
    """The pitch's punchline, from the live path rather than from a fixture. Idea.md §7
    chose the scenario so the cause is invisible to GitHub; an empty API response has to
    render the same line the empty fixture does."""
    collector = _FakeGitHub(_responses([], []))
    result = await collector.fetch(radius, WINDOW)

    assert result.ok
    assert result.events == []
    assert render_ci_status(ci_status_from(result, radius)) == (
        "Nothing shipped through CI in this window."
    )


async def test_the_live_path_counts_a_merge_in_a_populated_window(radius, live_mode):
    collector = _FakeGitHub(_responses([MERGED_PR], []))
    result = await collector.fetch(radius, WINDOW)

    status = ci_status_from(result, radius)
    assert status.merge_count == 1
    assert render_ci_status(status) == "1 merge shipped through CI in this window."


async def test_a_direct_push_to_the_default_branch_is_collected(radius, live_mode):
    """Handoff §5. A `git push` straight to main is the GitHub-shaped version of the
    product's whole thesis, and a collector that only reads pull requests never sees it."""
    collector = _FakeGitHub(_responses([], [DIRECT_PUSH]))
    result = await collector.fetch(radius, WINDOW)

    assert len(result.events) == 1
    pushed = result.events[0]
    assert pushed.actor.raw == "dinesh-r"
    assert pushed.in_band is False


async def test_a_direct_push_is_not_counted_as_shipped_through_ci(radius, live_mode):
    """The strongest claim the product makes must not be weakened by the exact case it
    exists to catch. The push is a candidate change; it did not ship through a PR."""
    collector = _FakeGitHub(_responses([], [DIRECT_PUSH]))
    result = await collector.fetch(radius, WINDOW)

    status = ci_status_from(result, radius)
    assert status.merge_count == 0
    assert render_ci_status(status) == "Nothing shipped through CI in this window."


async def test_a_pull_requests_own_merge_commit_is_not_also_a_push(radius, live_mode):
    """Otherwise every merge is counted twice: once as a PR, once as the commit it left on
    the default branch."""
    merge_commit = {
        "sha": MERGED_PR["merge_commit_sha"],
        "commit": {
            "author": {"name": "Priya S", "date": "2026-09-06T12:05:44Z"},
            "committer": {"name": "GitHub", "date": "2026-09-06T12:05:44Z"},
            "message": "Merge pull request #412",
        },
        "author": {"login": "priya-s"},
    }
    collector = _FakeGitHub(_responses([MERGED_PR], [merge_commit]))
    result = await collector.fetch(radius, WINDOW)

    assert len(result.events) == 1
    assert ci_status_from(result, radius).merge_count == 1


async def test_a_commit_behind_a_merged_pull_request_is_not_a_direct_push(radius, live_mode):
    """A merge commit's parents appear in the default branch's commit listing too. Asking
    GitHub which pull requests a commit belongs to is what tells them apart."""
    child = {
        "sha": "5c0a71e2fb3d48a9c6127e0b4d8f39a05e6c1d47",
        "commit": {
            "author": {"name": "Priya S", "date": "2026-09-06T11:58:00Z"},
            "committer": {"name": "Priya S", "date": "2026-09-06T11:58:00Z"},
            "message": "raise the ceiling",
        },
        "author": {"login": "priya-s"},
    }
    responses = _responses([MERGED_PR], [child])
    responses[f"/repos/faber-demo/billing-api/commits/{child['sha']}/pulls"] = [MERGED_PR]

    collector = _FakeGitHub(responses)
    result = await collector.fetch(radius, WINDOW)

    assert [event.raw_ref for event in result.events] == ["github:faber-demo/billing-api#412"]


async def test_the_live_path_looks_at_every_repo_in_the_radius(radius, live_mode):
    """Including the one-hop dependency. A CI-status line that only checked the alerting
    service's own repo would be a narrower claim than the brief prints."""
    collector = _FakeGitHub(_responses([], []))
    await collector.fetch(radius, WINDOW)

    assert "/repos/faber-demo/billing-api/pulls" in collector.paths
    assert "/repos/faber-demo/auth-service/pulls" in collector.paths


async def test_an_empty_repository_is_not_a_failure(radius, live_mode):
    """GitHub answers **409** on the commits endpoint when a repository has no commits yet.

    Found by `tests/collectors/test_github_live.py` against a real empty repo; kept here
    because the `github` marker never runs in CI and this is the assertion that must not
    regress. Letting the 409 escape would set `Brief.degraded` and render "we could not
    look" as "nothing shipped through CI" — an inversion of the strongest claim the product
    makes.
    """

    class _EmptyRepo(_FakeGitHub):
        async def _get(self, path: str, **params: str):
            if path.endswith("/commits"):
                raise urllib.error.HTTPError(path, 409, "Conflict", {}, None)
            return await super()._get(path, **params)

    collector = _EmptyRepo(_responses([MERGED_PR], []))
    result = await collector.fetch(radius, WINDOW)

    assert result.ok, result.error
    assert ci_status_from(result, radius).merge_count == 1


async def test_a_real_http_error_still_degrades_the_brief(radius, live_mode):
    """Only 409 means "empty". A 403 or 500 is a source that failed, and the brief has to
    say so rather than reporting a confident absence of change."""

    class _Forbidden(_FakeGitHub):
        async def _get(self, path: str, **params: str):
            if path.endswith("/commits"):
                raise urllib.error.HTTPError(path, 403, "Forbidden", {}, None)
            return await super()._get(path, **params)

    result = await _Forbidden(_responses([], [])).fetch(radius, WINDOW)

    assert not result.ok
    assert result.events == []


async def test_the_fixture_push_payload_normalizes_the_same_way(radius, fixture_mode):
    """Fixture parity for the push shape specifically (W5). The live path and the fixture
    path share `_normalize`, and this is what proves the recorded shape reaches it."""
    collector = GitHubCollector()
    collector.fixture_dir = "github_push"
    result = await collector.fetch(radius, WINDOW)

    assert len(result.events) == 1
    assert result.events[0].in_band is False
    assert ci_status_from(result, radius).merge_count == 0
