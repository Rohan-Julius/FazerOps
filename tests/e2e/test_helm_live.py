"""W11 — the Helm collector's live path, against the k3d cluster.

Fixture mode replays a recording and therefore never runs `helm` at all. Everything unique
to `_fetch_live` is untested until this file does: that `helm list -A -o json` and
`helm history` are invoked correctly, that their output parses, and — the one most likely
to rot — that Helm's **local-offset** RFC3339 timestamps survive `parse_timestamp`.

That last one is why this file exists rather than being assumed. `ledger/normalize.py` says
it plainly: a timezone bug does not raise, it reorders the causal chain, and the brief then
names the wrong change with total confidence.

Marked `cluster`, excluded from the CI default suite, and free — everything here is a
read against a local cluster.

    ./scripts/setup_k3d.sh && pytest -m cluster
"""

from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone

import pytest

from fazerops.collectors.helm import HelmCollector
from fazerops.models import NormalizedAction, TimeWindow
from fazerops.radius import ServiceManifest

pytestmark = pytest.mark.cluster


@pytest.fixture(autouse=True)
def live_mode(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    if shutil.which("helm") is None:
        pytest.skip("helm is not on PATH")


@pytest.fixture
def window() -> TimeWindow:
    """Wide enough to cover a cluster brought up at any point today."""
    now = datetime.now(timezone.utc)
    return TimeWindow(start=now - timedelta(days=30), end=now + timedelta(minutes=5))


@pytest.fixture
def radius():
    return ServiceManifest.load().resolve("billing-api")


async def test_the_live_path_reads_the_real_release(radius, window):
    """`setup_k3d.sh` installs `charts/billing-api` as a Helm release precisely so this can
    be true. If it ever goes back to `kubectl apply`, `helm history` returns nothing and
    W20b loses the revision it rolls back to."""
    result = await HelmCollector().fetch(radius, window)

    assert result.ok, result.error
    assert result.events, "no billing-api release found — run ./scripts/setup_k3d.sh"
    assert all(event.resource.name == "billing-api" for event in result.events)


async def test_helms_local_offset_timestamps_parse_to_utc(radius, window):
    """Helm reports the machine's offset, not `Z`. A naive parse here silently reorders the
    causal chain, and the symptom surfaces three modules away in the correlation scorer."""
    result = await HelmCollector().fetch(radius, window)

    for event in result.events:
        assert event.occurred_at.tzinfo is not None
        assert event.occurred_at.utcoffset() == timedelta(0)


async def test_revision_n_minus_one_is_carried_from_a_real_history(radius, window):
    """Handoff §5: revision N-1 is `helm_rollback`'s inverse for free (W20b). Proving it
    against a real `helm history` rather than a recording is the point of this test."""
    result = await HelmCollector().fetch(radius, window)
    reversible = [event for event in result.events if event.reversible]

    if not reversible:
        pytest.skip("release has a single revision — run an upgrade to exercise the inverse")

    for event in reversible:
        hint = event.inverse_hint
        assert hint["action_id"] == "helm_rollback"
        assert hint["target_revision"] == hint["current_revision"] - 1


async def test_releases_outside_the_radius_are_dropped(window):
    """`helm list -A` returns every release on the cluster — traefik included. The radius
    filter is what keeps a brief about billing-api free of kube-system."""
    unrelated = ServiceManifest.load().resolve("session-store")
    result = await HelmCollector().fetch(unrelated, window)

    assert result.ok, result.error
    assert result.events == []


async def test_an_install_is_a_create_and_an_upgrade_is_a_rollout(radius, window):
    """`helm history` has no verb field — the operation appears only in `description`, so
    this asserts the parse against strings Helm actually produced."""
    result = await HelmCollector().fetch(radius, window)
    actions = {event.action for event in result.events}

    assert actions <= {NormalizedAction.CREATE, NormalizedAction.ROLLOUT}
    assert NormalizedAction.UNKNOWN not in actions
