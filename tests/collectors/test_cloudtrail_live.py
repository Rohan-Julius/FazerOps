"""W10 — the live path, against a real AWS account.

Handoff §5 requires every collector to work in **both** modes, and fixture mode alone
cannot prove it: the fixture is a recording, so it exercises the normalizer but never the
client. Everything unique to `_fetch_live` — pagination, the `ReadOnly=false` lookup
attribute, and the fact that boto3 hands back `EventTime` as a `datetime` where the fixture
holds a string — is untested until this file runs.

**Marked `aws`, and excluded from the CI default suite** for the same reason `cluster` is:
CI has no credentials, and the zero-credential path is the one a judge runs.

**Nothing here costs money.** `lookup_events` against management events is not metered and
creates nothing. That is a deliberate constraint on this file, not a happy accident — no
test in it may ever mutate the account.

    aws sso login && pytest -m aws
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from fazerops.collectors.cloudtrail import CloudTrailCollector, _is_mutating
from fazerops.models import TimeWindow
from fazerops.radius import ServiceManifest

pytestmark = pytest.mark.aws


@pytest.fixture
def live_mode(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


@pytest.fixture
def window() -> TimeWindow:
    """Wide enough to contain W10a's recorded mutations, which stay in CloudTrail's own
    90-day history long after the resources that emitted them were destroyed."""
    now = datetime.now(timezone.utc)
    return TimeWindow(start=now - timedelta(days=2), end=now)


@pytest.fixture
def radius():
    return ServiceManifest.load().resolve("billing-api")


async def test_the_live_path_reaches_cloudtrail_and_returns_payloads(
    radius, window, live_mode
):
    """The one assertion fixture mode structurally cannot make: that the client is
    constructed correctly and the API answers."""
    collector = CloudTrailCollector()
    raw = await collector._fetch_live(radius, window)

    assert isinstance(raw, list)
    assert raw, "no write events in the last 48h — widen the window or run W10a first"
    assert all("CloudTrailEvent" in event for event in raw)


async def test_the_live_lookup_asks_aws_for_write_events_only(radius, window, live_mode):
    """`ReadOnly=false` is passed as the lookup attribute so reads are dropped by AWS rather
    than shipped over a rate-limited API and discarded here. If that attribute ever stops
    being applied, this is what notices — a busy account's window is mostly `Describe*`."""
    raw = await CloudTrailCollector()._fetch_live(radius, window)

    reads = [e["EventName"] for e in raw if str(e.get("ReadOnly", "")).lower() == "true"]
    assert not reads, f"read events came back from a write-only lookup: {reads[:5]}"


async def test_live_payloads_survive_the_same_filter_as_recorded_ones(
    radius, window, live_mode
):
    """Fixture parity, asserted against reality. The two modes share `_normalize`, so a
    live payload the filter rejects would be one the recorded fixture never covered."""
    collector = CloudTrailCollector()
    raw = await collector._fetch_live(radius, window)

    for event in raw:
        assert _is_mutating(event["EventName"], event), event["EventName"]


async def test_boto3s_datetime_event_time_normalizes_like_the_fixtures_string(
    radius, window, live_mode
):
    """boto3 deserializes `EventTime` into a `datetime`; the recorded fixture holds an ISO
    string. `_fetch_live` converts, so that `_normalize` — and therefore `ChangeEvent`'s
    timezone-aware validator — sees one shape regardless of mode."""
    raw = await CloudTrailCollector()._fetch_live(radius, window)

    assert all(isinstance(event["EventTime"], str) for event in raw)


async def test_a_full_live_fetch_produces_change_events(radius, window, live_mode):
    """End to end through the real template: fetch, normalize, filter by window and radius.
    This is the assertion that Handoff §5's "both modes working" actually means."""
    result = await CloudTrailCollector().fetch(radius, window)

    assert result.ok, result.error
    assert all(event.source == "cloudtrail" for event in result.events)
    # Ground rule #4 — lookup_events carries no prior value, so no inverse, so no claim.
    assert all(not event.reversible for event in result.events)


async def test_expired_credentials_degrade_the_brief_rather_than_killing_it(
    radius, window, monkeypatch
):
    """A dead source must set `Brief.degraded`, not raise. Collectors run as nodes in one
    Strands Graph batch (plan §3.2), where an exception is an opaque graph failure that
    takes the whole brief down — and a brief that cannot render is worse than a thin one.

    Forced with a bogus profile rather than by waiting for a token to expire.
    """
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    monkeypatch.setenv("AWS_PROFILE", "fazerops-does-not-exist")

    result = await CloudTrailCollector().fetch(radius, window)

    assert not result.ok
    assert result.events == []
    assert result.error
