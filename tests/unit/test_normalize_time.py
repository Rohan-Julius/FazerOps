"""W3 — timestamp normalization. Tier A.

The three sources report one instant three ways. If they do not collapse to the same UTC
moment the causal chain reorders, `temporal_proximity` scores garbage, and the brief names
the wrong change confidently. Nothing raises; you debug the scorer for three hours.
"""

from datetime import datetime, timedelta, timezone

import pytest

from fazerops.ledger.normalize import NaiveTimestampError, parse_timestamp

# One instant: 2026-09-06 14:03:11 UTC.
EXPECTED = datetime(2026, 9, 6, 14, 3, 11, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("source", "raw"),
    [
        ("cloudtrail", "2026-09-06T14:03:11Z"),
        ("k8s_audit", "2026-09-06T14:03:11.000000Z"),
        ("k8s_audit", "2026-09-06T14:03:11.123Z"),  # variable sub-second precision
        ("k8s_audit", "2026-09-06T14:03:11.1Z"),
        ("k8s_audit", "2026-09-06T14:03:11.123456789Z"),  # nanoseconds, truncated
        ("helm", "Sun Sep  6 07:03:11 2026 -0700"),  # local-formatted, double-spaced day
        ("helm", "Sun Sep 6 07:03:11 2026 -0700"),
        ("cloudtrail", "2026-09-06T16:03:11+02:00"),
    ],
)
def test_every_source_format_collapses_to_the_same_utc_instant(source, raw):
    parsed = parse_timestamp(raw)
    assert abs(parsed - EXPECTED) <= timedelta(seconds=1), (
        f"{source} format {raw!r} parsed to {parsed}, expected {EXPECTED}"
    )
    assert parsed.tzinfo is timezone.utc


def test_offset_is_honoured_not_discarded():
    """The regression that matters: reading 07:03:11-0700 as 07:03:11Z shifts the event
    seven hours and moves it out of the correlation window entirely."""
    assert parse_timestamp("Sun Sep  6 07:03:11 2026 -0700").hour == 14


@pytest.mark.parametrize(
    "raw",
    [
        "2026-09-06T14:03:11",  # ISO8601 with no offset
        "2026-09-06 14:03:11",
        "Sun Sep  6 07:03:11 2026",  # Helm table output without the offset column
    ],
)
def test_naive_timestamps_raise_rather_than_defaulting_to_utc(raw):
    """Assuming UTC buries a real collector bug under a plausible-looking timestamp."""
    with pytest.raises(NaiveTimestampError):
        parse_timestamp(raw)


def test_naive_datetime_object_raises_too():
    with pytest.raises(NaiveTimestampError):
        parse_timestamp(datetime(2026, 9, 6, 14, 3, 11))


def test_aware_datetime_object_is_converted_not_rejected():
    minus_seven = timezone(timedelta(hours=-7))
    assert parse_timestamp(datetime(2026, 9, 6, 7, 3, 11, tzinfo=minus_seven)) == EXPECTED


def test_unrecognised_format_raises_rather_than_returning_now():
    """A parser that falls back to the current time would place a stale event inside every
    window and rank it top on temporal proximity."""
    with pytest.raises(ValueError):
        parse_timestamp("last Tuesday afternoon")


def test_ordering_is_preserved_across_sources():
    """The whole point: a 38-minutes-prior K8s edit must sort before an alert reported by
    CloudTrail-style timestamps, regardless of the offsets they arrived in."""
    configmap_edit = parse_timestamp("Sun Sep  6 07:03:11 2026 -0700")  # 14:03:11Z
    unrelated_iam = parse_timestamp("2026-09-06T13:15:00Z")
    alert_fired = parse_timestamp("2026-09-06T14:41:00Z")

    assert [unrelated_iam, configmap_edit, alert_fired] == sorted(
        [configmap_edit, alert_fired, unrelated_iam]
    )
