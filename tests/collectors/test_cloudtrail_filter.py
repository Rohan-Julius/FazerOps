"""W10 — the mutating-event filter. Handoff §5: drop `Describe`, `Get`, `List`, `AssumeRole`.

Read events outnumber writes by orders of magnitude on a real account, so this filter is
what stands between a brief and four thousand `DescribeInstances` calls. It fails in two
directions and both are bad: too loose and the brief is unreadable, too tight and the
causal change never enters the candidate set — the silent failure this product cannot
afford.

The prefix assertions are not stylistic. **Lambda versions its CloudTrail event names**
(`UpdateFunctionConfiguration20150331v2`), which W10a discovered by recording a real
account, so an exact-match filter would drop every Lambda change while passing every test
written against a hand-authored fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fazerops.collectors.cloudtrail import _is_mutating

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "cloudtrail" / "billing_window.json"

# Handoff §5's nine named event types, as CloudTrail actually spells them.
HANDOFF_EVENTS = [
    "ModifyDBInstance",
    "ModifyDBParameterGroup",
    "AuthorizeSecurityGroupIngress",
    "RevokeSecurityGroupIngress",
    "PutRolePolicy",
    "AttachRolePolicy",
    "UpdateFunctionConfiguration20150331v2",
    "PutParameter",
    "UpdateSecret",
]

READ_EVENTS = [
    "DescribeInstances",
    "DescribeDBInstances",
    "GetObject",
    "GetFunction20150331v2",
    "ListBuckets",
    "ListRoles",
    "LookupEvents",
]


@pytest.mark.parametrize("event_name", HANDOFF_EVENTS)
def test_every_event_the_handoff_names_survives(event_name):
    assert _is_mutating(event_name)


@pytest.mark.parametrize("event_name", READ_EVENTS)
def test_read_events_are_dropped(event_name):
    assert not _is_mutating(event_name)


@pytest.mark.parametrize(
    "event_name",
    ["AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"],
)
def test_assume_role_is_dropped(event_name):
    """Handoff §5 names it separately from the read prefixes because it is a *write* that
    carries no change — every role session in the window would otherwise be a candidate."""
    assert not _is_mutating(event_name)


def test_a_versioned_lambda_read_is_still_a_read():
    """`GetFunction20150331v2` starts with `Get`, so prefix matching drops it — the same
    property that keeps `UpdateFunctionConfiguration20150331v2`."""
    assert not _is_mutating("GetFunction20150331v2")
    assert _is_mutating("UpdateFunctionConfiguration20150331v2")


def test_cloudtrails_own_readonly_flag_is_honoured_when_present():
    """It is authoritative in a way a name prefix cannot be. A read whose name happens not
    to start with one of the prefixes is still a read."""
    assert not _is_mutating("SelectResourceConfig", {"ReadOnly": "true"})
    assert _is_mutating("PutParameter", {"ReadOnly": "false"})


def test_an_empty_event_name_is_not_mutating():
    """A payload with no name is not a change; treating it as one puts an unattributable
    row in a brief a human is about to act on."""
    assert not _is_mutating("")


def test_every_recorded_event_survives_the_filter():
    """The recorded fixture is nine deliberate mutations. If the filter drops one, it is
    dropping a class of real change — this is the assertion that ties the filter to
    reality rather than to a list someone typed."""
    events = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for event in events:
        name = json.loads(event["CloudTrailEvent"])["eventName"]
        assert _is_mutating(name, event), name
