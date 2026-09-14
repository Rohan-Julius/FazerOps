"""W10 — `userIdentity` normalization and resource resolution.

Handoff §5: *"`userIdentity` shape varies significantly across event sources. Handle
`IAMUser`, `AssumedRole`, and `Root` explicitly; log and pass through anything else rather
than crashing."* All four cases are asserted here, because the failure modes differ:

* A wrong actor attributes a change to a human who did not make it — the one output of this
  product that is worse than no output.
* A **crash** on an unknown shape takes down a whole collector batch (they run as nodes in
  one Strands Graph batch, plan §3.2) over a single event AWS added a type for.

The `AssumedRole` and `IAMUser` payloads here are the **recorded** ones from
`fixtures/cloudtrail/`. `Root` is constructed and labelled as such — emitting a genuine root
event means authenticating as the account root, which is exactly what AWS says never to do.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fazerops.collectors.cloudtrail import CloudTrailCollector, _actor_from
from fazerops.models import NormalizedAction, TimeWindow
from fazerops.radius import ServiceManifest

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "cloudtrail" / "billing_window.json"

# The recorded events sit on 4 September; the demo window is 6 September. See
# fixtures/cloudtrail/README.md for why they are deliberately outside it.
WIDE = TimeWindow(
    start=datetime(2026, 9, 1, tzinfo=timezone.utc),
    end=datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc),
)


@pytest.fixture(scope="module")
def recorded() -> list[dict]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def radius():
    return ServiceManifest.load().resolve("billing-api")


@pytest.fixture
def fixture_mode(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")


def identity_of(recorded: list[dict], event_name: str) -> dict:
    for event in recorded:
        detail = json.loads(event["CloudTrailEvent"])
        if detail["eventName"].startswith(event_name):
            return detail["userIdentity"]
    raise AssertionError(f"{event_name} is not in the recorded fixture")


# --------------------------------------------------------------------------------------
# The three identity types Handoff §5 names
# --------------------------------------------------------------------------------------


def test_an_assumed_role_resolves_to_the_session_name(recorded):
    """The session name is the human; the role ARN is the costume. Attributing the change
    to the role would make every engineer who assumes it look like the same person."""
    actor = _actor_from(identity_of(recorded, "PutRolePolicy"))

    assert actor.raw == "fazerops-dev"
    assert "assumed-role" not in actor.raw


def test_an_iam_user_resolves_to_its_user_name(recorded):
    actor = _actor_from(identity_of(recorded, "DeleteParameter"))

    assert actor.raw == "billing-api-deployer"


def test_root_resolves_to_root():
    """Constructed, not recorded — see the module docstring. The shape is AWS's documented
    one: root carries no `userName`, which is exactly why it needs its own branch."""
    root_identity = {
        "type": "Root",
        "principalId": "111122223333",
        "arn": "arn:aws:iam::111122223333:root",
        "accountId": "111122223333",
        "accessKeyId": "ASIAIOSFODNN7EXAMPLE",
    }
    actor = _actor_from(root_identity)

    assert actor.raw == "root"
    assert actor.kind == "root"


def test_an_unknown_identity_type_passes_through_rather_than_raising():
    """Handoff §5's explicit instruction. AWS adds identity types; a service-linked
    principal looks like none of the three. Raising here would take down the whole
    collector batch over one event."""
    actor = _actor_from(
        {"type": "AWSService", "invokedBy": "rds.amazonaws.com"}
    )

    assert actor.raw == "rds.amazonaws.com"
    assert actor.resolved is False


def test_an_empty_identity_does_not_raise():
    actor = _actor_from({})

    assert actor.raw == "unknown"
    assert actor.resolved is False


# --------------------------------------------------------------------------------------
# End to end over the recorded fixture
# --------------------------------------------------------------------------------------


async def test_every_recorded_event_normalizes(fixture_mode):
    """Nine deliberate mutations in, nine `ChangeEvent`s out. A payload that normalizes to
    `None` is a class of real AWS change the ledger would never see."""
    collector = CloudTrailCollector()
    raw = collector._load_fixtures()

    assert len(raw) == 9
    assert all(collector._normalize(item) is not None for item in raw)


async def test_the_source_ip_is_read_from_the_event_record_not_the_identity(recorded, fixture_mode):
    """CloudTrail puts `sourceIPAddress` beside `userIdentity`, not inside it. Read from the
    identity, every event carried no source address although the recording has one on each."""
    collector = CloudTrailCollector()
    for raw in recorded:
        detail = json.loads(raw["CloudTrailEvent"])
        assert "sourceIPAddress" not in detail["userIdentity"]
        assert collector._normalize(raw).actor.source_ip == detail["sourceIPAddress"]


async def test_the_recorded_events_land_in_the_blast_radius(radius, fixture_mode):
    """The silent failure `keys.py` exists to prevent: an event written under one key and
    queried under another returns nothing, and the brief reports with total confidence that
    nothing changed. Every recorded event names a resource the manifest knows."""
    result = await CloudTrailCollector().fetch(radius, WIDE)

    assert result.ok
    assert len(result.events) == 9


async def test_the_resource_kinds_match_what_the_priors_table_expects(radius, fixture_mode):
    """W14's `type_prior` looks up `(action, resource_type)`. If the collector spells a kind
    differently from `config/priors.yaml`, the row never fires and the miss is invisible."""
    result = await CloudTrailCollector().fetch(radius, WIDE)
    kinds = {event.resource.kind for event in result.events}

    assert {"SecurityGroup", "IAMRole", "DBParameterGroup", "Parameter"} <= kinds


async def test_a_role_policy_change_is_attributed_to_the_role_not_the_policy(
    radius, fixture_mode
):
    """`PutRolePolicy` names both. The role is what a service manifest can own, so it is
    the only one of the two the blast radius could ever resolve."""
    result = await CloudTrailCollector().fetch(radius, WIDE)
    put = next(e for e in result.events if e.raw_ref and "billing-api-task-role" in str(
        e.resource.name))

    assert put.resource.kind == "IAMRole"
    assert put.action is NormalizedAction.UPDATE


async def test_an_aws_managed_policy_arn_never_becomes_the_subject(radius, fixture_mode):
    """`arn:aws:iam::aws:policy/...` belongs to AWS, not this account. It identifies no
    resource any manifest could own, so an event subject-ed to it is unreachable."""
    result = await CloudTrailCollector().fetch(radius, WIDE)

    assert all(not e.resource.name.startswith("arn:aws:iam::aws:") for e in result.events)


async def test_nothing_from_cloudtrail_claims_to_be_reversible(radius, fixture_mode):
    """Ground rule #4. `lookup_events` returns the requested value and not the prior one, so
    the inverse cannot be built from the ledger — and an event that cannot compute its
    inverse must not claim to be reversible."""
    result = await CloudTrailCollector().fetch(radius, WIDE)

    assert all(not event.reversible for event in result.events)
    assert all(event.inverse_hint is None for event in result.events)


async def test_diffs_are_labelled_as_having_no_prior_value(radius, fixture_mode):
    """Plan §3.6: show the requested value, labelled honestly. The renderer prints
    "new value; prior value not captured" off this flag."""
    result = await CloudTrailCollector().fetch(radius, WIDE)
    with_diffs = [event for event in result.events if event.diff is not None]

    assert with_diffs
    assert all(event.diff.prior_value_captured is False for event in with_diffs)
    assert all(event.diff.before is None for event in with_diffs)


async def test_aws_own_redaction_is_passed_through(radius, fixture_mode):
    """CloudTrail hides the SSM value itself. Rewriting it would conceal that AWS considered
    the field sensitive — which is information the brief should carry, not suppress."""
    result = await CloudTrailCollector().fetch(radius, WIDE)
    put = next(e for e in result.events if e.resource.name == "/billing-api/pool/max"
               and e.action is NormalizedAction.UPDATE)

    assert put.diff.after["value"] == "HIDDEN_DUE_TO_SECURITY_REASONS"


async def test_the_demo_window_holds_no_cloudtrail_events(radius, fixture_mode):
    """Idea §7 specifies the brief shows **three** changes, and they are the Kubernetes
    ones. If a recorded event ever lands inside the window the rehearsed narrative is wrong
    before anyone notices."""
    demo_window = TimeWindow(
        start=datetime(2026, 9, 6, 10, 41, tzinfo=timezone.utc),
        end=datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc),
    )
    result = await CloudTrailCollector().fetch(radius, demo_window)

    assert result.ok
    assert result.events == []
