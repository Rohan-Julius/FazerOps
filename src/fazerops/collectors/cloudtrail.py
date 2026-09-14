"""W10 — the CloudTrail collector. Handoff §5: *"build this first... cloud console changes
are the pilot teams' dominant source, so this collector carries the most weight."*

It carries the multi-source claim that is the defensibility argument: every incumbent
correlates the changes it was *told about*, and this is the collector that reads a control
plane directly, where a mutation is recorded whether or not anyone chose to announce it.

Everything below was written against `fixtures/cloudtrail/billing_window.json`, which is
**recorded from a real AWS account** (W10a, `scripts/capture_cloudtrail_fixture.py`) rather
than inferred from documentation. That distinction paid for itself immediately — see
`_is_mutating` on Lambda's versioned event names, which no amount of reading the API
reference would have revealed.

Three things this collector does not do, each for a stated reason:

* **`lookup_events`, not an S3 trail.** Handoff §5 chooses it deliberately: it surfaces
  management events only, which is exactly console and API mutations. The S3-delivered
  trail is the production path and is disclosed in the README rather than built.
* **No prior values.** `lookup_events` returns `requestParameters` — what was asked for —
  and essentially never the previous state. The diff is labelled
  *"new value; prior value not captured"* rather than reconstructed, per plan §3.6.
* **Nothing is marked reversible.** Ground rule #4 says an event may only claim to be
  reversible if the inverse can actually be built, and an inverse needs the prior value
  this source does not carry. `restore_db_parameter` (W20c) computes its inverse by reading
  live state at proposal time, which is the honest place to do it.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any

from ..config import require_offline_capable
from ..ledger.normalize import blast_radius_keys, normalize_action, normalize_actor
from ..models import Actor, BlastRadius, ChangeEvent, Diff, ResourceRef, TimeWindow
from .base import BaseCollector

logger = logging.getLogger(__name__)

REGION = "us-east-1"
MAX_EVENTS = 200

# AWS documents CloudTrail delivery as averaging about five minutes and explicitly not
# guaranteed. Measured on this account on 14 Sep (`ssm:DeleteParameter` probes on names that do
# not exist, polled through `lookup_events`): 124, 135, 135, 145, 146 s — median 135 s, ±10 s.
# Fifteen minutes is six times the worst of those on purpose. Five samples from one evening and
# one event source say nothing about the tail, and the asymmetry decides it: a margin that is
# too long costs a later follow-up, one that is too short lets a late change read as no change.
DELIVERY_LAG = timedelta(minutes=15)

# Handoff §5, verbatim: "drop anything starting `Describe`, `Get`, `List`, and drop
# `AssumeRole`." Read events are noise and they vastly outnumber writes — a 4-hour window
# on a busy account is thousands of `Describe*` calls and a handful of mutations.
READ_PREFIXES = ("Describe", "Get", "List", "Lookup", "Search", "Query", "BatchGet")
DROPPED_EXACT = frozenset({"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"})

# `Resources[].ResourceType` is CloudFormation-style and is the cleanest identifier the API
# gives — better than digging the name back out of `requestParameters`, whose key spelling
# differs per service (`groupId`, `dBParameterGroupName`, `roleName`, `secretId`, ...).
#
# The `kind` on the right is what `ResourceRef` carries into the blast-radius key and into
# W14's `type_prior` lookup, so these strings are load-bearing in two places at once.
RESOURCE_KINDS = {
    "AWS::EC2::SecurityGroup": "SecurityGroup",
    "AWS::IAM::Role": "IAMRole",
    "AWS::IAM::Policy": "IAMPolicy",
    "AWS::IAM::User": "IAMUser",
    "AWS::RDS::DBParameterGroup": "DBParameterGroup",
    "AWS::RDS::DBInstance": "DBInstance",
    "AWS::SSM::Parameter": "Parameter",
    "AWS::SecretsManager::Secret": "Secret",
    "AWS::Lambda::Function": "Function",
}

# When one event names several resources, this is which one the event is *about*. A
# `PutRolePolicy` names both the policy and the role; the role is what a service manifest
# knows and what the blast radius can therefore resolve, so the role wins.
KIND_PRIORITY = (
    "IAMRole",
    "DBParameterGroup",
    "DBInstance",
    "SecurityGroup",
    "Function",
    "Secret",
    "Parameter",
    "IAMUser",
    "IAMPolicy",
)

# The request field naming the resource, when `Resources` is empty. CloudTrail omits the
# block for some services — `PutParameter` is the one in this fixture — so this is a
# fallback, not the primary path.
NAME_FIELDS = (
    "name",
    "groupId",
    "dBParameterGroupName",
    "roleName",
    "secretId",
    "functionName",
    "userName",
)

# Which service a fallback-named resource belongs to, keyed on `eventSource`.
SOURCE_KINDS = {
    "ssm.amazonaws.com": "Parameter",
    "ec2.amazonaws.com": "SecurityGroup",
    "iam.amazonaws.com": "IAMRole",
    "rds.amazonaws.com": "DBParameterGroup",
    "secretsmanager.amazonaws.com": "Secret",
    "lambda.amazonaws.com": "Function",
}


class CloudTrailCollector(BaseCollector):
    source = "cloudtrail"
    fixture_dir = "cloudtrail"
    delivery_lag = DELIVERY_LAG

    async def _fetch_live(
        self, radius: BlastRadius, window: TimeWindow
    ) -> list[dict[str, Any]]:
        """`lookup_events` over the window, write events only.

        `ReadOnly=false` is passed as the lookup attribute so the read events are dropped
        by AWS rather than shipped over the wire and discarded here — the API is
        rate-limited and a busy account's window is mostly `Describe*`. `_is_mutating`
        still runs afterwards, because fixture mode has no such attribute and the two paths
        must filter identically (that is the whole point of `base.py`'s template).
        """
        require_offline_capable("CloudTrailCollector")

        def call() -> list[dict[str, Any]]:
            import boto3  # imported here so fixture mode never constructs a client

            client = boto3.client("cloudtrail", region_name=REGION)
            paginator = client.get_paginator("lookup_events")
            pages = paginator.paginate(
                LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
                StartTime=window.start,
                EndTime=window.end,
                PaginationConfig={"MaxItems": MAX_EVENTS},
            )

            events: list[dict[str, Any]] = []
            for page in pages:
                for event in page.get("Events", []):
                    # `EventTime` arrives as a datetime from boto3 and as a string from the
                    # fixture. Normalizing here keeps `_normalize` identical across modes.
                    when = event.get("EventTime")
                    if isinstance(when, datetime):
                        event["EventTime"] = when.isoformat()
                    events.append(event)
            return events

        return await asyncio.to_thread(call)

    def _normalize(self, raw: dict[str, Any]) -> ChangeEvent | None:
        detail = _detail(raw)
        if detail is None:
            return None

        event_name = detail.get("eventName") or raw.get("EventName") or ""
        if not _is_mutating(event_name, raw):
            return None

        occurred_at = detail.get("eventTime") or raw.get("EventTime")
        event_id = detail.get("eventID") or raw.get("EventId")
        if not occurred_at or not event_id:
            return None

        resource = _resource_from(raw, detail)
        if resource is None:
            return None

        actor = _actor_from(detail.get("userIdentity") or {})

        return ChangeEvent(
            id=f"ct-{event_id}",
            source="cloudtrail",
            occurred_at=occurred_at,
            actor=actor,
            action=normalize_action(event_name, "cloudtrail"),
            resource=resource,
            blast_radius_keys=blast_radius_keys(resource),
            in_band=_is_in_band(actor),
            # Ground rule #4 — see the module docstring. No prior value, so no inverse, so
            # no claim of reversibility.
            reversible=False,
            diff=_diff_from(detail),
            raw_ref=f"cloudtrail:{event_id}",
        )


# --------------------------------------------------------------------------------------
# Filtering
# --------------------------------------------------------------------------------------


def _is_mutating(event_name: str, raw: dict[str, Any] | None = None) -> bool:
    """Handoff §5's filter: drop reads, drop `AssumeRole`.

    **Prefix matching, not exact matching, and that is not a shortcut.** Lambda versions its
    CloudTrail event names — `UpdateFunctionConfiguration` is recorded as
    `UpdateFunctionConfiguration20150331v2` and reads appear as `GetFunction20150331v2`.
    Nothing in the API documentation says so; W10a discovered it by recording a real
    account. An exact-match filter would pass every test written against a hand-authored
    fixture and then silently drop every Lambda change in production.

    `ReadOnly` is consulted when CloudTrail supplies it — it is authoritative in a way a
    name prefix can never be — but the prefix rules run regardless, because the fixture and
    live paths must reach the same verdict and the field is not guaranteed to be present.
    """
    if not event_name:
        return False

    if raw is not None and str(raw.get("ReadOnly", "")).lower() == "true":
        return False

    if any(event_name.startswith(prefix) for prefix in DROPPED_EXACT):
        return False

    return not event_name.startswith(READ_PREFIXES)


# --------------------------------------------------------------------------------------
# Shapes
# --------------------------------------------------------------------------------------


def _detail(raw: dict[str, Any]) -> dict[str, Any] | None:
    """`lookup_events` nests the real event as a JSON *string* under `CloudTrailEvent`.

    Kept as a string in the fixture rather than unpacked, because that is what the API
    returns and a fixture that pre-parses it would be testing a shape AWS never emits.
    """
    payload = raw.get("CloudTrailEvent")
    if isinstance(payload, dict):
        return payload
    if not isinstance(payload, str):
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        logger.warning("cloudtrail: unparseable CloudTrailEvent on %s", raw.get("EventId"))
        return None


def _actor_from(identity: dict[str, Any]) -> Actor:
    """Handoff §5: handle `IAMUser`, `AssumedRole` and `Root` explicitly; **log and pass
    through anything else rather than crashing.**

    An unknown shape is a real possibility — AWS adds identity types, and service-linked
    principals do not look like any of the three. Raising would take down a whole collector
    batch over one event; guessing would attribute a change to the wrong human, which is
    worse than saying "unknown".
    """
    identity_type = identity.get("type")

    if identity_type == "IAMUser":
        raw_principal = identity.get("userName") or identity.get("arn") or "unknown"
    elif identity_type == "AssumedRole":
        # The session name is the human; the role arn is the costume. `sessionContext`
        # carries the role, and the principal id's suffix carries who assumed it.
        principal_id = identity.get("principalId") or ""
        session_name = principal_id.split(":", 1)[1] if ":" in principal_id else ""
        raw_principal = session_name or identity.get("arn") or "unknown"
    elif identity_type == "Root":
        raw_principal = "root"
    else:
        if identity_type:
            logger.info("cloudtrail: unhandled userIdentity type %r, passing through",
                        identity_type)
        raw_principal = (
            identity.get("userName")
            or identity.get("invokedBy")
            or identity.get("arn")
            or "unknown"
        )

    actor = normalize_actor(raw_principal, "cloudtrail")

    source_ip = identity.get("sourceIPAddress")
    if source_ip and not actor.source_ip:
        actor = actor.model_copy(update={"source_ip": source_ip})
    return actor


def _resource_from(raw: dict[str, Any], detail: dict[str, Any]) -> ResourceRef | None:
    """The one resource this event is about.

    `Resources` is preferred because it is typed and service-independent. It is sometimes
    absent — `PutParameter` in the recorded fixture carries none — so `requestParameters`
    is the fallback, keyed on `eventSource` to know what kind of thing was named.
    """
    region = detail.get("awsRegion")
    account = detail.get("recipientAccountId") or (detail.get("userIdentity") or {}).get(
        "accountId"
    )

    candidates: list[tuple[int, ResourceRef]] = []
    for entry in raw.get("Resources") or []:
        kind = RESOURCE_KINDS.get(entry.get("ResourceType", ""))
        name = entry.get("ResourceName")
        if not kind or not name:
            continue
        # A managed-policy ARN is AWS's, not this account's — it identifies no resource a
        # service manifest could own, so it must never become the event's subject.
        if name.startswith("arn:aws:iam::aws:"):
            continue
        rank = KIND_PRIORITY.index(kind) if kind in KIND_PRIORITY else len(KIND_PRIORITY)
        candidates.append((rank, ResourceRef(kind=kind, name=name, region=region,
                                             account=account)))

    if candidates:
        return min(candidates, key=lambda pair: pair[0])[1]

    request = detail.get("requestParameters") or {}
    kind = SOURCE_KINDS.get(detail.get("eventSource", ""))
    if not kind:
        return None

    for field in NAME_FIELDS:
        name = request.get(field)
        if isinstance(name, str) and name:
            return ResourceRef(kind=kind, name=name, region=region, account=account)

    return None


def _diff_from(detail: dict[str, Any]) -> Diff | None:
    """`requestParameters` as the "after", explicitly labelled as having no "before".

    Plan §3.6: show the requested value and label it honestly rather than reconstructing a
    prior value the API never returned. CloudTrail redacts some fields itself — the
    recorded `PutParameter` carries `HIDDEN_DUE_TO_SECURITY_REASONS` as its value — and
    that redaction is passed through as-is, because rewriting it would hide the fact that
    AWS considered the field sensitive.
    """
    request = detail.get("requestParameters")
    if not isinstance(request, dict) or not request:
        return None
    return Diff(before=None, after=request, prior_value_captured=False)


def _is_in_band(actor: Actor) -> bool:
    """Reported, never scored (Handoff §3). Resolved through the same identity map the
    other collectors use, so one principal is in-band everywhere or nowhere."""
    from ..ledger.normalize import default_identity_map

    return default_identity_map().is_in_band(actor)
