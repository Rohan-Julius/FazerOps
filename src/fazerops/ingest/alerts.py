"""Normalize an inbound alert into `Alert`, from any of three payload shapes.

Idea.md §6 rules out PagerDuty as a hard dependency: ingest is a generic webhook accepting
Alertmanager, CloudWatch or PagerDuty shapes. Accepting all three costs an afternoon and
removes a vendor dependency from the pitch.

**Everything in these payloads is untrusted.** An alert summary routinely contains user
input echoed through an error string, so it is attacker-influenceable by anyone who can
make the service log something. Two consequences enforced here:

* The service name is resolved against `config/service_manifest.yaml` — a bounded set. A
  payload naming a service that does not exist yields no radius rather than a wide one.
* Nothing from the payload is interpolated into a query, a command, or a prompt outside
  W16's `<untrusted_data>` envelope.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import ValidationError

from ..models import Alert
from ..radius import default_manifest
from .classify import classify


class UnrecognisedPayload(ValueError):
    """The payload matched none of the three known shapes.

    Deliberately not a permissive fallback: guessing at an unknown shape produces an alert
    with the wrong service and a brief that confidently investigates the wrong blast
    radius, which is worse than a 400.

    Also raised for a payload that matches a shape but is malformed inside it — a missing
    `startsAt`, a `labels` that is not a map. Every caller maps this one exception to a
    client error, and a sender that gets a 5xx instead retries a payload that can never
    succeed (Alertmanager does).
    """


class NothingFiring(UnrecognisedPayload):
    """An Alertmanager notification whose alerts have all resolved.

    Nothing is wrong any more, so there is nothing to investigate. A subclass rather than a
    new exception, so every caller's existing `except UnrecognisedPayload` already refuses it;
    a caller that wants to acknowledge resolutions quietly can catch this first.
    """


def normalize_alert(payload: Any) -> Alert:
    # A JSON body can be any JSON value; only an object can be one of the three shapes.
    if not isinstance(payload, dict):
        raise UnrecognisedPayload("payload is not a JSON object")
    try:
        if "alerts" in payload and isinstance(payload.get("alerts"), list):
            return _from_alertmanager(payload)
        if "AlarmName" in payload:
            return _from_cloudwatch(payload)
        if isinstance(payload.get("event"), dict) and "data" in payload["event"]:
            return _from_pagerduty(payload)
    except ValidationError as exc:
        # Field locations only. The values are the sender's untrusted input, and the message
        # goes back out in the response body and into logs.
        fields = sorted({".".join(str(part) for part in error["loc"]) or "?" for error in exc.errors()})
        raise UnrecognisedPayload(
            f"payload is missing or has malformed fields: {', '.join(fields)}"
        ) from exc
    except (AttributeError, TypeError) as exc:
        # A field of the wrong JSON type — `labels` as a list, a timestamp as a number — fails
        # as the first `.get` or `.strip` on it. The shape was recognised; its contents were not.
        raise UnrecognisedPayload("payload has a field of the wrong type for its shape") from exc
    raise UnrecognisedPayload(
        "payload matched none of: Alertmanager (alerts[]), CloudWatch (AlarmName), "
        "PagerDuty (event.data)"
    )


def _from_alertmanager(payload: dict[str, Any]) -> Alert:
    alerts = payload.get("alerts") or []
    if not alerts:
        raise UnrecognisedPayload("Alertmanager payload carried no alerts")

    # A grouped notification carries resolved alerts beside firing ones, in no promised order,
    # so the first *firing* alert is the one investigated. Only one is: an investigation is one
    # alert, one radius, one brief, and one dedupe key, and fanning a group out into several is
    # a different contract rather than a fix. An alert with no `status` is taken as firing —
    # Alertmanager always sends one, so only a hand-built payload omits it.
    firing = [alert for alert in alerts if isinstance(alert, dict) and alert.get("status") != "resolved"]
    if not firing:
        raise NothingFiring("Alertmanager payload carried no firing alerts")

    first = firing[0]
    labels = first.get("labels") or {}
    annotations = first.get("annotations") or {}
    summary = annotations.get("summary") or labels.get("alertname") or "unknown alert"

    return Alert(
        id=first.get("fingerprint") or labels.get("alertname") or "alertmanager",
        service=_resolve_service(labels.get("service") or labels.get("job"), summary),
        summary=summary,
        # Handoff §6 classifies over the name *and* the labels. Every label value is
        # offered as a signal rather than a chosen subset: which label carries the
        # condition is a convention that differs per alerting rule, and picking one would
        # be a guess about someone else's naming scheme.
        alert_class=classify(summary, signals=[labels.get("alertname"), *labels.values()]),
        fired_at=first.get("startsAt"),
        severity=labels.get("severity"),
        payload_shape="alertmanager",
        raw_ref="alertmanager",
    )


def _from_cloudwatch(payload: dict[str, Any]) -> Alert:
    summary = payload.get("AlarmDescription") or payload.get("AlarmName") or "unknown alarm"

    dimensions = (payload.get("Trigger") or {}).get("Dimensions") or []
    named = None
    for dimension in dimensions:
        # CloudWatch is inconsistent about the casing of these keys across integrations.
        key = dimension.get("name") or dimension.get("Name")
        if key in ("ServiceName", "Service", "TargetGroup"):
            named = dimension.get("value") or dimension.get("Value")
            break

    trigger = payload.get("Trigger") or {}

    return Alert(
        id=payload.get("AlarmName", "cloudwatch"),
        service=_resolve_service(named, summary),
        summary=summary,
        # `MetricName` is CloudWatch's equivalent of an alertname — `TargetResponseTime`
        # classifies where an alarm named after a service alone would not.
        alert_class=classify(
            summary, signals=[payload.get("AlarmName"), trigger.get("MetricName")]
        ),
        # CloudWatch emits `2026-09-06T14:41:00.000+0000` — an offset with no colon, which
        # fromisoformat rejects before Python 3.11 and accepts after. Normalized here so
        # the collector boundary stays the only place timestamps are parsed.
        fired_at=_normalize_offset(payload.get("StateChangeTime", "")),
        severity=payload.get("NewStateValue"),
        payload_shape="cloudwatch",
        raw_ref="cloudwatch",
    )


def _from_pagerduty(payload: dict[str, Any]) -> Alert:
    event = payload["event"]
    data = event.get("data") or {}
    summary = data.get("title") or "unknown incident"
    service = (data.get("service") or {}).get("summary")

    return Alert(
        id=data.get("id") or event.get("id") or "pagerduty",
        service=_resolve_service(service, summary),
        summary=summary,
        # PagerDuty carries no authored alert name — the title is all there is, so this
        # shape classifies from free text alone and is the weakest of the three.
        alert_class=classify(summary),
        fired_at=event.get("occurred_at") or data.get("created_at"),
        severity=data.get("urgency"),
        payload_shape="pagerduty",
        raw_ref="pagerduty",
    )


_OFFSET_NO_COLON = re.compile(r"([+-])(\d{2})(\d{2})$")


def _normalize_offset(value: str) -> str:
    return _OFFSET_NO_COLON.sub(r"\1\2:\3", value.strip())


def _resolve_service(named: str | None, summary: str) -> str:
    """Resolve the alert to a service the manifest knows about.

    The structured field wins. Falling back to the summary is a *bounded* match: it looks
    for known service names inside untrusted text, so the worst case is failing to find
    one — never inventing one, and never widening the radius beyond the manifest.
    """
    manifest = default_manifest()

    if named and manifest.knows(named):
        return named

    # Longest name first, so `billing-api` wins over a hypothetical `billing`.
    for candidate in sorted(manifest.service_names, key=len, reverse=True):
        if re.search(rf"\b{re.escape(candidate)}\b", summary):
            return candidate

    # Unknown but preserved: W4's resolver returns an empty radius for it, and the brief
    # says it could not resolve the service rather than investigating the wrong one.
    return named or "unknown"
