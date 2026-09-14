"""Builders shared by Phase G's tests (W40 onward).

Hand-built `ChangeEvent`s, because every gap needs a shape the recorded demo window does not
contain — a second incident, a later remediation, a second actor, a captured prior value. The
demo window holds the *shape* of the multi-key gap (Priya's two-key patch) but not an instance of
it: that entry is the first in the log for its ConfigMap, so no prior value was captured.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fazerops.models import (
    Actor,
    Alert,
    AlertClass,
    BlastRadius,
    Brief,
    Candidate,
    ChangeEvent,
    CIStatus,
    Diff,
    NormalizedAction,
    ResourceRef,
    TimeWindow,
    incident_id_for,
)

T0 = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)
SERVICE_KEY = "service:billing-api"

# The shape of Priya's recorded two-key patch. The recording itself captured no prior value (it
# is the first entry for its ConfigMap), so these builders supply one to make an instance of it.
MULTI_BEFORE = {"issuer": "https://auth.faber-demo.io", "session.ttl": "3600"}
MULTI_AFTER = {"issuer": "https://auth-v2.faber-demo.io", "session.ttl": "900"}


def person(name: str, kind: str = "human") -> Actor:
    return Actor(raw=name, canonical=name, resolved=True, kind=kind)


def configmap_change(
    event_id: str,
    *,
    at: datetime,
    actor: str = "dinesh",
    actor_kind: str = "human",
    kind: str = "ConfigMap",
    name: str = "billing-api-config",
    namespace: str = "billing",
    before: dict | None = None,
    after: dict | None = None,
) -> ChangeEvent:
    """A k8s audit change, carrying the hint the audit collector would: a single-key hint (and
    `reversible`) for a one-key update with a captured prior value, a `keys` hint with
    `reversible` False for a multi-key one."""
    resource = ResourceRef(kind=kind, name=name, namespace=namespace)
    diff = None
    if before is not None or after is not None:
        diff = Diff(before=before, after=after, prior_value_captured=before is not None)

    hint = None
    if kind == "ConfigMap" and diff is not None and before and len(diff.fields_changed) == 1:
        key = diff.fields_changed[0]
        hint = {
            "action_id": "revert_configmap_key",
            "namespace": namespace,
            "name": name,
            "key": key,
            "prior_value": before.get(key),
            "current_value": (after or {}).get(key),
        }
    elif kind == "ConfigMap" and diff is not None and before and diff.fields_changed:
        changed = diff.fields_changed
        hint = {
            "action_id": "revert_configmap_key",
            "namespace": namespace,
            "name": name,
            "keys": changed,
            "prior_values": {k: before.get(k) for k in changed},
            "current_values": {k: (after or {}).get(k) for k in changed},
        }

    return ChangeEvent(
        id=event_id,
        source="k8s_audit",
        occurred_at=at,
        actor=person(actor, actor_kind),
        action=NormalizedAction.UPDATE,
        resource=resource,
        diff=diff,
        blast_radius_keys={resource.blast_radius_key(), SERVICE_KEY},
        in_band=False,
        reversible=hint is not None and "key" in hint,
        inverse_hint=hint,
        raw_ref=f"test#{event_id}",
    )


def multi_key_change(event_id: str, *, at: datetime, actor: str = "priya", **kwargs) -> ChangeEvent:
    return configmap_change(
        event_id, at=at, actor=actor, before=MULTI_BEFORE, after=MULTI_AFTER, **kwargs
    )


BINARY_BEFORE = {"favicon.ico": "AAABAAEAEBAQAAEABAAoAQAAFgAAACgA"}
BINARY_AFTER = {"favicon.ico": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQ"}


def binary_data_change(
    event_id: str,
    *,
    at: datetime,
    actor: str = "priya",
    name: str = "billing-api-assets",
    namespace: str = "billing",
    before: dict | None = BINARY_BEFORE,
    after: dict | None = BINARY_AFTER,
) -> ChangeEvent:
    """A ConfigMap `binaryData` edit, as the audit collector records one: a real before and after,
    and no hint — no shipped action restores a binary map. `test_binary_data_capture.py` holds the
    same shape as the API server produced it."""
    resource = ResourceRef(kind="ConfigMap", name=name, namespace=namespace)
    return ChangeEvent(
        id=event_id,
        source="k8s_audit",
        occurred_at=at,
        actor=person(actor),
        action=NormalizedAction.UPDATE,
        resource=resource,
        diff=Diff(before=before, after=after, prior_value_captured=before is not None, field_path="binaryData"),
        blast_radius_keys={resource.blast_radius_key(), SERVICE_KEY},
        in_band=False,
        raw_ref=f"test#{event_id}",
    )


def cloudtrail_change(event_id: str, *, at: datetime, actor: str = "dinesh") -> ChangeEvent:
    """A CloudTrail change: a requested value and, as `lookup_events` guarantees, no prior."""
    resource = ResourceRef(kind="DBParameterGroup", name="billing-primary-params")
    return ChangeEvent(
        id=event_id,
        source="cloudtrail",
        occurred_at=at,
        actor=person(actor),
        action=NormalizedAction.UPDATE,
        resource=resource,
        diff=Diff(before=None, after={"parameters": "max_connections"}, prior_value_captured=False),
        blast_radius_keys={resource.blast_radius_key(), SERVICE_KEY},
        in_band=False,
        raw_ref=f"test#{event_id}",
    )


HISTORY = TimeWindow(start=T0 - timedelta(days=1), end=T0 + timedelta(days=2))


def gap_with_corpus(
    *,
    store_path=None,
    cause_before: dict = MULTI_BEFORE,
    cause_after: dict = MULTI_AFTER,
    fixes: dict[int, dict] | None = None,
    remediate: bool = True,
):
    """The smallest history the miner makes eligible: two incidents, two actors, each change
    followed by a human putting it back by hand. `fixes[n]` overrides what incident `n`'s human
    set the data to — a partial or a wrong fix, for the replay gate to disagree with.

    Returns `(ledger, store, gap)`, with the gap mined through the real `mine_history`.
    """
    from fazerops.actions.growth.miner import MinerThresholds, mine_history
    from fazerops.actions.growth.signals import GapSignalStore, decline_signal
    from fazerops.ledger.store import LedgerStore

    ledger, store = LedgerStore(), GapSignalStore(store_path)
    for number, actor, fired_at in ((1, "priya", T0), (2, "arun", T0 + timedelta(hours=6))):
        cause = configmap_change(
            f"evt-{number}",
            at=fired_at - timedelta(minutes=38),
            actor=actor,
            before=cause_before,
            after=cause_after,
        )
        ledger.record(cause)
        if remediate:
            ledger.record(
                configmap_change(
                    f"fix-{number}",
                    at=fired_at + timedelta(minutes=9),
                    actor="dinesh",
                    before=cause_after,
                    after=(fixes or {}).get(number, cause_before),
                )
            )
        brief = production_brief(f"alert-{number}", cause, fired_at=fired_at)
        # As `Automation.respond` does: the firing is in the ledger beside the changes it ranked.
        ledger.record_alert(brief.alert)
        store.record(decline_signal(brief))

    gaps = mine_history(ledger, store, HISTORY, thresholds=MinerThresholds())
    [gap] = [gap for gap in gaps if gap.eligible]
    return ledger, store, gap


def binary_gap_with_corpus(*, store_path=None):
    """`gap_with_corpus` for a ConfigMap's `binaryData` — the gap only rung 3 can express."""
    from fazerops.actions.growth.miner import MinerThresholds, mine_history
    from fazerops.actions.growth.signals import GapSignalStore, decline_signal
    from fazerops.ledger.store import LedgerStore

    ledger, store = LedgerStore(), GapSignalStore(store_path)
    for number, actor, fired_at in ((1, "priya", T0), (2, "arun", T0 + timedelta(hours=6))):
        cause = binary_data_change(f"bin-{number}", at=fired_at - timedelta(minutes=38), actor=actor)
        ledger.record(cause)
        ledger.record(
            binary_data_change(
                f"binfix-{number}", at=fired_at + timedelta(minutes=9), actor="dinesh", before=BINARY_AFTER, after=BINARY_BEFORE
            )
        )
        brief = production_brief(f"alert-b{number}", cause, fired_at=fired_at)
        ledger.record_alert(brief.alert)
        store.record(decline_signal(brief))

    [gap] = [gap for gap in mine_history(ledger, store, HISTORY, thresholds=MinerThresholds()) if gap.eligible]
    return ledger, store, gap


def brief_for(incident_id: str, *events: ChangeEvent, fired_at: datetime = T0) -> Brief:
    """A brief ranking `events` in the order given."""
    keys = set().union(*(event.blast_radius_keys for event in events)) if events else {SERVICE_KEY}
    return Brief(
        incident_id=incident_id,
        alert=Alert(
            id=incident_id,
            service="billing-api",
            summary="p99 latency above threshold",
            fired_at=fired_at,
            alert_class=AlertClass.LATENCY_SPIKE,
        ),
        radius=BlastRadius(service="billing-api", keys=keys, direct_keys=keys),
        window=TimeWindow(start=fired_at - timedelta(hours=4), end=fired_at),
        candidates=[
            Candidate(event=event, score=round(0.9 - 0.1 * index, 2), rank=index + 1)
            for index, event in enumerate(events)
        ],
        ci_status=CIStatus(merge_count=0),
    )


def production_brief(alert_id: str, *events: ChangeEvent, fired_at: datetime = T0) -> Brief:
    """`brief_for`, with the incident id production gives a brief — `incident_id_for` of its alert —
    so a signal drawn from it names an incident a ledger can hold (`generate.corroborate`)."""
    brief = brief_for(alert_id, *events, fired_at=fired_at)
    return brief.model_copy(update={"incident_id": incident_id_for(brief.alert)})
