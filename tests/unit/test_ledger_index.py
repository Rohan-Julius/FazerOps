"""W9 — the ledger index.

The failure this file exists to catch is silent and it is the worst one in the build: an
event is written under one key shape and queried under another, the query returns nothing,
and the brief reports with total confidence that nothing changed. There is no exception
and no log line. So the assertions here are about *retrievability*, not about storage.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from fazerops.ledger.store import LedgerStore
from fazerops.models import Actor, BlastRadius, ChangeEvent, ResourceRef, TimeWindow

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)
WINDOW = TimeWindow(start=ALERT_TIME - timedelta(hours=4), end=ALERT_TIME)

CONFIGMAP_KEY = "k8s:billing/configmap/billing-api-config"
SERVICE_KEY = "service:billing-api"
DEPENDENCY_KEY = "k8s:auth/configmap/auth-service-config"

BILLING = BlastRadius(
    service="billing-api",
    keys={CONFIGMAP_KEY, SERVICE_KEY, DEPENDENCY_KEY},
    direct_keys={CONFIGMAP_KEY, SERVICE_KEY},
)


def event(
    event_id: str,
    *,
    when: datetime = ALERT_TIME - timedelta(minutes=38),
    keys: set[str] | None = None,
    name: str = "billing-api-config",
    namespace: str = "billing",
) -> ChangeEvent:
    return ChangeEvent(
        id=event_id,
        source="k8s_audit",
        occurred_at=when,
        actor=Actor(raw="dinesh@faber-demo.io"),
        action="update",
        resource=ResourceRef(kind="ConfigMap", name=name, namespace=namespace),
        blast_radius_keys={CONFIGMAP_KEY, SERVICE_KEY} if keys is None else keys,
        in_band=False,
        raw_ref=f"fixture#{event_id}",
    )


# --------------------------------------------------------------------------------------
# The index
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("key", [CONFIGMAP_KEY, SERVICE_KEY])
def test_an_event_is_retrievable_by_every_key_it_carries(key):
    """Not just the first one. A ConfigMap change is reachable from the resource key *and*
    from the service key, because the two arrive by different routes: the audit collector
    knows the resource, the alert knows the service."""
    store = LedgerStore()
    store.record(event("audit-1"))

    radius = BlastRadius(service="billing-api", keys={key}, direct_keys={key})
    assert [e.id for e in store.query(radius)] == ["audit-1"]


def test_an_event_outside_the_radius_is_never_returned():
    """Project isolation. A marketing-namespace ConfigMap is not evidence about billing."""
    store = LedgerStore()
    store.record(event("audit-1"))
    store.record(
        event(
            "unrelated-1",
            keys={"k8s:marketing/configmap/marketing-config"},
            name="marketing-config",
            namespace="marketing",
        )
    )

    assert [e.id for e in store.query(BILLING)] == ["audit-1"]


def test_an_event_carrying_no_keys_is_unreachable():
    """Correct rather than unfortunate: a change nothing can attribute to a service cannot
    be evidence about that service. It is stored — the ledger is a record — but it never
    enters a candidate set."""
    store = LedgerStore()
    store.record(event("orphan-1", keys=set()))

    assert len(store) == 1
    assert store.query(BILLING) == []
    assert store.get("orphan-1") is not None


def test_a_one_hop_dependency_key_still_matches():
    """`radius.keys` includes the one-hop neighbours; W14's `radius_overlap` is what scores
    them lower. Filtering them out here would delete that distinction before scoring."""
    store = LedgerStore()
    store.record(
        event("auth-1", keys={DEPENDENCY_KEY}, name="auth-service-config", namespace="auth")
    )

    assert [e.id for e in store.query(BILLING)] == ["auth-1"]


# --------------------------------------------------------------------------------------
# The window
# --------------------------------------------------------------------------------------


def test_the_window_start_is_inclusive():
    store = LedgerStore()
    store.record(event("edge-start", when=WINDOW.start))
    assert [e.id for e in store.query(BILLING, WINDOW)] == ["edge-start"]


def test_the_window_end_is_exclusive():
    """Half-open `[start, end)`. An inclusive end double-counts the change landing exactly
    on the alert timestamp — the most suspicious event in the set, so the duplicate would
    take ranks 1 and 2 of the brief."""
    store = LedgerStore()
    store.record(event("edge-end", when=WINDOW.end))
    assert store.query(BILLING, WINDOW) == []


def test_events_before_the_window_are_dropped():
    store = LedgerStore()
    store.record(event("old", when=WINDOW.start - timedelta(seconds=1)))
    store.record(event("inside", when=WINDOW.start + timedelta(minutes=1)))
    assert [e.id for e in store.query(BILLING, WINDOW)] == ["inside"]


def test_omitting_the_window_returns_the_whole_radius_history():
    """W14b's recurrence feature asks whether this change has preceded this alert before,
    which is a question about history *outside* the current window."""
    store = LedgerStore()
    store.record(event("old", when=WINDOW.start - timedelta(days=3)))
    store.record(event("inside"))

    assert len(store.query(BILLING)) == 2
    assert len(store.query(BILLING, WINDOW)) == 1


def test_results_are_chronological_and_tie_break_deterministically():
    """The brief renders a timeline, and W15's golden ranking test needs the same input
    order on every run."""
    same_moment = ALERT_TIME - timedelta(minutes=10)
    store = LedgerStore()
    store.extend(
        [
            event("c", when=ALERT_TIME - timedelta(minutes=5)),
            event("b", when=same_moment),
            event("a", when=same_moment),
        ]
    )
    assert [e.id for e in store.query(BILLING, WINDOW)] == ["a", "b", "c"]


# --------------------------------------------------------------------------------------
# Idempotency and persistence
# --------------------------------------------------------------------------------------


def test_recording_the_same_id_twice_stores_one_event():
    """Collectors overlap by design — a Helm rollout appears in the K8s audit log too —
    and a re-fired alert re-investigates the same window."""
    store = LedgerStore()
    store.record(event("audit-1"))
    store.record(event("audit-1"))

    assert len(store) == 1
    assert [e.id for e in store.query(BILLING)] == ["audit-1"]


def test_extend_reports_only_events_that_were_new():
    store = LedgerStore()
    assert store.extend([event("a"), event("b")]) == 2
    assert store.extend([event("b"), event("c")]) == 1


def test_re_recording_an_id_removes_its_stale_index_entries():
    """A corrected payload must not leave the event reachable under a key it no longer
    claims — that is how a fixed record keeps producing the old wrong answer."""
    store = LedgerStore()
    store.record(event("audit-1", keys={CONFIGMAP_KEY}))
    store.record(event("audit-1", keys={SERVICE_KEY}))

    stale = BlastRadius(service="x", keys={CONFIGMAP_KEY}, direct_keys={CONFIGMAP_KEY})
    assert store.query(stale) == []
    assert [e.id for e in store.query(BILLING)] == ["audit-1"]


def test_the_ledger_survives_the_process(tmp_path):
    path = tmp_path / "ledger.jsonl"
    LedgerStore(path).extend(
        [event("audit-1"), event("audit-2", when=ALERT_TIME - timedelta(minutes=20))]
    )

    reopened = LedgerStore(path)
    assert [e.id for e in reopened.query(BILLING, WINDOW)] == ["audit-1", "audit-2"]
    assert reopened.query(BILLING)[0].occurred_at.tzinfo is not None


def test_a_reopened_ledger_deduplicates_by_id(tmp_path):
    """Append-only means the same id can appear on two lines. Later wins."""
    path = tmp_path / "ledger.jsonl"
    store = LedgerStore(path)
    store.record(event("audit-1", keys={CONFIGMAP_KEY}))
    store.record(event("audit-1", keys={SERVICE_KEY}))

    reopened = LedgerStore(path)
    assert len(reopened) == 1
    assert reopened.get("audit-1").blast_radius_keys == {SERVICE_KEY}


def test_a_truncated_final_line_does_not_lose_the_whole_ledger(tmp_path):
    """The shape a crash mid-append leaves. Refusing to open the file would trade the
    entire history for one event."""
    path = tmp_path / "ledger.jsonl"
    LedgerStore(path).record(event("audit-1"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"id": "audit-2", "source": "k8s_a')

    reopened = LedgerStore(path)
    assert [e.id for e in reopened.query(BILLING)] == ["audit-1"]


def test_an_in_memory_ledger_writes_nothing(tmp_path, monkeypatch):
    """The fixture demo must not leave state on a judge's machine."""
    monkeypatch.chdir(tmp_path)
    LedgerStore().record(event("audit-1"))
    assert list(tmp_path.iterdir()) == []
