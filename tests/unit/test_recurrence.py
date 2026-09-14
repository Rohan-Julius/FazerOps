"""W14b — the `recurrence` feature (Handoff §6, restored 6 Sep per plan §3.3).

*Has this (action, resource_type) preceded this alert signature before?* Two facts are
asserted and both are deliberate:

* On a cold ledger it returns **exactly 0.0** — not `None`, not a `KeyError`. The demo runs
  on a cold ledger, so 0.0 is the answer the on-camera path takes, and it is the correct
  answer rather than an absent one.
* Its **weight stays 0.0** in `weights.yaml`. The feature computes; the weighting declines
  to use it. A weight that drifted off zero would move the one ranking that is on camera,
  using the only term that provably cannot carry signal on a cold start.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fazerops.correlation.features import load_weights, recurrence
from fazerops.ledger.store import LedgerStore
from fazerops.models import (
    Actor,
    Alert,
    AlertClass,
    BlastRadius,
    ChangeEvent,
    ResourceRef,
)

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)

CONFIGMAP_KEY = "k8s:billing/configmap/billing-api-config"
SERVICE_KEY = "service:billing-api"

BILLING = BlastRadius(
    service="billing-api",
    keys={CONFIGMAP_KEY, SERVICE_KEY},
    direct_keys={CONFIGMAP_KEY, SERVICE_KEY},
)


def alert(
    alert_id: str = "a-now",
    *,
    at: datetime = ALERT_TIME,
    alert_class: AlertClass = AlertClass.LATENCY_SPIKE,
    service: str = "billing-api",
) -> Alert:
    return Alert(
        id=alert_id,
        service=service,
        summary="p99 latency above threshold",
        fired_at=at,
        alert_class=alert_class,
    )


def event(
    event_id: str,
    *,
    at: datetime,
    action: str = "update",
    kind: str = "ConfigMap",
) -> ChangeEvent:
    return ChangeEvent(
        id=event_id,
        source="k8s_audit",
        occurred_at=at,
        actor=Actor(raw="dinesh@faber-demo.io"),
        action=action,
        resource=ResourceRef(kind=kind, name="billing-api-config", namespace="billing"),
        blast_radius_keys={CONFIGMAP_KEY, SERVICE_KEY},
        in_band=False,
        raw_ref=f"fixture#{event_id}",
    )


CURRENT = event("e-now", at=ALERT_TIME - timedelta(minutes=38))


# --------------------------------------------------------------------------------------
# Cold start
# --------------------------------------------------------------------------------------


def test_an_empty_ledger_returns_exactly_zero():
    result = recurrence(CURRENT, alert(), BILLING, LedgerStore())
    assert result == 0.0
    assert isinstance(result, float)


def test_no_ledger_at_all_returns_exactly_zero():
    """The scorer may be called without a ledger — W15's golden test does. That path must
    give the same answer a cold ledger does, not raise."""
    assert recurrence(CURRENT, alert(), BILLING, None) == 0.0


def test_a_ledger_holding_changes_but_no_prior_alerts_returns_zero():
    """Changes alone are not recurrence. Without a prior alert of this signature there is
    nothing for the change to have *preceded* — the demo's exact state."""
    ledger = LedgerStore()
    ledger.extend([CURRENT, event("e-old", at=ALERT_TIME - timedelta(days=3))])
    assert recurrence(CURRENT, alert(), BILLING, ledger) == 0.0


# --------------------------------------------------------------------------------------
# Warm ledger
# --------------------------------------------------------------------------------------


def build_history() -> LedgerStore:
    """One prior latency alert, with a matching ConfigMap update in the window before it."""
    ledger = LedgerStore()
    past_alert_time = ALERT_TIME - timedelta(days=7)
    ledger.record_alert(alert("a-week-ago", at=past_alert_time))
    ledger.extend([event("e-week-ago", at=past_alert_time - timedelta(minutes=25))])
    return ledger


def test_a_matching_prior_pair_scores_non_zero():
    assert recurrence(CURRENT, alert(), BILLING, build_history()) > 0.0


def test_a_different_change_shape_does_not_recur():
    """The signature is (action, resource_type). A prior ConfigMap *update* says nothing
    about a Secret delete, and scoring it as if it did would make the feature fire on
    "something changed before an alert", which is always true."""
    ledger = build_history()
    unrelated = event("e-other", at=ALERT_TIME - timedelta(minutes=38), action="delete")
    assert recurrence(unrelated, alert(), BILLING, ledger) == 0.0


def test_a_prior_alert_of_a_different_class_is_not_this_signature():
    ledger = LedgerStore()
    past = ALERT_TIME - timedelta(days=7)
    ledger.record_alert(alert("a-oom", at=past, alert_class=AlertClass.OOM))
    ledger.extend([event("e-week-ago", at=past - timedelta(minutes=25))])
    assert recurrence(CURRENT, alert(), BILLING, ledger) == 0.0


def test_a_change_after_a_prior_alert_did_not_precede_it():
    """Recurrence is a claim about causal order. A change that landed *after* the previous
    alert fired cannot be a precedent for it."""
    ledger = LedgerStore()
    past = ALERT_TIME - timedelta(days=7)
    ledger.record_alert(alert("a-week-ago", at=past))
    ledger.extend([event("e-after", at=past + timedelta(minutes=25))])
    assert recurrence(CURRENT, alert(), BILLING, ledger) == 0.0


def test_recurrence_is_bounded_to_the_unit_interval():
    """It is a fraction of prior signature occurrences, so it composes with the other three
    features in the weighted sum without needing to be rescaled."""
    ledger = build_history()
    assert 0.0 <= recurrence(CURRENT, alert(), BILLING, ledger) <= 1.0


def test_the_current_alert_is_never_its_own_precedent():
    """`pipeline.investigate` records the alert as part of the run. Whether it records
    before or after scoring must not change the score."""
    ledger = LedgerStore()
    ledger.extend([CURRENT])
    ledger.record_alert(alert())
    assert recurrence(CURRENT, alert(), BILLING, ledger) == 0.0


def test_an_unclassified_alert_has_no_signature_to_recur_on():
    """Matching unclassified against unclassified would make the feature fire on the
    absence of a classification (W13) rather than on a repeated pattern."""
    ledger = LedgerStore()
    past = ALERT_TIME - timedelta(days=7)
    ledger.record_alert(alert("a-past", at=past, alert_class=AlertClass.UNCLASSIFIED))
    ledger.extend([event("e-week-ago", at=past - timedelta(minutes=25))])
    unclassified_now = alert(alert_class=AlertClass.UNCLASSIFIED)
    assert recurrence(CURRENT, unclassified_now, BILLING, ledger) == 0.0


# --------------------------------------------------------------------------------------
# The weight
# --------------------------------------------------------------------------------------


def test_the_weight_stays_zero_so_the_demo_ranking_cannot_move():
    """Plan §3.3: the feature is built, the weight declines to use it. Both facts are meant
    to be visible in `weights.yaml`, and this is what keeps the second one true."""
    assert float(load_weights()["weights"]["recurrence"]) == 0.0


def test_a_later_firing_of_the_same_rule_is_a_precedent():
    """Fixed 14 Sep: alerts were keyed on `alert.id`, the rule's own stable identifier, so the second
    firing of a rule overwrote the first and a re-fire never counted as history."""
    ledger = LedgerStore()
    past = ALERT_TIME - timedelta(days=7)
    ledger.record_alert(alert("fingerprint-1", at=past))
    ledger.extend([event("e-week-ago", at=past - timedelta(minutes=25))])

    now = alert("fingerprint-1")
    ledger.record_alert(now)

    assert [prior.fired_at for prior in ledger.prior_alerts(now)] == [past]
    assert recurrence(CURRENT, now, BILLING, ledger) > 0.0


def test_a_redelivered_firing_is_recorded_once(tmp_path):
    ledger = LedgerStore(tmp_path / "ledger.jsonl", key=None)
    ledger.record_alert(alert("fingerprint-1"))
    ledger.record_alert(alert("fingerprint-1"))

    assert len(LedgerStore(tmp_path / "ledger.jsonl", key=None)._alerts) == 1

