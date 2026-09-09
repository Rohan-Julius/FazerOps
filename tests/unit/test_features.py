"""W14 — the four correlation features, each tested as a claim about the world.

Wrong features silently produce plausible-looking wrong rankings, which is the worst
failure mode this build has: it looks like it is working. Nothing here asserts a *score* —
that is W15's golden test. These assert the shape of each feature independently, so that
when the ranking is wrong there is a file that says which feature lied.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from fazerops.correlation.features import (
    load_weights,
    radius_overlap,
    temporal_proximity,
)
from fazerops.models import (
    Actor,
    Alert,
    AlertClass,
    BlastRadius,
    ChangeEvent,
    Diff,
    ResourceRef,
)

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)

DIRECT_KEY = "k8s:billing/configmap/billing-api-config"
SERVICE_KEY = "service:billing-api"
DEPENDENCY_KEY = "k8s:auth/configmap/auth-service-config"

BILLING = BlastRadius(
    service="billing-api",
    keys={DIRECT_KEY, SERVICE_KEY, DEPENDENCY_KEY},
    direct_keys={DIRECT_KEY, SERVICE_KEY},
)

ALERT = Alert(
    id="a-1",
    service="billing-api",
    summary="p99 latency above threshold",
    fired_at=ALERT_TIME,
    alert_class=AlertClass.LATENCY_SPIKE,
)


def event(
    *,
    minutes_before: float = 38,
    keys: set[str] | None = None,
    action: str = "update",
    kind: str = "ConfigMap",
    diff: Diff | None = None,
) -> ChangeEvent:
    return ChangeEvent(
        id=f"e-{minutes_before}-{kind}",
        source="k8s_audit",
        occurred_at=ALERT_TIME - timedelta(minutes=minutes_before),
        actor=Actor(raw="dinesh@faber-demo.io"),
        action=action,
        resource=ResourceRef(kind=kind, name="billing-api-config", namespace="billing"),
        blast_radius_keys={DIRECT_KEY, SERVICE_KEY} if keys is None else keys,
        in_band=False,
        diff=diff,
        raw_ref="fixture#e",
    )


# --------------------------------------------------------------------------------------
# radius_overlap — exactly three values, never a continuum
# --------------------------------------------------------------------------------------


def test_a_direct_resource_scores_exactly_one():
    assert radius_overlap(event(keys={DIRECT_KEY}), BILLING) == 1.0


def test_a_one_hop_dependency_scores_exactly_a_half():
    assert radius_overlap(event(keys={DEPENDENCY_KEY}), BILLING) == 0.5


def test_no_overlap_scores_exactly_zero():
    assert radius_overlap(event(keys={"k8s:other/configmap/unrelated"}), BILLING) == 0.0


def test_a_direct_hit_outranks_a_dependency_however_many_keys_it_carries():
    """The three values are categorical, not a set-size measure. A dependency change that
    happens to touch many keys must never out-score a direct hit — a continuous overlap
    would let exactly that happen, and the demo's rank 1 and rank 3 are that pair."""
    sprawling_dependency = event(keys={DEPENDENCY_KEY, "service:auth-service"})
    assert radius_overlap(sprawling_dependency, BILLING) < radius_overlap(
        event(keys={DIRECT_KEY}), BILLING
    )


# --------------------------------------------------------------------------------------
# temporal_proximity
# --------------------------------------------------------------------------------------


def test_decay_is_monotonic_in_the_gap():
    gaps = [1, 5, 15, 38, 60, 113, 191, 239]
    scores = [temporal_proximity(event(minutes_before=gap), ALERT) for gap in gaps]
    assert scores == sorted(scores, reverse=True)


def test_the_demo_gap_outscores_a_four_hour_old_change():
    """38 minutes before vs the far edge of the window. If this ever inverts, the brief
    names the oldest change in the window as the cause."""
    assert temporal_proximity(event(minutes_before=38), ALERT) > temporal_proximity(
        event(minutes_before=240), ALERT
    )


def test_a_change_after_the_alert_scores_zero():
    """It cannot have caused the alert. A symmetric decay would rank the remediation
    attempt above the cause — the on-call engineer's own rollback at rank 1."""
    assert temporal_proximity(event(minutes_before=-5), ALERT) == 0.0


def test_half_life_is_inside_the_range_the_handoff_states():
    """Handoff §6: "tune half-life around 30-45 min." A regression guard for the 6 Sep bug
    where this sat at 90 and flattened the ranking."""
    half_life = float(load_weights()["temporal_half_life_minutes"])
    assert 30 <= half_life <= 45


def test_one_half_life_halves_the_score():
    """The decay is the stated exponential, not something merely decreasing."""
    half_life = float(load_weights()["temporal_half_life_minutes"])
    near = temporal_proximity(event(minutes_before=half_life), ALERT)
    far = temporal_proximity(event(minutes_before=2 * half_life), ALERT)
    assert near == pytest.approx(0.5)
    assert far == pytest.approx(0.25)
