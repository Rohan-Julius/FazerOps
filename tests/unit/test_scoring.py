"""W15 — the scorer's invariants, independent of any one fixture.

`test_ranking_golden.py` asserts the demo ranks correctly. This file asserts the
properties that must hold for *every* ranking, including the ones nobody has looked at:
scores stay in range, the ordering is total, and `in_band` never reaches the arithmetic.

Handoff §0 rule 3 — deterministic maths in Python — is what makes these assertions
possible. There is no model in this path to make any of them probabilistic.
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta, timezone

import pytest

from fazerops.correlation import features as features_module
from fazerops.correlation import scoring as scoring_module
from fazerops.correlation.scoring import load_weights, score_events
from fazerops.models import (
    Actor,
    Alert,
    AlertClass,
    BlastRadius,
    ChangeEvent,
    ResourceRef,
    TimeWindow,
)

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)

DIRECT_KEY = "k8s:billing/configmap/billing-api-config"
DEPENDENCY_KEY = "k8s:auth/configmap/auth-service-config"

RADIUS = BlastRadius(
    service="billing-api",
    keys={DIRECT_KEY, DEPENDENCY_KEY},
    direct_keys={DIRECT_KEY},
)
WINDOW = TimeWindow(start=ALERT_TIME - timedelta(hours=4), end=ALERT_TIME)
ALERT = Alert(
    id="a-1",
    service="billing-api",
    summary="billing-api p99 latency above threshold",
    fired_at=ALERT_TIME,
    alert_class=AlertClass.LATENCY_SPIKE,
)


def event(
    *,
    id: str = "e-1",
    minutes_before: float = 38,
    keys: set[str] | None = None,
    in_band: bool = False,
    kind: str = "ConfigMap",
    action: str = "update",
) -> ChangeEvent:
    return ChangeEvent(
        id=id,
        source="k8s_audit",
        occurred_at=ALERT_TIME - timedelta(minutes=minutes_before),
        actor=Actor(raw="dinesh@faber-demo.io"),
        action=action,
        resource=ResourceRef(kind=kind, name="billing-api-config", namespace="billing"),
        blast_radius_keys={DIRECT_KEY} if keys is None else keys,
        in_band=in_band,
        raw_ref=f"fixture#{id}",
    )


# --------------------------------------------------------------------------------------
# in_band is not an input — Handoff §3's circularity guard
# --------------------------------------------------------------------------------------


def test_in_band_is_not_an_input():
    """Two events identical but for `in_band` must score identically.

    Handoff §3 is explicit that boosting a change because it skipped CI is circular: the
    system would be ranking by the very fact it exists to *report*, and the demo's rank 1
    and rank 3 are both out of band, so the circularity would flatter the ranking without
    improving it. The fact belongs in the brief, weighed by a human.
    """
    in_band, out_of_band = score_events(
        [event(id="a", in_band=True), event(id="b", in_band=False)],
        ALERT,
        RADIUS,
        WINDOW,
    )
    assert in_band.score == out_of_band.score


def test_in_band_does_not_appear_in_the_scoring_source():
    """The assertion above proves it for one pair of events. This proves it for all of
    them: an `in_band` term added under some other condition would slip past a behavioural
    test that happens not to hit that branch.

    Read off the AST rather than the text, because both modules *discuss* `in_band` at
    length in their docstrings — a substring search over the source would either fail on
    the prose or have to be loosened until it stopped guarding anything.
    """
    for module in (scoring_module, features_module):
        tree = ast.parse(inspect.getsource(module))
        for node in ast.walk(tree):
            attribute = isinstance(node, ast.Attribute) and node.attr == "in_band"
            subscript = isinstance(node, ast.Constant) and node.value == "in_band"
            assert not (attribute or subscript), (
                f"{module.__name__} reads in_band at line {node.lineno} — "
                "Handoff §3 forbids it as an input"
            )


def test_in_band_survives_onto_the_candidate():
    """Not an input, but not discarded either — the brief reports it, and W11a's CI-status
    line is the pitch. A scorer that dropped the field would satisfy the guard above and
    still break the demo."""
    candidate = score_events([event(in_band=True)], ALERT, RADIUS, WINDOW)[0]
    assert candidate.event.in_band is True


# --------------------------------------------------------------------------------------
# Range and shape
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("minutes_before", [0, 1, 38, 191, 239, 10_000])
@pytest.mark.parametrize("keys", [{DIRECT_KEY}, {DEPENDENCY_KEY}, {"k8s:other/x/y"}])
def test_every_score_is_a_probability(minutes_before, keys):
    """`Candidate.score` is `Field(ge=0, le=1)`, so an out-of-range score raises at
    construction rather than ranking. Swept across the feature extremes because a weighted
    sum that forgets to divide only leaves range on inputs nobody tried."""
    candidate = score_events(
        [event(minutes_before=minutes_before, keys=keys)], ALERT, RADIUS, WINDOW
    )[0]
    assert 0.0 <= candidate.score <= 1.0


def test_ranks_are_dense_and_start_at_one():
    events = [event(id=f"e-{n}", minutes_before=n * 20) for n in range(1, 5)]
    candidates = score_events(events, ALERT, RADIUS, WINDOW)
    assert [c.rank for c in candidates] == [1, 2, 3, 4]


def test_scores_descend_with_rank():
    events = [event(id=f"e-{n}", minutes_before=n * 20) for n in range(1, 5)]
    scores = [c.score for c in score_events(events, ALERT, RADIUS, WINDOW)]
    assert scores == sorted(scores, reverse=True)


def test_every_feature_is_carried_onto_the_candidate():
    """Ground rule #3: the brief explains the ranking from these numbers rather than the
    model re-deriving them. All four are present including `recurrence`, whose weight is
    0.0 — the feature computes and the weight declines to use it (plan §3.3)."""
    candidate = score_events([event()], ALERT, RADIUS, WINDOW)[0]
    assert set(candidate.features) == {
        "radius_overlap",
        "temporal_proximity",
        "type_prior",
        "recurrence",
    }


def test_no_events_yields_no_candidates():
    """An empty candidate set is a legitimate answer — nothing changed in the radius — and
    must not be an exception. The brief says so in words; W4's resolver is what makes a
    *silently* empty set the bug to fear."""
    assert score_events([], ALERT, RADIUS, WINDOW) == []


# --------------------------------------------------------------------------------------
# Determinism — what makes the golden test a guarantee rather than a sample
# --------------------------------------------------------------------------------------


def test_a_tie_breaks_on_recency_then_id():
    """Two events with identical features must still order totally, and the same way every
    run. A set-iteration-order tie-break would flake the golden test for a reason that has
    nothing to do with the scorer."""
    older = event(id="zzz", minutes_before=60)
    newer = event(id="aaa", minutes_before=30)
    ranked = score_events([older, newer], ALERT, RADIUS, WINDOW)

    assert [c.event.id for c in ranked] == ["aaa", "zzz"]


def test_identical_events_break_the_tie_on_id():
    same_time = [event(id="b", minutes_before=38), event(id="a", minutes_before=38)]
    ranked = score_events(same_time, ALERT, RADIUS, WINDOW)

    assert ranked[0].score == ranked[1].score
    assert [c.event.id for c in ranked] == ["a", "b"]


def test_input_order_does_not_change_the_ranking():
    events = [event(id=f"e-{n}", minutes_before=n * 17) for n in range(1, 6)]
    forward = [c.event.id for c in score_events(events, ALERT, RADIUS, WINDOW)]
    backward = [c.event.id for c in score_events(list(reversed(events)), ALERT, RADIUS, WINDOW)]

    assert forward == backward


# --------------------------------------------------------------------------------------
# Weights
# --------------------------------------------------------------------------------------


def test_the_weighted_sum_is_normalized_by_the_weights_actually_declared():
    """`recurrence` carries weight 0.0, so it must not dilute the divisor — a scorer
    dividing by four features while only three can contribute would cap every score below
    its true value and quietly shrink the demo's rank-1 margin."""
    weights = load_weights()["weights"]
    perfect = score_events([event(minutes_before=0)], ALERT, RADIUS, WINDOW)[0]

    contributing = sum(v for k, v in weights.items() if k != "recurrence")
    expected = (
        perfect.features["radius_overlap"] * weights["radius_overlap"]
        + perfect.features["temporal_proximity"] * weights["temporal_proximity"]
        + perfect.features["type_prior"] * weights["type_prior"]
    ) / contributing

    assert perfect.score == pytest.approx(expected, abs=1e-6)


def test_the_half_life_stays_inside_the_range_handoff_6_states():
    """Regression guard for the 6 Sep bug, kept here as well as in `test_features.py`
    because it is the one number that moves the demo's margin without changing any code."""
    assert 30 <= load_weights()["temporal_half_life_minutes"] <= 45
