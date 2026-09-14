"""`correlation/sensitivity.py` — whether rank 1 depends on the weights, answered exactly.

The claims under test are mathematical, so they are checked the way a proof is checked:
worked examples with hand-computed answers, then a seeded sweep over random candidate sets
asserting the two properties the module promises — a dominant rank 1 survives *every*
weighting tried, and the reported flip weight really does bring the challenger level.
"""

from __future__ import annotations

import ast
import inspect
import random
from datetime import datetime, timezone

import pytest

from fazerops.correlation import sensitivity as sensitivity_module
from fazerops.correlation.sensitivity import rank_stability
from fazerops.models import Actor, Candidate, ChangeEvent, NormalizedAction, ResourceRef

T = datetime(2026, 9, 6, 14, 0, tzinfo=timezone.utc)


def _event(name: str) -> ChangeEvent:
    return ChangeEvent(
        id=name,
        source="k8s_audit",
        occurred_at=T,
        actor=Actor(raw="someone"),
        action=NormalizedAction.UPDATE,
        resource=ResourceRef(kind="ConfigMap", name=name, namespace="billing"),
        in_band=False,
        raw_ref=f"k8s_audit:{name}",
    )


def _weighted(features: dict[str, float], weights: dict[str, float]) -> float:
    return sum(features.get(n, 0.0) * w for n, w in weights.items()) / (sum(weights.values()) or 1.0)


def _ranked(rows: list[dict[str, float]], weights: dict[str, float]) -> list[Candidate]:
    scored = sorted(((_weighted(f, weights), i, f) for i, f in enumerate(rows)), key=lambda r: (-r[0], r[1]))
    return [
        Candidate(event=_event(f"c{i}"), score=round(score, 6), features=f, rank=rank)
        for rank, (score, i, f) in enumerate(scored, start=1)
    ]


def test_fewer_than_two_candidates_has_no_ranking_to_be_fragile():
    weights = {"weights": {"a": 1.0}}
    assert rank_stability([], weights) is None
    assert rank_stability(_ranked([{"a": 0.4}], weights["weights"]), weights) is None


def test_a_candidate_ahead_on_every_feature_is_dominant():
    w = {"a": 0.5, "b": 0.5}
    stability = rank_stability(_ranked([{"a": 0.9, "b": 0.6}, {"a": 0.2, "b": 0.6}], w), {"weights": w})
    assert stability.dominant is True
    assert stability.margin == pytest.approx(0.35)
    assert stability.feature is None and stability.weight_to is None


def test_the_nearest_flip_is_computed_exactly():
    """a: 1.0 vs 0.0, b: 0.2 vs 0.6, weights 0.5/0.5. Lead D = 0.3. Lowering a to
    0.5 - 0.3/1.0 = 0.2 is a move of 0.3; raising b to 0.5 + 0.3/0.4 = 1.25 is 0.75."""
    w = {"a": 0.5, "b": 0.5}
    stability = rank_stability(_ranked([{"a": 1.0, "b": 0.2}, {"a": 0.0, "b": 0.6}], w), {"weights": w})

    assert stability.dominant is False
    assert (stability.challenger_rank, stability.feature) == (2, "a")
    assert (stability.weight_from, stability.weight_to) == (0.5, pytest.approx(0.2))


def test_raising_a_zero_weight_feature_counts_as_a_flip():
    """`recurrence` ships at weight 0.0. A challenger ahead only on it is one small weight away
    from drawing level, and the report must say so rather than ignore unweighted features."""
    w = {"a": 1.0, "recurrence": 0.0}
    stability = rank_stability(_ranked([{"a": 1.0, "recurrence": 0.0}, {"a": 0.9, "recurrence": 1.0}], w), {"weights": w})
    assert (stability.feature, stability.weight_from, stability.weight_to) == ("recurrence", 0.0, pytest.approx(0.1))


def test_a_flip_needing_a_negative_weight_is_not_offered():
    """Rank 1 leads on a and c, trails on b. Lead D = 0.1·0.5 + 0.8·0.5 − 0.1·1.0 = 0.35. Lowering
    a alone would need 0.1 − 0.35/0.5 = −0.6, which is not a weight — and naively taking the
    smallest |Δ| (0.7) would still rank below raising b by 0.35. Lowering c is 0.7. Answer: b."""
    w = {"a": 0.1, "b": 0.1, "c": 0.8}
    rows = [{"a": 1.0, "b": 0.0, "c": 1.0}, {"a": 0.5, "b": 1.0, "c": 0.5}]
    stability = rank_stability(_ranked(rows, w), {"weights": w})
    assert (stability.feature, stability.weight_from, stability.weight_to) == ("b", 0.1, pytest.approx(0.45))


@pytest.mark.parametrize("seed", range(200))
def test_the_report_is_true_on_random_rankings(seed):
    rng = random.Random(seed)
    names = ["radius_overlap", "temporal_proximity", "type_prior", "recurrence"]
    weights = {n: rng.choice([0.0, rng.random()]) for n in names}
    weights["radius_overlap"] = weights["radius_overlap"] or 0.3
    rows = [{n: round(rng.random(), 3) for n in names} for _ in range(rng.randint(2, 5))]
    candidates = _ranked(rows, weights)
    stability = rank_stability(candidates, {"weights": weights})
    first = candidates[0].features

    if stability.dominant:
        for _ in range(50):
            trial = {n: rng.random() for n in names}
            assert all(_weighted(first, trial) >= _weighted(c.features, trial) - 1e-9 for c in candidates[1:])
        return

    moved = {**weights, stability.feature: stability.weight_to}
    challenger = candidates[stability.challenger_rank - 1].features
    assert _weighted(challenger, moved) == pytest.approx(_weighted(first, moved), abs=1e-3)


def test_rank_stability_never_reads_in_band():
    """Same AST guard as the scorer (`test_scoring.py`): this module sits beside it and is
    exactly where an `in_band` term could be slipped in as 'context'."""
    for node in ast.walk(ast.parse(inspect.getsource(sensitivity_module))):
        assert not (isinstance(node, ast.Attribute) and node.attr == "in_band")
        assert not (isinstance(node, ast.Constant) and node.value == "in_band")


def test_the_model_never_sees_the_stability_claim():
    """A statement about the scorer is not evidence about the world. The correlator's context
    is built from the alert and the candidates only."""
    from fazerops.agents.correlator import build_messages
    from fazerops.models import Alert, BlastRadius, Brief, CIStatus, RankStability, TimeWindow

    candidates = _ranked([{"a": 1.0}, {"a": 0.5}], {"a": 1.0})
    brief = Brief(
        incident_id="INC-1",
        alert=Alert(id="1", service="billing-api", summary="latency", fired_at=T),
        radius=BlastRadius(service="billing-api"),
        window=TimeWindow(start=T.replace(hour=10), end=T),
        candidates=candidates,
        ci_status=CIStatus(merge_count=0),
        stability=RankStability(dominant=True, margin=0.5),
    )
    assert "choice of weights" not in str(build_messages(brief)) and "margin" not in str(build_messages(brief))
