"""Does rank 1 depend on the weights? Answered exactly, not by sampling.

`config/weights.yaml` is hand-set, and the obvious question about any hand-set weighting is
whether the answer was tuned into it. Perturbing the weights and reporting "it held" answers
that question only for the perturbations someone chose to try. The score is linear in the
weights, so the question has a closed form instead:

* **Dominance.** If rank 1 is at least as high as every other candidate on *every* feature,
  then for any non-negative weights its weighted sum is at least theirs. No choice of
  weights ranks another candidate above it, and that is a proof rather than a sample.
* **Otherwise, the nearest flip.** For rank 1 against challenger *j*, the divisor is shared,
  so the order depends only on `D = Σ w_f · (x1_f − xj_f)`. Moving one weight `w_f` to
  `w_f − D / d_f` makes `D` zero — the challenger draws level, and the deterministic
  tie-break decides. The smallest such move, over every feature and every challenger, is
  how fragile the ranking is.

Changes are compared as a share of the total weight, so raising a zero-weight feature
(`recurrence`) is comparable with lowering a weighted one.

**Not an input to the score, and not model context.** It is a statement about the scorer.
`tests/unit/test_scoring.py` holds this module to the same `in_band` AST guard as the scorer.
"""

from __future__ import annotations

from ..models import Candidate, RankStability
from .features import load_weights

__all__ = ["rank_stability"]

# Feature values are products of floats; equality on a feature must not flip on 1e-17.
_EPSILON = 1e-9


def rank_stability(candidates: list[Candidate], weights: dict | None = None) -> RankStability | None:
    """`None` with fewer than two candidates — there is no ranking to be fragile."""
    if len(candidates) < 2:
        return None

    coefficients = {
        name: float(value) for name, value in ((weights or load_weights()).get("weights") or {}).items()
    }
    first, challengers = candidates[0], candidates[1:]
    margin = round(first.score - challengers[0].score, 6)

    names = sorted(set(first.features).union(*(c.features for c in challengers)))

    def gaps(challenger: Candidate) -> dict[str, float]:
        return {n: first.features.get(n, 0.0) - challenger.features.get(n, 0.0) for n in names}

    if all(d >= -_EPSILON for c in challengers for d in gaps(c).values()):
        return RankStability(dominant=True, margin=margin)

    total = sum(coefficients.values()) or 1.0
    best: tuple[float, Candidate, str, float, float] | None = None
    for challenger in challengers:
        d = gaps(challenger)
        lead = sum(coefficients.get(n, 0.0) * d[n] for n in names)
        for name in names:
            if abs(d[name]) <= _EPSILON:
                continue
            current = coefficients.get(name, 0.0)
            target = current - max(lead, 0.0) / d[name]
            if target < 0.0:
                continue  # would need a negative weight, which the scorer does not admit
            change = abs(target - current) / total
            if best is None or change < best[0]:
                best = (change, challenger, name, current, target)

    # Not dominant means some challenger beats rank 1 on some feature, so raising that
    # feature's weight always reaches a draw: `best` is never None here.
    assert best is not None
    _, challenger, name, current, target = best
    return RankStability(
        dominant=False,
        margin=margin,
        challenger_rank=challenger.rank,
        feature=name,
        weight_from=round(current, 4),
        weight_to=round(target, 4),
    )
