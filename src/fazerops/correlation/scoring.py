"""Correlation scoring — deterministic, in Python (Handoff §0 rule 3).

The model never computes a score. It reads the ranked candidates and writes the
explanation, citing evidence it was handed. That split is what makes W15's golden ranking
test possible at all: a model anywhere in this path would make the assertion that *is* the
demo capable of flaking.

The features themselves live in `features.py` (Handoff §6). This module does one thing:
the weighted sum, normalized to 0–1, with a deterministic tie-break. Weights are in
`config/weights.yaml` so they are tunable without a redeploy and visible to a judge —
Handoff §6: "a judge who can see the scoring function is a judge who believes the system."

**`in_band` is not an input.** Handoff §3 is explicit: boosting a change because it did not
go through CI is circular. The fact is reported in the brief and weighed by the human;
`tests/unit/test_scoring.py` asserts it never reaches the score.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Alert, BlastRadius, Candidate, ChangeEvent, TimeWindow
from .features import (
    load_weights,
    radius_overlap,
    recurrence,
    temporal_proximity,
    type_prior,
)

if TYPE_CHECKING:
    from ..ledger.store import LedgerStore

__all__ = ["load_weights", "score_events"]


def score_events(
    events: list[ChangeEvent],
    alert: Alert,
    radius: BlastRadius,
    window: TimeWindow,
    ledger: LedgerStore | None = None,
) -> list[Candidate]:
    """Rank events into candidates, highest score first.

    `ledger` is what `recurrence` queries; without it the feature is 0.0, which is the
    same answer a cold ledger gives. Ties break on recency, then on event id —
    deterministic, so the same inputs always produce the same brief. A nondeterministic
    tie-break would make the golden ranking test flake for reasons unrelated to the scorer.
    """
    weights = load_weights()
    coefficients = weights.get("weights") or {}

    scored: list[tuple[float, dict[str, float], ChangeEvent]] = []
    for event in events:
        features = {
            "radius_overlap": radius_overlap(event, radius),
            "temporal_proximity": temporal_proximity(event, alert, weights),
            "type_prior": type_prior(event, alert, weights),
            "recurrence": recurrence(event, alert, radius, ledger, weights),
        }
        total = sum(features[name] * float(coefficients.get(name, 0.0)) for name in features)
        divisor = sum(float(coefficients.get(name, 0.0)) for name in features) or 1.0
        scored.append((total / divisor, features, event))

    scored.sort(key=lambda row: (-row[0], -row[2].occurred_at.timestamp(), row[2].id))

    return [
        Candidate(event=event, score=round(score, 6), features=features, rank=index)
        for index, (score, features, event) in enumerate(scored, start=1)
    ]
