"""Correlation scoring — deterministic, in Python (Handoff §0 rule 3).

The model never computes a score. It reads the ranked candidates and writes the
explanation, citing evidence it was handed. That split is what makes W15's golden ranking
test possible at all: a model anywhere in this path would make the assertion that *is* the
demo capable of flaking.

**`in_band` is not an input.** Handoff §3 is explicit: boosting a change because it did not
go through CI is circular — the product's whole thesis is that out-of-band changes are
under-examined, and scoring them higher *because* they are out-of-band would manufacture
the finding it claims to discover. The fact is reported in the brief and weighed by the
human. `tests/unit/test_scoring.py` asserts it never reaches the score.

Status: `radius_overlap` and `temporal_proximity` are final. `type_prior` returns the
declared default from `weights.yaml` until W14 supplies the prior table — a declared
default, not a guess and not a KeyError path.
"""

from __future__ import annotations

import functools
import math
from pathlib import Path

import yaml

from ..models import Alert, BlastRadius, Candidate, ChangeEvent, TimeWindow

DEFAULT_WEIGHTS = Path(__file__).resolve().parents[3] / "config" / "weights.yaml"


@functools.lru_cache(maxsize=1)
def load_weights(path: str | None = None) -> dict:
    return yaml.safe_load(Path(path or DEFAULT_WEIGHTS).read_text(encoding="utf-8")) or {}


def radius_overlap(event: ChangeEvent, radius: BlastRadius) -> float:
    """1.0 for the service's own resources, 0.5 one hop out, 0.0 for no overlap.

    Exactly three values, not a continuous measure. A change to the alerting service's own
    ConfigMap is categorically more suspicious than one to a dependency's, and a smooth
    function over set sizes would let a large dependency out-score a direct hit.
    """
    if event.blast_radius_keys & radius.direct_keys:
        return 1.0
    if event.blast_radius_keys & radius.keys:
        return 0.5
    return 0.0


def temporal_proximity(event: ChangeEvent, alert: Alert, weights: dict | None = None) -> float:
    """Exponential decay backwards from the alert. Monotonic by construction.

    A change *after* the alert fired scores 0.0 — it cannot have caused it, and a symmetric
    decay would rank the remediation attempt above the cause.
    """
    weights = weights or load_weights()
    half_life = float(weights.get("temporal_half_life_minutes", 90))

    minutes_before = (alert.fired_at - event.occurred_at).total_seconds() / 60.0
    if minutes_before < 0:
        return 0.0
    return math.pow(0.5, minutes_before / half_life)


def type_prior(event: ChangeEvent, alert: Alert, weights: dict | None = None) -> float:
    """How often this kind of change causes this kind of alert.

    W14 replaces this body with the prior table from `config/priors.yaml`. Until then it
    returns the *declared* default so the ranking is driven by radius and time alone —
    which is honest, rather than a made-up prior that would have to be untangled later.
    """
    weights = weights or load_weights()
    return float(weights.get("type_prior_default", 0.5))


def score_events(
    events: list[ChangeEvent],
    alert: Alert,
    radius: BlastRadius,
    window: TimeWindow,
) -> list[Candidate]:
    """Rank events into candidates, highest score first.

    Ties break on recency, then on event id — deterministic, so the same inputs always
    produce the same brief. A nondeterministic tie-break would make the golden ranking
    test flake for reasons unrelated to the scorer.
    """
    weights = load_weights()
    coefficients = weights.get("weights") or {}

    scored: list[tuple[float, dict[str, float], ChangeEvent]] = []
    for event in events:
        features = {
            "radius_overlap": radius_overlap(event, radius),
            "temporal_proximity": temporal_proximity(event, alert, weights),
            "type_prior": type_prior(event, alert, weights),
        }
        total = sum(features[name] * float(coefficients.get(name, 0.0)) for name in features)
        divisor = sum(float(coefficients.get(name, 0.0)) for name in features) or 1.0
        scored.append((total / divisor, features, event))

    scored.sort(key=lambda row: (-row[0], -row[2].occurred_at.timestamp(), row[2].id))

    return [
        Candidate(event=event, score=round(score, 6), features=features, rank=index)
        for index, (score, features, event) in enumerate(scored, start=1)
    ]
