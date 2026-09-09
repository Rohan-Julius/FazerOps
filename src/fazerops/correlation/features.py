"""W14 + W14b — the four correlation features, as deterministic Python (Handoff §6).

Handoff §6 puts the features here and the weighted sum in `scoring.py`, and the split is
worth keeping: a feature is a claim about the world that can be argued with on its own
terms, while the weighting is a tuning decision. `tests/unit/test_features.py` tests the
claims; W15's golden ranking test tests the tuning.

**`in_band` is not a feature and never will be.** Handoff §3 is explicit that boosting a
change because it did not go through CI is circular — the product's whole thesis is that
out-of-band changes are under-examined, and scoring them higher *because* they are
out-of-band would manufacture the finding it claims to discover. The fact is reported in
the brief and weighed by the human.
"""

from __future__ import annotations

import functools
import math
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from ..models import Alert, BlastRadius, ChangeEvent, TimeWindow
from .priors import default_priors, normalize_type

if TYPE_CHECKING:  # the features read the ledger; the ledger knows nothing of them
    from ..ledger.store import LedgerStore

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
    half_life = float(weights.get("temporal_half_life_minutes", 40))

    minutes_before = (alert.fired_at - event.occurred_at).total_seconds() / 60.0
    if minutes_before < 0:
        return 0.0
    return math.pow(0.5, minutes_before / half_life)


def type_prior(event: ChangeEvent, alert: Alert, weights: dict | None = None) -> float:
    """How often this kind of change causes this kind of alert — `priors.py`'s table.

    A cell the table declares no row for falls back to `type_prior_default`, which is a
    *declared* default rather than a KeyError path. Every unlisted cell resolves; none
    raises. That is the whole reason the fallback lives here rather than inside the table:
    "no row" and "a row worth the default" are different facts about the ranking.
    """
    weights = weights or load_weights()
    declared = default_priors().lookup(event, alert.alert_class)
    if declared is not None:
        return declared
    return float(weights.get("type_prior_default", 0.5))


def recurrence(
    event: ChangeEvent,
    alert: Alert,
    radius: BlastRadius,
    ledger: LedgerStore | None = None,
    weights: dict | None = None,
) -> float:
    """W14b. Handoff §6: *has this (action, resource_type) preceded this alert signature
    before?* A ledger query, and **0.0 on cold start**.

    The fraction of prior alerts of the same signature — same class, same service — that
    had a change of this same shape in the window before them. It is a genuine query
    against the same store the demo populates (plan §3.3), not a parallel history: the
    ledger holds the changes already, so the only thing that had to be remembered is that
    an alert fired at all.

    Zero is the correct answer on the demo's cold start, not an absent one. There are no
    prior alerts, so no shape has recurred, and `weights.yaml` gives the feature a weight
    of 0.0 precisely because a term that cannot carry signal yet must not add noise to the
    one ranking that is on camera.
    """
    if ledger is None:
        return 0.0

    previous = ledger.prior_alerts(alert)
    if not previous:
        return 0.0

    weights = weights or load_weights()
    lookback = timedelta(hours=float(weights.get("recurrence_lookback_hours", 4)))
    signature = (event.action, normalize_type(event.resource.kind))

    matched = 0
    for past in previous:
        window = TimeWindow(start=past.fired_at - lookback, end=past.fired_at)
        for candidate in ledger.query(radius, window):
            if (candidate.action, normalize_type(candidate.resource.kind)) == signature:
                matched += 1
                break

    return matched / len(previous)
