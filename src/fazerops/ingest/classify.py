"""W13 — alert classification. Rules over the alert's own text, never a model.

Handoff §6: map the incoming alert to one of six signature classes with simple rules over
the alert name and labels. "Rules, not a model — it's five regexes and it never
hallucinates." The class feeds `type_prior` in W14's scoring table, so a misclassification
does not surface as a misclassification: every prior lookup is wrong, the ranking fails,
and it looks like a scoring bug three modules away.

Two design choices that are load-bearing, and both are about *not guessing*:

**Structured fields are read before free text.** An alert's name and labels are authored by
whoever wrote the alerting rule; the summary is a sentence that routinely quotes a
downstream symptom. The demo's own alert is the case in point — `BillingApiLatencyHigh`
with the summary "p99 latency above threshold; error rate climbing". Both a latency and an
error-rate pattern match that summary. Only the *name* says which one the alert is about.

**An unmatched alert is `unclassified`, not the nearest fit.** `unclassified` is a real
outcome that W14 handles with a declared default prior. A nearest-fit guess would supply a
confident wrong prior instead, which is strictly worse than no prior at all.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..models import AlertClass

# Word separators as these strings actually arrive: `DiskPressure` (lowercased to one
# word), `disk_pressure`, `disk-pressure`, `disk pressure`. Every multi-word pattern below
# joins on this rather than on `\s*`, because which convention a given alerting rule uses
# is not knowable from here.
_SEP = r"[\s_-]*"

# Ordered most-specific first, and the order is the tie-break: the first pattern to match
# wins. Generality increases downward, so a broad pattern can never shadow a narrow one.
# `error_rate_spike` is last on purpose — "error" appears inside summaries for nearly every
# other class here, and it is the only class whose vocabulary is a superset of the others'.
_RULES: tuple[tuple[AlertClass, re.Pattern[str]], ...] = (
    (
        AlertClass.OOM,
        re.compile(rf"\boom\b|oomkilled|out{_SEP}of{_SEP}memory|memory{_SEP}(exhaust|limit)"),
    ),
    (
        AlertClass.DISK_PRESSURE,
        re.compile(
            rf"disk{_SEP}pressure|no{_SEP}space{_SEP}left|"
            rf"disk{_SEP}(space|usage|full|utilization)|"
            rf"ephemeral{_SEP}storage|volume{_SEP}full"
        ),
    ),
    (
        AlertClass.CONNECTION_REFUSED,
        re.compile(
            rf"connection{_SEP}refused|econnrefused|"
            rf"(unable|failed|refusing){_SEP}to{_SEP}connect|"
            rf"connection{_SEP}pool{_SEP}exhaust"
        ),
    ),
    (
        AlertClass.AUTH_FAILURE,
        re.compile(
            rf"auth(entication|orization)?{_SEP}(failure|failed|error|denied|reject)|"
            rf"unauthori[sz]ed|forbidden|\b40[13]\b|"
            rf"(access|permission){_SEP}denied|invalid{_SEP}credentials"
        ),
    ),
    (
        AlertClass.LATENCY_SPIKE,
        re.compile(
            rf"latenc|\bp9[59]\b|response{_SEP}time|slow{_SEP}respon|apdex|"
            rf"duration{_SEP}high"
        ),
    ),
    (
        AlertClass.ERROR_RATE_SPIKE,
        re.compile(
            rf"error{_SEP}(rate|budget|ratio)|5xx|\b50[0234]\b|"
            rf"failure{_SEP}rate|errors?{_SEP}(spik|climb|surg|elevat)"
        ),
    ),
)


def classify(summary: str, *, signals: Iterable[str] = ()) -> AlertClass:
    """Classify an alert. `signals` are the authored fields — alert name, alarm name,
    label values — and are matched before `summary` falls back to free text.

    Matching is case-insensitive and whitespace-tolerant because these strings arrive in
    three conventions at once: `BillingApiLatencyHigh`, `billing-api-p99-latency`, and
    `DiskPressure`. Lowercasing collapses the first two; the patterns treat `-` and `_` as
    separators where it matters.
    """
    authored = " ".join(str(signal) for signal in signals if signal).lower()
    if authored:
        matched = _first_match(authored)
        if matched is not None:
            return matched

    return _first_match((summary or "").lower()) or AlertClass.UNCLASSIFIED


def _first_match(text: str) -> AlertClass | None:
    for alert_class, pattern in _RULES:
        if pattern.search(text):
            return alert_class
    return None
