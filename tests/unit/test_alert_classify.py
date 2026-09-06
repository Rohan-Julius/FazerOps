"""W13 — alert classification.

Classification feeds `type_prior`, and that is the whole reason this file is careful. A
misclassified alert does not surface as a misclassification: every prior lookup in W14's
table is wrong, the ConfigMap does not rank first, and the symptom is a ranking that looks
like a scoring bug in a module two hops away.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fazerops.ingest.alerts import normalize_alert
from fazerops.ingest.classify import classify
from fazerops.models import AlertClass

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "alerts"
CLASSES = FIXTURES / "classes"


def _load(name: str) -> dict:
    return json.loads((CLASSES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "name",
    [
        "latency_spike",
        "error_rate_spike",
        "connection_refused",
        "auth_failure",
        "oom",
        "disk_pressure",
    ],
)
def test_each_fixture_alert_maps_to_its_class(name):
    """Six fixtures, six classes, one file each. The fixture is named after the class it
    must produce, so a rule change that breaks one names itself in the failure."""
    assert normalize_alert(_load(name)).alert_class is AlertClass(name)


def test_an_unrecognised_alert_is_unclassified_never_a_guess():
    """`unclassified` is a real outcome that W14 answers with a declared default prior. A
    nearest-fit guess would supply a confident wrong prior, which is worse than none."""
    assert normalize_alert(_load("unclassified")).alert_class is AlertClass.UNCLASSIFIED


def test_every_class_has_a_fixture():
    """Guards the reverse direction: adding a class to the enum without a fixture leaves
    it untested, and an untested class is one nothing ever proves is reachable."""
    covered = {path.stem for path in CLASSES.glob("*.json")}
    assert covered == {member.value for member in AlertClass}


# --------------------------------------------------------------------------------------
# The rule that decides the demo
# --------------------------------------------------------------------------------------


def test_the_authored_name_beats_the_summarys_secondary_symptom():
    """The demo's own alert. Its summary matches both a latency and an error-rate pattern;
    only `BillingApiLatencyHigh` says which one the alert is about. Classify off the
    summary alone and the demo's `type_prior` lookup changes row."""
    summary = "billing-api p99 latency above threshold; error rate climbing"
    assert classify(summary, signals=["BillingApiErrorRateHigh"]) is AlertClass.ERROR_RATE_SPIKE
    assert classify(summary, signals=["BillingApiLatencyHigh"]) is AlertClass.LATENCY_SPIKE


@pytest.mark.parametrize("shape", ["alertmanager", "cloudwatch", "pagerduty"])
def test_all_three_ingest_shapes_classify_the_demo_alert_identically(shape):
    """Idea §6 promises generic ingest. Three shapes of one incident must not produce three
    priors — including PagerDuty, which carries no authored name and has only the title."""
    payload = json.loads((FIXTURES / f"{shape}.json").read_text(encoding="utf-8"))
    assert normalize_alert(payload).alert_class is AlertClass.LATENCY_SPIKE


# --------------------------------------------------------------------------------------
# Rule behaviour
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("OOMKilled", AlertClass.OOM),
        ("pod evicted, out of memory", AlertClass.OOM),
        ("DiskPressure", AlertClass.DISK_PRESSURE),
        ("no space left on device", AlertClass.DISK_PRESSURE),
        ("dial tcp 10.0.4.2:5432: connection refused", AlertClass.CONNECTION_REFUSED),
        ("ECONNREFUSED talking to billing-primary", AlertClass.CONNECTION_REFUSED),
        ("403 Forbidden on token exchange", AlertClass.AUTH_FAILURE),
        ("authentication failed for service account", AlertClass.AUTH_FAILURE),
        ("p99 response time degraded", AlertClass.LATENCY_SPIKE),
        ("5xx ratio above budget", AlertClass.ERROR_RATE_SPIKE),
    ],
)
def test_the_rules_cover_the_conventions_these_strings_actually_arrive_in(text, expected):
    """Three naming conventions reach this function at once — `BillingApiLatencyHigh`,
    `billing-api-p99-latency`, `DiskPressure` — plus raw driver errors quoted into a
    summary. Matching is case-insensitive and tolerant of `-` and `_` for that reason."""
    assert classify(text) is expected


def test_classification_is_case_and_separator_insensitive():
    for spelling in ("DiskPressure", "disk_pressure", "disk-pressure", "DISK PRESSURE"):
        assert classify(spelling) is AlertClass.DISK_PRESSURE


def test_a_generic_pattern_never_shadows_a_specific_one():
    """`_RULES` is ordered most-specific first and the first match wins. An OOM alert whose
    summary also mentions errors is an OOM alert — `error_rate_spike`'s vocabulary is a
    superset of the others', so ordering is the only thing keeping it from swallowing them.
    """
    assert classify("OOMKilled; error rate climbing") is AlertClass.OOM
    assert classify("connection refused, 500s spiking") is AlertClass.CONNECTION_REFUSED


def test_empty_input_is_unclassified_rather_than_an_error():
    """An alert with no summary is a thin alert, not a malformed one. It still investigates
    — with a declared default prior — rather than 400ing at the webhook."""
    assert classify("") is AlertClass.UNCLASSIFIED
    assert classify("", signals=[None, ""]) is AlertClass.UNCLASSIFIED
