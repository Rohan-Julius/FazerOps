"""W15 — the golden ranking test. This test *is* the demo, asserted.

Plan §2 rates the correlation path tier B: if the ConfigMap does not rank first, the
90-second narrative collapses. Everything else in this repo can be defended in prose; this
cannot, so it is asserted end-to-end through `pipeline.investigate` — the same call the
demo makes — rather than against the scorer in isolation. A scorer that ranks correctly
while the pipeline hands it the wrong candidate set is not a demo that works.

**Never cut** (CLAUDE.md working conventions), and deterministic by construction: no model
sits anywhere in this path (plan §3.2), so a flake here is a real regression.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from fazerops.ingest.alerts import normalize_alert
from fazerops.pipeline import investigate

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = json.loads((REPO_ROOT / "tests" / "golden" / "demo_ranking.json").read_text())


@pytest.fixture(scope="module")
def brief():
    payload = json.loads((REPO_ROOT / GOLDEN["alert"]["fixture"]).read_text())
    alert = normalize_alert(payload)
    return asyncio.run(investigate(alert, hours=GOLDEN["alert"]["window_hours"]))


def test_the_alert_classifies_as_the_golden_file_expects(brief):
    """The prior table is keyed on alert class, so a classification regression would move
    every score at once. Asserted here so that failure names itself instead of surfacing
    as three simultaneously wrong scores."""
    assert brief.alert.service == GOLDEN["alert"]["service"]
    assert brief.alert.alert_class.value == GOLDEN["alert"]["alert_class"]


def test_the_candidate_set_is_exactly_the_golden_one(brief):
    """Order asserted as a whole. A per-rank loop that passes on two of three candidates
    still describes a demo that shows the wrong thing."""
    expected = [(c["resource_kind"], c["resource_name"]) for c in GOLDEN["candidates"]]
    actual = [(c.event.resource.kind, c.event.resource.name) for c in brief.candidates]
    assert actual == expected


def test_the_configmap_change_is_rank_one_with_a_real_margin(brief):
    """The gate. A bare "rank 1" assertion passes on a coin-flip tie, which is the one
    result that would look green and demo red — the tie-break is deterministic, so a tie
    would resolve the same way in CI and on camera right up until a fixture is re-recorded.
    """
    first, second = brief.candidates[0], brief.candidates[1]

    assert first.event.resource.name == "billing-api-config"
    margin = first.score - second.score
    assert margin >= GOLDEN["minimum_rank_1_margin"], (
        f"rank-1 margin collapsed to {margin:.3f} "
        f"(floor {GOLDEN['minimum_rank_1_margin']}): {first.score:.3f} vs {second.score:.3f}"
    )


@pytest.mark.parametrize("expected", GOLDEN["candidates"], ids=lambda c: c["resource_name"])
def test_each_candidate_matches_its_golden_row(brief, expected):
    candidate = brief.candidates[expected["rank"] - 1]
    event = candidate.event

    assert event.resource.name == expected["resource_name"]
    assert event.resource.kind == expected["resource_kind"]
    assert event.resource.blast_radius_key() == expected["blast_radius_key"]
    assert event.action.value == expected["action"]
    assert event.source == expected["source"]
    assert event.in_band is expected["in_band"]

    low, high = expected["score_band"]
    assert low <= candidate.score <= high, (
        f"{expected['resource_name']} scored {candidate.score:.3f}, outside [{low}, {high}]"
    )


def test_the_evidence_ids_are_the_recorded_ones(brief):
    """Provenance, not correctness. These are real `auditID`s from a live API server
    (W7b); re-recording `fixtures/k8s_audit/` must fail here loudly rather than silently
    ranking a different set of events into the same shape."""
    assert [c.event.id for c in brief.candidates] == [
        c["evidence_id"] for c in GOLDEN["candidates"]
    ]


def test_every_candidate_cites_evidence_that_exists(brief):
    """Handoff §6: drop any claim that does not carry an event id. The brief is what the
    correlator (W18) will cite from, so an uncitable candidate is a fabrication waiting to
    happen one unit downstream."""
    for candidate in brief.candidates:
        assert candidate.event.id
        assert candidate.event.raw_ref


def test_the_demo_ranking_does_not_depend_on_the_weights(brief):
    """F2. The ConfigMap is ahead of every other change on every feature, so no weighting of
    `config/weights.yaml` ranks anything above it — the answer to "were the weights tuned to
    the demo?" is a property of the data, not a claim. A re-recorded fixture that loses this
    must be looked at, even if the margin floor above still passes."""
    assert brief.stability is not None
    assert brief.stability.dominant is True


def test_the_demo_reports_nothing_shipped_through_ci(brief):
    """Idea.md §7: the scenario was chosen because the cause is invisible to GitHub. If
    this line ever reads otherwise, the pitch is wrong, not just the brief."""
    assert brief.ci_status.merge_count == 0
    assert brief.candidates[0].event.in_band is False


def test_the_demo_brief_is_not_degraded(brief):
    """A degraded brief still renders and still ranks, so the demo would look fine while
    quietly resting on a dead collector."""
    assert brief.degraded is False


def test_the_ranking_is_stable_across_runs():
    """No model sits in this path (plan §3.2) and the tie-break is total, so the same
    inputs must produce byte-identical ranking. Re-run rather than trust the fixture: this
    is what makes the golden assertion a guarantee instead of a sample."""
    payload = json.loads((REPO_ROOT / GOLDEN["alert"]["fixture"]).read_text())

    runs = [
        [
            (c.event.id, c.score)
            for c in asyncio.run(
                investigate(normalize_alert(payload), hours=GOLDEN["alert"]["window_hours"])
            ).candidates
        ]
        for _ in range(3)
    ]

    assert runs[0] == runs[1] == runs[2]
