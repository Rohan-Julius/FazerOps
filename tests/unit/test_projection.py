"""W16 — projection and the token budget. Handoff §10.

"Don't paste raw CloudTrail JSON into a prompt, project it to the fields the model
actually needs." This is the half of W16 with no visible symptom: a projection leak still
produces a correct brief, and the only evidence is the bill. Plan §2 rates it tier A for
exactly that reason — a 10k-token prompt becomes 120k and nothing on screen changes.

So the assertions are about what is *absent*, which is the only kind of assertion that
catches a leak.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from fazerops.models import (
    Actor,
    Alert,
    AlertClass,
    Candidate,
    ChangeEvent,
    Diff,
    ResourceRef,
)
from fazerops.security.envelope import (
    MAX_PROJECTED_TOKENS,
    estimate_tokens,
    project_alert_for_llm,
    project_candidate_for_llm,
    project_event_for_llm,
    render_candidate_for_llm,
)

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)

RAW_REF = "k8s_audit:65a6f2b9-9a21-4c85-94bd-641b40bb50e6"


def event(**overrides) -> ChangeEvent:
    fields = {
        "id": "e-1",
        "source": "k8s_audit",
        "occurred_at": ALERT_TIME - timedelta(minutes=38),
        "actor": Actor(raw="dinesh@faber-demo.io", canonical="dinesh", resolved=True),
        "action": "update",
        "resource": ResourceRef(
            kind="ConfigMap", name="billing-api-config", namespace="billing"
        ),
        "diff": Diff(before={"pool.max": "100"}, after={"pool.max": "20"}),
        "blast_radius_keys": {"k8s:billing/configmap/billing-api-config"},
        "in_band": False,
        "raw_ref": RAW_REF,
    }
    fields.update(overrides)
    return ChangeEvent(**fields)


def as_text(payload) -> str:
    return json.dumps(payload, sort_keys=True)


# --------------------------------------------------------------------------------------
# What is withheld
# --------------------------------------------------------------------------------------


def test_the_raw_ref_never_reaches_the_model():
    """`raw_ref` is a pointer, so it is cheap — and withheld anyway. The model has no use
    for a path into a fixture directory, and a field the model cannot see is one a future
    refactor cannot inflate into the payload it points at."""
    assert RAW_REF not in as_text(project_event_for_llm(event()))


def test_the_blast_radius_keys_never_reach_the_model():
    """The scorer already consumed them (ground rule #3). Sending them invites the model
    to re-derive a radius it was not asked to compute, and to disagree with Python."""
    assert "blast_radius_keys" not in project_event_for_llm(event())
    assert "k8s:billing/configmap" not in as_text(project_event_for_llm(event()))


def test_the_inverse_hint_never_reaches_the_model():
    """Plan §3.5: opaque to the investigation layer. Only `actions/inverse.py` reads it,
    and a model that saw it would start proposing parameters instead of an `action_id`."""
    reversible = event(
        reversible=True,
        inverse_hint={"key": "pool.max", "restore_to": "SENTINEL-100", "executor": "k8s"},
    )
    assert "inverse_hint" not in project_event_for_llm(reversible)
    assert "SENTINEL-100" not in as_text(project_event_for_llm(reversible))


# --------------------------------------------------------------------------------------
# What is kept, and why
# --------------------------------------------------------------------------------------


def test_the_event_id_is_kept_because_citations_are_built_from_it():
    """Handoff §6: drop any claim that does not carry an event id. A projection without
    the id makes citation impossible, so W18's validator would reject everything."""
    assert project_event_for_llm(event())["event_id"] == "e-1"


def test_the_diff_keys_and_values_are_kept():
    projected = project_event_for_llm(event())
    assert projected["diff"]["changed_keys"] == ["pool.max"]
    assert projected["diff"]["before"] == {"pool.max": "100"}
    assert projected["diff"]["after"] == {"pool.max": "20"}


def test_an_uncaptured_prior_value_is_flagged_to_the_model():
    """CloudTrail returns no prior value (plan §3.6). A model shown only `after` writes
    "changed from the default" without hesitating — a fabrication the citation validator
    cannot catch, because the event id it cites is real."""
    cloudtrail = event(
        source="cloudtrail",
        diff=Diff(after={"max_connections": "20"}, prior_value_captured=False),
    )
    assert project_event_for_llm(cloudtrail)["diff"]["prior_value_captured"] is False


def test_the_score_and_rank_are_given_rather_than_asked_for():
    """Ground rule #3. The model is told the ranking; it does not compute one. `rank` is
    present so W18's validator can reject a narrative naming a cause ranked below #1."""
    projected = project_candidate_for_llm(
        Candidate(event=event(), score=0.81, features={"radius_overlap": 1.0}, rank=1)
    )
    assert projected["rank"] == 1
    assert projected["score"] == 0.81
    assert projected["features"]["radius_overlap"] == 1.0


def test_in_band_is_reported_to_the_model_but_was_not_scored():
    """Not an input to the score (Handoff §3, asserted in `test_scoring.py`) — and the
    single most load-bearing fact in the brief (Idea.md §7). Reported, not weighted."""
    projected = project_candidate_for_llm(Candidate(event=event(), score=0.81, rank=1))
    assert projected["in_band"] is False


def test_an_unresolved_actor_is_labelled_as_such():
    """An unmapped actor passes through with `resolved=False` (W3). The model must be able
    to say "an unresolved principal" rather than assert an identity we did not establish."""
    unknown = event(actor=Actor(raw="arn:aws:iam::683590131574:user/someone"))
    projected = project_event_for_llm(unknown)

    assert projected["actor"] == "arn:aws:iam::683590131574:user/someone"
    assert projected["actor_resolved"] is False


# --------------------------------------------------------------------------------------
# The budget
# --------------------------------------------------------------------------------------


def test_a_projected_event_fits_the_budget():
    assert estimate_tokens(as_text(project_event_for_llm(event()))) < MAX_PROJECTED_TOKENS


def test_a_projected_candidate_fits_the_budget_once_enveloped():
    """Measured on the enveloped, indented form — the string that is actually sent. A
    budget asserted against a compact dict nobody transmits measures nothing."""
    candidate = Candidate(
        event=event(), score=0.81, features={"radius_overlap": 1.0}, rank=1
    )
    assert estimate_tokens(render_candidate_for_llm(candidate)) < MAX_PROJECTED_TOKENS


def test_a_pathological_configmap_value_cannot_blow_the_budget():
    """The single field in this payload with no upper bound. A ConfigMap value can be a
    base64 blob or an entire nginx.conf, and Kubernetes will hold ~1MB of it."""
    huge = event(diff=Diff(before={"cert": "A" * 40_000}, after={"cert": "B" * 40_000}))
    projected = project_event_for_llm(huge)

    assert estimate_tokens(as_text(projected)) < MAX_PROJECTED_TOKENS
    assert "truncated" in projected["diff"]["before"]["cert"]


def test_many_keys_are_not_a_way_around_the_per_value_truncation():
    """Truncating each value bounds one key. A diff with a thousand of them is the same
    leak wearing a different shape, so the budget is asserted over the whole projection."""
    wide = event(diff=Diff(after={f"key-{n:03d}": "x" * 200 for n in range(500)}))
    projected = project_event_for_llm(wide)

    assert estimate_tokens(render_candidate_for_llm(Candidate(event=wide, score=0.5, rank=1))) < (
        MAX_PROJECTED_TOKENS
    )
    # The model is told the diff was trimmed, so it can never read a partial diff as a
    # complete one — silently dropping keys would make it assert the other 488 unchanged.
    kept = projected["diff"]["changed_keys"]
    assert kept, "at least one key survives — 'N keys omitted' alone is not evidence"
    assert projected["diff"]["keys_omitted"] == 500 - len(kept)


def test_an_oversized_key_name_is_bounded_like_a_value():
    """Values are truncated before they are costed, so a key *name* is the only part of a
    diff that could overrun the budget on its own — and at least one key is always kept, so
    an unbounded name would defeat the budget through the very guarantee protecting it."""
    projected = project_event_for_llm(
        event(diff=Diff(after={"a" * 5_000: "x", "bbb": "y", "ccc": "z"}))
    )

    assert len(projected["diff"]["changed_keys"]) == 3, "truncation, not omission"
    assert max(len(k) for k in projected["diff"]["changed_keys"]) < 120
    assert estimate_tokens(as_text(projected)) < MAX_PROJECTED_TOKENS


def test_the_estimator_over_counts_rather_than_under_counts():
    """No Nova tokenizer ships with this build, so the estimate must err upward: an
    under-counting budget check is worse than none, because it reads as a guarantee."""
    assert estimate_tokens("a" * 350) >= 100


def test_the_whole_demo_brief_is_projectable_within_budget():
    """Three candidates is the demo. The per-event budget only matters if the sum of them
    is still a prompt worth sending."""
    import asyncio
    from pathlib import Path

    from fazerops.ingest.alerts import normalize_alert
    from fazerops.pipeline import investigate

    root = Path(__file__).resolve().parents[2]
    payload = json.loads((root / "fixtures" / "alerts" / "alertmanager.json").read_text())
    brief = asyncio.run(investigate(normalize_alert(payload)))

    total = sum(estimate_tokens(render_candidate_for_llm(c)) for c in brief.candidates)
    assert total < MAX_PROJECTED_TOKENS * len(brief.candidates)
    assert estimate_tokens(as_text(project_alert_for_llm(brief.alert))) < MAX_PROJECTED_TOKENS
