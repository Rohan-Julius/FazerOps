"""W18 — the citation validator. Handoff §6, and the only place a model can put fiction
in front of a user.

Everything else in this pipeline is deterministic: the collectors read logs, the scorer is
arithmetic in Python, the renderer prints what it is handed. The narrative is the single
model-authored surface, so it is the single surface that needs policing.

Handoff §6: *"Structure the output so every claim carries an event id, and drop any claim
that doesn't."* These tests are that sentence, plus the rule beside it — *"it must not
assert a cause the scoring didn't rank."*

The two are enforced differently on purpose, and the tests say why at each point.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from fazerops.agents.correlator import (
    Claim,
    CorrelatorOutput,
    NarrativeRejected,
    build_messages,
    validate_narrative,
)
from fazerops.models import (
    Actor,
    Alert,
    AlertClass,
    Brief,
    BlastRadius,
    Candidate,
    ChangeEvent,
    CIStatus,
    Diff,
    ResourceRef,
    TimeWindow,
)

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)

REAL_ID = "65a6f2b9-9a21-4c85-94bd-641b40bb50e6"
SECOND_ID = "3c5ddd53-790c-4329-a689-608f920ab5e6"
FABRICATED = "00000000-dead-beef-0000-000000000000"


def event(event_id: str, *, kind: str = "ConfigMap", name: str = "billing-api-config"):
    return ChangeEvent(
        id=event_id,
        source="k8s_audit",
        occurred_at=ALERT_TIME - timedelta(minutes=38),
        actor=Actor(raw="dinesh@faber-demo.io", canonical="dinesh", resolved=True),
        action="update",
        resource=ResourceRef(kind=kind, name=name, namespace="billing"),
        diff=Diff(before={"pool.max": "100"}, after={"pool.max": "20"}),
        blast_radius_keys={"k8s:billing/configmap/billing-api-config"},
        in_band=False,
        raw_ref=f"k8s_audit:{event_id}",
    )


CANDIDATES = [
    Candidate(event=event(REAL_ID), score=0.81, rank=1),
    Candidate(event=event(SECOND_ID, kind="Secret", name="billing-api-db"), score=0.54, rank=2),
]


def response(**overrides):
    payload = {
        "primary_cause_event_id": REAL_ID,
        "confidence": "high",
        "claims": [{"text": "The pool was cut from 100 to 20.", "evidence_ids": [REAL_ID]}],
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------------------------------------
# Rule 1 — every evidence id must exist among the events passed in
# --------------------------------------------------------------------------------------


def test_a_well_formed_narrative_survives_intact():
    result = validate_narrative(response(), CANDIDATES)

    assert len(result.claims) == 1
    assert result.dropped == []
    assert result.evidence_ids == [REAL_ID]


def test_a_fabricated_event_id_is_dropped_not_surfaced():
    """The headline test. A model that invents an event id must not have that id reach a
    user — it looks exactly like a real citation, and an engineer at 3am will chase it."""
    result = validate_narrative(
        response(
            claims=[
                {"text": "The pool was cut to 20.", "evidence_ids": [REAL_ID]},
                {"text": "An RDS parameter also changed.", "evidence_ids": [FABRICATED]},
            ]
        ),
        CANDIDATES,
    )

    assert [c.text for c in result.claims] == ["The pool was cut to 20."]
    assert FABRICATED not in result.evidence_ids
    assert FABRICATED not in result.text


def test_a_claim_mixing_a_real_and_a_fake_id_is_dropped_whole():
    """The most dangerous shape there is: it reads as sourced. Every id must be real, not
    merely one of them — keeping the claim and filtering the bad id would leave a sentence
    the surviving evidence does not support."""
    result = validate_narrative(
        response(
            claims=[{"text": "Both changes hit the pool.", "evidence_ids": [REAL_ID, FABRICATED]}]
        ),
        CANDIDATES,
    )

    assert result.claims == []
    assert len(result.dropped) == 1
    assert FABRICATED in result.dropped[0].reason


def test_a_claim_with_no_evidence_is_dropped():
    """Handoff §6: *drop any claim that doesn't carry an event id*. An uncited claim is
    not a small problem — it is the model's own opinion wearing the same typeface as the
    evidence."""
    result = validate_narrative(
        response(claims=[{"text": "This is probably a memory leak.", "evidence_ids": []}]),
        CANDIDATES,
    )

    assert result.claims == []
    assert result.dropped[0].reason == "no evidence id"


def test_dropping_a_claim_keeps_the_others():
    """A whole answer must not be discarded over one bad sentence — evidence is thinnest
    exactly when the agent is most needed."""
    result = validate_narrative(
        response(
            claims=[
                {"text": "Kept one.", "evidence_ids": [REAL_ID]},
                {"text": "Dropped.", "evidence_ids": [FABRICATED]},
                {"text": "Kept two.", "evidence_ids": [SECOND_ID]},
            ]
        ),
        CANDIDATES,
    )

    assert [c.text for c in result.claims] == ["Kept one.", "Kept two."]
    assert len(result.dropped) == 1


def test_what_was_dropped_is_recorded_rather_than_swallowed():
    """A validator that silently improves the model's output hides the fact that the model
    needed improving — and W17's cassettes are how that gets noticed."""
    result = validate_narrative(
        response(claims=[{"text": "Invented.", "evidence_ids": [FABRICATED]}]), CANDIDATES
    )

    assert result.dropped[0].text == "Invented."
    assert "unknown event id" in result.dropped[0].reason


def test_evidence_ids_are_deduplicated_in_citation_order():
    result = validate_narrative(
        response(
            claims=[
                {"text": "One.", "evidence_ids": [SECOND_ID]},
                {"text": "Two.", "evidence_ids": [REAL_ID, SECOND_ID]},
            ]
        ),
        CANDIDATES,
    )

    assert result.evidence_ids == [SECOND_ID, REAL_ID]


# --------------------------------------------------------------------------------------
# Rule 2 — it must not assert a cause the scorer did not rank first
# --------------------------------------------------------------------------------------


def test_naming_a_cause_the_scorer_ranked_below_first_is_rejected():
    """Not dropped — rejected. This is not a bad sentence; it is the model overriding a
    ranking computed from features it cannot see, and the ranking is the product. There
    is nothing to salvage from a narrative built on a wrong premise."""
    with pytest.raises(NarrativeRejected, match="ranked"):
        validate_narrative(response(primary_cause_event_id=SECOND_ID), CANDIDATES)


def test_naming_a_cause_that_does_not_exist_at_all_is_rejected():
    with pytest.raises(NarrativeRejected):
        validate_narrative(response(primary_cause_event_id=FABRICATED), CANDIDATES)


def test_the_model_may_disagree_in_a_claim_but_not_in_the_verdict():
    """The prompt tells it to say so and lower confidence rather than substitute its own
    ordering. That path has to actually work, or the instruction is a lie."""
    result = validate_narrative(
        response(
            confidence="low",
            claims=[
                {
                    "text": "Rank 1 is a weak fit; the secret rotation may matter more.",
                    "evidence_ids": [REAL_ID, SECOND_ID],
                }
            ],
        ),
        CANDIDATES,
    )

    assert result.confidence == "low"
    assert len(result.claims) == 1


def test_an_empty_candidate_set_cannot_be_narrated():
    """With nothing scored there is no rank 1, so any asserted cause is invented by
    construction."""
    with pytest.raises(NarrativeRejected, match="no candidates"):
        validate_narrative(response(), [])


# --------------------------------------------------------------------------------------
# Malformed output
# --------------------------------------------------------------------------------------


def test_a_non_json_response_is_rejected():
    with pytest.raises(NarrativeRejected, match="not JSON"):
        validate_narrative("I'm sorry, I can't help with that.", CANDIDATES)


def test_a_json_string_response_round_trips():
    """Bedrock returns text; the caller may hand it over unparsed."""
    result = validate_narrative(json.dumps(response()), CANDIDATES)
    assert result.primary_cause_event_id == REAL_ID


def test_a_response_missing_required_fields_is_rejected():
    with pytest.raises(NarrativeRejected, match="output schema"):
        validate_narrative({"claims": []}, CANDIDATES)


def test_an_invented_confidence_value_is_rejected():
    with pytest.raises(NarrativeRejected):
        validate_narrative(response(confidence="certain"), CANDIDATES)


def test_extra_keys_are_rejected():
    """A model inventing `recommended_action` is doing the proposer's job. W22's catalog
    is the only thing permitted to name an action (ground rule #1)."""
    with pytest.raises(NarrativeRejected):
        validate_narrative(response(recommended_action="delete_namespace"), CANDIDATES)


def test_a_json_array_is_rejected():
    with pytest.raises(NarrativeRejected, match="JSON object"):
        validate_narrative("[]", CANDIDATES)


# --------------------------------------------------------------------------------------
# Input — what the model is shown
# --------------------------------------------------------------------------------------


def brief_with(candidates) -> Brief:
    return Brief(
        incident_id="INC-1",
        alert=Alert(
            id="a-1",
            service="billing-api",
            summary="p99 latency above threshold",
            fired_at=ALERT_TIME,
            alert_class=AlertClass.LATENCY_SPIKE,
        ),
        radius=BlastRadius(service="billing-api", keys={"k8s:billing/configmap/x"}),
        window=TimeWindow(start=ALERT_TIME - timedelta(hours=4), end=ALERT_TIME),
        candidates=candidates,
        ci_status=CIStatus(merge_count=0),
    )


def test_every_candidate_reaches_the_model_inside_its_own_envelope():
    """Enveloped per candidate, not as one block, so a hostile value in one ConfigMap
    cannot appear to comment on another event (ground rule #2, W16)."""
    text = build_messages(brief_with(CANDIDATES))[0]["content"][0]["text"]

    assert text.count("<untrusted_data") == 3  # the alert plus two candidates
    assert text.count("</untrusted_data>") == 3


def test_the_alert_summary_is_never_bare_in_the_prompt():
    text = build_messages(brief_with(CANDIDATES))[0]["content"][0]["text"]
    assert text.lstrip().startswith("<untrusted_data")


def test_only_the_top_n_candidates_are_sent():
    many = [
        Candidate(event=event(f"e-{n}"), score=1.0 - n / 100, rank=n) for n in range(1, 11)
    ]
    text = build_messages(brief_with(many), top_n=5)[0]["content"][0]["text"]

    assert text.count('event_id="e-') == 5


def test_an_empty_brief_tells_the_model_to_say_nothing_changed():
    """A model handed zero events and no instruction will pattern-match its way to a
    plausible cause. The absence has to be stated."""
    text = build_messages(brief_with([]))[0]["content"][0]["text"]
    assert "No changes were found" in text


# --------------------------------------------------------------------------------------
# The stub path — the CI and clean-machine default
# --------------------------------------------------------------------------------------


async def test_the_stub_narrative_passes_its_own_validator(monkeypatch):
    """The zero-network path must exercise the validator, not bypass it — otherwise CI
    proves nothing about the code that runs on a judge's machine."""
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    from fazerops.agents.correlator import correlate

    result = await correlate(brief_with(CANDIDATES))

    assert result.primary_cause_event_id == REAL_ID
    assert result.dropped == []
    assert result.evidence_ids == [REAL_ID]


async def test_the_stub_cites_only_real_ids(monkeypatch):
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    from fazerops.agents.correlator import correlate

    known = {c.event.id for c in CANDIDATES}
    assert set((await correlate(brief_with(CANDIDATES))).evidence_ids) <= known


def test_the_claim_model_rejects_an_empty_sentence():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Claim(text="", evidence_ids=[REAL_ID])


def test_the_output_schema_is_the_contract():
    """`extra="forbid"` is what makes "and nothing else" true rather than aspirational."""
    assert CorrelatorOutput.model_config["extra"] == "forbid"


# --------------------------------------------------------------------------------------
# The cassette path — how agent behaviour is asserted in CI with no credentials
# --------------------------------------------------------------------------------------


@pytest.fixture
def recorded(tmp_path, monkeypatch):
    """Record one response, then replay it through `correlate` in cassette mode.

    Goes through the real key derivation rather than writing the file by hand: a test that
    hand-places a cassette under a guessed key proves the validator works and proves
    nothing about whether replay can find it.
    """
    monkeypatch.setenv("FAZEROPS_LLM", "cassette")

    from fazerops.agents.cassette import Cassette, request_key
    from fazerops.agents.llm import recording_model_for

    def _record(payload, brief):
        model = recording_model_for("correlator")
        key = request_key("correlator", model, build_messages(brief))
        Cassette("correlator", directory=tmp_path).record(key, payload, model=model)
        return tmp_path

    return _record


async def test_a_fabricated_id_in_a_cassette_response_is_dropped(recorded, monkeypatch):
    """Plan §4's W18 artifact, end to end: the fiction is on tape, and the validator is
    what stops it reaching the brief."""
    brief = brief_with(CANDIDATES)
    directory = recorded(
        response(
            claims=[
                {"text": "The pool was cut to 20.", "evidence_ids": [REAL_ID]},
                {"text": "A security group was revoked.", "evidence_ids": [FABRICATED]},
            ]
        ),
        brief,
    )

    from fazerops.agents.correlator import correlate

    result = await correlate(brief, cassette_directory=directory)

    assert [c.text for c in result.claims] == ["The pool was cut to 20."]
    assert FABRICATED not in result.text


async def test_a_cassette_response_naming_the_wrong_cause_is_rejected(recorded):
    brief = brief_with(CANDIDATES)
    directory = recorded(response(primary_cause_event_id=SECOND_ID), brief)

    from fazerops.agents.correlator import correlate

    with pytest.raises(NarrativeRejected, match="ranked"):
        await correlate(brief, cassette_directory=directory)


async def test_cassette_mode_opens_no_socket(recorded, monkeypatch):
    """The guarantee CI rests on. Asserted here and not only in `test_cassette.py`,
    because it is `correlate` — not the cassette class — that decides whether a live call
    happens."""
    import socket

    brief = brief_with(CANDIDATES)
    directory = recorded(response(), brief)

    def forbidden(*args, **kwargs):
        raise AssertionError("cassette mode opened a socket")

    monkeypatch.setattr(socket, "socket", forbidden)

    from fazerops.agents.correlator import correlate

    assert (await correlate(brief, cassette_directory=directory)).primary_cause_event_id == REAL_ID


async def test_a_missing_cassette_fails_loudly_rather_than_calling_out(recorded, monkeypatch):
    """A prompt edit invalidates the key. That must surface as a miss telling you to
    re-record, never as a silent live call on a machine with no credentials."""
    from fazerops.agents.cassette import CassetteMiss
    from fazerops.agents.correlator import correlate

    with pytest.raises(CassetteMiss, match="FAZEROPS_LLM=record"):
        await correlate(brief_with(CANDIDATES), cassette_directory=recorded(response(), brief_with([])))
