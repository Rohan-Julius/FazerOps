"""W2 — the schema is the repo's first line of defence. Every assertion here exists
because the failure it prevents is silent at construction time and loud on demo day.
"""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from fazerops.models import (
    Actor,
    Alert,
    AlertClass,
    BlastRadius,
    Brief,
    Candidate,
    ChangeEvent,
    CIStatus,
    Diff,
    NormalizedAction,
    Proposal,
    ResourceRef,
    TimeWindow,
)

UTC_NOON = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)

CONFIGMAP = ResourceRef(kind="ConfigMap", name="billing-api-config", namespace="billing")
DINESH = Actor(raw="dinesh@example.com", canonical="dinesh", resolved=True, kind="human")


def _event(**overrides) -> ChangeEvent:
    base = dict(
        id="k8s-1",
        source="k8s_audit",
        occurred_at=UTC_NOON,
        actor=DINESH,
        action=NormalizedAction.UPDATE,
        resource=CONFIGMAP,
        in_band=False,
        raw_ref="audit.log#L42",
    )
    return ChangeEvent(**{**base, **overrides})


# --- occurred_at ----------------------------------------------------------------------


def test_naive_occurred_at_is_rejected():
    """The single highest-blast-radius bug in the repo. A naive datetime silently
    reorders the causal chain and the symptom appears in the scorer."""
    with pytest.raises(ValidationError):
        _event(occurred_at=datetime(2026, 9, 6, 12, 0))  # no tzinfo


def test_offset_datetimes_collapse_to_the_same_utc_instant():
    """Helm reports local-formatted times. 07:00-05:00 and 12:00Z are one moment."""
    minus_five = timezone(timedelta(hours=-5))
    helm_style = _event(occurred_at=datetime(2026, 9, 6, 7, 0, tzinfo=minus_five))

    assert helm_style.occurred_at == UTC_NOON
    assert helm_style.occurred_at.tzinfo is timezone.utc


# --- reversibility --------------------------------------------------------------------


def test_reversible_without_an_inverse_hint_is_a_validation_error():
    """Ground rule #4. An event claiming reversibility without the means to reverse it
    fails at the executor instead — mid-demo, with a mutation already applied."""
    with pytest.raises(ValidationError, match="inverse_hint"):
        _event(reversible=True, inverse_hint=None)


def test_reversible_with_an_inverse_hint_is_accepted():
    event = _event(reversible=True, inverse_hint={"key": "pool.max", "prior": "100"})
    assert event.inverse_hint == {"key": "pool.max", "prior": "100"}


def test_irreversible_events_need_no_hint():
    assert _event(reversible=False).inverse_hint is None


# --- blast radius keys ----------------------------------------------------------------


def test_blast_radius_keys_is_a_set_of_strings():
    event = _event(blast_radius_keys={"k8s:billing/configmap/billing-api-config"})
    assert isinstance(event.blast_radius_keys, set)
    assert all(isinstance(k, str) for k in event.blast_radius_keys)


def test_blast_radius_keys_defaults_to_empty_not_none():
    """A None here would need a guard at every query site; one of them would be missed."""
    assert _event().blast_radius_keys == set()


def test_namespaced_and_arn_resources_key_differently_but_deterministically():
    """Both sides of the ledger index call this. Disagreement returns an empty candidate
    set and a brief that confidently reports nothing changed."""
    assert CONFIGMAP.blast_radius_key() == "k8s:billing/configmap/billing-api-config"

    rds = ResourceRef(
        kind="DBInstance",
        name="billing-primary",
        arn="arn:aws:rds:us-east-1:111122223333:db:billing-primary",
    )
    assert rds.blast_radius_key() == "aws:arn:aws:rds:us-east-1:111122223333:db:billing-primary"

    # Same inputs, same key — every time.
    assert CONFIGMAP.blast_radius_key() == CONFIGMAP.blast_radius_key()


# --- actor ----------------------------------------------------------------------------


def test_unmapped_actor_passes_through_unresolved():
    """Handoff §3: partial identity mapping is fine. Dropping the actor is not."""
    actor = Actor(raw="arn:aws:iam::111122223333:user/contractor")
    assert actor.resolved is False
    assert actor.canonical is None
    assert actor.display == "arn:aws:iam::111122223333:user/contractor"


def test_resolved_actor_must_carry_a_canonical_identity():
    with pytest.raises(ValidationError, match="canonical"):
        Actor(raw="dinesh@example.com", resolved=True)


# --- diff -----------------------------------------------------------------------------


def test_diff_reports_only_the_fields_that_actually_changed():
    diff = Diff(
        before={"pool.max": "100", "timeout": "30s"},
        after={"pool.max": "20", "timeout": "30s"},
    )
    assert diff.fields_changed == ["pool.max"]


def test_cloudtrail_style_diff_marks_the_prior_value_as_uncaptured():
    """Plan §3.6 — we label it honestly rather than reconstructing it."""
    diff = Diff(after={"MaxConnections": "20"}, prior_value_captured=False)
    assert diff.before is None
    assert diff.prior_value_captured is False


# --- window ---------------------------------------------------------------------------


def test_window_is_half_open():
    window = TimeWindow(start=UTC_NOON, end=UTC_NOON + timedelta(hours=4))
    assert window.contains(UTC_NOON) is True
    assert window.contains(UTC_NOON + timedelta(hours=4)) is False
    assert window.hours == 4.0


def test_inverted_window_is_rejected():
    with pytest.raises(ValidationError):
        TimeWindow(start=UTC_NOON, end=UTC_NOON - timedelta(hours=1))


# --- blast radius ---------------------------------------------------------------------


def test_radius_overlap_is_set_intersection():
    radius = BlastRadius(
        service="billing-api",
        keys={"k8s:billing/configmap/billing-api-config", "aws:arn:...:db:billing-primary"},
        direct_keys={"k8s:billing/configmap/billing-api-config"},
    )
    assert radius.overlaps({"k8s:billing/configmap/billing-api-config"}) is True
    assert radius.overlaps({"k8s:other/configmap/unrelated"}) is False


# --- brief ----------------------------------------------------------------------------


def _brief(candidates) -> Brief:
    return Brief(
        incident_id="INC-1",
        alert=Alert(
            id="A-1",
            service="billing-api",
            summary="billing-api p99 latency above threshold",
            fired_at=UTC_NOON,
            alert_class=AlertClass.LATENCY_SPIKE,
        ),
        radius=BlastRadius(service="billing-api"),
        window=TimeWindow(start=UTC_NOON - timedelta(hours=4), end=UTC_NOON),
        candidates=candidates,
        ci_status=CIStatus(merge_count=0),
    )


def test_brief_rejects_out_of_order_ranks():
    """A mis-ranked brief puts the wrong change at the top of the Slack message — the
    exact failure the demo cannot survive, and it raises no exception on its own."""
    out_of_order = [
        Candidate(event=_event(id="a"), score=0.4, rank=2),
        Candidate(event=_event(id="b"), score=0.9, rank=1),
    ]
    with pytest.raises(ValidationError, match="ranks"):
        _brief(out_of_order)


def test_brief_accepts_dense_ordered_ranks_and_exposes_the_top_candidate():
    ordered = [
        Candidate(event=_event(id="b"), score=0.9, rank=1),
        Candidate(event=_event(id="a"), score=0.4, rank=2),
    ]
    brief = _brief(ordered)
    assert brief.top is not None
    assert brief.top.event.id == "b"


def test_empty_brief_is_valid_and_has_no_top_candidate():
    """A degraded run must still render. It reports nothing found; it does not crash."""
    brief = _brief([])
    assert brief.candidates == []
    assert brief.top is None


def test_score_outside_zero_to_one_is_rejected():
    with pytest.raises(ValidationError):
        Candidate(event=_event(), score=1.4, rank=1)


# --- proposal -------------------------------------------------------------------------


def test_proposal_forbids_extra_keys():
    """Free-form output here is the whole attack surface (W22). A model that invents a
    `command` field must fail validation, not have it silently ignored."""
    with pytest.raises(ValidationError):
        Proposal(
            action_id="revert_configmap_key",
            params={"key": "pool.max"},
            rationale="restore prior value",
            command="kubectl delete ns billing",  # the thing that must never work
        )


def test_proposal_carries_evidence_ids():
    proposal = Proposal(
        action_id="revert_configmap_key",
        params={"key": "pool.max", "value": "100"},
        rationale="pool.max was reduced 38 minutes before the alert",
        evidence_ids=["k8s-1"],
    )
    assert proposal.evidence_ids == ["k8s-1"]


# --- in_band --------------------------------------------------------------------------


def test_in_band_is_required_and_has_no_default():
    """Handoff §3 reports it and forbids it as a scoring input. Defaulting it would let a
    collector forget to set it and quietly report every change as in-band."""
    with pytest.raises(ValidationError):
        ChangeEvent(
            id="x",
            source="k8s_audit",
            occurred_at=UTC_NOON,
            actor=DINESH,
            action=NormalizedAction.UPDATE,
            resource=CONFIGMAP,
            raw_ref="audit.log#L1",
        )
