"""W22 — the proposer's contract. Handoff §7, plan §4.

The plan's three assertions: **extra keys rejected**, **`action_id` validated against the
catalog**, and **`evidence_ids` ⊆ the correlator's cited ids**.

Free-form output here is the whole attack surface — this is the one model response that
becomes a mutation — so the tests below are mostly about what the validator *refuses*.
Two of them are structural rather than behavioural, and those are the ones with teeth:

* the `action_id` enum is read out of the response **schema**, proving an uncatalogued
  action is not expressible rather than merely rejected afterwards;
* `tier` is proved absent from the model's schema entirely, so there is no field through
  which a Tier 2 action could argue its way down to an IC approval.

A validator tested only with hand-written good input proves the happy path, which is the
one path an attacker will not take.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fazerops.actions.catalog import default_catalog
from fazerops.agents.proposer import (
    ACTION_IDS,
    NO_ACTION,
    ProposalRejected,
    ProposerOutput,
    build_messages,
    propose,
    validate_proposal,
)
from fazerops.ingest.alerts import normalize_alert
from fazerops.models import Tier
from fazerops.pipeline import investigate

FIXTURE_ALERTS = Path(__file__).resolve().parents[2] / "fixtures" / "alerts"

VALID = {
    "action_id": "revert_configmap_key",
    "params": {
        "namespace": "billing",
        "name": "billing-api-config",
        "key": "pool.max",
        "target_value": "100",
    },
    "rationale": "The pool size was cut out of band 38 minutes before the alert.",
    "evidence_ids": [],  # filled per-test from the real brief
}


@pytest.fixture
async def brief(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    payload = json.loads((FIXTURE_ALERTS / "alertmanager.json").read_text(encoding="utf-8"))
    return await investigate(normalize_alert(payload))


@pytest.fixture
async def narrative(brief):
    """The real correlator output for this brief, so the subset rule is checked against
    what the analyst actually cited rather than against a list written to pass."""
    from fazerops.agents.correlator import correlate

    return await correlate(brief)


def _proposal(brief, narrative=None, **overrides):
    raw = {**VALID, "evidence_ids": [brief.candidates[0].event.id], **overrides}
    return validate_proposal(raw, brief, narrative)


# --------------------------------------------------------------------------------------
# Assertion 1 — extra keys rejected
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        {"command": "kubectl delete ns billing"},
        {"script": "rm -rf /"},
        {"tier": 1},
        {"requires_approval_from": "engineer"},
        {"executor": "fazerops.actions.executors.configmap:revert_key"},
    ],
)
async def test_an_extra_key_is_rejected_rather_than_dropped(brief, extra):
    """Ground rule #1 at the parse boundary.

    Refused, not silently stripped: a model reaching for `command` or `executor` is a
    model that has been talked into something, and the response is evidence about the run
    rather than noise to tidy away.
    """
    with pytest.raises(ProposalRejected, match="output schema"):
        _proposal(brief, **extra)


async def test_the_valid_shape_survives(brief):
    """The contract is four fields. This is the only shape that gets through."""
    proposal = _proposal(brief)

    assert proposal is not None
    assert set(proposal.model_dump()) == {
        "action_id",
        "params",
        "rationale",
        "evidence_ids",
        "tier",
    }


# --------------------------------------------------------------------------------------
# Assertion 2 — action_id validated against the catalog
# --------------------------------------------------------------------------------------


def test_the_action_id_enum_is_the_catalog():
    """Read from the catalog at import, so the two cannot drift. A hand-written enum is
    one that silently stops matching the day an action is added."""
    assert set(ACTION_IDS) == set(default_catalog().action_ids)
    assert ACTION_IDS == (
        "helm_rollback",
        "restore_db_parameter",
        "revert_configmap_key",
    )


def test_an_uncatalogued_action_is_not_expressible_in_the_response_schema():
    """The structural half, and the one that matters.

    A rejection *after* the fact can be forgotten at a call site. A `Literal` in the
    schema means the provider constrains generation and the string never exists — which
    is why this reads the schema rather than calling the validator.
    """
    schema = ProposerOutput.model_json_schema()
    allowed = set(schema["properties"]["action_id"]["enum"])

    assert allowed == {*default_catalog().action_ids, NO_ACTION}
    assert not any(name.startswith("delete") for name in allowed)


@pytest.mark.parametrize(
    "action_id",
    ["delete_namespace", "revert_configmap_key ", "REVERT_CONFIGMAP_KEY", "", "kubectl"],
)
async def test_an_action_outside_the_catalog_is_rejected(brief, action_id):
    with pytest.raises(ProposalRejected, match="output schema"):
        _proposal(brief, action_id=action_id)


async def test_parameters_failing_the_catalog_schema_are_rejected(brief):
    """`validate_params` runs **before anything constructs a client** — W20's ordering,
    relied on here rather than re-implemented."""
    with pytest.raises(ProposalRejected, match="rejected"):
        _proposal(brief, params={"namespace": "billing", "name": "billing-api-config"})


async def test_an_unknown_parameter_is_rejected(brief):
    """A parameter the schema does not declare is refused rather than passed through to an
    executor that might accept **kwargs."""
    with pytest.raises(ProposalRejected, match="rejected"):
        _proposal(brief, params={**VALID["params"], "force": "true"})


async def test_the_tier_comes_from_the_catalog_and_not_from_the_response(brief):
    """Handoff §7: tier is declared, never inferred — and never negotiated.

    `tier` is not in the model's schema at all, so there is no field to lie in. The
    assertion is therefore two-part: the value is the catalog's, and the key does not
    exist on the wire.
    """
    proposal = _proposal(brief)
    assert proposal.tier is default_catalog().get("revert_configmap_key").tier

    assert "tier" not in ProposerOutput.model_json_schema()["properties"]

    from fazerops.agents.proposer import _WireOutput

    assert "tier" not in _WireOutput.model_json_schema()["properties"]


async def test_a_tier_two_proposal_carries_tier_two(brief, narrative):
    """The Tier 2 action is routed by W26b on this field, so it has to be real here."""
    raw = {
        "action_id": "restore_db_parameter",
        "params": {
            "parameter_group": "billing-primary-params",
            "parameter": "max_connections",
            "target_value": "200",
        },
        "rationale": "Restore the connection limit.",
        "evidence_ids": [brief.candidates[0].event.id],
    }
    proposal = validate_proposal(raw, brief, narrative)

    assert proposal.tier is Tier.MANAGER_APPROVAL


# --------------------------------------------------------------------------------------
# Assertion 3 — evidence_ids ⊆ the correlator's cited ids
# --------------------------------------------------------------------------------------


async def test_evidence_ids_must_be_a_subset_of_what_the_analyst_cited(brief, narrative):
    """The plan's third assertion, against the real narrative.

    An action justified by evidence the analyst never cited arrives on the approval card
    reasoning from something that is not on the card — the human cannot follow it, which
    is the same failure as no rationale at all.
    """
    cited = set(narrative.evidence_ids)
    uncited = next(c.event.id for c in brief.candidates if c.event.id not in cited)

    with pytest.raises(ProposalRejected, match="the analyst did not"):
        _proposal(brief, narrative, evidence_ids=[uncited])


async def test_a_fabricated_evidence_id_is_rejected(brief, narrative):
    with pytest.raises(ProposalRejected, match="unknown event id"):
        _proposal(brief, narrative, evidence_ids=["evt-that-never-existed"])


async def test_one_real_and_one_invented_id_is_still_rejected(brief, narrative):
    """The shape that reads as sourced — W18 drops a claim like this, and the proposer
    refuses the whole proposal for it."""
    real = brief.candidates[0].event.id
    with pytest.raises(ProposalRejected, match="unknown event id"):
        _proposal(brief, narrative, evidence_ids=[real, "evt-invented"])


async def test_a_proposal_with_no_evidence_is_rejected(brief, narrative):
    """An action nobody can trace to a change is a guess, and a guess must not reach a
    card that has an Approve button on it."""
    with pytest.raises(ProposalRejected, match="no evidence ids"):
        _proposal(brief, narrative, evidence_ids=[])


# --------------------------------------------------------------------------------------
# Proposing nothing is a correct answer
# --------------------------------------------------------------------------------------


async def test_none_is_a_first_class_answer(brief, narrative):
    """A brief whose candidates carry no recorded prior value genuinely has no action
    behind it. A proposer that must always name one would name a wrong one."""
    raw = {"action_id": NO_ACTION, "params": {}, "rationale": "Nothing to revert.", "evidence_ids": []}

    assert validate_proposal(raw, brief, narrative) is None


async def test_declining_and_failing_validation_are_different_answers(brief, narrative):
    """`None` means the model declined — a correct outcome. `ProposalRejected` means it
    proposed something that did not survive checking, which belongs in the record."""
    declined = validate_proposal(
        {"action_id": NO_ACTION, "params": {}, "rationale": "", "evidence_ids": []},
        brief,
        narrative,
    )
    assert declined is None

    with pytest.raises(ProposalRejected):
        validate_proposal("not json", brief, narrative)


@pytest.mark.parametrize("raw", ["not json at all", "[1, 2, 3]", '"a string"'])
async def test_a_response_that_is_not_an_object_is_rejected(brief, raw):
    with pytest.raises(ProposalRejected):
        validate_proposal(raw, brief)


# --------------------------------------------------------------------------------------
# The stub path — the CI default and the judge's clean-machine default
# --------------------------------------------------------------------------------------


async def test_the_stub_proposes_the_demo_revert_through_the_real_validator(brief, narrative):
    """Derived from the ledger's own `inverse_hint`, not hardcoded — so the zero-network
    path exercises the validator instead of bypassing it, and stays true when the fixtures
    change."""
    proposal = await propose(brief, narrative)

    assert proposal is not None
    assert proposal.action_id == "revert_configmap_key"
    assert proposal.params == {
        "namespace": "billing",
        "name": "billing-api-config",
        "key": "pool.max",
        "target_value": "100",
    }
    assert proposal.evidence_ids == [brief.candidates[0].event.id]
    assert proposal.tier is Tier.ENGINEER_APPROVAL


async def test_the_stub_declines_when_nothing_carries_a_prior_value(brief, narrative):
    """The demo's rank-2 Secret has no recorded prior value, so an action against it
    cannot be undone — ground rule #4 forbids proposing it."""
    stripped = brief.model_copy(
        update={
            "candidates": [
                candidate.model_copy(
                    update={
                        "event": candidate.event.model_copy(
                            update={"reversible": False, "inverse_hint": None}
                        )
                    }
                )
                for candidate in brief.candidates
            ]
        }
    )

    assert await propose(stripped, narrative) is None


# --------------------------------------------------------------------------------------
# What the model is shown
# --------------------------------------------------------------------------------------


async def test_candidate_text_reaches_the_model_inside_an_envelope(brief, narrative):
    """Ground rule #2. Per candidate, not as one block — a hostile value in one ConfigMap
    must not appear to comment on another event."""
    text = build_messages(brief, narrative)[0]["content"][0]["text"]

    assert text.count("<untrusted_data") == len(brief.candidates) + 1  # candidates + alert
    for candidate in brief.candidates:
        assert candidate.event.id in text


async def test_the_narrative_is_shown_so_the_subset_rule_is_satisfiable(brief, narrative):
    """A model cannot satisfy a constraint it was not shown. The narrative is *not*
    enveloped — it is this system's own validated output, and wrapping it would teach the
    model that the tag means nothing."""
    text = build_messages(brief, narrative)[0]["content"][0]["text"]

    assert "Cited evidence ids:" in text
    for event_id in narrative.evidence_ids:
        assert event_id in text


async def test_an_empty_brief_is_told_to_propose_nothing(brief):
    empty = brief.model_copy(update={"candidates": []})
    text = build_messages(empty)[0]["content"][0]["text"]

    assert '"none"' in text


# --------------------------------------------------------------------------------------
# The graph node — plan §3.2's `correlator ──▶ proposer` edge
# --------------------------------------------------------------------------------------


async def test_the_proposer_joins_the_graph_by_injection(monkeypatch):
    """The diagram's last edge, built without `graph.py` importing the catalog.

    `tests/integration/test_layer_seam.py` now asserts `fazerops.agents.graph` imports with
    the automation layer deleted, so this test is the other half: the topology is still the
    one in plan §3.2 when the automation layer *is* present.
    """
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")

    from fazerops.agents.graph import investigate_via_graph
    from fazerops.agents.proposer import proposer_node

    payload = json.loads((FIXTURE_ALERTS / "alertmanager.json").read_text(encoding="utf-8"))
    brief, result = await investigate_via_graph(
        normalize_alert(payload), proposer_node=proposer_node
    )

    order = [node.node_id for node in result.execution_order]
    assert order[0] == "orchestrator"
    assert order[-1] == "proposer", "the proposer runs last — it reads the narrative"
    assert order.index("correlator") < order.index("proposer")


async def test_the_investigation_graph_still_runs_with_no_proposer():
    """Tier 0 is the product and must work with the automation layer deleted. The default
    graph is the investigation alone."""
    from fazerops.agents.graph import investigate_via_graph

    payload = json.loads((FIXTURE_ALERTS / "alertmanager.json").read_text(encoding="utf-8"))
    _, result = await investigate_via_graph(normalize_alert(payload))

    assert "proposer" not in [node.node_id for node in result.execution_order]


async def test_a_rejected_proposal_costs_the_proposal_and_not_the_graph(monkeypatch):
    """Every node in this graph degrades rather than raises. Taking the whole run down over
    a bad remediation would throw away the ranked, cited change list to punish the model."""
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")

    import fazerops.agents.proposer as proposer_module
    from fazerops.agents.graph import investigate_via_graph

    async def always_rejects(*args, **kwargs):
        raise ProposalRejected("synthetic rejection")

    monkeypatch.setattr(proposer_module, "propose", always_rejects)

    from fazerops.agents.graph import InvestigationState

    payload = json.loads((FIXTURE_ALERTS / "alertmanager.json").read_text(encoding="utf-8"))
    state = InvestigationState(normalize_alert(payload))
    brief, result = await investigate_via_graph(
        state.alert, proposer_node=proposer_module.proposer_node, state=state
    )

    assert brief.candidates, "the investigation survives a rejected proposal"
    # Says so by name rather than hiding it — but not as a degraded brief. `degraded` renders as
    # "a change source was unavailable", and every source answered.
    assert state.node_errors["proposer"] == "synthetic rejection"
    assert brief.degraded is False
