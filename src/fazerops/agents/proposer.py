"""W22 — the proposer agent. Handoff §7, plan §3.1 and §4.

Emits `{action_id, params, rationale, evidence_ids}` **and nothing else**. Free-form output
here is the whole attack surface: this is the one model response that becomes a mutation.

Four things stop it being one, and only the first is a prompt:

1. The prompt says choose from the catalog.
2. **`action_id` is a `Literal` built from `catalog.action_ids` at import time**, so an
   action outside the catalog is not expressible in the response schema. Same pattern as
   W19b's service enum, and the same reason: a schema constraint has no prompt to
   jailbreak past.
3. **`params` are validated by `catalog.validate_params` before anything constructs a
   client** — the ordering W20's test asserts.
4. **`tier` is read from the catalog, never from the response.** The model has no way to
   name a tier, so it cannot argue its way down to an IC approval.

What this module deliberately does **not** re-check is whether the target resource was in
the blast radius. That is `preconditions.py`'s job, answered from collected evidence, and
it runs inside `ActionRequest.execute()` before any executor resolves — plus
`blocks.approval_card` strips the Approve button when a precondition is unmet. A second
copy of the check here would be a second thing to keep in step with `keys.py`, and the
version that drifts is the one nothing executes against.

**Automation layer** (plan §3.5): this module consumes a `Brief` and emits a `Proposal`.
It may import `actions/`; the investigation layer may not import it.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..actions.catalog import (
    Catalog,
    UnknownAction,
    ValidationRejected,
    default_catalog,
    validate_params,
)
from ..models import Brief, Proposal
from ..security.envelope import render_alert_for_llm, render_candidate_for_llm

__all__ = [
    "ACTION_IDS",
    "NO_ACTION",
    "ProposalRejected",
    "ProposerOutput",
    "build_messages",
    "propose",
    "proposer_node",
    "validate_proposal",
]

# Read at import, from the catalog, for the reason the module docstring gives. `sorted` is
# the catalog's own order, so the enum is stable across runs and the cassette key with it.
ACTION_IDS: tuple[str, ...] = default_catalog().action_ids

# The model's way of saying "nothing here should be undone". A first-class answer: a brief
# whose top candidate has no recorded prior value genuinely has no action behind it, and a
# proposer that must always name one would name a wrong one.
NO_ACTION = "none"

TOP_N = 5  # Same as the correlator's. The proposal rests on what the analyst read.

_ActionId = Literal[(*ACTION_IDS, NO_ACTION)]  # type: ignore[valid-type]


class ProposalRejected(ValueError):
    """The model's proposal did not survive validation.

    Rejected **whole**, unlike the correlator's per-claim drops. There is no partial
    proposal: an action with one bad parameter is not a safer action, it is the same
    action aimed somewhere nobody checked.
    """


class ProposerOutput(BaseModel):
    """What the model is asked to return, and the strict contract it is checked against.

    `extra="forbid"` is the plan's first assertion. A response carrying a `command`, a
    `script` or a `tier` is refused rather than having the extra key quietly dropped —
    a model reaching for those keys is a model that has been talked into something, and
    the response is evidence, not noise.
    """

    model_config = ConfigDict(extra="forbid")

    action_id: _ActionId
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


def _wire_params_model() -> type[BaseModel]:
    """Build the provider-facing params schema from the catalog, one optional field per
    parameter name any action declares.

    **`params: dict[str, Any]` cannot be sent to Gemini.** Pydantic emits
    `"additionalProperties": true` for a bare dict field, and the Developer API rejects
    `additionalProperties` in either polarity — the same constraint this module already
    knew about `extra="forbid"`, applied to a field rather than to a model. That was missed
    when W22 was written and went unnoticed for a day because `propose()` is only exercised
    in stub mode in CI and no proposer cassette existed; the live path raised on every call
    (12 Sep, `docs/drift_log.md`).

    Rebuilding it from the catalog rather than hand-listing the fields is what keeps it from
    drifting when a fourth action lands — the same reason `ACTION_IDS` is read from the
    catalog at import rather than written out.

    It is also a **narrowing**, not a workaround: the model can now only name parameters
    some action actually declares, so an invented key is unrepresentable in the response
    rather than rejected after the fact. Per-action validation is still
    `catalog.validate_params`' job — this says nothing about which params go with which
    action, only that a name is one the catalog knows.
    """
    from pydantic import create_model

    fields: dict[str, Any] = {}
    for action in default_catalog():
        for parameter, spec in action.params.items():
            # **Required but nullable**, and the combination is deliberate. The union spans
            # three actions, so a parameter required by one is absent from another and the
            # schema cannot say "required for *this* action" — the type has to admit null.
            # But making the field itself optional as well told the model it could simply
            # omit it, and `gemini-3.5-flash-lite` then filled one parameter of four on most
            # runs (12 Sep, two recorded rounds). Required-and-nullable forces it to emit
            # every key and make an explicit decision about each.
            fields.setdefault(parameter, (spec.python_type | None, ...))

    return create_model("_WireParams", **fields)


_WireParams = _wire_params_model()


# The provider-facing schema. Gemini's Developer API rejects `additionalProperties` in
# either polarity, which Pydantic emits for both `extra="forbid"` and `extra="allow"` **and
# for a bare `dict[str, Any]` field** — hence `_WireParams` above. This model sets no
# `extra` at all — the same split, and the same reasoning, as W18's `_WireOutput`.
# Weakening `ProposerOutput` to fit would delegate our contract to whatever the provider
# happens to enforce, and the provider enforces less than we do.
#
# One-line docstring on purpose: Pydantic ships it as the schema `description`.
class _WireOutput(BaseModel):
    """Proposed remediation."""

    action_id: _ActionId
    params: _WireParams
    rationale: str = ""
    evidence_ids: list[str] = Field(default_factory=list)

    def to_proposal_dict(self) -> dict[str, Any]:
        """The shape `validate_proposal` polices.

        Unset parameters are dropped rather than sent through as `None`: every field is
        optional on the wire because the union spans three actions, so a `None` here means
        "this action does not take that parameter", not "it was given no value". Passing
        them on would make every proposal fail `validate_params` as carrying unknown keys.
        """
        payload = self.model_dump()
        payload["params"] = {
            name: value for name, value in (payload.get("params") or {}).items()
            if value is not None
        }
        return payload


# --------------------------------------------------------------------------------------
# Input
# --------------------------------------------------------------------------------------


def build_messages(brief: Brief, narrative: Any = None, *, top_n: int = TOP_N) -> list[dict]:
    """The user turn: the alert, the top-N candidates, and what the analyst concluded.

    Enveloped per candidate rather than as one block, for W18's reason — a hostile value in
    one ConfigMap must not appear to comment on another event.

    The narrative is included because rule 3 requires the proposal's evidence to be a
    subset of what the analyst cited, and a model cannot satisfy a constraint it was not
    shown. It is **not** enveloped: it is this system's own output, already validated by
    W18, and wrapping our own text in an untrusted-data tag would teach the model that the
    tag means nothing.
    """
    parts = [render_alert_for_llm(brief.alert)]
    parts += [render_candidate_for_llm(candidate) for candidate in brief.candidates[:top_n]]

    if narrative is not None and getattr(narrative, "claims", None):
        cited = ", ".join(narrative.evidence_ids) or "(none)"
        parts.append(
            "The analyst concluded:\n"
            + "\n".join(f"- {claim.text}" for claim in narrative.claims)
            + f"\n\nCited evidence ids: {cited}"
        )

    if not brief.candidates:
        parts.append(
            "No changes were found in this blast radius and window. There is nothing to "
            'revert; answer with action_id "none".'
        )

    return [{"role": "user", "content": [{"text": "\n\n".join(parts)}]}]


# --------------------------------------------------------------------------------------
# The validator
# --------------------------------------------------------------------------------------


def validate_proposal(
    raw: dict[str, Any] | str,
    brief: Brief,
    narrative: Any = None,
    *,
    catalog: Catalog | None = None,
) -> Proposal | None:
    """Parse and police one proposal. Returns `None` for an honest "no action".

    `None` and an exception are different answers and the difference matters: `None` means
    the model declined, which is a correct outcome; `ProposalRejected` means it proposed
    something that did not survive checking, which is a fact about the run that belongs in
    the incident record.
    """
    catalog = catalog if catalog is not None else default_catalog()

    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProposalRejected(f"response was not JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise ProposalRejected(f"expected a JSON object, got {type(raw).__name__}")

    try:
        parsed = ProposerOutput.model_validate(raw)
    except ValidationError as exc:
        # Covers both the plan's first assertion (an extra key) and its second (an
        # action_id outside the catalog) — the enum makes the second a schema failure
        # rather than a lookup that could have been forgotten.
        raise ProposalRejected(f"response did not match the output schema: {exc}") from exc

    if parsed.action_id == NO_ACTION:
        return None

    try:
        spec = catalog.get(parsed.action_id)
    except UnknownAction as exc:  # pragma: no cover - unreachable while the enum holds
        # Kept anyway: the enum is built at import from the catalog, so this can only fire
        # if the two are ever loaded from different files. Silence there would mean an
        # uncatalogued action reaching an executor.
        raise ProposalRejected(str(exc)) from exc

    try:
        # Before anything constructs a client — the ordering W20's test asserts, and the
        # reason a malformed proposal never reaches a half-built kubectl call that has
        # already assumed the `default` namespace.
        params = validate_params(spec, parsed.params)
    except ValidationRejected as exc:
        raise ProposalRejected(f"proposed parameters were rejected: {exc}") from exc

    known = {candidate.event.id for candidate in brief.candidates}
    cited = set(narrative.evidence_ids) if narrative is not None else known

    if not parsed.evidence_ids:
        raise ProposalRejected(
            "proposal carried no evidence ids; an action nobody can trace to a change is "
            "not a proposal, it is a guess"
        )

    fabricated = sorted(set(parsed.evidence_ids) - known)
    if fabricated:
        raise ProposalRejected(f"proposal cites unknown event id(s): {', '.join(fabricated)}")

    uncited = sorted(set(parsed.evidence_ids) - cited)
    if uncited:
        # The plan's third assertion. A proposal resting on evidence the analyst never
        # cited is reasoning the human reading the brief cannot follow — the action would
        # arrive justified by something that is not on the card.
        raise ProposalRejected(
            f"proposal cites event id(s) the analyst did not: {', '.join(uncited)}"
        )

    return Proposal(
        action_id=parsed.action_id,
        params=params,
        rationale=parsed.rationale,
        evidence_ids=parsed.evidence_ids,
        # Declared, never inferred, and never taken from the response (Handoff §7). W26
        # applies `thresholds.yaml` promotion on top of this; nothing demotes.
        tier=spec.tier,
    )


# --------------------------------------------------------------------------------------
# Running it
# --------------------------------------------------------------------------------------


def _stub_proposal(brief: Brief, narrative: Any = None) -> dict[str, Any] | None:
    """The canned response for `FAZEROPS_LLM=stub`, derived from the ledger's own hint.

    Built from `request_from_hint` rather than hardcoded, so the CI default exercises the
    *validator* instead of bypassing it, and so it stays true when the fixtures change. A
    candidate with no recorded prior value yields `None` — which is the honest answer and
    the one the demo's rank-2 Secret produces.
    """
    from ..actions.inverse import request_from_hint

    for candidate in brief.candidates:
        request = request_from_hint(candidate.event.inverse_hint)
        if request is None:
            continue

        cited = set(narrative.evidence_ids) if narrative is not None else None
        if cited is not None and candidate.event.id not in cited:
            continue

        resource = f"{candidate.event.resource.kind} {candidate.event.resource.name}"
        return {
            "action_id": request.action_id,
            "params": request.params,
            "rationale": (
                f"{resource} was changed out of band shortly before the alert; this "
                f"restores the value it held before that change."
            ),
            "evidence_ids": [candidate.event.id],
        }

    return None


async def propose(
    brief: Brief,
    narrative: Any = None,
    *,
    meter: Any | None = None,
    cassette_directory: Any | None = None,
    catalog: Catalog | None = None,
) -> Proposal | None:
    """Produce a validated proposal for a brief, under whichever mode is active.

    Returns `None` when nothing should be done. Raises `ProposalRejected` when the model
    proposed something that failed validation — the caller renders the brief without a
    proposal, which is a read-only brief and still the product.
    """
    from ..config import LlmMode, llm_mode
    from .cassette import Cassette, request_key
    from .llm import model_for, provider_for, recording_model_for
    from .prompts.proposer import SYSTEM_PROMPT

    mode = llm_mode()

    if mode is LlmMode.STUB:
        raw = _stub_proposal(brief, narrative)
        return None if raw is None else validate_proposal(raw, brief, narrative, catalog=catalog)

    messages = build_messages(brief, narrative)
    model = (
        recording_model_for("proposer")
        if mode is LlmMode.CASSETTE
        else model_for("proposer", mode)
    )
    from .correlator import generation_params_for

    key = request_key(
        "proposer", model, messages, system=SYSTEM_PROMPT, **generation_params_for(mode)
    )
    cassette = Cassette("proposer", directory=cassette_directory)

    if mode is LlmMode.CASSETTE:
        return validate_proposal(cassette.replay(key), brief, narrative, catalog=catalog)

    response, usage = await _invoke(provider_for(mode), model, messages)
    if meter is not None:
        meter.record(
            "proposer",
            model,
            usage["in"],
            usage["out"],
            estimated=usage.get("estimated", False),
        )
    if mode is LlmMode.RECORD:
        cassette.record(key, response, model=model)

    return validate_proposal(response, brief, narrative, catalog=catalog)


async def _invoke(provider, model: str, messages: list[dict]) -> tuple[dict, dict]:
    """One live call, through Strands' `Model` interface whichever provider is active.

    Same two-branch construction as W18's correlator and for the same reason: both
    providers implement Strands' `Model`, so only the constructor differs (plan §9.2).

    **Not exercised by any test that runs in CI** — Bedrock inference is blocked
    account-wide and the Gemini path needs a key CI does not have. It compiles; that is not
    evidence it works, and `tests/cassettes/README.md` carries the obligation to record
    against a real model before either is trusted.
    """
    from ..config import require_offline_capable
    from .correlator import _bedrock_model, _estimated_usage, _gemini_model, _usage_from
    from .llm import Provider
    from .prompts.proposer import SYSTEM_PROMPT

    require_offline_capable("proposer")

    client = _gemini_model(model) if provider is Provider.GEMINI else _bedrock_model(model)

    output: _WireOutput | None = None
    usage: dict[str, int] | None = None
    async for event in client.structured_output(_WireOutput, messages, SYSTEM_PROMPT):
        usage = _usage_from(event) or usage
        if "output" in event:
            output = event["output"]

    if output is None:
        raise ProposalRejected("the model returned no structured output")

    return output.to_proposal_dict(), usage or _estimated_usage(messages, output)


# --------------------------------------------------------------------------------------
# The graph node — plan §3.2's `correlator ──▶ proposer` edge
# --------------------------------------------------------------------------------------


def proposer_node(state: Any) -> Any:
    """Build the graph's proposer node for an `InvestigationState`.

    Lives here rather than in `graph.py` because it reads the action catalog, and
    `graph.py` is investigation-layer: a graph module importing this one would be the seam
    violation `tests/integration/test_layer_seam.py` exists to catch. `graph.py` takes this
    as a `proposer_node=` factory instead, so the dependency runs automation → investigation
    and never back.

    Like every other node it **never raises**. A rejected proposal costs the brief its
    proposal and nothing else — the ranked, cited change list is the product, and taking
    the whole graph down over a bad remediation would throw that away to punish the model.
    """
    from .graph import FunctionNode, _brief_from

    async def run() -> str:
        brief = _brief_from(state, narrative=state.narrative)
        try:
            state.proposal = await propose(brief, state.narrative)
        except ProposalRejected as exc:
            state.node_errors["proposer"] = str(exc)
            return "proposal rejected"
        if state.proposal is None:
            return "no action proposed"
        return f"proposed {state.proposal.action_id}"

    return FunctionNode("proposer", run, state)
