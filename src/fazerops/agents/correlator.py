"""W18 — the correlator agent and its citation validator. Handoff §6.

**This is the only place a model can put fiction in front of a user.** The collectors are
deterministic, the scorer is arithmetic in Python, and the renderer prints what it is
given. The narrative is the one surface authored by a language model, so it is the one
surface that needs a validator between the model and the screen.

Handoff §6 states the rule: *"Structure the output so every claim carries an event id, and
drop any claim that doesn't."* That sentence is `validate_narrative` below.

Two failure classes, deliberately handled differently:

- **An uncited or fabricated claim is dropped.** The rest of the narrative may be sound,
  and discarding a whole answer over one bad sentence would make the agent useless at
  exactly the moment evidence is thin.
- **A primary cause other than rank 1 is rejected outright.** That is not a bad sentence,
  it is the model overriding a ranking computed from features it cannot see — and the
  ranking is the product. There is nothing to salvage.

Every drop and every rejection is recorded on the result rather than swallowed, because a
validator that silently improves the model's output hides the fact that the model needed
improving.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..models import Brief, Candidate
from ..security.envelope import render_alert_for_llm, render_candidate_for_llm

__all__ = [
    "Claim",
    "CorrelatorOutput",
    "DroppedClaim",
    "NarrativeRejected",
    "ValidatedNarrative",
    "build_messages",
    "validate_narrative",
]

TOP_N = 5  # Handoff §6: "the top-N scored candidates". Beyond this the tail is noise.


class Claim(BaseModel):
    """One sentence and the events it rests on."""

    model_config = ConfigDict(frozen=True)

    text: str = Field(min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)


class CorrelatorOutput(BaseModel):
    """What the model is asked to return. Parsed before it is trusted.

    `extra="forbid"` because a model that invents a `recommended_action` key is trying to
    do the proposer's job, and W22's catalog is the only thing allowed to name an action.
    """

    model_config = ConfigDict(extra="forbid")

    primary_cause_event_id: str
    confidence: Literal["high", "medium", "low"]
    claims: list[Claim] = Field(default_factory=list)


# The schema handed to the provider, which is deliberately **not** the schema we validate
# against. Gemini's Developer API accepts a subset of JSON Schema and rejects
# `additionalProperties` in either polarity — which Pydantic emits for both `extra="forbid"`
# and `extra="allow"`. So this model sets no `extra` at all.
#
# Weakening `CorrelatorOutput` to fit would delegate our contract to whatever the provider
# happens to enforce, and the provider enforces less than we do. The cost of the split is
# that an invented key is dropped here rather than reaching `CorrelatorOutput`'s
# `extra="forbid"` — acceptable, because with a `response_schema` the provider constrains
# generation and the model cannot emit one. The strict check still guards the cassette
# replay path, a hand-edited tape, and any future provider without schema enforcement.
#
# Docstring kept to one line on purpose: Pydantic ships it to the API as the schema
# `description`, and a paragraph about JSON Schema is tokens the model has to read.
class _WireOutput(BaseModel):
    """Correlation result."""

    primary_cause_event_id: str
    confidence: Literal["high", "medium", "low"]
    claims: list[Claim] = Field(default_factory=list)


class DroppedClaim(BaseModel):
    model_config = ConfigDict(frozen=True)

    text: str
    reason: str


class ValidatedNarrative(BaseModel):
    """What survives the validator, plus an honest account of what did not."""

    model_config = ConfigDict(frozen=True)

    primary_cause_event_id: str
    confidence: Literal["high", "medium", "low"]
    claims: list[Claim] = Field(default_factory=list)
    dropped: list[DroppedClaim] = Field(default_factory=list)

    @property
    def evidence_ids(self) -> list[str]:
        """Every cited id, deduplicated, in first-citation order — the order a reader
        meets them in, which is what the brief renders."""
        seen: list[str] = []
        for claim in self.claims:
            for event_id in claim.evidence_ids:
                if event_id not in seen:
                    seen.append(event_id)
        return seen

    @property
    def text(self) -> str:
        return " ".join(claim.text for claim in self.claims)


class NarrativeRejected(ValueError):
    """The model asserted a cause the scorer did not rank first, or returned something
    that is not a narrative at all. The brief renders without a narrative rather than
    with a wrong one."""


# --------------------------------------------------------------------------------------
# Input
# --------------------------------------------------------------------------------------


def build_messages(brief: Brief, *, top_n: int = TOP_N) -> list[dict[str, Any]]:
    """The user turn: the alert and the top-N candidates, each individually enveloped.

    Enveloped *per candidate* rather than as one block, so a hostile value inside one
    ConfigMap cannot appear to comment on another event — each block carries its own
    `source` and `event_id`, and W16's escaping guarantees it cannot close them.
    """
    parts = [render_alert_for_llm(brief.alert)]
    parts += [render_candidate_for_llm(c) for c in brief.candidates[:top_n]]

    if not brief.candidates:
        parts.append(
            "No changes were found in this blast radius and window. Say so plainly and "
            "set confidence to low."
        )

    return [{"role": "user", "content": [{"text": "\n\n".join(parts)}]}]


# --------------------------------------------------------------------------------------
# The validator — Handoff §6's rule, as code
# --------------------------------------------------------------------------------------


def validate_narrative(
    raw: dict[str, Any] | str, candidates: list[Candidate]
) -> ValidatedNarrative:
    """Parse and police one model response.

    `candidates` is the ground truth: the only event ids that exist, and the ranking the
    model may not contradict. Passing the candidate list rather than a set of ids is
    deliberate — the rank-1 rule needs the order, and taking both from one argument means
    they cannot drift apart at a call site.
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise NarrativeRejected(f"response was not JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise NarrativeRejected(f"expected a JSON object, got {type(raw).__name__}")

    try:
        parsed = CorrelatorOutput.model_validate(raw)
    except ValidationError as exc:
        raise NarrativeRejected(f"response did not match the output schema: {exc}") from exc

    known_ids = {candidate.event.id for candidate in candidates}
    top_id = candidates[0].event.id if candidates else None

    # Rule 3 first: if the model named the wrong cause there is nothing worth keeping, and
    # filtering claims out of a narrative built on a wrong premise would produce something
    # that reads as agreement.
    if top_id is None:
        raise NarrativeRejected("no candidates were scored, so no cause can be asserted")
    if parsed.primary_cause_event_id != top_id:
        raise NarrativeRejected(
            f"model named {parsed.primary_cause_event_id!r} as the primary cause; the "
            f"scorer ranked {top_id!r} first. Handoff §6: it must not assert a cause the "
            "scoring did not rank."
        )

    kept: list[Claim] = []
    dropped: list[DroppedClaim] = []
    for claim in parsed.claims:
        reason = _rejection_reason(claim, known_ids)
        if reason is None:
            kept.append(claim)
        else:
            dropped.append(DroppedClaim(text=claim.text, reason=reason))

    return ValidatedNarrative(
        primary_cause_event_id=parsed.primary_cause_event_id,
        confidence=parsed.confidence,
        claims=kept,
        dropped=dropped,
    )


def _rejection_reason(claim: Claim, known_ids: set[str]) -> str | None:
    if not claim.evidence_ids:
        return "no evidence id"

    fabricated = [event_id for event_id in claim.evidence_ids if event_id not in known_ids]
    if fabricated:
        # Every id must be real, not merely one of them. A claim citing one genuine event
        # and one invented one is the most dangerous shape there is: it reads as sourced.
        return f"cites unknown event id(s): {', '.join(sorted(fabricated))}"

    return None


# --------------------------------------------------------------------------------------
# Running it — one entry point across all five modes (plan §5)
# --------------------------------------------------------------------------------------


def _stub_narrative(brief: Brief) -> dict[str, Any]:
    """The canned response for `FAZEROPS_LLM=stub`, built from the ranked candidates.

    Derived from the data rather than hardcoded, so it stays true when the fixtures change
    and so the zero-network path exercises the *validator* rather than bypassing it. It is
    deliberately plain: this is the CI default and a judge's clean-machine default, and a
    stub that wrote better prose than the model would flatter the demo.
    """
    top = brief.top
    if top is None:
        return {
            "primary_cause_event_id": "",
            "confidence": "low",
            "claims": [],
        }

    event = top.event
    resource = f"{event.resource.kind} {event.resource.name}"
    # Same rounding as `render.text`, which prints this event's age two lines above the
    # narrative. Flooring here put "37 minutes" beside the renderer's "38" — one event
    # disagreeing with itself on screen, in the shot the demo lingers on.
    minutes = f"{(brief.alert.fired_at - event.occurred_at).total_seconds() / 60.0:.0f}"

    claims = [
        {
            "text": (
                f"{resource} was changed by {event.actor.display} {minutes} minutes "
                f"before the alert fired."
            ),
            "evidence_ids": [event.id],
        }
    ]
    if event.diff is not None and event.diff.before and event.diff.after:
        changes = ", ".join(
            f"{key}: {event.diff.before.get(key)} → {event.diff.after.get(key)}"
            for key in event.diff.fields_changed
        )
        claims.append({"text": f"The change set {changes}.", "evidence_ids": [event.id]})
    if not event.in_band:
        claims.append(
            {
                "text": "It did not arrive through CI, so no pull request describes it.",
                "evidence_ids": [event.id],
            }
        )

    return {
        "primary_cause_event_id": event.id,
        "confidence": "high" if top.score >= 0.7 else "medium",
        "claims": claims,
    }


async def correlate(
    brief: Brief,
    *,
    meter: Any | None = None,
    cassette_directory: Any | None = None,
) -> ValidatedNarrative:
    """Produce a validated narrative for a brief, under whichever mode is active.

    Returns the validated result; raises `NarrativeRejected` if the model's answer cannot
    be salvaged. Callers render the brief without a narrative in that case — a brief with
    no explanation is still a ranked, cited list of what changed, which is the product.
    """
    from ..config import LlmMode, llm_mode
    from .cassette import Cassette, request_key
    from .llm import model_for, provider_for, recording_model_for
    from .prompts.correlator import SYSTEM_PROMPT

    mode = llm_mode()

    if mode is LlmMode.STUB:
        return validate_narrative(_stub_narrative(brief), brief.candidates)

    messages = build_messages(brief)
    # Cassette replay must rebuild the key that `record` wrote, which included the model
    # id from the record assignment — so it asks for that one, not for its own (it has none).
    model = (
        recording_model_for("correlator")
        if mode is LlmMode.CASSETTE
        else model_for("correlator", mode)
    )
    key = request_key("correlator", model, messages, system=SYSTEM_PROMPT)
    cassette = Cassette("correlator", directory=cassette_directory)

    if mode is LlmMode.CASSETTE:
        return validate_narrative(cassette.replay(key), brief.candidates)

    response, usage = await _invoke(provider_for(mode), model, messages)
    if meter is not None:
        meter.record(
            "correlator",
            model,
            usage["in"],
            usage["out"],
            estimated=usage.get("estimated", False),
        )
    if mode is LlmMode.RECORD:
        cassette.record(key, response, model=model)

    return validate_narrative(response, brief.candidates)


async def _invoke(provider, model: str, messages: list[dict[str, Any]]) -> tuple[dict, dict]:
    """One live call, through Strands' `Model` interface whichever provider is active.

    Both providers go through `structured_output`, so the response is schema-constrained by
    the provider rather than coaxed out of free text and parsed hopefully. That is what
    plan §5 means by "constrained structured output", and it is why the two branches below
    differ only in which `Model` object they construct — **the definition of "Strands
    throughout" surviving the §9.2 provider switch.**

    **Neither branch is exercised by any test.** Bedrock inference is blocked account-wide
    and the Gemini branch needs a key CI does not have. They compile; that is not evidence
    they work, and `tests/cassettes/README.md` carries the obligation to record against a
    real model before either is trusted.
    """
    from ..config import require_offline_capable
    from .llm import Provider
    from .prompts.correlator import SYSTEM_PROMPT

    require_offline_capable("correlator")

    client = (
        _gemini_model(model) if provider is Provider.GEMINI else _bedrock_model(model)
    )

    output: _WireOutput | None = None
    usage: dict[str, int] | None = None
    async for event in client.structured_output(_WireOutput, messages, SYSTEM_PROMPT):
        usage = _usage_from(event) or usage
        if "output" in event:
            output = event["output"]

    if output is None:
        raise NarrativeRejected("the model returned no structured output")

    return output.model_dump(), usage or _estimated_usage(messages, output)


def _bedrock_model(model: str):
    """Kept wired through the Gemini deviation (plan §9.2). This is the spec path, and
    deleting it would make the reversal a rewrite instead of an env var."""
    from strands.models import BedrockModel

    return BedrockModel(
        model_id=model,
        region_name="us-east-1",
        temperature=0.0,
        max_tokens=1200,
    )


def _gemini_model(model: str):
    """The active path (plan §9.2)."""
    import os

    from strands.models.gemini import GeminiModel

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "FAZEROPS_LLM=gemini needs GEMINI_API_KEY. See .env.example; the key is never "
            "committed — tests/test_no_secrets.py matches the AIza… shape."
        )

    return GeminiModel(
        model_id=model,
        client_args={"api_key": api_key},
        params={"temperature": 0.0, "max_output_tokens": 1200},
    )


def _usage_from(event: dict) -> dict[str, int] | None:
    """Pull real token counts out of a Strands event, if the provider sent any.

    **VERIFIED 11 Sep, and it does not fire on the Gemini path.** Strands'
    `GeminiModel.structured_output` yields exactly one event — `{"output": ...}` — and
    never a `metadata` event, so there is no usage to read and `_estimated_usage` below is
    what the ledger records. That is now labelled rather than silent: entries carry
    `estimated: true`.

    Kept, not deleted, because the shape below is what `_format_chunk` emits on the
    *streaming* path, which the Bedrock branch and a future tool-calling orchestrator
    (W19b) both use. When either runs, this starts returning real counts.
    """
    metadata = (event.get("event") or {}).get("metadata") or event.get("metadata") or {}
    counts = metadata.get("usage") or {}
    if "inputTokens" in counts:
        return {"in": int(counts["inputTokens"]), "out": int(counts.get("outputTokens", 0))}
    return None


def _estimated_usage(messages: list[dict[str, Any]], output: _WireOutput) -> dict[str, int]:
    """Fallback when the provider reports no usage. Deliberately conservative (W16's
    estimator over-counts): a budget that under-reports is worse than none, because it
    reads as a guarantee."""
    from ..security.envelope import estimate_tokens

    sent = json.dumps(messages, default=str)
    return {
        "in": estimate_tokens(sent),
        "out": estimate_tokens(output.model_dump_json()),
        "estimated": True,
    }
