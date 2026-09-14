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

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..models import Brief, Candidate
from ..security.envelope import render_alert_for_llm, render_candidate_for_llm

logger = logging.getLogger(__name__)

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
    key = request_key(
        "correlator", model, messages, system=SYSTEM_PROMPT, **generation_params_for(mode)
    )
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
    if response is None:
        # Raised here, after the meter, and not inside `_invoke`. A response cut off at
        # `max_output_tokens` is the costliest call there is — the whole cap, spent thinking —
        # and raising before `record` left it off the ledger and out of both caps.
        raise NarrativeRejected("the model returned no structured output")
    if mode is LlmMode.RECORD:
        cassette.record(key, response, model=model)

    return validate_narrative(response, brief.candidates)


async def _invoke(
    provider, model: str, messages: list[dict[str, Any]]
) -> tuple[dict | None, dict]:
    """One live call, through Strands' `Model` interface whichever provider is active.

    Returns `None` for the response when the model produced no structured output (a
    truncation), with the usage it was billed for anyway — the caller meters, then rejects.

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
        return None, usage or _estimated_usage(messages, None)

    return output.model_dump(), usage or _estimated_usage(messages, output)


BEDROCK_PARAMS: dict[str, Any] = {"temperature": 0.0, "max_tokens": 1200}

GEMINI_PARAMS: dict[str, Any] = {
    "temperature": 0.0,
    # **Thoughts count against this cap.** 1200 held for a Lite that does not think; on
    # 3.1 Pro at its default level the same prompt spent 604, 1150 and 2449 tokens thinking
    # across three runs, and the 1150 run stopped at MAX_TOKENS with a 36-token half-answer.
    # The answer itself is ~400 tokens, so this bounds a runaway, not the response.
    "max_output_tokens": 8192,
    # `low`, not Pro's default `high` (13 Sep, the user's call). Thinking is the bulk of a
    # ~20s correlator call: ~2,450 thought tokens against a ~290-token answer. One probe at
    # `low` thought for 309 and still produced a valid, schema-conforming narrative. The
    # work that needs reasoning — ranking — is deterministic Python (ground rule #3); the
    # model is explaining a ranking it was handed, not deriving one.
    "thinking_config": {"thinking_level": "low"},
}

# Vertex answers a preview model's exhausted shared quota with 429 and an overloaded backend with
# 5xx, and both clear on their own. Strands retries them for a streamed `Agent`; `structured_output`
# below calls the SDK directly and had no retry, so a single 429 nulled a deployed brief's narrative
# on 14 Sep (GCP's request metrics show it at 14:49Z). Three attempts and at most 6 s of waiting —
# inside the graph backstop, and short enough that a real outage still degrades the brief.
TRANSIENT_RETRY_DELAYS_SECONDS: tuple[float, ...] = (2.0, 4.0)


async def _retrying_transient(call: Callable[[], Awaitable[Any]]) -> Any:
    from google.genai import errors

    for attempt, delay in enumerate((*TRANSIENT_RETRY_DELAYS_SECONDS, None), start=1):
        try:
            return await call()
        except errors.APIError as exc:
            transient = exc.code == 429 or (exc.code or 0) >= 500
            if delay is None or not transient:
                raise
            logger.warning(
                "gemini returned %s on attempt %d; retrying in %.0fs", exc.code, attempt, delay
            )
            await asyncio.sleep(delay)


def generation_params_for(mode: Any) -> dict[str, Any]:
    """The generation parameters a live call under `mode` sends — and so part of its
    cassette key.

    **The key omitted these until 13 Sep**, the same class of gap as the system prompt on
    12 Sep: `request_key` has always accepted `**params` and no agent passed any, so moving
    3.1 Pro's thinking from `high` to `low` would have replayed `high`-thinking tapes
    without a single miss. Replay asks for the *recording* provider's parameters, as it
    asks for the recording model.
    """
    from ..config import (
        OFFLINE_LLM_MODES,
        ConfigError,
        GeminiThinking,
        LlmMode,
        gemini_thinking,
    )
    from .llm import Provider, provider_for, recording_provider_for

    offline = mode in OFFLINE_LLM_MODES
    provider = recording_provider_for() if offline else provider_for(mode)
    if provider is not Provider.GEMINI:
        return dict(BEDROCK_PARAMS)

    params = dict(GEMINI_PARAMS)
    thinking = None if offline else gemini_thinking()
    if thinking is None:
        return params

    default = GEMINI_PARAMS["thinking_config"]["thinking_level"]
    if mode is LlmMode.RECORD and thinking.value != default:
        # Same reason as `model_for`'s refusal: replay rebuilds the key from these defaults.
        raise ConfigError(
            f"FAZEROPS_GEMINI_THINKING={thinking.value!r} differs from the committed "
            f"{default!r}; cassettes must be recorded with the defaults."
        )
    if thinking is GeminiThinking.OFF:
        params.pop("thinking_config")
    else:
        params["thinking_config"] = {"thinking_level": thinking.value}
    return params


def _bedrock_model(model: str):
    """Kept wired through the Gemini deviation (plan §9.2). This is the spec path, and
    deleting it would make the reversal a rewrite instead of an env var."""
    from strands.models import BedrockModel

    return BedrockModel(model_id=model, region_name="us-east-1", **BEDROCK_PARAMS)


def _gemini_model(model: str):
    """The active path (plan §9.2), served from Vertex AI unless `FAZEROPS_GEMINI_BACKEND`
    says otherwise."""
    import os

    from strands.models.gemini import GeminiModel

    from ..config import GeminiBackend, gemini_backend, llm_mode

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "FAZEROPS_LLM=gemini needs GEMINI_API_KEY. See .env.example; the key is never "
            "committed — tests/test_no_secrets.py matches the AIza… shape."
        )

    class MeteredGeminiModel(GeminiModel):
        """Strands' `structured_output`, keeping the two things it throws away (13 Sep).

        Upstream validates `response.parsed` and discards the response. That dropped:

        1. **Usage.** `_estimated_usage` measures the answer's text, but a thinking model
           is billed for its thoughts too — 2,449 thought tokens against a 291-token answer
           on `gemini-3.1-pro-preview`. An estimate that blind reads as a guarantee, which
           is worse than no meter. Thoughts are counted as output because that is how they
           are billed.
        2. **Truncation.** A response cut off at `max_output_tokens` has `parsed=None`, and
           upstream turns that into a Pydantic error about `NoneType`. Yielding no output
           lets the caller's own "returned no structured output" path say what happened.
        """

        async def structured_output(self, output_model, prompt, system_prompt=None, **kwargs):
            params = {
                **(self.config.get("params") or {}),
                "response_mime_type": "application/json",
                "response_schema": output_model.model_json_schema(),
            }
            request = self._format_request(prompt, None, system_prompt, params)
            # Bound to a local on purpose. Chained inline, the `genai.Client` is collectable
            # before the await resumes, its finaliser closes the aiohttp session, and the
            # call dies inside aiohttp on `assert self._connector is not None`.
            client = self._get_client()
            response = await _retrying_transient(
                lambda: client.aio.models.generate_content(**request)
            )

            usage = response.usage_metadata
            if usage is not None:
                yield {
                    "metadata": {
                        "usage": {
                            "inputTokens": usage.prompt_token_count or 0,
                            "outputTokens": (usage.candidates_token_count or 0)
                            + (usage.thoughts_token_count or 0),
                        }
                    }
                }
            if response.parsed is not None:
                yield {"output": output_model.model_validate(response.parsed)}

    return MeteredGeminiModel(
        model_id=model,
        # Passed explicitly rather than left to the SDK's own `GOOGLE_GENAI_USE_VERTEXAI`
        # lookup: an endpoint chosen by an env var this repo never names is a demo-day
        # surprise waiting in someone's shell profile.
        client_args={"api_key": api_key, "vertexai": gemini_backend() is GeminiBackend.VERTEX},
        # The same function the cassette key reads, so the parameters sent and the
        # parameters keyed cannot drift apart.
        params=generation_params_for(llm_mode()),
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


def _estimated_usage(messages: list[dict[str, Any]], output: BaseModel | None) -> dict[str, int]:
    """Fallback when the provider reports no usage. Deliberately conservative (W16's
    estimator over-counts): a budget that under-reports is worse than none, because it
    reads as a guarantee.

    `output` is `None` for a response that produced no structured output: the prompt was
    still sent and billed, so it is still counted, and the output nobody saw is counted as 0."""
    from ..security.envelope import estimate_tokens

    sent = json.dumps(messages, default=str)
    return {
        "in": estimate_tokens(sent),
        "out": estimate_tokens(output.model_dump_json()) if output is not None else 0,
        "estimated": True,
    }
