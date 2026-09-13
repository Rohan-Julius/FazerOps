"""W17 — which model each agent gets, per `FAZEROPS_LLM`. Plan §5.

Per-agent assignment rather than one global model, because the three agents have
genuinely different requirements:

- **correlator** writes the narrative that appears on camera, so phrasing matters — and
  only here.
- **orchestrator** and **proposer** emit constrained structured output. They choose from
  an enum and fill a schema; prose quality is irrelevant and Lite is 13× cheaper.

That split is what makes the interim Nova path cost $0.0064/run against the Claude path's
$0.047. Assignment is a `model_id` argument (plan §1.1, verified), so switching models is
config rather than a rewrite.

**As of 11 Sep that promise is load-bearing across *providers*, not just model ids**
(plan §9.2). Bedrock inference is blocked account-wide, so the active path is Gemini —
and Strands ships `GeminiModel` with the same `model_id` shape as `BedrockModel`, which
is why the switch is a table entry here rather than a rewrite of three agents.

Bedrock stays wired. `demo` and `sonnet` are untouched and reachable the moment access
lands; §9.2 names the reversal. Gemini is the fallback, never the destination.
"""

from __future__ import annotations

from enum import Enum

from ..config import GEMINI_MODEL_ENV, ConfigError, LlmMode, gemini_model_overrides, llm_mode

__all__ = [
    "AGENTS",
    "MODEL_ASSIGNMENT",
    "Provider",
    "model_for",
    "provider_for",
    "recording_model_for",
    "requires_network",
]

# `writer_author` is W42's rung 3 — the one agent that writes code — and it runs off the incident
# path, only when catalog growth has decided a writer is needed. It takes the stronger model in
# every path: its output is read by a human and gated by an AST allowlist, and a weaker model
# there costs rejected candidates rather than money saved.
AGENTS = ("orchestrator", "correlator", "proposer", "writer_author")


class Provider(str, Enum):
    """Who serves the tokens. Separate from the model id because the *client* differs —
    `BedrockModel` takes a region and an IAM identity, `GeminiModel` takes an API key."""

    BEDROCK = "bedrock"
    GEMINI = "gemini"

NOVA_LITE = "amazon.nova-lite-v1:0"
NOVA_PRO = "amazon.nova-pro-v1:0"
HAIKU = "anthropic.claude-haiku-4-5-20251001-v1:0"
SONNET = "anthropic.claude-sonnet-4-5-20250929-v1:0"

# **The split is back, because the reason it was dropped is gone** (13 Sep, plan §9.2).
# On 11 Sep all three agents ran one Lite: the AI Studio free tier capped every stronger
# model at 20 requests/day, and quota rather than cost was the scarce resource. Gemini is
# now served from Vertex AI against GCP credits, where the binding constraint is cost again
# — so §5's reasoning applies as written, in the shape `sonnet` already gives it.
#
# The proposer takes the stronger model with the correlator, not the cheap one with the
# orchestrator. It reads the same attacker-influenceable diff W27 poisons; W22's validator
# holds whatever it says, but a model steered off "none" costs the brief its proposal.
# The orchestrator only routes three manifest-bounded tools, where Pro adds latency per turn
# and nothing a judge can see.
GEMINI_PRO = "gemini-3.1-pro-preview"
GEMINI_FLASH = "gemini-3.8-flash"

PROVIDER: dict[LlmMode, Provider] = {
    LlmMode.NOVA: Provider.BEDROCK,
    LlmMode.DEMO: Provider.BEDROCK,
    LlmMode.SONNET: Provider.BEDROCK,
    LlmMode.GEMINI: Provider.GEMINI,
}

MODEL_ASSIGNMENT: dict[LlmMode, dict[str, str]] = {
    # All Nova Lite — the cheap interactive-iteration path, $0.0010/run.
    LlmMode.NOVA: dict.fromkeys(AGENTS, NOVA_LITE),
    # The active demo path while Anthropic access is blocked (plan §1.2 U5). Nova Pro
    # carries the correlator because its output is the thing a judge reads.
    LlmMode.DEMO: {
        "orchestrator": NOVA_LITE,
        "correlator": NOVA_PRO,
        "proposer": NOVA_LITE,
        "writer_author": NOVA_PRO,
    },
    # Target path if Anthropic access lands. Wired so that switching is a env var, not a
    # code change — but do not switch after Sep 12: an unrehearsed model change on demo
    # week is not worth the prose (plan §5).
    LlmMode.SONNET: {
        "orchestrator": HAIKU,
        "correlator": SONNET,
        "proposer": SONNET,
        "writer_author": SONNET,
    },
    # The active path (plan §9.2). Same split as `sonnet`, different provider.
    LlmMode.GEMINI: {
        "orchestrator": GEMINI_FLASH,
        "correlator": GEMINI_PRO,
        "proposer": GEMINI_PRO,
        "writer_author": GEMINI_PRO,
    },
}

# `record` records against whichever path is active, and cassettes must hold what the demo
# replays — recording against a path the demo never runs produces tape nobody plays.
#
# **This is what makes the §9.2 reversal a one-line change.** Point `record` at `demo` the
# moment Bedrock access lands, re-record, and the cassettes are Bedrock's again.
ACTIVE_PATH = LlmMode.GEMINI

MODEL_ASSIGNMENT[LlmMode.RECORD] = MODEL_ASSIGNMENT[ACTIVE_PATH]
PROVIDER[LlmMode.RECORD] = PROVIDER[ACTIVE_PATH]


def model_for(agent: str, mode: LlmMode | None = None) -> str:
    """The Bedrock model id for one agent under the active mode.

    Raises for `stub` and `cassette`: those modes must never construct a model client at
    all, and returning a plausible id would let a bug reach for the network in the one
    configuration that guarantees it will not.
    """
    if agent not in AGENTS:
        raise ValueError(f"unknown agent {agent!r}; expected one of {AGENTS}")

    mode = mode if mode is not None else llm_mode()
    if mode not in MODEL_ASSIGNMENT:
        raise ValueError(
            f"FAZEROPS_LLM={mode.value} does not call a model, so it has no model id. "
            "Check `requires_network()` before asking for one."
        )
    default = MODEL_ASSIGNMENT[mode][agent]

    # `FAZEROPS_GEMINI_MODEL_*` reach **live** Gemini runs and nothing else. Cassette replay
    # never gets here (`recording_model_for` reads the table), which is what keeps a clone
    # with its own `.env` green in CI.
    if mode is LlmMode.GEMINI:
        return gemini_model_overrides().get(agent, default)
    if mode is LlmMode.RECORD and PROVIDER[mode] is Provider.GEMINI:
        chosen = gemini_model_overrides().get(agent, default)
        if chosen != default:
            # A tape keyed on a model the table does not name is one replay can never find:
            # recording succeeds, the file looks right, and every clone's CI misses.
            raise ConfigError(
                f"{GEMINI_MODEL_ENV[agent]}={chosen!r} differs from the committed "
                f"{default!r}. Cassettes must be recorded with the models `agents/llm.py` "
                "assigns — unset it to record, or change the table and re-record everything."
            )
    return default


def provider_for(mode: LlmMode | None = None) -> Provider:
    """Which client serves this mode. Raises for the offline modes, same as `model_for`."""
    mode = mode if mode is not None else llm_mode()
    if mode not in PROVIDER:
        raise ValueError(f"FAZEROPS_LLM={mode.value} does not call a model")
    return PROVIDER[mode]


def requires_network(mode: LlmMode | None = None) -> bool:
    mode = mode if mode is not None else llm_mode()
    return mode in MODEL_ASSIGNMENT


def recording_provider_for() -> Provider:
    """The provider whose responses the cassettes hold — `recording_model_for`'s twin, for
    the same reason: replay must rebuild the key record wrote, and that key now carries the
    provider's generation parameters."""
    from ..config import LlmMode

    return PROVIDER[LlmMode.RECORD]


def recording_model_for(agent: str) -> str:
    """The model whose responses a cassette holds.

    `cassette` mode has no model of its own — it never calls one — but it still needs a
    model id to rebuild the request key, because the key that *recorded* the tape included
    one. Deriving it from the `record` assignment is what keeps replay finding what record
    wrote; asking `model_for` would correctly refuse, since an offline mode having a model
    id is exactly the bug that check exists to prevent.
    """
    from ..config import LlmMode

    return MODEL_ASSIGNMENT[LlmMode.RECORD][agent]
