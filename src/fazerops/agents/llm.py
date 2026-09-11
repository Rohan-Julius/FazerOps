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

from ..config import LlmMode, llm_mode

__all__ = [
    "AGENTS",
    "MODEL_ASSIGNMENT",
    "Provider",
    "model_for",
    "provider_for",
    "recording_model_for",
    "requires_network",
]

AGENTS = ("orchestrator", "correlator", "proposer")


class Provider(str, Enum):
    """Who serves the tokens. Separate from the model id because the *client* differs —
    `BedrockModel` takes a region and an IAM identity, `GeminiModel` takes an API key."""

    BEDROCK = "bedrock"
    GEMINI = "gemini"

NOVA_LITE = "amazon.nova-lite-v1:0"
NOVA_PRO = "amazon.nova-pro-v1:0"
HAIKU = "anthropic.claude-haiku-4-5-20251001-v1:0"
SONNET = "anthropic.claude-sonnet-4-5-20250929-v1:0"

# **Gemini does NOT inherit the cheap/expensive split, and that is a deliberate reversal**
# (11 Sep, plan §9.2). §5 gave the correlator the better model because its narrative is on
# camera and the other two only fill a schema from an enum. That split optimised *cost*.
#
# On the Gemini free tier the binding constraint is not cost, it is **requests per day**:
# 2.5 Flash / 2.5 Flash Lite / 3 Flash allow 20 RPD, while 3.1 and 3.5 Flash Lite allow
# 500. Twenty requests does not survive one afternoon of prompt tuning, let alone the
# rehearsals and video takes on Sep 13. Every model with real headroom is a Lite, so the
# split cannot be preserved as written — and a nominal split between two Lites would be
# the appearance of §5's reasoning without its substance.
#
# One model, the newest with 500 RPD. Quota is the scarce resource here, not dollars.
GEMINI_FLASH_LITE = "gemini-3.5-flash-lite"

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
    },
    # Target path if Anthropic access lands. Wired so that switching is a env var, not a
    # code change — but do not switch after Sep 12: an unrehearsed model change on demo
    # week is not worth the prose (plan §5).
    LlmMode.SONNET: {
        "orchestrator": HAIKU,
        "correlator": SONNET,
        "proposer": SONNET,
    },
    # The active path (plan §9.2). Same split as `demo`, different provider.
    LlmMode.GEMINI: dict.fromkeys(AGENTS, GEMINI_FLASH_LITE),
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
    return MODEL_ASSIGNMENT[mode][agent]


def provider_for(mode: LlmMode | None = None) -> Provider:
    """Which client serves this mode. Raises for the offline modes, same as `model_for`."""
    mode = mode if mode is not None else llm_mode()
    if mode not in PROVIDER:
        raise ValueError(f"FAZEROPS_LLM={mode.value} does not call a model")
    return PROVIDER[mode]


def requires_network(mode: LlmMode | None = None) -> bool:
    mode = mode if mode is not None else llm_mode()
    return mode in MODEL_ASSIGNMENT


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
