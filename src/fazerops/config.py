"""The two orthogonal switches the whole build runs on (plan §5).

    FAZEROPS_MODE = fixture | live                       where collector data comes from
    FAZEROPS_LLM  = stub | cassette | record | nova | demo | sonnet | gemini

`fixture` + `stub` is the zero-credential, zero-network path — the CI default, and the
path a judge hits on a clean machine with no AWS config. It is guarded by
`tests/integration/test_no_network.py`, not by convention.

Read from the environment on every call rather than cached at import. Caching would make
the switches untestable without process restarts, and the cost is a dict lookup.
"""

from __future__ import annotations

import os
from enum import Enum


class Mode(str, Enum):
    FIXTURE = "fixture"
    LIVE = "live"


class LlmMode(str, Enum):
    STUB = "stub"
    """Canned deterministic structured output. No network. The CI default."""

    CASSETTE = "cassette"
    """Replay of recorded responses, keyed on request hash. No network."""

    RECORD = "record"
    """Records cassettes against whichever model path is active. Network."""

    NOVA = "nova"
    """All Nova Lite — the cheap interactive-iteration path."""

    DEMO = "demo"
    """The active demo path while Anthropic access is blocked (plan §1.2 U5):
    Nova Pro correlator, Nova Lite orchestrator and proposer."""

    SONNET = "sonnet"
    """Target path if Anthropic access lands. Wired but currently unreachable."""

    GEMINI = "gemini"
    """**The active path from 11 Sep** (plan §9.2). Bedrock inference is blocked
    account-wide, so the three agents run on Gemini rather than on a stub — a stub would
    make the agent claim hollow. Bedrock stays wired: this is a fallback, not a
    destination, and §9.2 names the reversal."""


class GeminiBackend(str, Enum):
    """Which Google endpoint serves `FAZEROPS_LLM=gemini`. Same models, same key variable,
    different client flag — so the choice is a switch, not a code path."""

    VERTEX = "vertex"
    """**The default from 13 Sep** (plan §9.2). Vertex AI express mode, billed against GCP
    credits. The AI Studio free tier capped the stronger models at 20 requests/day, which
    is what had forced all three agents onto one Lite."""

    AISTUDIO = "aistudio"
    """The 11 Sep path. A Vertex express key is refused here, and vice versa."""


class GeminiThinking(str, Enum):
    """`FAZEROPS_GEMINI_THINKING`. Gemini 3 models take a `thinking_level`; older ones
    reject the field, so `off` omits it rather than sending a level they cannot parse."""

    OFF = "off"
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


OFFLINE_LLM_MODES = frozenset({LlmMode.STUB, LlmMode.CASSETTE})

# One variable per agent rather than one for all three: the split in `agents/llm.py` is
# deliberate, and a single override would quietly collapse it.
GEMINI_MODEL_ENV = {
    agent: f"FAZEROPS_GEMINI_MODEL_{agent.upper()}"
    for agent in ("orchestrator", "correlator", "proposer")
}


class ConfigError(ValueError):
    """A switch was set to something that is not a valid value. Failing loudly beats
    silently falling back to a default, which on demo day means running the wrong path."""


def _read(name: str, enum: type[Enum], default: Enum) -> Enum:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return enum(raw.strip().lower())
    except ValueError:
        valid = ", ".join(member.value for member in enum)
        raise ConfigError(f"{name}={raw!r} is not valid; expected one of: {valid}") from None


def mode() -> Mode:
    return _read("FAZEROPS_MODE", Mode, Mode.FIXTURE)


def llm_mode() -> LlmMode:
    return _read("FAZEROPS_LLM", LlmMode, LlmMode.STUB)


def gemini_backend() -> GeminiBackend:
    return _read("FAZEROPS_GEMINI_BACKEND", GeminiBackend, GeminiBackend.VERTEX)


def gemini_model_overrides() -> dict[str, str]:
    """Agents whose Gemini model is set in the environment, for someone whose key reaches a
    different set of models — an AI Studio free-tier key may not reach Pro at all.

    **Free text, not an enum.** Which models a key can call changes by account, tier and
    month; a list here would reject the one model a user's key actually serves.
    """
    overrides = {}
    for agent, name in GEMINI_MODEL_ENV.items():
        raw = os.environ.get(name, "").strip()
        if raw:
            overrides[agent] = raw
    return overrides


def gemini_thinking() -> GeminiThinking | None:
    """The thinking level set in the environment, or `None` to keep the default."""
    if not os.environ.get("FAZEROPS_GEMINI_THINKING", "").strip():
        return None
    return _read("FAZEROPS_GEMINI_THINKING", GeminiThinking, GeminiThinking.LOW)


def is_offline() -> bool:
    """True when nothing in this process is permitted to open a socket."""
    return mode() is Mode.FIXTURE and llm_mode() in OFFLINE_LLM_MODES


def require_offline_capable(component: str) -> None:
    """Called by anything about to construct a network client.

    The failure this prevents is a boto3 client built at import time in fixture mode: it
    does not raise, it silently reaches for IMDS and hangs for the credential-chain
    timeout — which on a judge's machine looks like the demo being broken.
    """
    if is_offline():
        raise RuntimeError(
            f"{component} attempted to construct a network client while "
            f"FAZEROPS_MODE={mode().value} and FAZEROPS_LLM={llm_mode().value}. "
            "The fixture path must not touch the network."
        )
