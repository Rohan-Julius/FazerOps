"""The two orthogonal switches the whole build runs on (plan §5).

    FABEROPS_MODE = fixture | live                       where collector data comes from
    FABEROPS_LLM  = stub | cassette | record | nova | demo | sonnet

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


OFFLINE_LLM_MODES = frozenset({LlmMode.STUB, LlmMode.CASSETTE})


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
    return _read("FABEROPS_MODE", Mode, Mode.FIXTURE)


def llm_mode() -> LlmMode:
    return _read("FABEROPS_LLM", LlmMode, LlmMode.STUB)


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
            f"FABEROPS_MODE={mode().value} and FABEROPS_LLM={llm_mode().value}. "
            "The fixture path must not touch the network."
        )
