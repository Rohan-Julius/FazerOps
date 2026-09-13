"""`FAZEROPS_GEMINI_MODEL_*` and `FAZEROPS_GEMINI_THINKING` — a clone's `.env` choosing the
models its key can reach, without moving what CI replays.

The failure these tests exist for is quiet: an override that leaked into cassette mode, or
into a recording, would key tapes on a model the committed table does not name. Recording
would succeed, and every other clone's CI would miss.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fazerops.agents.correlator import GEMINI_PARAMS, generation_params_for
from fazerops.agents.llm import MODEL_ASSIGNMENT, model_for, recording_model_for
from fazerops.config import GEMINI_MODEL_ENV, ConfigError, LlmMode

DEFAULTS = MODEL_ASSIGNMENT[LlmMode.GEMINI]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (*GEMINI_MODEL_ENV.values(), "FAZEROPS_GEMINI_THINKING"):
        monkeypatch.delenv(name, raising=False)


def test_a_live_run_uses_the_models_the_env_names(monkeypatch):
    monkeypatch.setenv("FAZEROPS_GEMINI_MODEL_CORRELATOR", "gemini-3.5-flash")

    assert model_for("correlator", LlmMode.GEMINI) == "gemini-3.5-flash"
    assert model_for("proposer", LlmMode.GEMINI) == DEFAULTS["proposer"], "one agent only"


def test_cassette_replay_ignores_the_env(monkeypatch):
    """What keeps a clone with its own `.env` green in CI."""
    for name in GEMINI_MODEL_ENV.values():
        monkeypatch.setenv(name, "gemini-3.5-flash-lite")
    monkeypatch.setenv("FAZEROPS_GEMINI_THINKING", "high")

    assert all(recording_model_for(agent) == DEFAULTS[agent] for agent in DEFAULTS)
    assert generation_params_for(LlmMode.CASSETTE) == GEMINI_PARAMS
    assert generation_params_for(LlmMode.STUB) == GEMINI_PARAMS


def test_recording_refuses_a_model_the_table_does_not_name(monkeypatch):
    monkeypatch.setenv("FAZEROPS_GEMINI_MODEL_PROPOSER", "gemini-3.5-flash")

    with pytest.raises(ConfigError, match="FAZEROPS_GEMINI_MODEL_PROPOSER"):
        model_for("proposer", LlmMode.RECORD)


def test_recording_accepts_an_override_equal_to_the_default(monkeypatch):
    """A `.env` that spells out the defaults is not drift, and must not block a recording."""
    monkeypatch.setenv("FAZEROPS_GEMINI_MODEL_PROPOSER", DEFAULTS["proposer"])

    assert model_for("proposer", LlmMode.RECORD) == DEFAULTS["proposer"]


@pytest.mark.parametrize("level", ["minimal", "medium", "high"])
def test_a_live_run_sends_the_thinking_level_the_env_names(monkeypatch, level):
    monkeypatch.setenv("FAZEROPS_GEMINI_THINKING", level)

    assert generation_params_for(LlmMode.GEMINI)["thinking_config"] == {"thinking_level": level}


def test_thinking_off_omits_the_field_for_models_that_reject_it(monkeypatch):
    monkeypatch.setenv("FAZEROPS_GEMINI_THINKING", "off")

    params = generation_params_for(LlmMode.GEMINI)
    assert "thinking_config" not in params
    assert params["max_output_tokens"] == GEMINI_PARAMS["max_output_tokens"]


def test_recording_refuses_a_different_thinking_level(monkeypatch):
    monkeypatch.setenv("FAZEROPS_GEMINI_THINKING", "high")

    with pytest.raises(ConfigError, match="FAZEROPS_GEMINI_THINKING"):
        generation_params_for(LlmMode.RECORD)


def test_an_unknown_thinking_level_fails_loudly(monkeypatch):
    monkeypatch.setenv("FAZEROPS_GEMINI_THINKING", "lo")

    with pytest.raises(ConfigError, match="FAZEROPS_GEMINI_THINKING"):
        generation_params_for(LlmMode.GEMINI)


def test_the_live_client_is_built_with_the_overridden_params(monkeypatch):
    """The parameters sent and the parameters keyed come from one function."""
    from fazerops.agents.correlator import _gemini_model

    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("FAZEROPS_LLM", "gemini")
    monkeypatch.setenv("FAZEROPS_GEMINI_THINKING", "off")

    assert "thinking_config" not in _gemini_model("gemini-2.5-flash").config["params"]


def test_env_example_documents_every_override():
    example = (Path(__file__).resolve().parents[2] / ".env.example").read_text(encoding="utf-8")

    for name in (*GEMINI_MODEL_ENV.values(), "FAZEROPS_GEMINI_THINKING", "FAZEROPS_GEMINI_BACKEND"):
        assert f"\n{name}=\n" in example, f"{name} missing from .env.example"
