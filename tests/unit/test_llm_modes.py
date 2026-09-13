"""W17 — per-agent model assignment across the five modes. Plan §5.

The assignment table is the thing that decides what a run costs, and it is one dict. The
risk is not that it is complicated; it is that `stub` or `cassette` quietly acquires a
model id and something reaches for the network in the one configuration that promises it
will not.
"""

from __future__ import annotations

import pytest

from fazerops.agents.budget import PRICING, estimate_usd
from fazerops.agents.llm import AGENTS, MODEL_ASSIGNMENT, model_for, requires_network
from fazerops.config import LlmMode


@pytest.mark.parametrize("mode", [LlmMode.STUB, LlmMode.CASSETTE])
def test_the_offline_modes_have_no_model_at_all(mode):
    """Not "a cheap model" — none. Returning a plausible id would let a bug construct a
    client on the zero-network path, and that path is what a judge runs."""
    assert not requires_network(mode)
    with pytest.raises(ValueError, match="does not call a model"):
        model_for("correlator", mode)


@pytest.mark.parametrize(
    "mode", [LlmMode.NOVA, LlmMode.DEMO, LlmMode.RECORD, LlmMode.SONNET, LlmMode.GEMINI]
)
def test_every_network_mode_assigns_all_three_agents(mode):
    assert requires_network(mode)
    assert set(MODEL_ASSIGNMENT[mode]) == set(AGENTS)


def test_every_assigned_model_has_a_price():
    """An unpriced model is charged at the worst known rate, which is safe but silently
    wrong in the ledger. Every model we actually assign should be priced properly."""
    for mode, assignment in MODEL_ASSIGNMENT.items():
        for agent, model in assignment.items():
            assert model in PRICING, f"{mode.value}/{agent} uses unpriced {model}"


def test_the_demo_path_puts_the_expensive_model_only_on_the_correlator():
    """Plan §5's split: the correlator's narrative is on camera, so phrasing matters
    there and only there. The other two fill a schema from an enum."""
    demo = MODEL_ASSIGNMENT[LlmMode.DEMO]

    assert demo["correlator"] == "amazon.nova-pro-v1:0"
    assert demo["orchestrator"] == demo["proposer"] == "amazon.nova-lite-v1:0"
    assert estimate_usd(demo["correlator"], 1_000, 0) > estimate_usd(
        demo["orchestrator"], 1_000, 0
    )


def test_record_follows_whatever_path_is_active():
    """Cassettes must hold what the demo replays. Until 11 Sep the active path *was*
    `demo`; §9.2 made it `gemini`, and `record` follows `ACTIVE_PATH` rather than naming a
    mode — which is what makes the reversal a one-line change instead of a bug waiting for
    whoever forgets to update this too."""
    from fazerops.agents.llm import ACTIVE_PATH

    assert MODEL_ASSIGNMENT[LlmMode.RECORD] == MODEL_ASSIGNMENT[ACTIVE_PATH]


def test_the_demo_path_is_cheaper_than_the_sonnet_path():
    """The reason the interim path was acceptable at all (plan §5: $0.0064 vs $0.047)."""
    def run_cost(mode):
        assignment = MODEL_ASSIGNMENT[mode]
        return (
            estimate_usd(assignment["orchestrator"], 4_000, 400)
            + estimate_usd(assignment["correlator"], 3_800, 900)
            + estimate_usd(assignment["proposer"], 2_000, 300)
        )

    assert run_cost(LlmMode.DEMO) < run_cost(LlmMode.SONNET) / 5


def test_an_unknown_agent_is_rejected():
    with pytest.raises(ValueError, match="unknown agent"):
        model_for("collector", LlmMode.DEMO)


def test_the_active_mode_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("FAZEROPS_LLM", "demo")
    assert model_for("correlator") == "amazon.nova-pro-v1:0"

    monkeypatch.setenv("FAZEROPS_LLM", "nova")
    assert model_for("correlator") == "amazon.nova-lite-v1:0"


def test_cassette_borrows_the_recording_assignment_for_its_key():
    """`cassette` has no model of its own and must not acquire one — but it still needs
    the id that `record` baked into the request key, or every replay misses."""
    from fazerops.agents.llm import recording_model_for

    assert recording_model_for("correlator") == MODEL_ASSIGNMENT[LlmMode.RECORD]["correlator"]
    with pytest.raises(ValueError):
        model_for("correlator", LlmMode.CASSETTE)


# --------------------------------------------------------------------------------------
# The §9.2 hybrid — Gemini active, Bedrock wired and reversible
# --------------------------------------------------------------------------------------


def test_gemini_is_the_active_path():
    """Plan §9.2. `record` must follow whatever is active, or the cassettes hold tape the
    demo never plays."""
    from fazerops.agents.llm import ACTIVE_PATH, MODEL_ASSIGNMENT, PROVIDER, Provider

    assert ACTIVE_PATH is LlmMode.GEMINI
    assert PROVIDER[LlmMode.RECORD] is Provider.GEMINI
    assert MODEL_ASSIGNMENT[LlmMode.RECORD] == MODEL_ASSIGNMENT[LlmMode.GEMINI]


def test_the_bedrock_paths_are_still_wired():
    """The deviation is a fallback, not a migration. `demo` and `sonnet` must remain
    reachable so the §9.2 reversal is an env var rather than a rewrite."""
    from fazerops.agents.llm import PROVIDER, Provider

    assert PROVIDER[LlmMode.DEMO] is Provider.BEDROCK
    assert PROVIDER[LlmMode.SONNET] is Provider.BEDROCK
    assert model_for("correlator", LlmMode.DEMO) == "amazon.nova-pro-v1:0"


def test_gemini_restores_the_split_in_sonnets_shape():
    """§5's split was dropped on 11 Sep for a free-tier quota that Vertex does not have
    (13 Sep, plan §9.2). Restored in the shape `sonnet` already gives it: the cheap model
    routes, the stronger one writes and proposes."""
    gemini = MODEL_ASSIGNMENT[LlmMode.GEMINI]
    sonnet = MODEL_ASSIGNMENT[LlmMode.SONNET]

    assert set(gemini) == set(AGENTS)
    assert gemini["correlator"] == gemini["proposer"] != gemini["orchestrator"]
    assert (sonnet["correlator"] == sonnet["proposer"]) and (
        sonnet["orchestrator"] != sonnet["correlator"]
    )


@pytest.mark.parametrize(
    ("raw", "vertexai"), [(None, True), ("vertex", True), ("AISTUDIO", False)]
)
def test_the_gemini_client_is_pointed_at_the_chosen_backend(monkeypatch, raw, vertexai):
    """Vertex by default. A Vertex express key is refused by AI Studio and the reverse, so
    the wrong default is a 403 on every agent — asserted on the constructed client, which
    builds without touching the network."""
    from fazerops.agents.correlator import _gemini_model

    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    if raw is None:
        monkeypatch.delenv("FAZEROPS_GEMINI_BACKEND", raising=False)
    else:
        monkeypatch.setenv("FAZEROPS_GEMINI_BACKEND", raw)

    assert _gemini_model("gemini-3.8-flash").client_args["vertexai"] is vertexai


def test_an_unknown_gemini_backend_fails_loudly(monkeypatch):
    from fazerops.config import ConfigError, gemini_backend

    monkeypatch.setenv("FAZEROPS_GEMINI_BACKEND", "vertx")
    with pytest.raises(ConfigError, match="FAZEROPS_GEMINI_BACKEND"):
        gemini_backend()


def test_provider_for_refuses_the_offline_modes():
    from fazerops.agents.llm import provider_for

    for mode in (LlmMode.STUB, LlmMode.CASSETTE):
        with pytest.raises(ValueError, match="does not call a model"):
            provider_for(mode)
