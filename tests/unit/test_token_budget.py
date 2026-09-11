"""W17 — the token meter. Plan §5's guardrails.

The two failure modes this guards against are both invisible: a context leak still renders
a correct brief, and a runaway tool loop still renders a correct brief. Neither shows up
on screen, and AWS credit consumption lags Cost Explorer by up to 24h, so the ledger is
the only real-time signal there is.

Which means the assertions worth writing are about the ledger surviving things — a crash,
a second process, a torn line — rather than about arithmetic.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone

import pytest

from fazerops.agents.budget import (
    PRICING,
    BudgetExceeded,
    TokenMeter,
    estimate_usd,
)


@pytest.fixture
def ledger(tmp_path):
    return tmp_path / ".fazerops" / "token_ledger.jsonl"


@pytest.fixture
def meter(ledger):
    return TokenMeter(ledger_path=ledger)


def lines(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# --------------------------------------------------------------------------------------
# Every call is written down
# --------------------------------------------------------------------------------------


def test_every_call_appends_a_ledger_line(meter, ledger):
    meter.record("correlator", "amazon.nova-pro-v1:0", 3_800, 900)
    meter.record("proposer", "amazon.nova-lite-v1:0", 2_000, 300)

    assert len(lines(ledger)) == 2


def test_a_ledger_line_carries_exactly_the_fields_plan_5_names(meter, ledger):
    """`{ts, agent, model, in, out, est_usd}`. Asserted as a set so that adding a field is
    a deliberate act — anything reading this file back (the day cap does) parses it."""
    meter.record("correlator", "amazon.nova-pro-v1:0", 100, 50)

    assert set(lines(ledger)[0]) == {
        "ts", "agent", "model", "in", "out", "est_usd", "estimated",
    }


def test_the_ledger_directory_is_created_on_first_write(ledger):
    assert not ledger.parent.exists()
    TokenMeter(ledger_path=ledger).record("proposer", "amazon.nova-lite-v1:0", 10, 10)
    assert ledger.is_file()


def test_measured_and_estimated_counts_are_distinguishable(meter, ledger):
    """Plan §5 makes this file the real-time spend signal, because AWS credit consumption
    lags Cost Explorer by up to 24h. A signal that cannot say whether it measured or
    guessed is a worse signal than one that admits it.

    Not hypothetical: Strands' Gemini `structured_output` emits no usage event, so every
    correlator entry recorded on 11 Sep is an estimate.
    """
    meter.record("correlator", "gemini-3.5-flash-lite", 700, 120, estimated=True)
    meter.record("proposer", "gemini-3.5-flash-lite", 100, 20)

    first, second = lines(ledger)
    assert first["estimated"] is True
    assert second["estimated"] is False


def test_the_timestamp_is_timezone_aware(meter, ledger):
    """`spent_today` compares dates across processes and machines. A naive timestamp makes
    "today" mean whatever the writer's local clock said."""
    meter.record("proposer", "amazon.nova-lite-v1:0", 10, 10)
    assert datetime.fromisoformat(lines(ledger)[0]["ts"]).tzinfo is not None


# --------------------------------------------------------------------------------------
# The caps
# --------------------------------------------------------------------------------------


def test_the_run_token_cap_raises(ledger):
    meter = TokenMeter(ledger_path=ledger, run_token_cap=1_000)
    meter.record("orchestrator", "amazon.nova-lite-v1:0", 400, 100)

    with pytest.raises(BudgetExceeded, match="over the 1,000 cap"):
        meter.record("orchestrator", "amazon.nova-lite-v1:0", 400, 200)


def test_the_call_that_breaks_the_budget_is_still_recorded(ledger):
    """The tokens were spent before we were told about them. A meter whose own alarm
    creates a gap in the audit trail has erased the one run you would want to read."""
    meter = TokenMeter(ledger_path=ledger, run_token_cap=100)

    with pytest.raises(BudgetExceeded):
        meter.record("orchestrator", "amazon.nova-lite-v1:0", 900, 100)

    assert len(lines(ledger)) == 1
    assert lines(ledger)[0]["in"] == 900


def test_the_run_cap_is_not_tripped_by_a_call_that_merely_reaches_it(ledger):
    """Strictly greater than. A cap that fires *at* the limit makes the documented figure
    off by one, and the documented figure is what plan §5 quotes."""
    meter = TokenMeter(ledger_path=ledger, run_token_cap=1_000)
    meter.record("orchestrator", "amazon.nova-lite-v1:0", 600, 400)

    assert meter.tokens == 1_000


def test_the_day_cap_raises(ledger):
    meter = TokenMeter(ledger_path=ledger, day_usd_cap=0.001, run_token_cap=10**9)

    with pytest.raises(BudgetExceeded, match="over the \\$0.00 cap"):
        meter.record("correlator", "anthropic.claude-sonnet-4-5-20250929-v1:0", 100_000, 0)


def test_the_day_cap_counts_spend_from_earlier_processes(ledger):
    """The cap is *per day*, and a day is many runs — most of them separate `python -m`
    invocations. An in-memory total would reset with every one of them, which is exactly
    the usage pattern the cap exists to bound."""
    first = TokenMeter(ledger_path=ledger, day_usd_cap=1.0, run_token_cap=10**9)
    first.record("correlator", "anthropic.claude-sonnet-4-5-20250929-v1:0", 200_000, 0)

    second = TokenMeter(ledger_path=ledger, day_usd_cap=1.0, run_token_cap=10**9)
    assert second.usd == 0.0, "a fresh meter starts its own run at zero"
    assert second.spent_today() == pytest.approx(0.6, abs=1e-6)

    with pytest.raises(BudgetExceeded, match="today's spend"):
        second.record("correlator", "anthropic.claude-sonnet-4-5-20250929-v1:0", 200_000, 0)


def test_yesterdays_spend_does_not_count_against_today(ledger, meter):
    ledger.parent.mkdir(parents=True, exist_ok=True)
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    ledger.write_text(
        json.dumps(
            {
                "ts": yesterday.isoformat(),
                "agent": "correlator",
                "model": "amazon.nova-pro-v1:0",
                "in": 1,
                "out": 1,
                "est_usd": 99.0,
            }
        )
        + "\n"
    )
    assert meter.spent_today() == 0.0


def test_a_torn_final_line_does_not_break_the_day_total(ledger, meter):
    """A run killed mid-write — which is what a runaway loop invites you to do — leaves a
    partial line. The budget check must survive reading it, or the guardrail dies exactly
    when it is needed."""
    meter.record("correlator", "amazon.nova-pro-v1:0", 1_000, 100)
    with ledger.open("a") as handle:
        handle.write('{"ts": "2026-09-1')

    assert meter.spent_today() > 0.0


# --------------------------------------------------------------------------------------
# Pricing
# --------------------------------------------------------------------------------------


def test_cost_is_computed_per_million_tokens():
    # Nova Pro: $0.80/1M in, $3.20/1M out.
    assert estimate_usd("amazon.nova-pro-v1:0", 1_000_000, 0) == pytest.approx(0.80)
    assert estimate_usd("amazon.nova-pro-v1:0", 0, 1_000_000) == pytest.approx(3.20)


def test_an_unknown_model_is_priced_at_the_worst_known_rate():
    """A typo in a model id must not buy silence from the budget. Erring expensive stops a
    run early; erring cheap is how a guardrail becomes decoration."""
    worst = max(PRICING.values())
    assert estimate_usd("amazon.nova-typo-v9:0", 1_000_000, 0) == pytest.approx(worst[0])
    assert estimate_usd("amazon.nova-typo-v9:0", 1_000_000, 0) > estimate_usd(
        "amazon.nova-lite-v1:0", 1_000_000, 0
    )


def test_the_demo_path_run_cost_matches_plan_5():
    """Plan §5 quotes $0.0064 for the interim path — Nova Pro correlator, Nova Lite
    orchestrator and proposer, at ~9,800 in / ~1,600 out. Asserted so that a pricing edit
    cannot silently invalidate a figure the plan and the README both cite."""
    total = (
        estimate_usd("amazon.nova-lite-v1:0", 4_000, 400)
        + estimate_usd("amazon.nova-pro-v1:0", 3_800, 900)
        + estimate_usd("amazon.nova-lite-v1:0", 2_000, 300)
    )
    assert total == pytest.approx(0.0064, abs=0.0005)


# --------------------------------------------------------------------------------------
# The runaway-loop signal
# --------------------------------------------------------------------------------------


def test_per_agent_totals_expose_a_runaway_orchestrator(ledger):
    """Plan §5: *"orchestrator tokens exceeding correlator tokens on any run is the
    signal"*. The orchestrator's job is small and bounded; out-spending the agent that
    reads fifteen projected events means it is looping, and nothing on screen says so.

    The run cap is lifted here so the *breakdown* is what is under test — at the real
    25k cap this loop trips `BudgetExceeded` on its sixth call, which the next test
    asserts is exactly what should happen.
    """
    meter = TokenMeter(ledger_path=ledger, run_token_cap=10**9)
    for _ in range(10):
        meter.record("orchestrator", "amazon.nova-lite-v1:0", 4_000, 400)
    meter.record("correlator", "amazon.nova-pro-v1:0", 3_800, 900)

    per_agent = meter.per_agent
    assert per_agent["orchestrator"] > per_agent["correlator"]


def test_the_real_run_cap_stops_a_runaway_loop_before_it_gets_expensive(meter):
    """The guardrail, at its documented setting. A four-turn orchestrator costs ~4.4k
    tokens a turn, so the 25k cap bites during the sixth — well before a loop that
    produces no visible symptom has spent anything that matters."""
    with pytest.raises(BudgetExceeded, match="per-agent"):
        for _ in range(10):
            meter.record("orchestrator", "amazon.nova-lite-v1:0", 4_000, 400)

    assert meter.tokens > 25_000
    assert meter.usd < 0.01, "the cap bites long before the money does"


def test_a_healthy_run_has_the_correlator_ahead(meter):
    meter.record("orchestrator", "amazon.nova-lite-v1:0", 4_000, 400)
    meter.record("correlator", "amazon.nova-pro-v1:0", 3_800, 900)
    meter.record("proposer", "amazon.nova-lite-v1:0", 2_000, 300)

    assert meter.tokens == 11_400
    assert meter.tokens < 25_000, "the documented run cap"
