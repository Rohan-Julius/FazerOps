"""W17 — the token meter. Plan §5's guardrails, as code rather than discipline.

Two failure modes justify this module, and neither is caught by watching the console:

1. **A context leak.** Pasting raw CloudTrail JSON takes a run from ~10k to ~120k tokens.
   W16's projection is the fix; this is the alarm for when the fix regresses.
2. **A runaway tool loop.** An agentic orchestrator under a bad prompt can call
   `resolve_blast_radius` ten times. Unlike a context leak it produces **no visible
   symptom** — the brief still renders, correctly, and only the bill knows.

**AWS credit consumption lags Cost Explorer by up to 24h**, so Cost Explorer cannot be the
feedback loop during a build that lasts nine days. `.fazerops/token_ledger.jsonl` is the
real-time signal, and it is append-only so a crashed run still leaves its spend behind.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import date, datetime, timezone
from pathlib import Path

__all__ = ["BudgetExceeded", "TokenMeter", "estimate_usd", "PRICING"]

LEDGER_PATH = Path(".fazerops") / "token_ledger.jsonl"

# Per-run and per-day caps, plan §5. The run cap is tokens because a single runaway loop
# is a token problem; the day cap is dollars because accumulated spend across many small
# runs is a money problem. Different questions, so different units.
RUN_TOKEN_CAP = 25_000
DAY_USD_CAP = 3.00

# UNVERIFIED (U6) — plan §5 flags the AWS figures as third-party aggregator numbers, not
# the AWS pricing page; the Gemini rates are likewise unconfirmed against Google's page. They drive a *guardrail*, not a bill, so being wrong makes the alarm fire
# at the wrong threshold rather than costing money. Verify before quoting them anywhere.
PRICING: dict[str, tuple[float, float]] = {
    # model id: ($ per 1M input tokens, $ per 1M output tokens)
    "amazon.nova-micro-v1:0": (0.035, 0.14),
    "amazon.nova-lite-v1:0": (0.06, 0.24),
    "amazon.nova-2-lite-v1:0": (0.06, 0.24),
    "amazon.nova-pro-v1:0": (0.80, 3.20),
    "anthropic.claude-haiku-4-5-20251001-v1:0": (1.00, 5.00),
    "anthropic.claude-sonnet-4-5-20250929-v1:0": (3.00, 15.00),
    "anthropic.claude-sonnet-5": (3.00, 15.00),
    # Gemini — the active path (plan §9.2). **Paid-tier rates deliberately**, even though
    # the build runs inside the free tier: a guardrail priced at $0 cannot fire, and the
    # free tier is a rate limit rather than a spending guarantee. If the build ever spills
    # past it, the ledger is already counting in real money.
    "gemini-3.5-flash-lite": (0.10, 0.40),
    "gemini-3.1-flash-lite": (0.10, 0.40),
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-pro": (1.25, 10.00),
}

# An unknown model is priced at the most expensive rate we know rather than at zero.
# A typo in a model id must not buy silence from the budget — erring expensive stops a run
# early, and erring cheap is how a guardrail becomes decoration.
_WORST_RATE = max(PRICING.values())


class BudgetExceeded(RuntimeError):
    """A cap was passed. Raised *after* the usage is recorded — see `TokenMeter.record`."""


def estimate_usd(model: str, tokens_in: int, tokens_out: int) -> float:
    rate_in, rate_out = PRICING.get(model, _WORST_RATE)
    return (tokens_in * rate_in + tokens_out * rate_out) / 1_000_000


class TokenMeter:
    """One instance per run. Thread-safe, because W19's graph runs collectors concurrently
    and a shared meter counted from several threads is the one place a lost update turns a
    guardrail into a lie.
    """

    def __init__(
        self,
        *,
        ledger_path: Path | str | None = None,
        run_token_cap: int = RUN_TOKEN_CAP,
        day_usd_cap: float = DAY_USD_CAP,
    ) -> None:
        self.ledger_path = Path(ledger_path) if ledger_path is not None else LEDGER_PATH
        self.run_token_cap = run_token_cap
        self.day_usd_cap = day_usd_cap

        self._lock = threading.Lock()
        self.tokens_in = 0
        self.tokens_out = 0
        self.usd = 0.0
        self.calls: list[dict] = []

    # ----------------------------------------------------------------------------------

    @property
    def tokens(self) -> int:
        return self.tokens_in + self.tokens_out

    @property
    def per_agent(self) -> dict[str, int]:
        """Tokens by agent. Plan §5: *"orchestrator tokens exceeding correlator tokens on
        any run is the signal"* — the orchestrator's job is small and bounded, so it
        out-spending the agent that reads fifteen events means it is looping."""
        totals: dict[str, int] = {}
        for call in self.calls:
            totals[call["agent"]] = totals.get(call["agent"], 0) + call["in"] + call["out"]
        return totals

    def record(
        self,
        agent: str,
        model: str,
        tokens_in: int,
        tokens_out: int,
        *,
        estimated: bool = False,
    ) -> dict:
        """Record one model call, then enforce the caps.

        **The order matters.** The tokens were already spent by the time we are told about
        them, so the ledger line is written before `BudgetExceeded` is raised. A meter that
        refuses to record the call that broke the budget is a meter whose own alarm creates
        a gap in the audit trail — and that gap is exactly the run you would want to read.
        """
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent": agent,
            "model": model,
            "in": int(tokens_in),
            "out": int(tokens_out),
            "est_usd": round(estimate_usd(model, tokens_in, tokens_out), 8),
            # Whether the *token counts* are measured or inferred — `est_usd` is always a
            # derived figure, but these are not always. Added 11 Sep after the first real
            # call proved the distinction matters: Strands' Gemini `structured_output`
            # yields only `{"output": ...}` and emits no usage event at all, so that path
            # falls back to W16's estimator. A ledger that presented an estimate as a
            # measurement would be the wrong kind of wrong for a file whose entire job is
            # to be the spend signal Cost Explorer cannot be (it lags 24h).
            "estimated": bool(estimated),
        }

        with self._lock:
            self.tokens_in += entry["in"]
            self.tokens_out += entry["out"]
            self.usd += entry["est_usd"]
            self.calls.append(entry)
            run_tokens, run_usd = self.tokens, self.usd

        self._append(entry)

        if run_tokens > self.run_token_cap:
            raise BudgetExceeded(
                f"run used {run_tokens:,} tokens, over the {self.run_token_cap:,} cap "
                f"(${run_usd:.4f}); per-agent: {self.per_agent}"
            )

        spent_today = self.spent_today()
        if spent_today > self.day_usd_cap:
            raise BudgetExceeded(
                f"today's spend ${spent_today:.4f} is over the ${self.day_usd_cap:.2f} cap "
                f"({self.ledger_path})"
            )

        return entry

    # ----------------------------------------------------------------------------------

    def _append(self, entry: dict) -> None:
        """Append one JSON line, creating the directory on first write.

        Opened in append mode per call rather than held open for the meter's lifetime: a
        run that is killed mid-flight — which is what a runaway loop invites you to do —
        must still leave every line it already paid for on disk.
        """
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with self.ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def spent_today(self, today: date | None = None) -> float:
        """Read the day's spend back off the ledger, not off this instance.

        The cap is *per day*, and a day contains many runs — most of them separate
        processes. An in-memory total would reset with every `python -m` invocation, which
        is precisely the usage pattern the cap exists to bound.
        """
        if not self.ledger_path.is_file():
            return 0.0

        today = today or datetime.now(timezone.utc).date()
        total = 0.0
        for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                stamped = datetime.fromisoformat(entry["ts"]).date()
            except (json.JSONDecodeError, KeyError, ValueError):
                continue  # a torn final line from a killed run must not break the read
            if stamped == today:
                total += float(entry.get("est_usd", 0.0))
        return total
