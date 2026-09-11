#!/usr/bin/env python
"""Record the agent cassettes against a real model. Plan §5's `record` mode.

Run this once, whenever the prompt or the active model changes:

    .venv/bin/python scripts/record_cassettes.py

**Never hand-author a cassette.** The whole point is that CI replays what a real model
actually said — `tests/cassettes/README.md` states the obligation and W10a explains why it
matters: recording real CloudTrail is what revealed that Lambda versions its event names,
which a hand-written fixture would have passed while dropping every Lambda change.

Costs a small number of requests against the Gemini free tier. The active model is chosen
for its 500 requests/day quota (see `agents/llm.py`), so this is cheap — but it is not
free, and the script records the minimum set rather than looping.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))


def load_dotenv() -> None:
    """Read `.env` if present. Deliberately not `python-dotenv`: one fewer dependency, and
    the parsing rules here are ours rather than a library's."""
    env_file = REPO_ROOT / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


async def main() -> int:
    load_dotenv()

    if not os.environ.get("GEMINI_API_KEY"):
        print(
            "error: GEMINI_API_KEY is not set.\n"
            "  Put it in .env (gitignored) — never in .env.example, which is committed.",
            file=sys.stderr,
        )
        return 2

    os.environ["FAZEROPS_MODE"] = "fixture"
    os.environ["FAZEROPS_LLM"] = "record"

    from fazerops.agents.budget import TokenMeter
    from fazerops.agents.correlator import correlate
    from fazerops.agents.orchestrator import orchestrate
    from fazerops.ingest.alerts import normalize_alert
    from fazerops.pipeline import investigate

    alert_path = REPO_ROOT / "fixtures" / "alerts" / "alertmanager.json"
    alert = normalize_alert(json.loads(alert_path.read_text(encoding="utf-8")))

    meter = TokenMeter()

    # The orchestrator first, and on its own rather than implicitly through `investigate`.
    # Recording it here means the run that writes the tape is the run whose decision is
    # asserted, and a loop that never dispatches is visible right now instead of surfacing
    # as a degraded brief in CI three days later.
    plan = await orchestrate(alert, meter=meter)
    print(
        f"recorded orchestrator cassette: service={plan.service} "
        f"window={plan.window.hours:.0f}h dispatched={plan.dispatched}"
    )
    if not plan.dispatched:
        print(
            f"error: the orchestrator did not dispatch ({plan.note}). Nothing was recorded "
            "for it — a cassette of a degraded run replays as the agent working.",
            file=sys.stderr,
        )
        return 1

    brief = await investigate(alert)
    print(f"brief: {len(brief.candidates)} candidates, rank 1 = {brief.top.event.resource.name}")

    narrative = await correlate(brief, meter=meter)

    print(f"\nrecorded correlator cassette ({meter.tokens} tokens, ${meter.usd:.6f} total)")
    print(f"  confidence: {narrative.confidence}")
    print(f"  claims kept: {len(narrative.claims)}  dropped: {len(narrative.dropped)}")
    for claim in narrative.claims:
        print(f"    - {claim.text}")
    for dropped in narrative.dropped:
        # Not a failure of the recording — it is the validator doing its job, and it is
        # worth seeing, because a real model dropping claims here is the signal that the
        # prompt needs work rather than the validator.
        print(f"    ! dropped: {dropped.text!r} ({dropped.reason})")

    # Replay immediately. A cassette that was written but cannot be found by the key the
    # replay path derives is worse than no cassette — it passes recording and fails CI.
    os.environ["FAZEROPS_LLM"] = "cassette"

    replayed_plan = await orchestrate(alert)
    assert not replayed_plan.degraded, f"orchestrator cassette did not replay: {replayed_plan.note}"
    assert replayed_plan.service == plan.service
    assert replayed_plan.window.hours == plan.window.hours

    replayed = await correlate(brief)
    assert replayed.primary_cause_event_id == narrative.primary_cause_event_id

    print("\nreplay verified: both cassettes are readable by cassette mode")

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
