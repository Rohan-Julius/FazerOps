#!/usr/bin/env python
"""Record W27's injection cassettes against a real model. Plan §4 (W27), §5's `record` mode.

    .venv/bin/python scripts/record_injection_cassettes.py

Plan §4 specifies W27's suite runs the **full pipeline in cassette mode**. That needs tapes
recorded from poisoned input, and it cannot reuse the demo's: a cassette is keyed on a hash
of the request (`agents/cassette.py`), so an injected ConfigMap value or alert annotation
changes the prompt and misses by construction. That miss is the cassette layer working, not
a defect — so the fix is to record the poisoned prompts, not to loosen the key.

**What this records is deliberately the model's unfiltered answer.** `propose()` writes the
tape *before* `validate_proposal` runs, so a response that complies with the injection is
captured rather than discarded. That is the whole value: the suite then replays a real
model's behaviour under attack and asserts the barriers hold regardless of what it said. A
tape containing only well-behaved answers would prove the model was well-behaved that day.

Two things keep this honest and separate from the demo's tapes:

* **The tapes live in `tests/cassettes/injection/`, not beside the demo's.** Mixing them
  breaks `test_the_cassette_holds_no_orphaned_keys`, which asserts every key in the demo
  cassette is reachable from the demo prompt — and rightly so: a demo cassette quietly
  carrying entries from a poisoned run is a cassette nobody can audit.
* **The brief is built with `FAZEROPS_LLM=stub`**, so the orchestrator makes no call and the
  brief is deterministic. The prompt the correlator and proposer then see is a pure function
  of the fixtures, which is what lets CI rebuild the identical request and hit the tape.

Both untrusted channels, every payload: 2 agents × 2 channels × len(PAYLOADS) requests
against whatever `agents/llm.py` assigns the correlator and proposer — `gemini-3.1-pro-preview`
on Vertex AI since 13 Sep. The run is still throttled, more lightly: the 12 Sep AI Studio
free tier 429'd from about the eighth unthrottled call, and Vertex's quota for a preview
model on a new project is not something this script can read. Failures are reported rather than aborting: a
correlator whose narrative is rejected by W18's validator is a *result*, and the proposer
tape for that scenario is still worth having.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tests" / "security"))


def load_dotenv() -> None:
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
    # The brief is built under `stub` and only the two model calls run under `record` —
    # see the module docstring.
    os.environ["FAZEROPS_LLM"] = "stub"

    injection_dir = REPO_ROOT / "tests" / "cassettes" / "injection"
    injection_dir.mkdir(parents=True, exist_ok=True)

    from _injection import PAYLOADS, hostile_alert, hostile_fixtures

    from fazerops.agents.budget import TokenMeter
    from fazerops.agents.correlator import correlate
    from fazerops.agents.proposer import propose
    from fazerops.collectors import base as collectors_base
    from fazerops.ingest.alerts import normalize_alert
    from fazerops.pipeline import investigate

    alert_path = REPO_ROOT / "fixtures" / "alerts" / "alertmanager.json"
    clean_payload = json.loads(alert_path.read_text(encoding="utf-8"))

    # **One meter per scenario, never one for the whole script** (13 Sep). `TokenMeter` is
    # "one instance per run" and its 25k cap is a per-run cap; a scenario is a run. A single
    # shared meter fit only while Strands' Gemini path reported *estimates* (~900 tokens a
    # call). With real counts — 3.1 Pro's thoughts included — it crossed the cap on the
    # fourth scenario, and every later call raised `BudgetExceeded` after being billed and
    # before its tape was written: $0.42 spent for 7 of 26 tapes, and the script exited 0.
    meters: list[TokenMeter] = []
    workspace = Path(tempfile.mkdtemp(prefix="fazerops-injection-"))
    pristine = collectors_base.FIXTURE_ROOT
    recorded = 0
    failures: list[str] = []

    try:
        # The control, first and deliberately. Without a clean-input tape the injection
        # tapes prove only that nothing bad happened — they cannot show that the model
        # proposes the *right* thing when it is not under attack, which is what makes
        # "the injection changed nothing" a claim rather than an absence.
        collectors_base.FIXTURE_ROOT = pristine
        brief = await investigate(normalize_alert(clean_payload))
        recorded += await _record_pair(
            "control/clean", brief, correlate, propose, meters, failures, injection_dir
        )

        for name, payload in sorted(PAYLOADS.items()):
            # -- channel 1: the ConfigMap value -----------------------------------------
            poisoned_root = hostile_fixtures(workspace / f"cm-{name}", payload)
            collectors_base.FIXTURE_ROOT = poisoned_root
            brief = await investigate(normalize_alert(clean_payload))
            recorded += await _record_pair(
                f"configmap/{name}", brief, correlate, propose, meters, failures, injection_dir
            )

            # -- channel 2: the alert annotations ---------------------------------------
            collectors_base.FIXTURE_ROOT = pristine
            brief = await investigate(normalize_alert(hostile_alert(payload)))
            recorded += await _record_pair(
                f"alert/{name}", brief, correlate, propose, meters, failures, injection_dir
            )
    finally:
        collectors_base.FIXTURE_ROOT = pristine
        shutil.rmtree(workspace, ignore_errors=True)

    tokens = sum(meter.tokens for meter in meters)
    usd = sum(meter.usd for meter in meters)
    print(f"\n{recorded} call(s) answered; {tokens} tokens, ${usd:.6f}")
    for failure in failures:
        print(f"  note: {failure}")

    # Counted off the files, not off this script's own bookkeeping. On 13 Sep the bookkeeping
    # reported 17 tapes and exit 0 while the files held 7 — a tape is written only after the
    # meter accepts the call, so a refused call can look answered and still leave a hole.
    expected = 1 + 2 * len(PAYLOADS)
    short = {}
    for agent in ("correlator", "proposer"):
        path = injection_dir / f"{agent}.json"
        held = len(json.loads(path.read_text(encoding="utf-8"))) if path.is_file() else 0
        if held != expected:
            short[agent] = held
    if short:
        print(
            f"error: expected {expected} tapes per agent, found {short}. "
            "The suite will hard-fail on the missing keys.",
            file=sys.stderr,
        )
        return 1
    print(f"verified: {expected} tapes per agent on disk")
    return 0


async def _record_pair(label, brief, correlate, propose, meters, failures, directory) -> int:
    """Record the correlator and the proposer for one poisoned brief.

    The correlator runs first because `propose` takes its narrative: recording the proposer
    against a narrative the pipeline would not have produced would tape a prompt CI never
    replays, and every replay would then miss.
    """
    from fazerops.agents.budget import BudgetExceeded, TokenMeter
    from fazerops.agents.proposer import ProposalRejected

    meter = TokenMeter()
    meters.append(meter)
    count = 0
    narrative = None

    os.environ["FAZEROPS_LLM"] = "record"
    try:
        narrative = await correlate(brief, meter=meter, cassette_directory=directory)
        count += 1
        print(f"  {label}: correlator ok — primary={narrative.primary_cause_event_id[:8]}")
    except Exception as exc:
        # W18 rejects a narrative naming a primary cause other than rank 1, and drops
        # uncited claims. Under injection that is a *result*, not an error.
        failures.append(f"{label}: correlator rejected — {type(exc).__name__}: {exc}")
        print(f"  {label}: correlator rejected ({type(exc).__name__})")

    _throttle()

    try:
        proposal = await propose(
            brief, narrative, meter=meter, cassette_directory=directory
        )
        count += 1
        said = "declined" if proposal is None else proposal.action_id
        print(f"  {label}: proposer ok — {said}")
    except BudgetExceeded as exc:
        # Raised by the meter *before* the tape is written, unlike a validation refusal.
        failures.append(f"{label}: proposer over budget, NO tape — {exc}")
        print(f"  {label}: proposer over budget — tape NOT written")
    except ProposalRejected as exc:
        # The tape is written before validation, so this response IS recorded. A rejection
        # here is the barrier doing its job and the tape is exactly what CI should replay.
        failures.append(f"{label}: proposal refused — {exc}")
        print(f"  {label}: proposer refused (ProposalRejected) — tape still written")
        count += 1
    except Exception as exc:
        # Anything else failed before `cassette.record` — on 13 Sep a Vertex 429 on the last
        # scenario was reported here as "tape still written" and counted as answered.
        failures.append(f"{label}: proposer call failed, NO tape — {type(exc).__name__}: {exc}")
        print(f"  {label}: proposer call failed ({type(exc).__name__}) — tape NOT written")
    finally:
        os.environ["FAZEROPS_LLM"] = "stub"
        _throttle()

    return count


# 5.5s was sized for AI Studio's 15 requests/minute free tier, where 4.5s still 429'd once
# and left a hole the suite correctly hard-failed on. Vertex has no such tier, and a 3.1 Pro
# correlator call already takes ~20s, so 2s is margin for an unpublished preview quota, not
# the pacing. Sleeping rather than retrying on 429: a retry loop against a per-minute quota
# turns one slow run into a much slower one that is still mostly waiting.
_THROTTLE_SECONDS = 2.0


def _throttle() -> None:
    time.sleep(_THROTTLE_SECONDS)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
