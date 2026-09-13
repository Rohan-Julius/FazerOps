#!/usr/bin/env python
"""Record W42 rung 3's writer-author cassette against a real model.

    .venv/bin/python scripts/record_writer_cassettes.py

Records one call per authorable contract in `writers/k8s_support.CONTRACTS` — today a ConfigMap's
`data` and `binaryData`. Separate from `record_cassettes.py` so re-recording rung 3 never re-bills
the three incident-path agents. The tape is rewritten from empty, so a changed prompt leaves no
orphaned key behind.

Costs real money on Vertex (3.1 Pro, thinking billed as output). Each tape entry is written as soon
as the model answers — **before** validation — so a rejected writer is reported as rejected, with
the validator's reasons, and the script exits non-zero. A committed tape must be one that passes.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from record_cassettes import load_dotenv  # noqa: E402

TAPE = REPO_ROOT / "tests" / "cassettes" / "writer_author.json"


async def main() -> int:
    load_dotenv()
    if not os.environ.get("GEMINI_API_KEY"):
        print("error: GEMINI_API_KEY is not set (put it in .env).", file=sys.stderr)
        return 2

    os.environ["FAZEROPS_MODE"] = "fixture"
    os.environ["FAZEROPS_LLM"] = "record"

    from fazerops.actions.growth.authoring import accept_authored, render_module, validate_module
    from fazerops.actions.writers.k8s_support import CONTRACTS, writer_contract
    from fazerops.agents.budget import TokenMeter
    from fazerops.agents.writer_author import author_writer

    TAPE.unlink(missing_ok=True)
    meter = TokenMeter()
    recorded = {}
    failed = False

    for kind, field in CONTRACTS:
        contract = writer_contract(kind, field)
        authored = await author_writer(contract, meter=meter)
        recorded[(kind, field)] = authored
        print(f"--- {kind}:{field} from {authored.model}\n{authored.read_source}\n{authored.write_source}")

        problems = accept_authored(kind, field, authored.read_source, authored.write_source)
        if not problems:
            problems = validate_module(
                render_module(kind, authored.read_source, authored.write_source, candidate_id="-", model="-", field=field)
            )
        if problems:
            failed = True
            print(f"REJECTED {kind}:{field} — the tape was written but must not be committed:", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
        else:
            print(f"accepted {kind}:{field}: allowlist, probe and template all pass\n")

    print(f"spend ${meter.usd:.4f}, {meter.tokens} tokens")
    if failed:
        return 1

    os.environ["FAZEROPS_LLM"] = "cassette"
    for (kind, field), authored in recorded.items():
        replayed = await author_writer(writer_contract(kind, field))
        assert (replayed.read_source, replayed.write_source) == (authored.read_source, authored.write_source)
    print("replay verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
