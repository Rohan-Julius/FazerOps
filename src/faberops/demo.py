"""The single entry point a judge runs. Handoff §13 requires a quickstart that works on a
clean machine: fresh clone, no AWS credentials, no network, no cluster.

Deliberately not routed through the HTTP server. `run_demo.sh` should not depend on a port
being free, and a judge should not have to read two terminals to see one finding.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .config import llm_mode, mode
from .ingest.alerts import UnrecognisedPayload, normalize_alert
from .pipeline import investigate
from .render.text import render_brief

FIXTURE_ALERTS = Path(__file__).resolve().parents[2] / "fixtures" / "alerts"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="faberops-demo", description=__doc__)
    parser.add_argument(
        "--alert",
        default=str(FIXTURE_ALERTS / "alertmanager.json"),
        help="Path to an alert payload (Alertmanager, CloudWatch or PagerDuty shape)",
    )
    parser.add_argument("--hours", type=int, default=4, help="Correlation window, 1-24")
    args = parser.parse_args(argv)

    payload = json.loads(Path(args.alert).read_text(encoding="utf-8"))
    try:
        alert = normalize_alert(payload)
    except UnrecognisedPayload as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    brief = asyncio.run(investigate(alert, hours=args.hours))

    print(f"[mode={mode().value} llm={llm_mode().value}]\n")
    print(render_brief(brief))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
