"""`python -m fazerops.actions.growth` — the catalog-growth job and the lifecycle report.

    mine        collect history, mine it, write PR bundles, and — with --commit-to — commit
                each attested bundle to a local branch checked as CI will check it (§8)
    lifecycle   graduation progress for provisional actions, and tombstone recommendations (W45)

State lives under `--state-dir` (default `$FAZEROPS_STATE_DIR` or `.fazerops`), the same
directory `actions.server` writes, so the job mines what incidents recorded. Bundles are signed
when `FAZEROPS_EVIDENCE_KEY` is set. Nothing here pushes or posts. A rung-3 candidate is
contained on the cluster `FAZEROPS_SANDBOX_CONTEXT` names, and blocked if it names none.
"""

from __future__ import annotations

import argparse
import asyncio
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ...models import TimeWindow

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    from ..runtime import DEFAULT_STATE_DIR, STATE_DIR_ENV

    parser = argparse.ArgumentParser(prog="python -m fazerops.actions.growth")
    parser.add_argument("--state-dir", default=None, help=f"default ${STATE_DIR_ENV} or {DEFAULT_STATE_DIR}")
    sub = parser.add_subparsers(dest="command", required=True)

    mine = sub.add_parser("mine", help="collect, mine, bundle and optionally commit eligible gaps")
    mine.add_argument("--hours", type=int, default=24 * 7)
    mine.add_argument("--since", type=datetime.fromisoformat, default=None)
    mine.add_argument("--until", type=datetime.fromisoformat, default=None)
    mine.add_argument("--out", default=None, help="bundle directory (default <state-dir>/proposals)")
    mine.add_argument("--no-collect", action="store_true", help="mine only what the ledger already holds")
    mine.add_argument("--commit-to", default=None, help="a git repository to commit attested bundles into, on new branches")
    mine.add_argument("--base", default="HEAD", help="the revision each branch starts from; with --open-pr, the PR's base branch")
    mine.add_argument("--open-pr", action="store_true", help="push each committed branch and open its pull request (outward-facing)")
    mine.add_argument("--remote", default="origin")

    sub.add_parser("lifecycle", help="graduation and retirement recommendations")

    args = parser.parse_args(argv)
    if args.command == "mine" and args.open_pr and not args.commit_to:
        parser.error("--open-pr needs --commit-to: a pull request is opened from a committed branch")
    state_dir = Path(args.state_dir or os.environ.get(STATE_DIR_ENV) or DEFAULT_STATE_DIR)

    if args.command == "mine":
        return asyncio.run(_mine(args, state_dir))
    return _lifecycle(state_dir)


async def _mine(args: argparse.Namespace, state_dir: Path) -> int:
    from .job import describe, mine_once
    from .pr import EVIDENCE_KEY_ENV, evidence_key_from_env

    until = args.until or datetime.now(timezone.utc)
    since = args.since or until - timedelta(hours=args.hours)
    key = evidence_key_from_env()
    if key is None:
        print(f"{EVIDENCE_KEY_ENV} is not set: bundles are written unattested, and nothing is committed")

    added, outcomes = await mine_once(
        state_dir,
        TimeWindow(start=since, end=until),
        collect=not args.no_collect,
        out_dir=args.out,
        evidence_key=key,
        repo=args.commit_to,
        base=args.base,
        open_prs=args.open_pr,
        remote=args.remote,
    )
    if not args.no_collect:
        print(f"collected {added} new change(s) for {since.isoformat()} → {until.isoformat()}")
    if not outcomes:
        print("no eligible gaps")
    for outcome in outcomes:
        print(describe(outcome))
    return 0


def _lifecycle(state_dir: Path) -> int:
    from ...ledger.store import LedgerStore
    from ..catalog import default_catalog
    from .lifecycle import graduation_status, retirement_candidates
    from .signals import GapSignalStore

    ledger = LedgerStore(state_dir / "ledger.jsonl")
    store = GapSignalStore(state_dir / "gap_signals.jsonl")
    catalog = default_catalog()
    now = datetime.now(timezone.utc)
    provisional = [action for action in catalog if action.provisional and not action.retired]
    for action in provisional:
        status = graduation_status(action.id, store, ledger, now=now)
        verdict = "ready to graduate (a human clears `provisional`)" if status.graduated else "provisional"
        print(f"{action.id}: {status.confirmed}/{status.required} confirmed, {status.contested} contested — {verdict}")
    if not provisional:
        print("no provisional actions")

    incidents = list(dict.fromkeys(signal.incident_id for signal in store.signals() if signal.incident_id))
    for action_id in retirement_candidates(catalog, store, incidents):
        print(f"{action_id}: unused across recent incidents — recommend `retired: true` (a human's edit)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
