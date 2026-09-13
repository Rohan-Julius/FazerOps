"""The continuous catalog-growth job — `docs/catalog_self_extension.md` §8, up to the pull request.

    collect → mine → generate (rungs 1–3) → corpus replay → containment [rung 3, observed]
            → PR bundle → attested evidence → local branch, checked as CI will check it
            → [opt-in] pushed, and its pull request opened

Off the incident path, on a schedule: `actions.server` runs it beside the incident path
(`run_on_schedule`), and `python -m fazerops.actions.growth mine` runs it once. Every step is a
module that already refuses on its own; this file runs them in order and records, per gap, how
far each got and why it stopped.

**Commit is local; the pull request is opt-in.** Given a repository, an attested bundle becomes a
local `catalog-growth/<candidate>` branch made in a throwaway worktree, and the job runs CI's own
check on it before reporting it committed. Only with `open_prs` is the branch pushed and its PR
opened — the one outward-facing step, taken with the operator's credentials, against a base the
job fetches first. An unattested bundle is never committed: CI would reject it.

Idempotent by construction: signals and demonstrations are first-write-wins, a candidate's id,
bundle directory and branch are functions of its gap, a committed branch is not recommitted, and
an open PR for a branch is returned rather than opened twice.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict

from ...models import TimeWindow
from .signals import GapKey

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ...ledger.store import LedgerStore
    from ...radius import ServiceManifest
    from .miner import MinerThresholds
    from .signals import GapSignalStore

__all__ = [
    "CycleOutcome",
    "CycleStatus",
    "collect_history",
    "describe",
    "mine_once",
    "run_cycle",
    "run_on_schedule",
]

logger = logging.getLogger(__name__)


class CycleStatus(str, Enum):
    BUNDLED = "bundled"
    COMMITTED = "committed"
    ALREADY_COMMITTED = "already_committed"
    COMMIT_REJECTED = "commit_rejected"
    PR_OPENED = "pr_opened"
    PR_FAILED = "pr_failed"
    NO_CANDIDATE = "no_candidate"
    REPLAY_BLOCKED = "replay_blocked"
    CONTAINMENT_BLOCKED = "containment_blocked"


class CycleOutcome(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    key: GapKey
    status: CycleStatus
    rung: int | None = None
    bundle: str | None = None
    attested: bool = False
    branch: str | None = None
    commit: str | None = None
    pr_url: str | None = None
    detail: str | None = None


def describe(outcome: CycleOutcome) -> str:
    gap = outcome.key
    parts = [f"{gap.source}·{gap.resource_kind.value}·{gap.verb.value}·{gap.field_path.value}: {outcome.status.value}"]
    if outcome.rung is not None:
        parts.append(f"rung {outcome.rung}")
    if outcome.pr_url:
        parts.append(outcome.pr_url)
    elif outcome.branch:
        parts.append(f"branch {outcome.branch}")
    elif outcome.bundle:
        parts.append(f"→ {outcome.bundle}")
    text = ", ".join(parts)
    return f"{text} ({outcome.detail})" if outcome.detail else text


async def collect_history(
    ledger: LedgerStore,
    window: TimeWindow,
    *,
    manifest: ServiceManifest | None = None,
    collectors: list[Any] | None = None,
) -> int:
    """Every service radius's changes in `window`, into the durable ledger. Returns new events.

    The miner's fourth signal is a human fixing something *after* an incident, which no
    investigation saw, so the job collects history itself rather than relying on briefs.
    """
    from ...pipeline import build_collectors, gather_changes
    from ...radius import default_manifest

    manifest = manifest if manifest is not None else default_manifest()
    added = 0
    for service in manifest.service_names:
        results = await gather_changes(collectors if collectors is not None else build_collectors(), manifest.resolve(service), window)
        for result in results:
            added += ledger.extend(result.events)
    return added


Opener = Callable[..., str]


async def run_cycle(
    ledger: LedgerStore,
    store: GapSignalStore,
    window: TimeWindow,
    *,
    out_dir: Path | str,
    evidence_key: bytes | None = None,
    repo: Path | str | None = None,
    base: str = "HEAD",
    open_prs: bool = False,
    remote: str = "origin",
    opener: Opener | None = None,
    sandbox: Any | None = None,
    meter: Any | None = None,
    cassette_directory: Any | None = None,
    manifest: ServiceManifest | None = None,
    thresholds: MinerThresholds | None = None,
) -> list[CycleOutcome]:
    """`base` is any revision when only committing; with `open_prs` it is the remote branch the
    PR targets, fetched first, and each branch starts from `<remote>/<base>`."""
    from .authoring import author_candidate, verify_candidate_containment
    from .generate import ContainmentRequired, CorpusDisagreement, emit_pr_bundle, replay_corpus
    from .miner import load_thresholds, mine_history
    from .pr import AlreadyCommitted, attest_bundle, check_agent_commits, commit_bundle_to_branch, open_pull_request, sync_base
    from .sandbox import RecipeClass, recipe_for

    thresholds = thresholds if thresholds is not None else load_thresholds()
    opener = opener if opener is not None else open_pull_request
    outcomes: list[CycleOutcome] = []
    start_from: str | None = None

    for gap in mine_history(ledger, store, window, manifest=manifest, thresholds=thresholds):
        if not gap.eligible:
            continue
        key = gap.key

        result = await author_candidate(gap, store, thresholds=thresholds, meter=meter, cassette_directory=cassette_directory)
        candidate = result.candidate
        if candidate is None:
            last = result.rungs[-1]
            detail = "; ".join(result.problems) if result.problems else last.reason.value
            outcomes.append(CycleOutcome(key=key, status=CycleStatus.NO_CANDIDATE, rung=last.rung, detail=detail))
            continue

        report = replay_corpus(candidate, store, ledger, thresholds=thresholds)
        containment = None
        if (
            report.passed
            and candidate.rung == 3
            and recipe_for(f"k8s/{key.resource_kind.value}").recipe_class is RecipeClass.OBSERVED
        ):
            try:
                containment = await asyncio.to_thread(verify_candidate_containment, candidate, store, ledger, sandbox=sandbox)
            except Exception as exc:  # no reachable sandbox is a blocked candidate, not a crashed job
                outcomes.append(
                    CycleOutcome(key=key, status=CycleStatus.CONTAINMENT_BLOCKED, rung=3, detail=f"{type(exc).__name__}: {exc}"[:300])
                )
                continue

        try:
            directory = emit_pr_bundle(candidate, report, out_dir, containment=containment)
        except CorpusDisagreement as exc:
            outcomes.append(CycleOutcome(key=key, status=CycleStatus.REPLAY_BLOCKED, rung=candidate.rung, detail=str(exc)))
            continue
        except ContainmentRequired as exc:
            outcomes.append(CycleOutcome(key=key, status=CycleStatus.CONTAINMENT_BLOCKED, rung=candidate.rung, detail=str(exc)))
            continue

        attested = evidence_key is not None
        if attested:
            attest_bundle(directory, ledger, key=evidence_key)
        bundled = {"key": key, "rung": candidate.rung, "bundle": str(directory), "attested": attested}

        if repo is None:
            outcomes.append(CycleOutcome(status=CycleStatus.BUNDLED, **bundled))
            continue
        if not attested:
            outcomes.append(
                CycleOutcome(status=CycleStatus.BUNDLED, detail="unattested, so not committed: CI would reject it", **bundled)
            )
            continue

        if start_from is None:
            start_from = sync_base(repo, base, remote=remote) if open_prs else base

        try:
            branch, sha = commit_bundle_to_branch(repo, directory, base=start_from)
            status = CycleStatus.COMMITTED
        except AlreadyCommitted as exc:
            branch, sha, status = exc.branch, None, CycleStatus.ALREADY_COMMITTED

        if sha is not None:
            violations = check_agent_commits(repo, start_from, branch, evidence_key=evidence_key)
            if violations:
                detail = "; ".join(f"{v.rule.value}: {v.detail}" for v in violations)[:500]
                outcomes.append(CycleOutcome(status=CycleStatus.COMMIT_REJECTED, branch=branch, commit=sha, detail=detail, **bundled))
                continue

        if open_prs:
            try:
                url = opener(repo, branch, directory, base_branch=base, remote=remote)
                outcomes.append(CycleOutcome(status=CycleStatus.PR_OPENED, branch=branch, commit=sha, pr_url=url, **bundled))
            except Exception as exc:  # a forge that is down leaves a committed branch to retry next cycle
                detail = f"{type(exc).__name__}: {getattr(exc, 'stderr', None) or exc}"[:300]
                outcomes.append(CycleOutcome(status=CycleStatus.PR_FAILED, branch=branch, commit=sha, detail=detail, **bundled))
            continue

        outcomes.append(CycleOutcome(status=status, branch=branch, commit=sha, **bundled))

    return outcomes


async def mine_once(
    state_dir: Path | str,
    window: TimeWindow,
    *,
    collect: bool = True,
    collectors: list[Any] | None = None,
    out_dir: Path | str | None = None,
    evidence_key: bytes | None = None,
    repo: Path | str | None = None,
    base: str = "HEAD",
    open_prs: bool = False,
    remote: str = "origin",
    opener: Opener | None = None,
    sandbox: Any | None = None,
) -> tuple[int, list[CycleOutcome]]:
    """One cycle over a state directory, read fresh from disk.

    Fresh stores on purpose: the automation server appends to the same files while it serves
    incidents, and a cycle must mine what it wrote. Both stores tolerate a concurrent append —
    first write wins, and a torn final line is skipped — so neither process locks the other.
    """
    from ...ledger.store import LedgerStore
    from .signals import GapSignalStore

    state_dir = Path(state_dir)
    ledger = LedgerStore(state_dir / "ledger.jsonl")
    store = GapSignalStore(state_dir / "gap_signals.jsonl")
    added = await collect_history(ledger, window, collectors=collectors) if collect else 0
    outcomes = await run_cycle(
        ledger,
        store,
        window,
        out_dir=out_dir if out_dir is not None else state_dir / "proposals",
        evidence_key=evidence_key,
        repo=repo,
        base=base,
        open_prs=open_prs,
        remote=remote,
        opener=opener,
        sandbox=sandbox,
    )
    return added, outcomes


def run_on_schedule(
    state_dir: Path | str,
    *,
    every_minutes: float,
    window_hours: float = 24 * 7,
    evidence_key: bytes | None = None,
    repo: Path | str | None = None,
    base: str = "HEAD",
    open_prs: bool = False,
    remote: str = "origin",
    sandbox: Any | None = None,
    stop: threading.Event | None = None,
    iterations: int | None = None,
    report: Callable[[str], None] | None = None,
) -> None:
    """Run a cycle, wait, repeat — until `stop` is set or `iterations` have run.

    A cycle that raises is logged and the schedule continues: the job exists to notice gaps over
    weeks, and one bad hour must not end it.
    """
    stop = stop if stop is not None else threading.Event()
    report = report if report is not None else logger.info
    completed = 0

    while not stop.is_set():
        now = datetime.now(timezone.utc)
        window = TimeWindow(start=now - timedelta(hours=window_hours), end=now)
        try:
            added, outcomes = asyncio.run(
                mine_once(
                    state_dir,
                    window,
                    evidence_key=evidence_key,
                    repo=repo,
                    base=base,
                    open_prs=open_prs,
                    remote=remote,
                    sandbox=sandbox,
                )
            )
            report(f"catalog growth: {added} new change(s), {len(outcomes)} eligible gap(s)")
            for outcome in outcomes:
                report(f"catalog growth: {describe(outcome)}")
        except Exception:
            logger.exception("a catalog-growth cycle failed; the schedule continues")

        completed += 1
        if iterations is not None and completed >= iterations:
            return
        stop.wait(every_minutes * 60)
