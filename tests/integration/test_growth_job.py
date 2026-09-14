"""The continuous catalog-growth job — §8's lifecycle run end to end, off the incident path.

Closes the gap Phase G's first pass left: every step existed and nothing ran them. Asserted here:
an eligible gap becomes an attested bundle; a re-run changes nothing; a generated writer is
bundled only after a sandbox contained it, and a job with no reachable sandbox reports the
candidate blocked rather than crashing; and the CLI runs the same job against a state directory.
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import _sandbox_fakes as fakes  # noqa: E402
from _growth_events import HISTORY, binary_gap_with_corpus, gap_with_corpus  # noqa: E402

from fazerops.actions.growth.__main__ import main  # noqa: E402
from fazerops.actions.growth.job import CycleStatus, collect_history, run_cycle  # noqa: E402
from fazerops.actions.growth.miner import MinerThresholds  # noqa: E402
from fazerops.actions.growth.pr import EVIDENCE_KEY_ENV, verify_attestation  # noqa: E402
from fazerops.actions.growth.signals import GapSignalStore  # noqa: E402
from fazerops.ledger.store import LedgerStore  # noqa: E402
from fazerops.models import TimeWindow  # noqa: E402

KEY = secrets.token_hex(32).encode("utf-8")
THRESHOLDS = MinerThresholds()


async def test_an_eligible_gap_becomes_an_attested_bundle(tmp_path):
    ledger, store, _ = gap_with_corpus()
    [outcome] = await run_cycle(ledger, store, HISTORY, out_dir=tmp_path, evidence_key=KEY, thresholds=THRESHOLDS)

    assert (outcome.status, outcome.rung, outcome.attested) == (CycleStatus.BUNDLED, 1, True)
    record = json.loads((Path(outcome.bundle) / "evidence.json").read_text(encoding="utf-8"))
    assert verify_attestation(record, KEY)


async def test_a_second_cycle_changes_nothing(tmp_path):
    ledger, store, _ = gap_with_corpus()
    first = await run_cycle(ledger, store, HISTORY, out_dir=tmp_path, evidence_key=KEY, thresholds=THRESHOLDS)
    recorded = (len(store), len(store.demonstrations()))
    again = await run_cycle(ledger, store, HISTORY, out_dir=tmp_path, evidence_key=KEY, thresholds=THRESHOLDS)

    assert [o.bundle for o in again] == [o.bundle for o in first]
    assert (len(store), len(store.demonstrations())) == recorded


async def test_without_a_key_the_bundle_is_written_and_says_it_is_unattested(tmp_path):
    ledger, store, _ = gap_with_corpus()
    [outcome] = await run_cycle(ledger, store, HISTORY, out_dir=tmp_path, thresholds=THRESHOLDS)

    assert outcome.status is CycleStatus.BUNDLED and outcome.attested is False
    assert not (Path(outcome.bundle) / "evidence.json").exists()


async def test_a_generated_writer_is_bundled_only_after_containment(tmp_path, monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    ledger, store, _ = binary_gap_with_corpus()

    [contained] = await run_cycle(ledger, store, HISTORY, out_dir=tmp_path / "a", sandbox=fakes.factory(), thresholds=THRESHOLDS)
    assert (contained.status, contained.rung) == (CycleStatus.BUNDLED, 3), contained.detail
    manifest = json.loads((Path(contained.bundle) / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["containment"]["verdict"] == "contained"

    [blocked] = await run_cycle(
        ledger, store, HISTORY, out_dir=tmp_path / "b", sandbox=fakes.factory(complete=False), thresholds=THRESHOLDS
    )
    assert blocked.status is CycleStatus.CONTAINMENT_BLOCKED and blocked.bundle is None


async def test_no_reachable_sandbox_blocks_the_candidate_and_not_the_job(tmp_path, monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    ledger, store, _ = binary_gap_with_corpus()

    [outcome] = await run_cycle(ledger, store, HISTORY, out_dir=tmp_path, thresholds=THRESHOLDS)
    assert outcome.status is CycleStatus.CONTAINMENT_BLOCKED
    assert "network client" in outcome.detail


async def test_nothing_eligible_produces_nothing(tmp_path):
    assert await run_cycle(LedgerStore(), GapSignalStore(), HISTORY, out_dir=tmp_path, thresholds=THRESHOLDS) == []


async def test_collection_fills_the_durable_ledger_from_every_service_radius(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    ledger = LedgerStore()
    added = await collect_history(ledger, TimeWindow(start=HISTORY.start, end=HISTORY.end))

    assert added > 0
    assert any(event.resource.name == "billing-api-config" for event in ledger._events.values())


def test_the_cli_runs_the_job_against_a_state_directory(tmp_path, monkeypatch, capsys):
    ledger, store, _ = gap_with_corpus(store_path=tmp_path / "gap_signals.jsonl")
    # The key before the ledger: a ledger started without it stays unsigned, and the job then
    # refuses to mine it where a key exists (`ledger/chain.py`).
    monkeypatch.setenv(EVIDENCE_KEY_ENV, KEY.decode())
    durable = LedgerStore(tmp_path / "ledger.jsonl")
    durable.extend(ledger._events.values())
    # The firings too: the job corroborates every signal's incident against them.
    for alert in ledger._alerts.values():
        durable.record_alert(alert)

    code = main(
        [
            "--state-dir", str(tmp_path),
            "mine", "--no-collect",
            "--since", HISTORY.start.isoformat(),
            "--until", HISTORY.end.isoformat(),
        ]
    )

    out = capsys.readouterr().out
    assert code == 0
    assert "k8s_audit·ConfigMap·update·data: bundled, rung 1" in out
    assert list((tmp_path / "proposals").glob("gap-*/evidence.json"))


# --------------------------------------------------------------------------------------
# Commit — to a local branch, never the checkout, never pushed
# --------------------------------------------------------------------------------------

import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402

from fazerops.actions.growth import job as job_module  # noqa: E402
from fazerops.actions.growth.job import run_on_schedule  # noqa: E402
from fazerops.actions.growth.pr import check_agent_commits  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "R", "GIT_AUTHOR_EMAIL": "r@example.com", "GIT_COMMITTER_NAME": "R", "GIT_COMMITTER_EMAIL": "r@example.com"}
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env
    ).stdout


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for relative in ("config/actions.yaml", "src/fazerops/security/credentials.py"):
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / relative, root / relative)
    _git(root, "init", "-q")
    _git(root, "checkout", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    return root


@needs_git
async def test_an_attested_bundle_is_committed_to_a_branch_that_passes_ci_without_touching_the_checkout(tmp_path):
    repo = _repo(tmp_path)
    ledger, store, _ = gap_with_corpus()
    arguments = dict(out_dir=tmp_path / "p", evidence_key=KEY, repo=repo, base="main", thresholds=THRESHOLDS)

    [outcome] = await run_cycle(ledger, store, HISTORY, **arguments)

    assert outcome.status is CycleStatus.COMMITTED, outcome.detail
    assert outcome.branch.startswith("catalog-growth/gap-")
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip() == "main"
    assert _git(repo, "status", "--porcelain") == ""
    assert len(_git(repo, "worktree", "list").splitlines()) == 1, "the throwaway worktree is gone"
    assert check_agent_commits(repo, "main", outcome.branch, evidence_key=KEY) == []

    [again] = await run_cycle(ledger, store, HISTORY, **arguments)
    assert again.status is CycleStatus.ALREADY_COMMITTED and again.branch == outcome.branch


@needs_git
async def test_an_unattested_bundle_is_never_committed(tmp_path):
    repo = _repo(tmp_path)
    ledger, store, _ = gap_with_corpus()
    [outcome] = await run_cycle(ledger, store, HISTORY, out_dir=tmp_path / "p", repo=repo, base="main", thresholds=THRESHOLDS)

    assert outcome.status is CycleStatus.BUNDLED and "not committed" in outcome.detail
    assert "catalog-growth" not in _git(repo, "branch", "--list")


@needs_git
async def test_a_generated_writer_is_committed_with_its_contained_run_signed(tmp_path, monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    repo = _repo(tmp_path)
    ledger, store, _ = binary_gap_with_corpus()

    [outcome] = await run_cycle(
        ledger, store, HISTORY, out_dir=tmp_path / "p", evidence_key=KEY, repo=repo, base="main", sandbox=fakes.factory(), thresholds=THRESHOLDS
    )
    assert (outcome.status, outcome.rung) == (CycleStatus.COMMITTED, 3), outcome.detail
    assert "k8s_configmap_binarydata.py" in _git(repo, "show", "--name-only", "--format=", outcome.branch)


@needs_git
def test_the_cli_commits_attested_bundles(tmp_path, monkeypatch, capsys):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    ledger, _, _ = gap_with_corpus(store_path=state / "gap_signals.jsonl")
    monkeypatch.setenv(EVIDENCE_KEY_ENV, KEY.decode())
    durable = LedgerStore(state / "ledger.jsonl")
    durable.extend(ledger._events.values())
    for alert in ledger._alerts.values():
        durable.record_alert(alert)

    code = main(
        [
            "--state-dir", str(state), "mine", "--no-collect",
            "--since", HISTORY.start.isoformat(), "--until", HISTORY.end.isoformat(),
            "--commit-to", str(repo), "--base", "main",
        ]
    )
    assert code == 0
    assert "data: committed, rung 1, branch catalog-growth/gap-" in capsys.readouterr().out


def _repo_with_remote(tmp_path: Path) -> tuple[Path, Path]:
    """A working clone whose `origin` is a bare repository standing in for GitHub."""
    seed = _repo(tmp_path)
    remote = tmp_path / "remote.git"
    _git(tmp_path, "clone", "-q", "--bare", str(seed), str(remote))
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", str(remote), str(clone))
    return clone, remote


FAKE_GH = """#!/bin/sh
# Stands in for the GitHub CLI: no open PR exists, and creating one prints its URL.
echo "$@" >> "{log}"
case "$2" in
  list) exit 0 ;;
  create) echo "https://github.com/acme/fazerops-demo/pull/7" ;;
esac
"""


@needs_git
async def test_a_committed_branch_is_pushed_and_its_pull_request_opened(tmp_path):
    from fazerops.actions.growth.pr import open_pull_request

    clone, remote = _repo_with_remote(tmp_path)
    gh, log = tmp_path / "gh", tmp_path / "gh.log"
    gh.write_text(FAKE_GH.format(log=log), encoding="utf-8")
    gh.chmod(0o755)
    ledger, store, _ = gap_with_corpus()

    [outcome] = await run_cycle(
        ledger, store, HISTORY, out_dir=tmp_path / "p", evidence_key=KEY, repo=clone, base="main", open_prs=True,
        opener=lambda *args, **kwargs: open_pull_request(*args, **kwargs, gh=str(gh)), thresholds=THRESHOLDS,
    )

    assert outcome.status is CycleStatus.PR_OPENED, outcome.detail
    assert outcome.pr_url == "https://github.com/acme/fazerops-demo/pull/7"
    assert outcome.branch in _git(remote, "branch", "--list", "catalog-growth/*"), "the branch reached the remote"
    calls = log.read_text(encoding="utf-8")
    assert f"--head {outcome.branch} --base main" in calls and "--body-file" in calls
    assert check_agent_commits(clone, "origin/main", outcome.branch, evidence_key=KEY) == []


@needs_git
async def test_an_open_pull_request_is_not_opened_twice(tmp_path):
    clone, _ = _repo_with_remote(tmp_path)
    ledger, store, _ = gap_with_corpus()
    opened: list[str] = []

    def opener(repo, branch, bundle, *, base_branch, remote):
        opened.append(branch)
        return "https://github.com/acme/fazerops-demo/pull/7"

    arguments = dict(out_dir=tmp_path / "p", evidence_key=KEY, repo=clone, base="main", open_prs=True, opener=opener, thresholds=THRESHOLDS)
    [first] = await run_cycle(ledger, store, HISTORY, **arguments)
    [again] = await run_cycle(ledger, store, HISTORY, **arguments)

    assert (first.status, again.status) == (CycleStatus.PR_OPENED, CycleStatus.PR_OPENED)
    assert again.commit is None, "the second cycle made no new commit"
    assert opened == [first.branch, first.branch], "and asked the opener, which returns the open PR"


@needs_git
async def test_a_forge_that_refuses_leaves_the_branch_for_the_next_cycle(tmp_path):
    clone, _ = _repo_with_remote(tmp_path)
    ledger, store, _ = gap_with_corpus()

    def down(*args, **kwargs):
        raise RuntimeError("503 from the forge")

    [outcome] = await run_cycle(
        ledger, store, HISTORY, out_dir=tmp_path / "p", evidence_key=KEY, repo=clone, base="main", open_prs=True, opener=down, thresholds=THRESHOLDS
    )
    assert outcome.status is CycleStatus.PR_FAILED and "503" in outcome.detail
    assert outcome.branch in _git(clone, "branch", "--list")


@needs_git
async def test_a_branch_that_fails_the_check_is_never_pushed_on_a_later_cycle(tmp_path):
    """A rejected branch is left where it is, so the next cycle finds it already committed. It is
    checked again rather than trusted for existing — here, a branch that passed when committed and
    has since gained an agent commit outside the catalog."""
    from fazerops.actions.growth.pr import AGENT_TRAILER

    clone, remote = _repo_with_remote(tmp_path)
    ledger, store, _ = gap_with_corpus()
    opened: list[str] = []

    def opener(repo, branch, bundle, *, base_branch, remote):
        opened.append(branch)
        return "https://github.com/acme/fazerops-demo/pull/7"

    arguments = {"out_dir": tmp_path / "p", "evidence_key": KEY, "repo": clone, "base": "main", "opener": opener, "thresholds": THRESHOLDS}
    [committed] = await run_cycle(ledger, store, HISTORY, **arguments)
    assert committed.status is CycleStatus.COMMITTED, committed.detail

    _git(clone, "checkout", "-q", committed.branch)
    (clone / "README.md").write_text("an agent wrote this\n", encoding="utf-8")
    _git(clone, "add", "-A")
    _git(clone, "commit", "-q", "-m", f"docs: helpful\n\n{AGENT_TRAILER}\n")
    _git(clone, "checkout", "-q", "main")

    [pushed] = await run_cycle(ledger, store, HISTORY, **arguments, open_prs=True)
    [again] = await run_cycle(ledger, store, HISTORY, **arguments)

    assert (pushed.status, again.status) == (CycleStatus.COMMIT_REJECTED, CycleStatus.COMMIT_REJECTED)
    assert "path_not_allowed" in pushed.detail
    assert opened == [], "the opener was never asked to push the rejected branch"
    assert "catalog-growth" not in _git(remote, "branch", "--list")


def test_the_schedule_keeps_running_after_a_failed_cycle(tmp_path, monkeypatch):
    calls: list[dict] = []

    async def once(state_dir, window, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise RuntimeError("the first hour went wrong")
        return 3, []

    monkeypatch.setattr(job_module, "mine_once", once)
    lines: list[str] = []
    run_on_schedule(tmp_path, every_minutes=0, iterations=2, evidence_key=KEY, report=lines.append)

    assert len(calls) == 2 and calls[1]["evidence_key"] == KEY
    assert lines == ["catalog growth: 3 new change(s), 0 eligible gap(s)"]


def test_the_lifecycle_report_runs_on_an_empty_state_directory(tmp_path, capsys):
    assert main(["--state-dir", str(tmp_path), "lifecycle"]) == 0
    assert "no provisional actions" in capsys.readouterr().out
