"""The recorded demo's story, end to end, against the live k3d cluster — without Slack or GitHub.

`scripts/demo_world.py story` stages it for the camera; this test runs the same world through the
same automation, so a take cannot fail for a reason nobody has seen:

1. `priya@` edits two keys of `auth-service-config`; an alert fires; the proposer declines (the
   shipped catalog restores one key); a decline is recorded and a one-shot is offered, contained in
   a real sandbox; `dinesh@` fixes it by hand.
2. `arun@` does the same; the same happens.
3. The growth job collects, mines a gap across two incidents and two actors, replays the widening
   against both hand fixes, signs the evidence, commits it to a clone of FaberOps itself — its own
   `config/actions.yaml` — and "opens" the PR against a bare remote standing in for GitHub; the
   agent-commit check FaberOps' CI runs passes.
4. Merged, FaberOps' catalog restores the change class — the gap is closed.

Marked `cluster`. Mutates only `auth/auth-service-config`, and restores its data afterwards.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

pytestmark = pytest.mark.cluster

KEY = secrets.token_hex(32).encode("utf-8")


@pytest.fixture
def world(tmp_path, monkeypatch):
    if shutil.which("kubectl") is None or shutil.which("openssl") is None:
        pytest.skip("needs kubectl and openssl")
    import demo_world

    try:
        original = demo_world.current_data()
    except SystemExit as exc:
        pytest.skip(f"no reachable k3d cluster: {exc}")

    monkeypatch.setenv("FAZEROPS_MODE", "live")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    monkeypatch.setenv("FAZEROPS_SANDBOX_CONTEXT", "k3d-fazerops")
    state = tmp_path / "identities"
    demo_world.setup(state)
    yield demo_world, state
    demo_world.kubectl("-n", demo_world.NAMESPACE, "patch", "configmap", demo_world.CONFIGMAP, "--type", "merge", "-p", json.dumps({"data": original}))


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "R", "GIT_AUTHOR_EMAIL": "r@example.com", "GIT_COMMITTER_NAME": "R", "GIT_COMMITTER_EMAIL": "r@example.com"}
    return subprocess.run(["git", "-c", "commit.gpgsign=false", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout


def _faberops_clone(tmp_path: Path) -> tuple[Path, Path]:
    """FaberOps itself, as its committed history holds it: a bare copy standing in for GitHub, and a
    clone of it the job commits into — never this working tree."""
    remote = tmp_path / "github.git"
    _git(tmp_path, "clone", "-q", "--bare", str(REPO_ROOT), str(remote))
    _git(remote, "branch", "-f", "main", "HEAD")
    clone = tmp_path / "faberops"
    _git(tmp_path, "clone", "-q", "--branch", "main", str(remote), str(clone))
    return clone, remote


async def test_the_demo_story_ends_in_a_pull_request_that_closes_the_gap(world, tmp_path):
    import time

    from fazerops.actions.catalog import Catalog
    from fazerops.actions.growth.job import CycleStatus, mine_once
    from fazerops.actions.growth.pr import check_agent_commits
    from fazerops.actions.growth.signals import GapSignalStore, SignalKind
    from fazerops.actions.runtime import Automation
    from fazerops.actions.writers.registry import request_for_event
    from fazerops.collectors.k8s_audit import K8sAuditCollector
    from fazerops.ingest.alerts import normalize_alert
    from fazerops.models import TimeWindow

    demo_world, identities = world
    started = datetime.now(timezone.utc) - timedelta(minutes=1)
    automation = Automation.assemble(state_dir=tmp_path / "state")

    for actor in ("priya", "arun"):
        demo_world.change(actor, identities)
        time.sleep(2)
        response = await automation.respond(normalize_alert(demo_world.alert_payload()), collectors=[K8sAuditCollector()])

        top = response.brief.top.event
        assert (top.actor.display, top.resource.name) == (actor, demo_world.CONFIGMAP), "the edit is the top candidate"
        assert response.proposal is None, "the shipped catalog cannot restore two keys, so the proposer declines"
        assert response.one_shot.offered, response.one_shot
        assert response.one_shot.containment.contained and response.one_shot.containment.sandbox_ran

        time.sleep(2)
        demo_world.fix(identities)
        time.sleep(2)

    declines = [s for s in GapSignalStore(tmp_path / "state" / "gap_signals.jsonl").signals() if s.kind is SignalKind.DECLINE]
    assert {s.actor for s in declines} == {"priya", "arun"}

    clone, remote = _faberops_clone(tmp_path)
    opened: list[str] = []

    def opener(repo, branch, bundle, *, base_branch, remote):
        _git(Path(repo), "push", "-q", remote, f"refs/heads/{branch}:refs/heads/{branch}")
        opened.append(branch)
        return f"https://github.com/Rohan-Julius/FaberOps/pull/{len(opened)}"

    _, outcomes = await mine_once(
        tmp_path / "state",
        TimeWindow(start=started, end=datetime.now(timezone.utc)),
        collectors=[K8sAuditCollector()],
        evidence_key=KEY,
        repo=clone,
        base="main",
        open_prs=True,
        opener=opener,
    )
    [outcome] = [o for o in outcomes if o.key.resource_kind.value == "ConfigMap"]
    assert (outcome.status, outcome.rung) == (CycleStatus.PR_OPENED, 1), outcome.detail
    assert check_agent_commits(clone, "origin/main", outcome.branch, evidence_key=KEY) == []
    assert outcome.branch in _git(remote, "branch", "--list", "catalog-growth/*")

    _git(clone, "merge", "-q", "--ff-only", outcome.branch)
    merged = Catalog.load(clone / "config" / "actions.yaml")
    assert merged.get("revert_configmap_key").params["keys"].type == "list[str]"
    arun_edit = next(
        candidate.event for candidate in response.brief.candidates if candidate.event.actor.display == "arun"
    )
    assert request_for_event(arun_edit, merged) is not None, "merged, the catalog restores this change class"
