"""W42 — the PR's CI checks, and the commit a bundle becomes. `docs/catalog_self_extension.md` §7.1, §7.7.

Two checks, each closing a different path from generated output to authority:

* **Evidence resolves.** Every ledger event a bundle cites must exist in the ledger — the
  discipline `validate_proposal` already applies to `evidence_ids`. CI has no ledger, so the
  check is split across the two places that each hold half of what it needs. Where the ledger
  lives, `attest_bundle` resolves every cited event and signs the list — ids and event digests —
  with an HMAC key only that deployment holds. The commit carries the signed file, and CI verifies
  the signature with the same key, held as a CI secret. So CI rejects a PR whose evidence was not
  resolved by a holder of the ledger key; with no key configured it rejects every agent-authored
  catalog change, because a check that cannot run is not a check that passed. What this does
  **not** prove is that the ledger itself is honest — only that the evidence came from it.
* **Agent-authored commits grant nothing.** A commit authored by the catalog-growth identity,
  or carrying its trailer, is rejected if it touches `credentials._ACTIONS_FOR` (in any file),
  declares or changes a tier or an approver, or deletes an action. Retirement is a tombstone
  (§7.6), never a deletion.

**What "agent-authored" can honestly mean here.** The emitter below always sets both the
author identity and the trailer. A commit that lies about its author is not caught by this
check — that is branch protection's job, and a forged author is a compromised pipeline rather
than an agent overreaching. The check exists so that the agent's own output cannot grant
itself scope, and so that nobody can quietly remove the rule by editing the emitter alone.

**Committing is local; opening a PR is opt-in.** `commit_bundle` and `commit_bundle_to_branch`
make a local branch. `open_pull_request` pushes it and opens the PR with the operator's own `gh`
credentials, and the job calls it only when a deployment has turned PR opening on — it is the
outward-facing step.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import hmac
import json
import os
import subprocess
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict

__all__ = [
    "AGENT_EMAIL",
    "AGENT_NAME",
    "AGENT_TRAILER",
    "EvidenceCheck",
    "Rule",
    "Violation",
    "check_agent_commits",
    "check_evidence",
    "commit_bundle",
    "main",
]

AGENT_NAME = "FazerOps Catalog Growth"
AGENT_EMAIL = "catalog-growth@fazerops.invalid"
AGENT_TRAILER = "Agent-Authored: fazerops-catalog-growth"

CREDENTIALS_PATH = "src/fazerops/security/credentials.py"
ACTIONS_PATH = "config/actions.yaml"
GENERATED_DIR = "src/fazerops/actions/writers/generated/"
EVIDENCE_DIR = "catalog-growth/evidence/"
EVIDENCE_KEY_ENV = "FAZEROPS_EVIDENCE_KEY"


class Rule(str, Enum):
    ACTIONS_FOR_TOUCHED = "actions_for_touched"
    TIER_AUTHORED = "tier_authored"
    ACTION_DELETED = "action_deleted"
    MALFORMED_CATALOG = "malformed_catalog"
    # W45: graduating or retiring an action is a human's catalog edit, and an agent's new
    # action is born provisional.
    PROVISIONAL_CLEARED = "provisional_cleared"
    LIFECYCLE_AUTHORED = "lifecycle_authored"
    # W42 rung 1: an agent may change an existing entry only by a declared widening.
    ENTRY_REWRITTEN = "entry_rewritten"
    WIDENING_UNDECLARED = "widening_undeclared"
    # An agent commit touches the catalog and generated writers, and nothing else — which
    # also puts `_ACTIONS_FOR`, `WRITER_MODULES` and every executor out of its reach.
    PATH_NOT_ALLOWED = "path_not_allowed"
    # W42 rung 3: a generated module must still be exactly what the authoring gate accepted.
    GENERATED_WRITER_INVALID = "generated_writer_invalid"
    # §7.1: a catalog change carries evidence a holder of the ledger key resolved and signed.
    EVIDENCE_MISSING = "evidence_missing"
    EVIDENCE_UNVERIFIED = "evidence_unverified"
    # W43 in CI: a generated module is exactly the one a contained sandbox run was signed for.
    CONTAINMENT_UNVERIFIED = "containment_unverified"


_APPROVAL_FIELDS = ("tier", "requires_approval_from")
_LIFECYCLE_FIELDS = ("provisional", "retired")


class Violation(BaseModel):
    model_config = ConfigDict(frozen=True)

    commit: str
    rule: Rule
    detail: str


class EvidenceCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    cited: int
    unresolved: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.cited > 0 and not self.unresolved


def check_evidence(bundle: Path | str, ledger: Any) -> EvidenceCheck:
    manifest = json.loads((Path(bundle) / "manifest.json").read_text(encoding="utf-8"))
    cited = [str(event_id) for event_id in manifest.get("cited_event_ids") or []]
    return EvidenceCheck(
        cited=len(cited),
        unresolved=tuple(event_id for event_id in cited if event_id not in ledger),
    )


class EvidenceUnresolved(ValueError):
    """A bundle cites an event the ledger does not hold, so nothing is signed."""


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _attested_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {name: record.get(name) for name in ("candidate_id", "action_id", "cited", "containment", "module_digest")}


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def attest_bundle(bundle: Path | str, ledger: Any, *, key: bytes) -> Path:
    """Resolve every cited event in `ledger` and sign the result. Runs where the ledger lives.

    The signature also covers what the bundle says about containment and, for a generated writer,
    the digest of the exact module that was contained — so CI can reject a module that was never
    run in a sandbox, or one swapped after its run, without a cluster of its own.
    """
    bundle = Path(bundle)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    cited = sorted(str(event_id) for event_id in manifest.get("cited_event_ids") or [])
    missing = [event_id for event_id in cited if ledger.get(event_id) is None]
    if not cited or missing:
        raise EvidenceUnresolved(f"cannot attest {manifest['candidate_id']}: unresolved {missing or '(nothing cited)'}")

    payload = {
        "candidate_id": manifest["candidate_id"],
        "action_id": manifest["action_id"],
        "cited": [
            {"id": event_id, "digest": hashlib.sha256(ledger.get(event_id).model_dump_json().encode("utf-8")).hexdigest()}
            for event_id in cited
        ],
        "containment": manifest.get("containment"),
        "module_digest": _digest((bundle / "writer.py").read_text(encoding="utf-8")) if (bundle / "writer.py").is_file() else None,
    }
    record = {**payload, "mac": hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()}
    path = bundle / "evidence.json"
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return path


def verify_attestation(record: dict[str, Any], key: bytes) -> bool:
    expected = hmac.new(key, _canonical(_attested_payload(record)), hashlib.sha256).hexdigest()
    return isinstance(record.get("mac"), str) and hmac.compare_digest(record["mac"], expected)


def evidence_key_from_env() -> bytes | None:
    value = os.environ.get(EVIDENCE_KEY_ENV)
    return value.encode("utf-8") if value else None


def commit_bundle(repo: Path | str, bundle: Path | str) -> str:
    """Append the bundle's entry to `config/actions.yaml` on a new branch, as the agent, with its
    attested evidence beside it. Refuses a bundle nobody attested: CI would reject it anyway."""
    repo, bundle = Path(repo), Path(bundle)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    evidence = bundle / "evidence.json"
    if not evidence.is_file():
        raise EvidenceUnresolved(f"{manifest['candidate_id']} has no attested evidence; run attest_bundle where the ledger lives")

    _git(repo, "checkout", "-q", "-b", f"catalog-growth/{manifest['candidate_id']}")
    evidence_path = f"{EVIDENCE_DIR}{manifest['candidate_id']}.json"
    (repo / evidence_path).parent.mkdir(parents=True, exist_ok=True)
    (repo / evidence_path).write_text(evidence.read_text(encoding="utf-8"), encoding="utf-8")
    _git(repo, "add", evidence_path)
    actions = repo / ACTIONS_PATH
    if manifest["rung"] == 1:
        from .generate import apply_params

        actions.write_text(
            apply_params(actions.read_text(encoding="utf-8"), manifest["action_id"], manifest["params"]),
            encoding="utf-8",
        )
    else:
        with actions.open("a", encoding="utf-8") as handle:
            handle.write("\n" + (bundle / "catalog_entry.yaml").read_text(encoding="utf-8"))
    if manifest["rung"] == 3:
        module = repo / manifest["module_path"]
        module.parent.mkdir(parents=True, exist_ok=True)
        module.write_text((bundle / "writer.py").read_text(encoding="utf-8"), encoding="utf-8")
        _git(repo, "add", manifest["module_path"])
    _git(repo, "add", ACTIONS_PATH)

    message = (
        f"feat(catalog): propose {manifest['action_id']} from {manifest['candidate_id']}\n\n"
        f"Cites: {', '.join(manifest['cited_event_ids'])}\n\n"
        f"{AGENT_TRAILER}\n"
    )
    _git(repo, "commit", "-q", "-m", message, as_agent=True)
    return _git(repo, "rev-parse", "HEAD").strip()


class AlreadyCommitted(RuntimeError):
    def __init__(self, branch: str) -> None:
        super().__init__(f"{branch} already exists; a candidate is committed once")
        self.branch = branch


def commit_bundle_to_branch(repo: Path | str, bundle: Path | str, *, base: str = "HEAD") -> tuple[str, str]:
    """`commit_bundle` inside a throwaway worktree, returning `(branch, sha)`.

    The job commits into a repository somebody may be working in. A worktree leaves that
    repository's checked-out branch, index and working tree exactly as they were; only the new
    branch remains. Pushing it, and opening the PR, stay a human's outward-facing act.
    """
    import tempfile

    repo = Path(repo)
    manifest = json.loads((Path(bundle) / "manifest.json").read_text(encoding="utf-8"))
    branch = f"catalog-growth/{manifest['candidate_id']}"
    exists = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], capture_output=True
    )
    if exists.returncode == 0:
        raise AlreadyCommitted(branch)

    with tempfile.TemporaryDirectory(prefix="fazerops-growth-") as scratch:
        worktree = Path(scratch) / "worktree"
        _git(repo, "worktree", "add", "-q", "--detach", str(worktree), base)
        try:
            sha = commit_bundle(worktree, bundle)
        finally:
            _git(repo, "worktree", "remove", "--force", str(worktree))
    return branch, sha


def sync_base(repo: Path | str, base_branch: str, *, remote: str = "origin") -> str:
    """Fetch the PR's base branch and return the ref a branch should start from, so a proposal is
    made against what the remote holds now rather than a stale local copy."""
    _git(Path(repo), "fetch", "-q", remote, base_branch)
    return f"{remote}/{base_branch}"


def open_pull_request(
    repo: Path | str, branch: str, bundle: Path | str, *, base_branch: str, remote: str = "origin", gh: str = "gh"
) -> str:
    """Push `branch` and open its pull request, returning the PR's URL. **Outward-facing**: the job
    calls this only when told to open PRs. Idempotent — an open PR for the branch is returned as is.

    Opened with the operator's own `gh` credentials rather than a workflow token, because a PR a
    workflow's `GITHUB_TOKEN` opens does not trigger other workflows — and the one it must trigger
    is the catalog-growth check.
    """
    repo, bundle = Path(repo), Path(bundle)
    listed = subprocess.run(
        [gh, "pr", "list", "--head", branch, "--state", "open", "--json", "url", "--jq", ".[0].url"],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if listed.returncode == 0 and listed.stdout.strip():
        return listed.stdout.strip()

    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    _git(repo, "push", "-q", remote, f"refs/heads/{branch}:refs/heads/{branch}")
    created = subprocess.run(
        [
            gh, "pr", "create",
            "--head", branch,
            "--base", base_branch,
            "--title", f"catalog: propose {manifest['action_id']} from {manifest['candidate_id']}",
            "--body-file", str(bundle / "PR.md"),
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return created.stdout.strip().splitlines()[-1]


def check_agent_commits(
    repo: Path | str, base: str, head: str, *, evidence_key: bytes | None = None
) -> list[Violation]:
    """Every rule an agent-authored commit in `base..head` breaks. `evidence_key` is the ledger's
    attestation key; without it, no agent-authored catalog change is accepted."""
    repo = Path(repo)
    violations: list[Violation] = []

    for sha in _git(repo, "rev-list", "--reverse", f"{base}..{head}").split():
        if not _is_agent_authored(repo, sha):
            continue

        patch = _git(repo, "show", "--format=", "--unified=0", sha)
        changed = [
            line
            for line in patch.splitlines()
            if line[:1] in "+-" and not line.startswith(("+++", "---"))
        ]
        files = set(_git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", sha).split())

        outside = sorted(
            path
            for path in files
            if path != ACTIONS_PATH
            and not (path.startswith(GENERATED_DIR) and path.endswith(".py"))
            and not (path.startswith(EVIDENCE_DIR) and path.endswith(".json"))
        )
        if outside:
            violations.append(
                Violation(
                    commit=sha,
                    rule=Rule.PATH_NOT_ALLOWED,
                    detail=f"agent-authored commits may touch only the catalog and generated writers: {', '.join(outside)}",
                )
            )

        for path in sorted(p for p in files if p.startswith(GENERATED_DIR) and p.endswith(".py")):
            source = _show(repo, sha, path)
            if source is None:
                continue  # deleted in this commit; nothing left to validate
            from .authoring import validate_module

            problems = validate_module(source)
            if problems:
                violations.append(
                    Violation(commit=sha, rule=Rule.GENERATED_WRITER_INVALID, detail=f"{path}: {'; '.join(problems)}")
                )

        # Two routes, because either alone has a hole: the line scan catches `_ACTIONS_FOR`
        # mutated from another file; the AST comparison catches a change to the literal that
        # never repeats the name on a changed line (a new entry inside the existing dict).
        if any("_ACTIONS_FOR" in line for line in changed) or (
            CREDENTIALS_PATH in files
            and _actions_for(repo, f"{sha}^") != _actions_for(repo, sha)
        ):
            violations.append(
                Violation(
                    commit=sha,
                    rule=Rule.ACTIONS_FOR_TOUCHED,
                    detail="agent-authored commits may not grant permissions (§7.7)",
                )
            )

        if ACTIONS_PATH in files:
            violations.extend(_catalog_violations(repo, sha))

        if ACTIONS_PATH in files or any(path.startswith(GENERATED_DIR) for path in files):
            violations.extend(_evidence_violations(repo, sha, files, evidence_key))

    return violations


def _evidence_violations(repo: Path, sha: str, files: set[str], key: bytes | None) -> list[Violation]:
    def flag(rule: Rule, detail: str) -> list[Violation]:
        return [Violation(commit=sha, rule=rule, detail=detail)]

    attested = sorted(path for path in files if path.startswith(EVIDENCE_DIR) and path.endswith(".json"))
    text = _show(repo, sha, attested[0]) if len(attested) == 1 else None
    if text is None:
        return flag(Rule.EVIDENCE_MISSING, "an agent-authored catalog change must add exactly one attested evidence file")
    if key is None:
        return flag(Rule.EVIDENCE_UNVERIFIED, f"no {EVIDENCE_KEY_ENV} is configured, so the evidence cannot be verified and is not accepted")
    try:
        record = json.loads(text)
        cited = {entry["id"] for entry in record["cited"]}
    except (ValueError, KeyError, TypeError):
        return flag(Rule.EVIDENCE_UNVERIFIED, f"{attested[0]} is not an attestation")
    if not verify_attestation(record, key):
        return flag(Rule.EVIDENCE_UNVERIFIED, f"{attested[0]} was not signed with the ledger's key")
    if not cited:
        return flag(Rule.EVIDENCE_UNVERIFIED, "the attestation cites nothing")

    body = _git(repo, "log", "-1", "--format=%B", sha)
    stated = {
        event_id.strip()
        for line in body.splitlines()
        if line.startswith("Cites:")
        for event_id in line.removeprefix("Cites:").split(",")
        if event_id.strip()
    }
    if stated != cited:
        return flag(Rule.EVIDENCE_UNVERIFIED, "the commit cites different events from its attestation")

    containment = record.get("containment") or {}
    for module in sorted(path for path in files if path.startswith(GENERATED_DIR) and path.endswith(".py")):
        source = _show(repo, sha, module)
        if source is None:
            continue
        if not (containment.get("required") and containment.get("verdict") == "contained"):
            return flag(Rule.CONTAINMENT_UNVERIFIED, f"{module}: its attestation carries no contained sandbox run (W43)")
        if record.get("module_digest") != _digest(source):
            return flag(Rule.CONTAINMENT_UNVERIFIED, f"{module} is not the module whose sandbox run was signed")
    return []


def _catalog_violations(repo: Path, sha: str) -> list[Violation]:
    try:
        before = _declared(repo, f"{sha}^")
        after = _declared(repo, sha)
    except (yaml.YAMLError, TypeError, AttributeError) as exc:
        return [Violation(commit=sha, rule=Rule.MALFORMED_CATALOG, detail=str(exc))]

    violations = [
        Violation(
            commit=sha,
            rule=Rule.ACTION_DELETED,
            detail=f"{action_id} was deleted; retirement is a tombstone (§7.6)",
        )
        for action_id in sorted(set(before) - set(after))
    ]

    def flag(rule: Rule, detail: str) -> None:
        violations.append(Violation(commit=sha, rule=rule, detail=detail))

    for action_id, entry in sorted(after.items()):
        prior = before.get(action_id)
        was = prior or {}

        approval = {f: entry.get(f) for f in _APPROVAL_FIELDS}
        if approval != {f: was.get(f) for f in _APPROVAL_FIELDS}:
            flag(Rule.TIER_AUTHORED, f"{action_id}: {approval}")

        if prior is None:
            if entry.get("provisional") is not True:
                flag(Rule.PROVISIONAL_CLEARED, f"{action_id}: an agent-proposed action must be `provisional: true`")
            continue

        if any(entry.get(f) != prior.get(f) for f in _LIFECYCLE_FIELDS):
            flag(Rule.LIFECYCLE_AUTHORED, f"{action_id}: graduation and retirement are a human's edit (W45)")

        governed = {"params", *_APPROVAL_FIELDS, *_LIFECYCLE_FIELDS}
        rewritten = sorted(f for f in set(entry) | set(prior) if f not in governed and entry.get(f) != prior.get(f))
        if rewritten:
            flag(Rule.ENTRY_REWRITTEN, f"{action_id}: {', '.join(rewritten)} changed; only a declared widening may")

        if _params(entry) != _params(prior) and not _is_declared_widening(action_id, prior, entry):
            flag(Rule.WIDENING_UNDECLARED, f"{action_id}: params changed other than by a declared widening (W42 rung 1)")

    return violations


def _params(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    from .generate import _param

    return {name: _param(spec or {}) for name, spec in (entry.get("params") or {}).items()}


def _is_declared_widening(action_id: str, prior: dict[str, Any], entry: dict[str, Any]) -> bool:
    from .generate import WIDENINGS

    return any(
        widening.action_id == action_id and widening.apply(_params(prior)) == _params(entry)
        for widening in WIDENINGS
    )


def _declared(repo: Path, rev: str) -> dict[str, dict[str, Any]]:
    text = _show(repo, rev, ACTIONS_PATH)
    if text is None:
        return {}
    entries = (yaml.safe_load(text) or {}).get("actions") or []
    return {entry["id"]: entry for entry in entries}


def _actions_for(repo: Path, rev: str) -> str | None:
    text = _show(repo, rev, CREDENTIALS_PATH)
    if text is None:
        return None
    for node in ast.parse(text).body:
        target = node.target if isinstance(node, ast.AnnAssign) else (
            node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1 else None
        )
        if isinstance(target, ast.Name) and target.id == "_ACTIONS_FOR" and node.value is not None:
            return ast.dump(node.value)
    return None


def _is_agent_authored(repo: Path, sha: str) -> bool:
    email, _, body = _git(repo, "log", "-1", "--format=%ae%n%B", sha).partition("\n")
    return email.strip() == AGENT_EMAIL or AGENT_TRAILER in body


def _show(repo: Path, rev: str, path: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"{rev}:{path}"],
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def _git(repo: Path, *args: str, as_agent: bool = False) -> str:
    env = dict(os.environ)
    if as_agent:
        env.update(
            GIT_AUTHOR_NAME=AGENT_NAME,
            GIT_AUTHOR_EMAIL=AGENT_EMAIL,
            GIT_COMMITTER_NAME=AGENT_NAME,
            GIT_COMMITTER_EMAIL=AGENT_EMAIL,
        )
    # The agent holds no signing key, and an unsigned commit is the honest record of that.
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check_generated_pr")
    sub = parser.add_subparsers(dest="command", required=True)

    commits = sub.add_parser("commits", help="reject agent-authored commits that grant scope")
    commits.add_argument("--repo", default=".")
    commits.add_argument("--base", required=True)
    commits.add_argument("--head", default="HEAD")

    evidence = sub.add_parser("evidence", help="reject a bundle whose cited events do not resolve")
    evidence.add_argument("--bundle", required=True)
    evidence.add_argument("--ledger", required=True)

    args = parser.parse_args(argv)

    if args.command == "commits":
        violations = check_agent_commits(args.repo, args.base, args.head, evidence_key=evidence_key_from_env())
        for violation in violations:
            print(f"{violation.commit[:12]} {violation.rule.value}: {violation.detail}")
        return 1 if violations else 0

    from ...ledger.store import LedgerStore

    ledger_path = Path(args.ledger)
    if not ledger_path.is_file():
        print(f"no ledger at {ledger_path}; evidence cannot be verified, so it is not accepted")
        return 1
    result = check_evidence(args.bundle, LedgerStore(ledger_path))
    if not result.passed:
        print(f"cited {result.cited}; unresolved: {', '.join(result.unresolved) or '(none cited)'}")
    return 0 if result.passed else 1


if __name__ == "__main__":  # pragma: no cover - `python -m fazerops.actions.growth.pr`, as a PR workflow runs it
    raise SystemExit(main())
