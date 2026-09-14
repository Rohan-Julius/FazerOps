"""W42 — candidate generation and the generated PR's CI checks. Plan §4 Phase G.

The plan's two assertions:

* **CI rejects a PR whose cited event ids do not resolve in the ledger** — and one citing nothing,
  and one checked with no ledger at all. A check that cannot run has not passed.
* **CI rejects any agent-authored commit touching `credentials._ACTIONS_FOR`** — an agent proposing
  its own IAM permissions is the same category as proposing its own tier, so authoring a tier is
  rejected the same way.

Plus the properties generation itself must hold: rungs tried in order and recorded, no field an
agent may not author, no ledger text in anything a reviewer reads, and an entry that does not
load until a human has declared its tier.

The commit checks run against a real temporary git repository, because the property is about
what git records — author, trailer, diff — and a mocked git would test the mock.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "security"))

from _growth_events import MULTI_AFTER, gap_with_corpus  # noqa: E402
from _injection import PAYLOADS  # noqa: E402

from fazerops.actions.catalog import DEFAULT_ACTIONS, WRITER_EXECUTOR, ActionSpec, Catalog  # noqa: E402
from fazerops.actions.growth.generate import (  # noqa: E402
    AGENT_MAY_NOT_AUTHOR,
    NotEligible,
    RungOutcome,
    RungReason,
    emit_pr_bundle,
    generate,
    replay_corpus,
)
from fazerops.actions.writers.registry import WriterRegistry  # noqa: E402
from fazerops.models import Tier  # noqa: E402
from fazerops.actions.growth.miner import Gap, GapAggregate  # noqa: E402
from fazerops.actions.growth.pr import (  # noqa: E402
    AGENT_EMAIL,
    AGENT_NAME,
    AGENT_TRAILER,
    EVIDENCE_DIR,
    EVIDENCE_KEY_ENV,
    EvidenceUnresolved,
    Rule,
    attest_bundle,
    check_agent_commits,
    check_evidence,
    commit_bundle,
    main,
)
from fazerops.actions.growth.signals import FieldPath, GapSignalStore, ResourceKind  # noqa: E402
from fazerops.ledger.store import LedgerStore  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

# The ledger's attestation key, made per run: in a deployment it is held where the ledger lives
# and, separately, as the CI secret.
KEY_TEXT = secrets.token_hex(32)
KEY = KEY_TEXT.encode("utf-8")
EVIDENCE_RULES = {Rule.EVIDENCE_MISSING, Rule.EVIDENCE_UNVERIFIED}


@pytest.fixture
def history():
    return gap_with_corpus()


@pytest.fixture
def bundle(history, tmp_path):
    ledger, store, gap = history
    # Rung 2: most of the CI assertions below are about appending a *new* generated entry.
    candidate = generate(gap, store, widenings=()).candidate
    directory = emit_pr_bundle(candidate, replay_corpus(candidate, store, ledger), tmp_path / "proposals")
    attest_bundle(directory, ledger, key=KEY)
    return directory, candidate, ledger


def _rules(repo: Path, head: str, base: str = "main") -> list[Rule]:
    """The rules a test is about. A hand-made agent commit to the catalog also carries no attested
    evidence, which the evidence tests below assert on their own."""
    return [v.rule for v in check_agent_commits(repo, base, head, evidence_key=KEY) if v.rule not in EVIDENCE_RULES]


def _eligible(**key) -> Gap:
    """A synthetic but fully eligible aggregate, for change classes the fixtures cannot record."""
    aggregate = GapAggregate(
        **{"source": "k8s_audit", "verb": "update", **key},
        decline_count=3,
        incident_count=3,
        distinct_actors=3,
        prior_value_recorded=True,
    )
    return Gap(aggregate=aggregate, eligible=True)


# --------------------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------------------


def test_rung_one_widens_the_existing_action_for_the_multi_key_gap(history):
    _, store, gap = history
    result = generate(gap, store)

    assert [(r.rung, r.reason) for r in result.rungs] == [(1, RungReason.GENERATED)]
    candidate = result.candidate
    assert (candidate.rung, candidate.writer, candidate.action_id) == (1, None, "revert_configmap_key")
    assert set(candidate.entry) == {"id", "params"}, "a widening changes params and nothing else"
    assert candidate.entry["params"]["keys"] == {"type": "list[str]", "required": False}
    assert candidate.entry["params"]["key"]["required"] is False


def test_rung_two_is_reached_only_when_no_widening_applies(history):
    _, store, gap = history
    result = generate(gap, store, widenings=())

    assert [(r.rung, r.reason) for r in result.rungs] == [
        (1, RungReason.NO_SUPPORTED_WIDENING),
        (2, RungReason.GENERATED),
    ]
    assert result.candidate.rung == 2
    assert result.candidate.rungs == result.rungs


def test_the_generated_entry_authors_nothing_an_agent_may_not(history):
    _, store, gap = history
    entry = generate(gap, store, widenings=()).candidate.entry

    assert not set(entry) & AGENT_MAY_NOT_AUTHOR
    assert entry["provisional"] is True
    assert entry["writer"] == "k8s/ConfigMap:data"
    assert sorted(entry["params"]) == ["name", "namespace"]


def test_the_generated_entry_does_not_load_until_a_human_declares_a_tier(history):
    _, store, gap = history
    entry = generate(gap, store, widenings=()).candidate.entry

    with pytest.raises(ValidationError, match="tier"):
        ActionSpec.model_validate(entry)

    reviewed = ActionSpec.model_validate({**entry, "tier": 1})
    assert reviewed.executor == WRITER_EXECUTOR


def test_the_candidate_cites_the_motivating_changes_and_their_remediations(history):
    _, store, gap = history
    assert generate(gap, store).candidate.cited_event_ids == ("evt-1", "evt-2", "fix-1", "fix-2")


def test_regenerating_a_gap_returns_the_same_candidate(history):
    _, store, gap = history
    assert generate(gap, store) == generate(gap, store)


def test_an_ineligible_gap_is_refused_even_when_labelled_eligible():
    """The verdict is recomputed from the aggregate, so a hand-built `Gap(eligible=True)` over one
    incident is not how the threshold gets skipped."""
    forged = Gap(
        aggregate=GapAggregate(
            source="k8s_audit",
            resource_kind="ConfigMap",
            verb="update",
            field_path="data",
            decline_count=1,
            incident_count=1,
            distinct_actors=1,
            prior_value_recorded=True,
        ),
        eligible=True,
    )
    with pytest.raises(NotEligible, match="below_incident_threshold"):
        generate(forged, GapSignalStore())


def test_a_gap_no_writer_contract_covers_stops_without_authoring():
    result = generate(
        _eligible(resource_kind=ResourceKind.STATEFULSET, field_path=FieldPath.DATA), GapSignalStore()
    )

    assert [(r.rung, r.reason) for r in result.rungs] == [
        (1, RungReason.NO_SUPPORTED_WIDENING),
        (2, RungReason.NO_REGISTERED_WRITER),
        (3, RungReason.NO_AUTHORABLE_CONTRACT),
    ]
    assert result.candidate is None


def test_a_configmap_gap_with_no_widening_and_no_writer_needs_authoring():
    """Deterministic generation hands rung 3 off rather than doing it: authoring calls a model,
    and lives in `growth/authoring.py`."""
    result = generate(
        _eligible(resource_kind=ResourceKind.CONFIGMAP, field_path=FieldPath.DATA),
        GapSignalStore(),
        widenings=(),
        registry=WriterRegistry([]),
    )

    assert result.rungs[-1] == RungOutcome(rung=3, reason=RungReason.WRITER_AUTHORING_REQUIRED)
    assert result.candidate is None


def test_a_delete_is_not_expressed_as_a_revert():
    result = generate(
        _eligible(resource_kind=ResourceKind.CONFIGMAP, field_path=FieldPath.DATA, verb="delete"),
        GapSignalStore(),
    )
    assert result.candidate is None
    assert RungReason.NO_REGISTERED_WRITER in [r.reason for r in result.rungs]


def test_a_gap_already_closed_by_a_catalog_action_generates_nothing(history, tmp_path):
    _, store, gap = history
    path = tmp_path / "actions.yaml"
    path.write_text(
        DEFAULT_ACTIONS.read_text(encoding="utf-8")
        + "\n  - id: restore_configmap\n    tier: 1\n    description: d\n"
        "    writer: k8s/ConfigMap:data\n"
        "    params: {namespace: {type: str}, name: {type: str}}\n",
        encoding="utf-8",
    )

    result = generate(gap, store, catalog=Catalog.load(path))
    assert result.candidate is None
    assert result.rungs[-1].reason is RungReason.ALREADY_IN_CATALOG


# --------------------------------------------------------------------------------------
# The bundle
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("payload", sorted(PAYLOADS))
def test_the_bundle_carries_no_ledger_text(payload, tmp_path):
    """Values and key names are both attacker-writable (§7.1, §10a). A reviewer reads the bundle,
    so neither may appear in it — only enums, counts and ledger ids."""
    hostile_key = PAYLOADS[payload][:48]
    ledger, store, gap = gap_with_corpus(
        cause_before={hostile_key: "a", "session.ttl": "3600"},
        cause_after={hostile_key: PAYLOADS[payload], "session.ttl": "900"},
    )
    candidate = generate(gap, store).candidate
    directory = emit_pr_bundle(candidate, replay_corpus(candidate, store, ledger), tmp_path)

    text = "".join(path.read_text(encoding="utf-8") for path in directory.iterdir())
    assert PAYLOADS[payload][:16] not in text
    assert hostile_key[:16] not in text
    assert MULTI_AFTER["issuer"] not in text


def test_the_bundle_names_what_the_reviewer_must_set(bundle):
    directory, candidate, _ = bundle
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    body = (directory / "PR.md").read_text(encoding="utf-8")

    assert manifest["authored_by"] == "agent"
    assert set(manifest["reviewer_must_set"]) == {"tier", "requires_approval_from", "credentials._ACTIONS_FOR"}
    assert "`tier:`" in body and "_ACTIONS_FOR" in body
    assert "tier:" not in (directory / "catalog_entry.yaml").read_text(encoding="utf-8").replace("# tier:", "")


# --------------------------------------------------------------------------------------
# CI — evidence resolves
# --------------------------------------------------------------------------------------


def test_ci_accepts_a_bundle_whose_evidence_resolves(bundle):
    directory, _, ledger = bundle
    assert check_evidence(directory, ledger).passed


def test_ci_rejects_a_bundle_citing_an_event_the_ledger_does_not_hold(bundle):
    directory, _, ledger = bundle
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cited_event_ids"].append("evt-forged")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = check_evidence(directory, ledger)
    assert not result.passed
    assert result.unresolved == ("evt-forged",)


def test_ci_rejects_a_bundle_that_cites_nothing(bundle):
    directory, _, ledger = bundle
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cited_event_ids"] = []
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert not check_evidence(directory, ledger).passed


def test_ci_fails_closed_without_a_ledger(bundle, tmp_path, capsys):
    directory, _, _ = bundle
    assert main(["evidence", "--bundle", str(directory), "--ledger", str(tmp_path / "absent.jsonl")]) == 1
    assert "not accepted" in capsys.readouterr().out


def test_ci_resolves_against_a_durable_ledger_file(bundle, tmp_path):
    directory, _, ledger = bundle
    path = tmp_path / "ledger.jsonl"
    durable = LedgerStore(path)
    for event_id in ("evt-1", "evt-2", "fix-1", "fix-2"):
        durable.record(ledger.get(event_id))

    assert main(["evidence", "--bundle", str(directory), "--ledger", str(path)]) == 0


# --------------------------------------------------------------------------------------
# CI — agent-authored commits grant nothing
# --------------------------------------------------------------------------------------


def _run(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _commit(repo: Path, message: str, *, agent: bool) -> str:
    name, email = (AGENT_NAME, AGENT_EMAIL) if agent else ("A Reviewer", "reviewer@example.com")
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": name,
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": name,
        "GIT_COMMITTER_EMAIL": email,
    }
    _run(repo, "add", "-A")
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-C", str(repo), "commit", "-q", "-m", message],
        check=True,
        capture_output=True,
        env=env,
    )
    return _run(repo, "rev-parse", "HEAD").strip()


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    # The catalog is the pinned one (`tests/conftest.py`), like every other catalog the suite reads.
    for relative, source in (
        ("config/actions.yaml", DEFAULT_ACTIONS),
        ("src/fazerops/security/credentials.py", REPO_ROOT / "src/fazerops/security/credentials.py"),
    ):
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source, root / relative)
    _run(root, "init", "-q")
    _run(root, "checkout", "-q", "-b", "main")
    _commit(root, "chore: base", agent=False)
    # Work happens on a branch, as a PR's does. Committing on `main` itself would make
    # `main..HEAD` empty and every check below pass by inspecting nothing — which is what the
    # first run of these tests did.
    _run(root, "checkout", "-q", "-b", "proposal")
    return root


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{old!r} not found in {path.name}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


GRANT = '    "helm_rollback": [],\n'


@needs_git
def test_the_emitted_commit_passes_and_its_entry_does_not_load(repo, bundle):
    directory, candidate, _ = bundle
    head = commit_bundle(repo, directory)

    assert check_agent_commits(repo, "main", head, evidence_key=KEY) == []
    author = _run(repo, "log", "-1", "--format=%ae%n%B", head)
    assert AGENT_EMAIL in author and AGENT_TRAILER in author

    with pytest.raises(ValidationError, match="tier"):
        Catalog.load(repo / "config" / "actions.yaml")


@needs_git
def test_an_agent_commit_granting_permissions_is_rejected(repo):
    """The plan's assertion. The new entry sits *inside* the existing literal, so no changed line
    repeats `_ACTIONS_FOR` — which is why the check also compares the literal's AST."""
    _edit(
        repo / "src/fazerops/security/credentials.py",
        GRANT,
        GRANT + '    "revert_configmap_data": ["iam:PassRole"],\n',
    )
    head = _commit(repo, "feat: widen scope", agent=True)

    assert Rule.ACTIONS_FOR_TOUCHED in {v.rule for v in check_agent_commits(repo, "main", head)}


@needs_git
def test_permissions_granted_from_another_file_are_rejected(repo):
    module = repo / "src/fazerops/actions/writers/generated_widget.py"
    module.parent.mkdir(parents=True, exist_ok=True)
    module.write_text(
        "from fazerops.security import credentials\n"
        'credentials._ACTIONS_FOR["widget"] = ["rds:*"]\n',
        encoding="utf-8",
    )
    head = _commit(repo, "feat: widget writer", agent=True)

    assert Rule.ACTIONS_FOR_TOUCHED in {v.rule for v in check_agent_commits(repo, "main", head)}


@needs_git
def test_the_trailer_alone_marks_a_commit_as_agent_authored(repo):
    _edit(repo / "src/fazerops/security/credentials.py", GRANT, GRANT + '    "x": ["rds:*"],\n')
    head = _commit(repo, f"chore: tidy\n\n{AGENT_TRAILER}\n", agent=False)

    assert Rule.ACTIONS_FOR_TOUCHED in {v.rule for v in check_agent_commits(repo, "main", head)}


@needs_git
def test_an_agent_commit_declaring_a_tier_is_rejected(repo, bundle):
    directory, candidate, _ = bundle
    commit_bundle(repo, directory)
    _edit(
        repo / "config/actions.yaml",
        f"  - id: {candidate.action_id}\n",
        f"  - id: {candidate.action_id}\n    tier: 1\n",
    )
    head = _commit(repo, "feat: self-approve", agent=True)

    assert _rules(repo, head) == [Rule.TIER_AUTHORED]


@needs_git
def test_an_agent_commit_lowering_a_declared_tier_is_rejected(repo):
    _edit(
        repo / "config/actions.yaml",
        "    tier: 2\n    description: Restore a single RDS",
        "    tier: 1\n    description: Restore a single RDS",
    )
    head = _commit(repo, "fix: tier", agent=True)

    assert Rule.TIER_AUTHORED in [v.rule for v in check_agent_commits(repo, "main", head)]


@needs_git
def test_an_agent_commit_deleting_an_action_is_rejected(repo):
    text = (repo / "config/actions.yaml").read_text(encoding="utf-8")
    start = text.index("  - id: helm_rollback")
    end = text.index("  - id: restore_db_parameter")
    (repo / "config/actions.yaml").write_text(text[:start] + text[end:], encoding="utf-8")
    head = _commit(repo, "chore: retire", agent=True)

    assert _rules(repo, head) == [Rule.ACTION_DELETED]


@needs_git
def test_a_human_may_grant_permissions_and_declare_the_tier(repo, bundle):
    """The rule is about who authored the commit, not what the change is. Setting a tier and a
    grant is exactly the reviewer's job (§8)."""
    directory, candidate, _ = bundle
    commit_bundle(repo, directory)
    _edit(
        repo / "config/actions.yaml",
        f"  - id: {candidate.action_id}\n",
        f"  - id: {candidate.action_id}\n    tier: 1\n",
    )
    _edit(
        repo / "src/fazerops/security/credentials.py",
        GRANT,
        GRANT + f'    "{candidate.action_id}": [],\n',
    )
    head = _commit(repo, "review: declare tier 1 and grant nothing", agent=False)

    assert check_agent_commits(repo, "main", head, evidence_key=KEY) == []
    assert candidate.action_id in Catalog.load(repo / "config" / "actions.yaml")


@needs_git
def test_an_agent_catalog_change_without_attested_evidence_is_rejected(repo):
    with (repo / "config/actions.yaml").open("a", encoding="utf-8") as handle:
        handle.write(
            "\n  - id: revert_configmap_data\n    description: d\n    writer: k8s/ConfigMap:data\n"
            "    provisional: true\n    params: {namespace: {type: str}, name: {type: str}}\n"
        )
    head = _commit(repo, f"feat(catalog): propose\n\nCites: evt-1\n\n{AGENT_TRAILER}\n", agent=True)

    assert [v.rule for v in check_agent_commits(repo, "main", head, evidence_key=KEY)] == [Rule.EVIDENCE_MISSING]


@needs_git
def test_evidence_signed_with_any_other_key_is_rejected(repo, history, tmp_path):
    ledger, store, gap = history
    candidate = generate(gap, store, widenings=()).candidate
    directory = emit_pr_bundle(candidate, replay_corpus(candidate, store, ledger), tmp_path / "p")
    attest_bundle(directory, ledger, key=secrets.token_hex(32).encode("utf-8"))
    head = commit_bundle(repo, directory)

    assert [v.rule for v in check_agent_commits(repo, "main", head, evidence_key=KEY)] == [Rule.EVIDENCE_UNVERIFIED]


@needs_git
def test_evidence_edited_after_it_was_signed_is_rejected(repo, bundle):
    directory, _, _ = bundle
    record = json.loads((directory / "evidence.json").read_text(encoding="utf-8"))
    record["cited"].append({"id": "evt-forged", "digest": "0" * 64})
    (directory / "evidence.json").write_text(json.dumps(record), encoding="utf-8")
    head = commit_bundle(repo, directory)

    assert [v.rule for v in check_agent_commits(repo, "main", head, evidence_key=KEY)] == [Rule.EVIDENCE_UNVERIFIED]


@needs_git
def test_a_commit_citing_other_events_than_its_attestation_is_rejected(repo, bundle):
    directory, _, _ = bundle
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    manifest["cited_event_ids"] = ["evt-1"]
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    head = commit_bundle(repo, directory)

    [violation] = check_agent_commits(repo, "main", head, evidence_key=KEY)
    assert violation.rule is Rule.EVIDENCE_UNVERIFIED and "different events" in violation.detail


@needs_git
def test_ci_fails_closed_without_the_evidence_key(repo, bundle):
    directory, _, _ = bundle
    head = commit_bundle(repo, directory)

    [violation] = check_agent_commits(repo, "main", head, evidence_key=None)
    assert violation.rule is Rule.EVIDENCE_UNVERIFIED and EVIDENCE_KEY_ENV in violation.detail


@needs_git
def test_the_ci_entry_point_reads_the_key_from_its_environment(repo, bundle, monkeypatch):
    directory, _, _ = bundle
    commit_bundle(repo, directory)

    monkeypatch.delenv(EVIDENCE_KEY_ENV, raising=False)
    assert main(["commits", "--repo", str(repo), "--base", "main", "--head", "HEAD"]) == 1
    monkeypatch.setenv(EVIDENCE_KEY_ENV, KEY_TEXT)
    assert main(["commits", "--repo", str(repo), "--base", "main", "--head", "HEAD"]) == 0


def test_nothing_is_attested_that_the_ledger_does_not_hold(history, tmp_path):
    ledger, store, gap = history
    candidate = generate(gap, store, widenings=()).candidate
    directory = emit_pr_bundle(candidate, replay_corpus(candidate, store, ledger), tmp_path / "p")
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    manifest["cited_event_ids"].append("evt-forged")
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(EvidenceUnresolved, match="evt-forged"):
        attest_bundle(directory, ledger, key=KEY)
    assert not (directory / "evidence.json").exists()


@needs_git
def test_an_unattested_bundle_is_never_committed(repo, history, tmp_path):
    ledger, store, gap = history
    candidate = generate(gap, store, widenings=()).candidate
    directory = emit_pr_bundle(candidate, replay_corpus(candidate, store, ledger), tmp_path / "p")

    with pytest.raises(EvidenceUnresolved, match="no attested evidence"):
        commit_bundle(repo, directory)
    assert _run(repo, "rev-parse", "--abbrev-ref", "HEAD").strip() == "proposal"


@needs_git
def test_the_ci_entry_point_exits_non_zero_on_a_violation(repo):
    _edit(repo / "src/fazerops/security/credentials.py", GRANT, GRANT + '    "x": ["rds:*"],\n')
    _commit(repo, "feat: scope", agent=True)

    assert main(["commits", "--repo", str(repo), "--base", "HEAD~1", "--head", "HEAD"]) == 1
    assert main(["commits", "--repo", str(repo), "--base", "HEAD", "--head", "HEAD"]) == 0


# --------------------------------------------------------------------------------------
# CI — the lifecycle is a human's edit (W45)
# --------------------------------------------------------------------------------------


@needs_git
def test_an_agent_commit_graduating_its_own_action_is_rejected(repo, bundle):
    directory, _, _ = bundle
    commit_bundle(repo, directory)
    _edit(repo / "config/actions.yaml", "provisional: true", "provisional: false")
    head = _commit(repo, "chore: graduate", agent=True)

    assert _rules(repo, head) == [Rule.LIFECYCLE_AUTHORED]


@needs_git
def test_an_agent_commit_retiring_an_action_is_rejected(repo):
    _edit(repo / "config/actions.yaml", "  - id: helm_rollback\n", "  - id: helm_rollback\n    retired: true\n")
    head = _commit(repo, "chore: retire", agent=True)

    assert _rules(repo, head) == [Rule.LIFECYCLE_AUTHORED]


@needs_git
def test_an_agent_proposing_an_action_that_is_not_provisional_is_rejected(repo):
    with (repo / "config/actions.yaml").open("a", encoding="utf-8") as handle:
        handle.write(
            "\n  - id: revert_configmap_data\n    description: d\n    writer: k8s/ConfigMap:data\n"
            "    params: {namespace: {type: str}, name: {type: str}}\n"
        )
    head = _commit(repo, "feat: straight to production", agent=True)

    assert _rules(repo, head) == [Rule.PROVISIONAL_CLEARED]


# --------------------------------------------------------------------------------------
# CI — rung 1: an existing entry changes only by a declared widening
# --------------------------------------------------------------------------------------


@needs_git
def test_a_rung_one_bundle_rewrites_only_the_params_block_and_loads(repo, history, tmp_path):
    ledger, store, gap = history
    candidate = generate(gap, store).candidate
    directory = emit_pr_bundle(candidate, replay_corpus(candidate, store, ledger), tmp_path / "p")
    attest_bundle(directory, ledger, key=KEY)
    before = (repo / "config/actions.yaml").read_text(encoding="utf-8").splitlines()

    head = commit_bundle(repo, directory)

    assert check_agent_commits(repo, "main", head, evidence_key=KEY) == []
    after = (repo / "config/actions.yaml").read_text(encoding="utf-8").splitlines()
    import difflib

    changed = [l for l in difflib.unified_diff(before, after, lineterm="", n=0) if l[:1] in "+-" and l[:3] not in ("+++", "---")]
    assert changed and all(l[1:].startswith("      ") for l in changed), changed

    action = Catalog.load(repo / "config/actions.yaml").get("revert_configmap_key")
    assert action.params["keys"].type == "list[str]"
    assert action.tier is Tier.ENGINEER_APPROVAL and not action.provisional


@needs_git
def test_an_agent_widening_nobody_declared_is_rejected(repo):
    _edit(
        repo / "config/actions.yaml",
        "      target_value: {type: str, required: true}\n",
        "      target_value: {type: str, required: true}\n      kubeconfig: {type: str, required: false}\n",
    )
    head = _commit(repo, "feat: widen", agent=True)

    assert _rules(repo, head) == [Rule.WIDENING_UNDECLARED]


@needs_git
def test_an_agent_rewriting_an_existing_entry_is_rejected(repo):
    _edit(
        repo / "config/actions.yaml",
        "executor: fazerops.actions.executors.configmap:revert_key",
        "executor: fazerops.actions.executors.helm:rollback",
    )
    head = _commit(repo, "fix: executor", agent=True)

    assert _rules(repo, head) == [Rule.ENTRY_REWRITTEN]


@needs_git
def test_an_agent_commit_outside_the_catalog_and_generated_writers_is_rejected(repo):
    (repo / "README.md").write_text("an agent wrote this\n", encoding="utf-8")
    head = _commit(repo, "docs: helpful", agent=True)

    assert _rules(repo, head) == [Rule.PATH_NOT_ALLOWED]
