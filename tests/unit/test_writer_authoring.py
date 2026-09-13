"""W42 rung 3 — a writer authored by a model, and the three gates around it. Plan §4 Phase G.

The model is the least trusted component in the system, so this file is mostly about what the
gates **refuse**:

1. **The AST allowlist** rejects every way a function could do more than read or patch one
   named resource — imports, dunder and private attributes, arbitrary calls, a second client
   method, an aliased client, a use of the credential, loops that can hang.
2. **The template** — CI re-renders a generated module from its two functions and rejects any
   other difference, so a later agent commit cannot widen it.
3. **The probe** runs the functions in a separate interpreter against a fake client and rejects
   a wrong target, a merged or altered body, a leaked value, or a hang.

And the end-to-end path in stub and cassette mode: rung 3 is reached only when rungs 1 and 2
cannot express the gap, replay evaluates it without ever loading the generated code, and the
bundle carries the module for a human to read. The cassette was recorded against Vertex AI by
`scripts/record_writer_cassettes.py`.
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import _sandbox_fakes as fakes  # noqa: E402
from _growth_events import gap_with_corpus  # noqa: E402

from fazerops.actions.growth import authoring  # noqa: E402
from fazerops.actions.growth.authoring import (  # noqa: E402
    author_candidate,
    probe,
    render_module,
    validate_module,
    validate_sources,
    verify_candidate_containment,
)
from fazerops.actions.growth.generate import ContainmentRequired, RungReason, emit_pr_bundle, replay_corpus  # noqa: E402
from fazerops.actions.growth.pr import AGENT_EMAIL, AGENT_NAME, Rule, attest_bundle, check_agent_commits, commit_bundle  # noqa: E402
from fazerops.actions.writers.k8s_support import writer_contract  # noqa: E402
from fazerops.actions.writers.registry import WRITER_MODULES, WriterRegistry, default_registry  # noqa: E402
from fazerops.agents.writer_author import _stub  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
CASSETTES = REPO_ROOT / "tests" / "cassettes"
NO_WRITERS = WriterRegistry([])

GOOD = _stub(writer_contract("ConfigMap"))
READ, WRITE = GOOD["read_source"], GOOD["write_source"]

READ_HEAD = "def read(params, *, client):\n"
WRITE_HEAD = "def write(params, values, *, credential, client):\n"
PATCH = '    patched = client.patch_namespaced_config_map(name=params["name"], namespace=params["namespace"], body={"data": dict(values)})\n'
RETURN = '    return {"namespace": params["namespace"], "name": params["name"], "keys": sorted(values), "resource_version": patched.metadata.resource_version}\n'


def _write(*body: str) -> str:
    return WRITE_HEAD + "".join(body)


# --------------------------------------------------------------------------------------
# 1 — the allowlist
# --------------------------------------------------------------------------------------


def test_the_stub_writer_passes_every_gate():
    assert validate_sources("ConfigMap", READ, WRITE) == []
    assert probe("ConfigMap", READ, WRITE).passed
    assert validate_module(render_module("ConfigMap", READ, WRITE, candidate_id="gap-x", model="stub")) == []


@pytest.mark.parametrize(
    "write_source",
    [
        pytest.param(_write("    import os\n", PATCH, RETURN), id="import"),
        pytest.param(_write('    __import__("os").system("id")\n', PATCH, RETURN), id="dunder-import"),
        pytest.param(_write('    eval("1")\n', PATCH, RETURN), id="eval"),
        pytest.param(_write('    open("/etc/passwd")\n', PATCH, RETURN), id="open"),
        pytest.param(_write("    x = values.__class__\n", PATCH, RETURN), id="dunder-attribute"),
        pytest.param(_write("    x = client._api_client\n", PATCH, RETURN), id="private-attribute"),
        pytest.param(_write('    client.delete_namespaced_config_map(name=params["name"], namespace="billing")\n', PATCH, RETURN), id="second-method"),
        pytest.param(_write(PATCH, PATCH, RETURN), id="patch-twice"),
        pytest.param(_write('    patched = client.replace_namespaced_config_map(name=params["name"], namespace=params["namespace"], body={})\n', RETURN), id="wrong-method"),
        pytest.param(_write("    c = client\n", PATCH, RETURN), id="aliased-client"),
        pytest.param(_write("    x = credential\n", PATCH, RETURN), id="uses-credential"),
        pytest.param(_write("    while True:\n        pass\n", PATCH, RETURN), id="while"),
        pytest.param(_write("    f = lambda: 1\n", PATCH, RETURN), id="lambda"),
        pytest.param(_write("    global x\n", PATCH, RETURN), id="global"),
        pytest.param(_write("    try:\n        pass\n    except Exception:\n        pass\n", PATCH, RETURN), id="try"),
        pytest.param(_write("    x = getattr(values, 'get')\n", PATCH, RETURN), id="getattr"),
        pytest.param(_write("    dict = 1\n", PATCH, RETURN), id="rebinds-builtin"),
        pytest.param(_write("    x = values.update({})\n", PATCH, RETURN), id="unlisted-method"),
        pytest.param(_write("    kwargs = {}\n", '    patched = client.patch_namespaced_config_map(**kwargs)\n', RETURN), id="unpacking"),
        pytest.param("def write(params, values, credential, client):\n" + PATCH + RETURN, id="wrong-signature"),
        pytest.param("def write(params, values, *, credential=None, client=None):\n" + PATCH + RETURN, id="defaults"),
        pytest.param("@staticmethod\n" + WRITE_HEAD + PATCH + RETURN, id="decorator"),
        pytest.param(WRITE_HEAD + PATCH + RETURN + "\ndef helper():\n    pass\n", id="extra-function"),
        pytest.param("def write(params: dict, values, *, credential, client):\n" + PATCH + RETURN, id="annotation"),
        pytest.param("async " + WRITE_HEAD + PATCH + RETURN, id="async"),
        pytest.param("x" * 5000, id="oversized"),
    ],
)
def test_the_allowlist_rejects(write_source):
    assert validate_sources("ConfigMap", READ, write_source) != []


def test_read_may_not_patch():
    read_that_writes = READ_HEAD + PATCH.replace("patched", "obj") + "    return dict(obj.data or {})\n"
    assert any("read_namespaced_config_map" in p for p in validate_sources("ConfigMap", read_that_writes, WRITE))


def test_a_kind_with_no_contract_is_refused():
    assert validate_sources("Secret", READ, WRITE) == ["no writer contract exists for 'Secret'"]


# --------------------------------------------------------------------------------------
# 2 — the template
# --------------------------------------------------------------------------------------


def _module() -> str:
    return render_module("ConfigMap", READ, WRITE, candidate_id="gap-x", model="stub")


def test_provenance_comments_may_differ_and_nothing_else_may():
    assert validate_module(_module().replace("authored by stub", "authored by someone")) == []
    assert validate_module(_module().replace('authored_by="agent"', 'authored_by="human"')) != []
    assert validate_module(_module().replace('scope_field="namespace"', 'scope_field="name"')) != []
    assert validate_module(_module() + "\nimport os\n") != []
    assert validate_module(_module().replace("KIND = 'ConfigMap'", "KIND = 'Secret'")) != []


# --------------------------------------------------------------------------------------
# 3 — the probe
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "write_source, fragment",
    [
        pytest.param(
            _write('    patched = client.patch_namespaced_config_map(name="other", namespace=params["namespace"], body={"data": dict(values)})\n', RETURN),
            "exactly once",
            id="wrong-target",
        ),
        pytest.param(
            _write('    patched = client.patch_namespaced_config_map(name=params["name"], namespace=params["namespace"], body={"data": {k: v for k, v in values.items() if v is not None}})\n', RETURN),
            "exactly once",
            id="drops-deletions",
        ),
        pytest.param(
            _write(PATCH, '    return {"namespace": params["namespace"], "values": dict(values)}\n'),
            "key names only",
            id="leaks-values",
        ),
        pytest.param(_write(PATCH, "    return sorted(values)\n"), "dict", id="not-a-dict"),
    ],
)
def test_the_probe_rejects(write_source, fragment):
    assert validate_sources("ConfigMap", READ, write_source) == [], "these pass the allowlist on purpose"
    result = probe("ConfigMap", READ, write_source)
    assert not result.passed
    assert any(fragment in problem for problem in result.problems), result.problems


def test_the_probe_bounds_a_hang_the_allowlist_would_have_stopped():
    """Called directly, past the allowlist, to prove the second gate holds on its own."""
    result = probe("ConfigMap", READ, _write("    while True:\n        pass\n"), timeout=1.0)
    assert result.problems == ("probe timed out after 1s",)


def test_the_probe_offers_no_builtins_beyond_the_allowlist():
    result = probe("ConfigMap", READ, _write('    open("/etc/hosts")\n', PATCH, RETURN))
    assert not result.passed and "probe raised" in result.problems[0]


# --------------------------------------------------------------------------------------
# End to end
# --------------------------------------------------------------------------------------


async def test_rung_three_is_never_reached_while_a_cheaper_rung_applies(monkeypatch):
    async def must_not_author(*args, **kwargs):
        raise AssertionError("a cheaper rung applied; no model may be called")

    monkeypatch.setattr("fazerops.agents.writer_author.author_writer", must_not_author)
    _, store, gap = gap_with_corpus()

    assert (await author_candidate(gap, store)).candidate.rung == 1
    assert (await author_candidate(gap, store, widenings=())).candidate.rung == 2


async def _rung_three(monkeypatch, llm: str):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", llm)
    ledger, store, gap = gap_with_corpus()
    result = await author_candidate(gap, store, widenings=(), registry=NO_WRITERS, cassette_directory=CASSETTES)
    return ledger, store, result


@pytest.mark.parametrize("llm", ["stub", "cassette"])
async def test_an_authored_writer_passes_replay_without_being_loaded(monkeypatch, llm, tmp_path):
    ledger, store, result = await _rung_three(monkeypatch, llm)

    assert [(r.rung, r.reason) for r in result.rungs] == [
        (1, RungReason.NO_SUPPORTED_WIDENING),
        (2, RungReason.NO_REGISTERED_WRITER),
        (3, RungReason.GENERATED),
    ], result.problems
    candidate = result.candidate
    assert candidate.writer == "k8s/ConfigMap:data"
    assert candidate.module_path == "src/fazerops/actions/writers/generated/k8s_configmap_data.py"
    assert validate_module(candidate.module_source) == []
    if llm == "cassette":
        assert candidate.authored_by_model == "gemini-3.1-pro-preview"

    report = replay_corpus(candidate, store, ledger, registry=NO_WRITERS)
    assert report.passed, report

    containment = verify_candidate_containment(candidate, store, ledger, sandbox=fakes.factory())
    assert containment.contained, containment

    directory = emit_pr_bundle(candidate, report, tmp_path, containment=containment)
    assert (directory / "writer.py").read_text(encoding="utf-8") == candidate.module_source
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    assert "writers.registry.WRITER_MODULES" in manifest["reviewer_must_set"]
    assert manifest["containment"] == {"required": True, "verdict": "contained", "recipe_class": "observed", "runs": 2}
    body = (directory / "PR.md").read_text(encoding="utf-8")
    assert "```python" in body and "## Containment" in body


async def test_containment_runs_once_per_recorded_fix_and_stops_at_the_first_failure(monkeypatch):
    ledger, store, result = await _rung_three(monkeypatch, "stub")

    every = fakes.factory()
    report = verify_candidate_containment(result.candidate, store, ledger, sandbox=every)
    assert report.contained and report.runs == 2 and len(every.built) == 2

    failing = fakes.factory(complete=False)
    report = verify_candidate_containment(result.candidate, store, ledger, sandbox=failing)
    assert not report.contained and report.runs == 1 and len(failing.built) == 1


async def test_a_generated_writer_reaches_a_pr_only_after_containment(monkeypatch, tmp_path):
    """§8: `sandbox containment check [k8s only; else straight to PR]`. ConfigMap is observed."""
    ledger, store, result = await _rung_three(monkeypatch, "stub")
    candidate = result.candidate
    report = replay_corpus(candidate, store, ledger, registry=NO_WRITERS)

    with pytest.raises(ContainmentRequired, match="needs a containment run"):
        emit_pr_bundle(candidate, report, tmp_path / "none")

    uncontained = verify_candidate_containment(candidate, store, ledger, sandbox=fakes.factory(complete=False))
    with pytest.raises(ContainmentRequired, match="not contained"):
        emit_pr_bundle(candidate, report, tmp_path / "failed", containment=uncontained)


async def test_a_rejected_writer_yields_no_candidate_and_says_why(monkeypatch):
    from fazerops.agents import writer_author

    async def bad_author(contract, **kwargs):
        return writer_author.AuthoredWriter(read_source=READ, write_source=_write("    import os\n", PATCH, RETURN), model="m")

    monkeypatch.setattr(writer_author, "author_writer", bad_author)
    _, store, gap = gap_with_corpus()
    result = await author_candidate(gap, store, widenings=(), registry=NO_WRITERS)

    assert result.candidate is None
    assert result.rungs[-1].reason is RungReason.WRITER_REJECTED
    assert any("Import" in problem for problem in result.problems)


def test_a_generated_writer_is_inert_until_a_human_registers_it():
    assert not any(module.startswith("fazerops.actions.writers.generated") for module in WRITER_MODULES)
    assert {writer.authored_by for writer in default_registry()} == {"human"}


def test_authoring_builds_the_contract_from_the_human_table_only():
    """Nothing from the ledger reaches the model that writes code: its whole input is this."""
    assert set(writer_contract("ConfigMap")) == {
        "resource_kind", "field", "read_attribute", "body_field", "read_signature", "write_signature",
        "read_method", "write_method", "params_keys",
    }
    assert "ledger" not in Path(authoring.__file__).read_text(encoding="utf-8").split("author_writer(")[1].split(")")[0]


# --------------------------------------------------------------------------------------
# CI — generated modules are re-validated on every agent-authored commit
# --------------------------------------------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(repo: Path, *args: str, agent: bool = False) -> str:
    env = dict(os.environ)
    if agent:
        env.update(GIT_AUTHOR_NAME=AGENT_NAME, GIT_AUTHOR_EMAIL=AGENT_EMAIL, GIT_COMMITTER_NAME=AGENT_NAME, GIT_COMMITTER_EMAIL=AGENT_EMAIL)
    else:
        env.update(GIT_AUTHOR_NAME="R", GIT_AUTHOR_EMAIL="r@example.com", GIT_COMMITTER_NAME="R", GIT_COMMITTER_EMAIL="r@example.com")
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env
    ).stdout


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "config").mkdir(parents=True)
    shutil.copy(REPO_ROOT / "config" / "actions.yaml", root / "config" / "actions.yaml")
    _git(root, "init", "-q")
    _git(root, "checkout", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    _git(root, "checkout", "-q", "-b", "proposal")
    return root


@needs_git
async def test_a_rung_three_commit_passes_and_a_tampered_module_does_not(monkeypatch, repo, tmp_path):
    ledger, store, result = await _rung_three(monkeypatch, "stub")
    candidate = result.candidate
    directory = emit_pr_bundle(
        candidate,
        replay_corpus(candidate, store, ledger, registry=NO_WRITERS),
        tmp_path,
        containment=verify_candidate_containment(candidate, store, ledger, sandbox=fakes.factory()),
    )
    key = secrets.token_hex(32).encode("utf-8")
    attest_bundle(directory, ledger, key=key)

    head = commit_bundle(repo, directory)
    assert check_agent_commits(repo, "main", head, evidence_key=key) == []

    module = repo / candidate.module_path
    module.write_text(module.read_text(encoding="utf-8").replace("return dict(obj.data or {})", "return {}\n    import os"), encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "tweak", agent=True)
    tampered = _git(repo, "rev-parse", "HEAD").strip()

    assert Rule.GENERATED_WRITER_INVALID in {v.rule for v in check_agent_commits(repo, head, tampered)}


async def _contained_bundle(monkeypatch, tmp_path):
    ledger, store, result = await _rung_three(monkeypatch, "stub")
    candidate = result.candidate
    directory = emit_pr_bundle(
        candidate,
        replay_corpus(candidate, store, ledger, registry=NO_WRITERS),
        tmp_path,
        containment=verify_candidate_containment(candidate, store, ledger, sandbox=fakes.factory()),
    )
    return directory, ledger


@needs_git
async def test_ci_rejects_a_generated_module_whose_signed_evidence_has_no_contained_run(monkeypatch, repo, tmp_path):
    """W43 in CI, with no cluster: the containment verdict is inside the signature."""
    directory, ledger = await _contained_bundle(monkeypatch, tmp_path)
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    manifest["containment"] = {"required": False, "why": "skipped"}
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    key = secrets.token_hex(32).encode("utf-8")
    attest_bundle(directory, ledger, key=key)

    head = commit_bundle(repo, directory)
    assert {v.rule for v in check_agent_commits(repo, "main", head, evidence_key=key)} == {Rule.CONTAINMENT_UNVERIFIED}


@needs_git
async def test_ci_rejects_a_module_swapped_after_its_sandbox_run(monkeypatch, repo, tmp_path):
    directory, ledger = await _contained_bundle(monkeypatch, tmp_path)
    key = secrets.token_hex(32).encode("utf-8")
    attest_bundle(directory, ledger, key=key)
    module = directory / "writer.py"
    swapped = module.read_text(encoding="utf-8").replace("return dict(obj.data or {})", "return dict(obj.data or dict())")
    assert swapped != module.read_text(encoding="utf-8") and validate_module(swapped) == [], "a valid module, just not the contained one"
    module.write_text(swapped, encoding="utf-8")

    head = commit_bundle(repo, directory)
    [violation] = check_agent_commits(repo, "main", head, evidence_key=key)
    assert violation.rule is Rule.CONTAINMENT_UNVERIFIED and "not the module" in violation.detail
