"""W29 — the AgentCore deploy path syncs the Dockerfile the toolkit actually builds from.

The toolkit builds from `.bedrock_agentcore/<agent>/Dockerfile`, a copy taken at `configure`, so an edit
to the root Dockerfile silently never reached the image (14 Sep: it shipped without `google-genai`). The
copy is gitignored, so no test can compare the two in CI; what can be tested is that the one deploy
path makes them identical before it deploys. The script runs for real here, against a fake `agentcore`
that records the Dockerfile it would have built from at the moment it was called.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "deploy_agentcore.sh"

FAKE_AGENTCORE = """#!/usr/bin/env bash
cp .bedrock_agentcore/fazerops/Dockerfile "$RECORD_DIR/built_from"
printf '%s\\n' "$@" > "$RECORD_DIR/args"
"""


@pytest.fixture
def checkout(tmp_path):
    if shutil.which("bash") is None:
        pytest.skip("needs bash")
    (tmp_path / "scripts").mkdir()
    shutil.copy(SCRIPT, tmp_path / "scripts" / SCRIPT.name)
    (tmp_path / "Dockerfile").write_text('FROM python:3.12-slim\nRUN pip install ".[gemini]"\n', encoding="utf-8")
    (tmp_path / ".bedrock_agentcore" / "fazerops").mkdir(parents=True)
    (tmp_path / ".bedrock_agentcore" / "fazerops" / "Dockerfile").write_text("FROM stale\nRUN pip install .\n", encoding="utf-8")
    (tmp_path / ".bedrock_agentcore.yaml").write_text("default_agent: fazerops\n", encoding="utf-8")
    fake = tmp_path / "fake-agentcore"
    fake.write_text(FAKE_AGENTCORE, encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    (tmp_path / "record").mkdir()
    return tmp_path


def _run(checkout: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "AGENTCORE_BIN": str(checkout / "fake-agentcore"), "RECORD_DIR": str(checkout / "record")}
    return subprocess.run(["bash", str(checkout / "scripts" / SCRIPT.name)], env=env, capture_output=True, text=True, timeout=30)


def test_the_toolkit_builds_from_the_root_dockerfile_not_a_stale_copy(checkout):
    result = _run(checkout)

    assert result.returncode == 0, result.stderr
    assert (checkout / "record" / "built_from").read_text() == (checkout / "Dockerfile").read_text()


def test_it_deploys_locally_built_with_the_runtime_configuration_and_never_a_key(checkout):
    _run(checkout)
    args = (checkout / "record" / "args").read_text().splitlines()

    assert args[:3] == ["deploy", "--local-build", "--auto-update-on-conflict"]
    envs = {args[i + 1] for i, arg in enumerate(args) if arg == "--env"}
    assert {
        "FAZEROPS_LLM=gemini",
        "FAZEROPS_GEMINI_KEY_PROVIDER=fazerops-gemini",
        "FAZEROPS_SESSION_STORE=dynamodb",
        "FAZEROPS_SESSION_REGION=sa-east-1",
    } <= envs
    assert not any(value.startswith(("GEMINI_API_KEY", "AIza")) for value in envs)


def test_it_refuses_to_deploy_an_unconfigured_agent(checkout):
    (checkout / ".bedrock_agentcore.yaml").unlink()

    result = _run(checkout)

    assert result.returncode != 0
    assert "configure first" in result.stderr
    assert not (checkout / "record" / "args").exists()


def test_the_image_installs_the_gemini_extra():
    """The other half of the 14 Sep defect: without the extra the image builds, answers /ping, and
    fails on the first live invocation."""
    install = [line for line in (REPO / "Dockerfile").read_text().splitlines() if "pip install" in line]

    assert install and all("[gemini]" in line for line in install)
