"""W1a — secret hygiene. The repo goes public before submission; a committed Slack bot
token is a security incident and a revoked app mid-build, not a lint failure.

Scans *tracked* files only. Untracked working-tree junk is the .gitignore's problem.
"""

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Real credential prefixes, not generic "password"-style heuristics — those produce
# false positives on documentation and get muted, which defeats the check.
SECRET_PATTERNS = {
    "slack_bot_token": re.compile(r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}"),
    "slack_app_token": re.compile(r"xapp-[0-9]-[A-Z0-9]{9,}-[0-9]{10,}-[a-f0-9]{40,}"),
    "slack_user_token": re.compile(r"xoxp-[0-9]{10,}-"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_pat": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
}

# This file necessarily contains the patterns it searches for.
SELF = "tests/test_no_secrets.py"


def _tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line and line != SELF]


def test_no_tracked_file_contains_a_credential():
    offenders = []
    for rel_path in _tracked_files():
        path = REPO_ROOT / rel_path
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable; credential patterns are ASCII by construction
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                offenders.append(f"{rel_path}: {name}")

    assert not offenders, "Credentials found in tracked files:\n  " + "\n  ".join(offenders)


def test_dotenv_is_gitignored():
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "\n.env\n" in "\n" + gitignore, ".env must be gitignored"

    result = subprocess.run(
        ["git", "check-ignore", "-q", ".env"],
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, "git does not actually ignore .env"


def test_ds_store_is_gitignored():
    """It is untracked right now and would be swept into the first commit otherwise."""
    result = subprocess.run(["git", "check-ignore", "-q", ".DS_Store"], cwd=REPO_ROOT)
    assert result.returncode == 0, ".DS_Store must be gitignored"


def test_env_example_holds_no_values():
    """The template is committed; it must be a list of empty keys, not a filled-in .env."""
    example = REPO_ROOT / ".env.example"
    assert example.exists(), ".env.example must exist so nobody improvises a .env"

    # Two switches carry safe non-secret defaults; everything else must be empty.
    allowed_values = {"FABEROPS_MODE": "fixture", "FABEROPS_LLM": "stub"}

    for line in example.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        assert value == allowed_values.get(key, ""), (
            f".env.example must not carry a real value for {key!r}"
        )


@pytest.mark.parametrize("pattern_name", sorted(SECRET_PATTERNS))
def test_patterns_actually_match_a_known_shape(pattern_name):
    """A regex that matches nothing passes the scan above for the wrong reason."""
    samples = {
        "slack_bot_token": "xoxb-1234567890-9876543210-" + "a" * 24,
        "slack_app_token": "xapp-1-A012345BC-1234567890-" + "d" * 64,
        "slack_user_token": "xoxp-1234567890-abc",
        "aws_access_key": "AKIA" + "Q" * 16,
        "github_pat": "ghp_" + "b" * 36,
        "private_key": "-----BEGIN RSA PRIVATE KEY-----",
    }
    assert SECRET_PATTERNS[pattern_name].search(samples[pattern_name])
