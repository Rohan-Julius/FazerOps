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
    # Added 11 Sep with the Gemini path (plan §9.2). W1a had a hole: a Google API key
    # matched none of the patterns above, so it would have committed clean into a repo
    # that is about to go public.
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    # AI Studio issues this second shape, and it is the one actually handed out in Sep
    # 2026. Found the hard way on 11 Sep: a real key landed in `.env.example` and the
    # `AIza` rule above did not match it. It was caught only by the "values must be empty"
    # test, which covers exactly one file — in any other tracked file it would have passed.
    # gitleaks does catch it, but gitleaks runs before a push and this runs every commit.
    "google_oauth_key": re.compile(r"\bAQ\.[A-Za-z0-9_\-]{30,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
}

# This file necessarily contains the patterns it searches for.
SELF = "tests/test_no_secrets.py"

# AWS's own documentation placeholders, and nothing else.
#
# `fixtures/cloudtrail/` is recorded from a real account (W10a) and the capture redacts the
# access key ids it contains — to these values, because AWS publishes them for exactly this
# purpose and gitleaks allowlists them for exactly this reason.
#
# **Exact literals, never a pattern.** `.gitleaks.toml` states the rule this follows:
# nothing is allowlisted to make a real finding go away. A pattern like `.*EXAMPLE` would
# let a genuine key through the moment someone appended the word, whereas a fixed string
# can only ever hide itself — and `test_a_realistic_key_is_still_caught` proves the scanner
# still works with the allowlist in place.
DOCUMENTATION_PLACEHOLDERS = (
    "AKIAIOSFODNN7EXAMPLE",
    "ASIAIOSFODNN7EXAMPLE",
)


def _without_placeholders(text: str) -> str:
    for placeholder in DOCUMENTATION_PLACEHOLDERS:
        text = text.replace(placeholder, "")
    return text


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
        text = _without_placeholders(text)
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                offenders.append(f"{rel_path}: {name}")

    assert not offenders, "Credentials found in tracked files:\n  " + "\n  ".join(offenders)


def test_a_realistic_key_is_still_caught():
    """The allowlist above must not blunt the scanner. A key that merely *resembles* a
    documentation placeholder is still a finding — only the two exact published literals
    are ignored."""
    pattern = SECRET_PATTERNS["aws_access_key"]

    assert pattern.search(_without_placeholders("AKIAZ6KJFT53DW3PDHYP"))
    assert pattern.search(_without_placeholders("ASIAIOSFODNN7EXAMPLX"))
    assert not pattern.search(_without_placeholders("ASIAIOSFODNN7EXAMPLE"))


def test_the_recorded_cloudtrail_fixture_carries_no_real_identifiers():
    """W10a's redaction, asserted from the outside. The capture script refuses to write a
    fixture whose identifiers survived, but that guard lives in a script nobody runs in CI
    — this is the assertion that runs on every commit."""
    fixture = REPO_ROOT / "fixtures" / "cloudtrail" / "billing_window.json"
    if not fixture.is_file():
        pytest.skip("CloudTrail fixture not present")

    text = fixture.read_text(encoding="utf-8")

    assert "111122223333" in text, "account id should be the documentation placeholder"
    assert not re.search(r"\b(?!111122223333)\d{12}\b", text), "a real AWS account id"
    assert not re.search(r"\bAROA(?!EXAMPLEPRINCIPALID)[0-9A-Z]{17,}\b", text)


def test_the_google_key_pattern_does_not_fire_on_a_placeholder():
    """`.env.example` ships `GEMINI_API_KEY=` empty and the README names the variable.
    Neither may trip the scanner, or W1a gets muted the way plan §1 warns about — the
    positive case is covered by `test_patterns_actually_match_a_known_shape`."""
    pattern = SECRET_PATTERNS["google_api_key"]

    assert not pattern.search("GEMINI_API_KEY=")
    assert not pattern.search("Set GEMINI_API_KEY to your key from aistudio.google.com")
    assert not pattern.search("AIzaTooShort")

    oauth = SECRET_PATTERNS["google_oauth_key"]
    assert not oauth.search("GEMINI_API_KEY=")
    assert not oauth.search("AQ.short")


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
    allowed_values = {"FAZEROPS_MODE": "fixture", "FAZEROPS_LLM": "stub"}

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
        "google_api_key": "AIza" + "S" * 35,
        "google_oauth_key": "AQ.Ab" + "7" * 40,
        "private_key": "-----BEGIN RSA PRIVATE KEY-----",
    }
    assert SECRET_PATTERNS[pattern_name].search(samples[pattern_name])
