"""W37a — the compliance half of the README, enforced rather than remembered.

Handoff §13 lists what the README must contain because the rules require it or judges check
for it. Missing a prior-work disclosure is disqualifying in a way no amount of good code
offsets, and the failure mode is not that someone disagrees about the wording — it is that
a section quietly disappears in an edit three days before submission and nobody re-reads
the file.

The link check is the sharper half. `docs/`, `PLAN_FAZEROPS.md` and `CLAUDE.md` are
gitignored, so a README link to any of them resolves fine on this machine and 404s the
moment the repo goes public — on the first link a judge clicks. Checking that a file exists
is not enough; it has to be a file git actually tracks.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"

# Markdown inline links, minus the ones pointing at a URL or an in-page anchor.
_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

REQUIRED_SECTIONS = [
    "## Quickstart",
    "## Stated limitations",
    "## Safety",
    "## Prior-work disclosure",
    "## License",
]

# Handoff §13's four stated limitations, each identified by a phrase specific enough that
# deleting the limitation deletes the match.
REQUIRED_LIMITATIONS = {
    "manifest-based blast radius": "checked-in manifest",
    "hand-authored priors": "hand-authored",
    "CloudTrail lookup_events, not an S3 trail": "`lookup_events`",
    "fixture-backed demo": "runs on fixtures",
    # Plan §9.2's two acknowledged gaps, which are limitations for the same reason.
    "no post-execution verification": "no post-execution verification",
    "Idea Q2 premise not validated": "not validated with pilot teams",
}


@pytest.fixture(scope="module")
def readme() -> str:
    return README.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def tracked_files() -> set[str]:
    listing = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return set(listing.stdout.split())


@pytest.mark.parametrize("heading", REQUIRED_SECTIONS)
def test_the_required_sections_are_present(readme, heading):
    assert heading in readme


@pytest.mark.parametrize("limitation,phrase", REQUIRED_LIMITATIONS.items())
def test_every_stated_limitation_is_stated(readme, limitation, phrase):
    """Handoff §13 names four; plan §9.2 adds two acknowledged gaps. A limitation that is
    only in the plan is not disclosed to anyone reading the repository."""
    assert phrase in readme, limitation


def test_nothing_unattended_is_claimed_in_so_many_words(readme):
    """Ground rule #5, and the one claim a judge can trivially disprove if the copy drifts.
    "Auto-remediation" must never be allowed to imply autonomy the code does not have."""
    assert "Nothing in this system is unattended" in readme
    assert "executed on approval" in readme


def test_the_prior_work_disclosure_says_when_the_code_was_written(readme):
    """The rule is about *code*, not about thinking. The disclosure has to distinguish the
    two explicitly, or it is not a disclosure."""
    assert "All code in this repository was written during the submission period" in readme
    assert "predate the submission period" in readme


def test_the_license_file_exists_and_is_mit(readme):
    """Detectable in the GitHub About panel means the file has to be recognisable, not just
    present — GitHub reads the text, so the first line matters."""
    license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert license_text.lstrip().startswith("MIT License")


def test_every_relative_link_points_at_a_file_git_tracks(readme, tracked_files):
    """The defect this exists for: `docs/`, `PLAN_FAZEROPS.md` and `CLAUDE.md` are
    gitignored. A link to one of them works on the machine that wrote it and 404s for every
    person who reads the public repository."""
    broken: list[str] = []

    for target in _LINK.findall(readme):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        path = target.split("#", 1)[0].lstrip("./")
        if not path:
            continue
        if path not in tracked_files and not any(
            tracked.startswith(f"{path.rstrip('/')}/") for tracked in tracked_files
        ):
            broken.append(target)

    assert not broken, f"README links to files git does not track: {broken}"
