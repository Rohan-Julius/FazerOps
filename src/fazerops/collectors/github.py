"""The GitHub collector, and behind it W11a — the pitch's punchline.

Idea.md §7 chose the demo scenario so the cause is *invisible to GitHub*: "that single
fact is the entire pitch." The line the brief prints — *"Nothing shipped through CI in
this window"* — is therefore the most important sentence in the product, and the easiest
one to fake.

It is not faked. `CIStatus` carries a count, the renderer branches on it, and
`tests/unit/test_ci_status.py` runs the same renderer over a *non-empty* fixture to prove
the line changes. A hardcoded string would pass a test written only against the demo
fixture, and would keep passing right up until a judge asked what happens when something
*did* ship.
"""

from __future__ import annotations

from typing import Any

from ..ledger.normalize import blast_radius_keys, normalize_action, normalize_actor
from ..models import BlastRadius, ChangeEvent, CIStatus, ResourceRef
from .base import BaseCollector, CollectorResult


class GitHubCollector(BaseCollector):
    source = "github"
    fixture_dir = "github"

    def _normalize(self, raw: dict[str, Any]) -> ChangeEvent | None:
        merged_at = raw.get("merged_at")
        if not merged_at:
            return None  # an open or closed-unmerged PR shipped nothing

        repo = ((raw.get("base") or {}).get("repo") or {}).get("full_name")
        if not repo:
            return None

        resource = ResourceRef(kind="Repo", name=repo)
        actor = normalize_actor((raw.get("user") or {}).get("login", ""), "github")

        return ChangeEvent(
            id=f"gh-{repo}-{raw['number']}",
            source="github",
            occurred_at=merged_at,
            actor=actor,
            action=normalize_action("merge", "github"),
            resource=resource,
            blast_radius_keys=blast_radius_keys(resource),
            # A merge is in-band by definition — it is the pipeline. Reported, not scored.
            in_band=True,
            reversible=False,
            raw_ref=f"github:{repo}#{raw['number']}",
        )


def ci_status_from(result: CollectorResult, radius: BlastRadius) -> CIStatus:
    """Build the brief's CI-status line from collected data, never from an assumption.

    A failed GitHub collector is reported as zero merges *and* leaves `Brief.degraded`
    true upstream — otherwise an auth error would silently render as the strongest claim
    the product makes.
    """
    repos = sorted(key.split(":", 1)[1] for key in radius.keys if key.startswith("repo:"))
    return CIStatus(merge_count=len(result.events), repos_checked=repos)


def render_ci_status(ci_status: CIStatus) -> str:
    """The one line Idea.md §7 calls the entire pitch."""
    if ci_status.merge_count == 0:
        return "Nothing shipped through CI in this window."
    if ci_status.merge_count == 1:
        return "1 merge shipped through CI in this window."
    return f"{ci_status.merge_count} merges shipped through CI in this window."
