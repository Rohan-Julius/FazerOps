#!/usr/bin/env python3
"""W11 — regenerate `fixtures/helm/billing_api.json` from the real k3d release.

Same principle as `capture_audit_fixture.py` (W7b): a hand-written fixture is a mock of
the source it stands in for, and a judge who opens `fixtures/` can tell. So the demo
workload is installed and upgraded for real, and Helm's own `helm history -o json` output
becomes the fixture.

**Shapes are real; the clock is staged.** Captured revisions carry whatever wall-clock time
the capture ran at, so `updated` is shifted onto the demo's narrative — the same single
edit `capture_audit_fixture.py` makes, for the same reason. Every other field is Helm's
verbatim.

The three narrative times all sit *before* the correlation window opens at 10:41. That is
the story, not an accident: billing-api ships through Helm, the last release was the
morning before the page, and the change that actually broke it was a hand edit inside the
window that Helm never saw.

    ./scripts/setup_k3d.sh && .venv/bin/python scripts/capture_helm_fixture.py
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLUSTER = "fazerops"
CONTEXT = f"k3d-{CLUSTER}"
CHART = REPO_ROOT / "charts" / "billing-api"
FIXTURE = REPO_ROOT / "fixtures" / "helm" / "billing_api.json"

RELEASE = "billing-api"
NAMESPACE = "billing"

# Idea §7. The alert fires at 14:41 and the window is [10:41, 14:41). Every revision is
# outside it — see the module docstring.
NARRATIVE_TIMES = [
    datetime(2026, 9, 1, 9, 15, 2, tzinfo=timezone.utc),  # the original install
    datetime(2026, 9, 5, 10, 22, 41, tzinfo=timezone.utc),  # a routine upgrade
    datetime(2026, 9, 6, 9, 47, 18, tzinfo=timezone.utc),  # the last release before the page
]

# Upgrades that produce a genuine new revision without needing a new image pulled into the
# cluster on a judge's slow connection. The tag is the only thing that moves.
UPGRADE_TAGS = ["1.27.3-alpine", "1.27.4-alpine"]


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"failed: {' '.join(cmd[:5])}...\n{result.stderr.strip()}")
    return result.stdout


def helm(*args: str) -> str:
    return run(["helm", "--kube-context", CONTEXT, *args])


def rebuild_release() -> None:
    """Uninstall and reinstall so the history is exactly the revisions this script made.

    Capturing whatever revisions happen to be lying around would make the fixture depend on
    how many times someone ran `setup_k3d.sh`, and the collector's tests assert on revision
    numbers.
    """
    subprocess.run(
        ["helm", "--kube-context", CONTEXT, "uninstall", RELEASE, "-n", NAMESPACE],
        capture_output=True,
        text=True,
        check=False,
    )
    helm("upgrade", "--install", RELEASE, str(CHART), "-n", NAMESPACE,
         "--create-namespace", "--wait", "--timeout", "180s")
    for tag in UPGRADE_TAGS:
        helm("upgrade", RELEASE, str(CHART), "-n", NAMESPACE,
             "--set", f"image.tag={tag}", "--wait", "--timeout", "180s")


def shift_onto_the_demo_window(history: list[dict]) -> list[dict]:
    """Rewrite `updated`, and nothing else.

    Helm emits RFC3339 with the *local* offset rather than UTC — the fixture keeps an
    offset for that reason, because a collector that only ever sees `Z` would not be tested
    against the format Helm actually produces (`ledger/normalize.py` exists for exactly
    this class of bug).
    """
    history = sorted(history, key=lambda entry: entry["revision"])
    if len(history) > len(NARRATIVE_TIMES):
        raise SystemExit(
            f"{len(history)} revisions but only {len(NARRATIVE_TIMES)} narrative times — "
            "add a time or drop an upgrade; the script must not invent one"
        )

    staged = timezone(timedelta(hours=5, minutes=30))  # keep a non-UTC offset in the fixture
    for entry, when in zip(history, NARRATIVE_TIMES):
        entry["updated"] = when.astimezone(staged).isoformat()
    return history


def main() -> int:
    rebuild_release()
    history = json.loads(helm("history", RELEASE, "-n", NAMESPACE, "-o", "json"))

    payload = {
        "release": RELEASE,
        "namespace": NAMESPACE,
        "history": shift_onto_the_demo_window(history),
    }

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(payload['history'])} revisions to {FIXTURE.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
