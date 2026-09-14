"""Which revision the Helm collector's rollback hint targets.

"Revision N-1 is the inverse of revision N" holds only when N-1 deployed. After a failed upgrade
and a successful retry, the adjacent revision is the failed one, and a rollback to it restores the
release that did not work.
"""

from __future__ import annotations

from typing import Any

from fazerops.collectors.helm import HelmCollector


def _history(*statuses: str) -> list[dict[str, Any]]:
    revisions = []
    for revision, status in enumerate(statuses, start=1):
        verb = "Install" if revision == 1 else "Upgrade"
        outcome = "failed: timed out waiting for the condition" if status == "failed" else "complete"
        revisions.append(
            {
                "revision": revision,
                "updated": f"2026-09-0{revision}T10:00:00+00:00",
                "status": status,
                "chart": "billing-api-0.1.0",
                "app_version": "1.4.2",
                "description": f"{verb} {outcome}",
            }
        )
    return [{"release": "billing-api", "namespace": "billing", "history": revisions}]


def _by_revision(*statuses: str):
    collector = HelmCollector()
    events = (collector._normalize(item) for item in collector._prepare(_history(*statuses)))
    return {int(event.raw_ref.rsplit("@", 1)[1]): event for event in events if event is not None}


def test_a_rollback_skips_a_failed_revision_to_the_last_one_that_deployed():
    events = _by_revision("superseded", "superseded", "failed", "deployed")

    assert events[4].inverse_hint["target_revision"] == 2
    assert events[3].inverse_hint["target_revision"] == 2


def test_a_pending_revision_is_not_a_rollback_target_either():
    events = _by_revision("superseded", "pending-upgrade", "deployed")

    assert events[3].inverse_hint["target_revision"] == 1


def test_with_no_earlier_revision_that_deployed_there_is_no_hint():
    events = _by_revision("failed", "deployed")

    assert events[2].reversible is False
    assert events[2].inverse_hint is None


def test_an_all_deployed_history_still_targets_revision_n_minus_one():
    events = _by_revision("superseded", "superseded", "deployed")

    assert events[3].inverse_hint["target_revision"] == 2
    assert events[2].inverse_hint["target_revision"] == 1
