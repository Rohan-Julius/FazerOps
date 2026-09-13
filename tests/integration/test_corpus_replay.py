"""W42 — the correctness gate. Plan §4 Phase G, `docs/catalog_self_extension.md` §7a.

> *The candidate is replayed in dry-run against every historical incident that motivated it and
> its diff compared to the remediation the human actually performed. Disagreement blocks the PR.*

Containment (W43) proves a writer touched nothing it did not declare. **This is the only thing
that argues the action is the right one**, so it is asserted in both directions — agreement
passes; a partial fix, a different value, a missing anchor or no corpus at all blocks the bundle
from being written — and **for every rung that can reach it**: rung 1's widened action and rung
2's writer-backed entry are compared through the same `inverse.writes`.

It also closes the plan's stated dependency end to end: the corpus is mined, persisted, reloaded
from disk in a fresh store, and replayed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _growth_events import MULTI_AFTER, MULTI_BEFORE, gap_with_corpus  # noqa: E402

from fazerops.actions.executors import configmap as configmap_executor  # noqa: E402
from fazerops.actions.growth.generate import (  # noqa: E402
    WIDENINGS,
    CorpusDisagreement,
    MismatchReason,
    ReplayReport,
    emit_pr_bundle,
    generate,
    replay_corpus,
)
from fazerops.actions.growth.signals import GapSignalStore  # noqa: E402
from fazerops.actions.writers import k8s_configmap  # noqa: E402
from fazerops.ledger.store import LedgerStore  # noqa: E402

# The human restored one key and deliberately left the other.
PARTIAL = {"issuer": MULTI_BEFORE["issuer"], "session.ttl": MULTI_AFTER["session.ttl"]}
# The human fixed both keys, but not to what they were before.
DIFFERENT = {"issuer": "https://auth-v3.faber-demo.io", "session.ttl": MULTI_BEFORE["session.ttl"]}


@pytest.fixture(params=[1, 2], ids=["rung1-widening", "rung2-writer"])
def rung(request):
    return request.param


def _replayed(rung: int, **history):
    ledger, store, gap = gap_with_corpus(**history)
    candidate = generate(gap, store, widenings=WIDENINGS if rung == 1 else ()).candidate
    assert candidate.rung == rung
    return candidate, replay_corpus(candidate, store, ledger)


def test_a_candidate_that_agrees_with_every_remediation_passes(rung):
    _, report = _replayed(rung)

    assert (report.total, report.agreed) == (2, 2)
    assert report.passed


@pytest.mark.parametrize(
    "fix, reason",
    [
        (PARTIAL, MismatchReason.CHANGES_MORE_THAN_THE_HUMAN),
        (DIFFERENT, MismatchReason.DIFFERENT_VALUE),
    ],
    ids=["partial-fix", "different-value"],
)
def test_disagreement_blocks_the_pr(rung, fix, reason, tmp_path):
    candidate, report = _replayed(rung, fixes={1: fix, 2: fix})

    assert not report.passed
    assert {result.reason for result in report.results} == {reason}

    with pytest.raises(CorpusDisagreement):
        emit_pr_bundle(candidate, report, tmp_path / "proposals")
    assert not (tmp_path / "proposals").exists(), "a blocked candidate writes nothing"


def test_one_disagreeing_remediation_is_enough_to_block(rung):
    _, report = _replayed(rung, fixes={2: PARTIAL})

    assert (report.total, report.agreed) == (2, 1)
    assert not report.passed


def test_no_corpus_cannot_pass(rung, tmp_path):
    """Two declines across two actors are eligible — but with no human remediation there is
    nothing to argue the action is right, and the gate says so rather than passing vacuously."""
    candidate, report = _replayed(rung, remediate=False)

    assert report.total == 0
    assert not report.passed
    with pytest.raises(CorpusDisagreement, match="no recorded human remediation"):
        emit_pr_bundle(candidate, report, tmp_path)


def test_replay_is_a_dry_run_and_constructs_no_client(rung, monkeypatch):
    def no_cluster():
        raise AssertionError("replay must never reach a cluster")

    monkeypatch.setattr(k8s_configmap, "_core_v1", no_cluster)
    monkeypatch.setattr(configmap_executor, "_core_v1", no_cluster)
    _, report = _replayed(rung)
    assert report.passed


def test_a_remediation_whose_anchor_left_the_ledger_blocks():
    ledger, store, gap = gap_with_corpus()
    candidate = generate(gap, store).candidate

    thinned = LedgerStore()
    thinned.extend(ledger.get(event_id) for event_id in ("evt-2", "fix-1", "fix-2"))

    report = replay_corpus(candidate, store, thinned)
    assert MismatchReason.ANCHOR_NOT_IN_LEDGER in {result.reason for result in report.results}
    assert not report.passed


def test_the_corpus_is_replayed_from_disk_after_a_restart(tmp_path):
    """The plan's dependency, end to end: W40 persisted the remediations, a fresh process loads
    them, and replay has real values to compare against."""
    path = tmp_path / "gap_signals.jsonl"
    ledger, store, gap = gap_with_corpus(store_path=path)
    candidate = generate(gap, store).candidate

    reloaded = GapSignalStore(path)
    assert reloaded.demonstrations(candidate.key)[0].after == MULTI_BEFORE

    report = replay_corpus(candidate, reloaded, ledger)
    assert (report.total, report.passed) == (2, True)


def test_a_report_for_another_candidate_is_refused(tmp_path):
    candidate, _ = _replayed(1)
    forged = ReplayReport(candidate_id="gap-000000000000", results=())

    with pytest.raises(ValueError, match="not"):
        emit_pr_bundle(candidate, forged, tmp_path)
