"""W18 — the committed cassette, asserted against the real pipeline.

`test_correlator_contract.py` proves the validator's rules using responses it constructs.
This file proves something different and equally necessary: that the tape actually on disk
— recorded from a real model on 11 Sep — is **findable and replayable** by the code path
CI runs.

A cassette that was written but cannot be located by the key replay derives is worse than
no cassette at all: recording succeeds, the file looks right in review, and CI fails.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from fazerops.agents.correlator import correlate
from fazerops.ingest.alerts import normalize_alert
from fazerops.pipeline import investigate

REPO_ROOT = Path(__file__).resolve().parents[2]
CASSETTE = REPO_ROOT / "tests" / "cassettes" / "correlator.json"

pytestmark = pytest.mark.skipif(
    not CASSETTE.is_file(), reason="no correlator cassette recorded yet"
)


@pytest.fixture(scope="module")
def brief():
    payload = json.loads(
        (REPO_ROOT / "fixtures" / "alerts" / "alertmanager.json").read_text(encoding="utf-8")
    )
    return asyncio.run(investigate(normalize_alert(payload)))


@pytest.fixture
def replayed(brief, monkeypatch):
    monkeypatch.setenv("FAZEROPS_LLM", "cassette")
    return asyncio.run(correlate(brief))


def test_the_recorded_cassette_replays(replayed):
    """The key derivation and the tape agree. If a prompt edit lands without a re-record,
    this is what goes red — deliberately, rather than the demo going quiet."""
    assert replayed.primary_cause_event_id == "65a6f2b9-9a21-4c85-94bd-641b40bb50e6"


def test_the_real_models_narrative_survives_the_validator(replayed):
    """Not a given. On the **first** real recording the model cited the alert id as
    evidence and this dropped to one claim — which is what exposed that
    `render_alert_for_llm` was labelling the alert block with `event_id`. The prompt was
    fixed, not the validator.
    """
    assert replayed.dropped == [], f"real model output lost claims: {replayed.dropped}"
    assert len(replayed.claims) >= 2


def test_every_cited_id_is_a_real_event_in_the_brief(brief, replayed):
    known = {candidate.event.id for candidate in brief.candidates}
    assert set(replayed.evidence_ids) <= known


def test_the_narrative_names_the_change_and_the_value(replayed):
    """What the demo shows on camera. Asserted loosely — the wording is the model's and
    will move between recordings; the facts are ours and must not."""
    text = replayed.text.lower()

    assert "billing-api-config" in text
    assert "pool.max" in text or "pool" in text
    assert "20" in text


def test_the_cassette_records_which_model_produced_it(brief):
    """Provenance. A tape whose model is unknown cannot be judged stale when the
    assignment changes — and `agents/llm.py` has already changed provider once."""
    entries = json.loads(CASSETTE.read_text(encoding="utf-8"))

    assert entries, "cassette file is empty"
    for entry in entries.values():
        assert entry["model"], "every recording names its model"


def test_the_cassette_holds_no_orphaned_keys():
    """One live key per recorded brief. A prompt change invalidates a key permanently, so
    orphans accumulate silently and make the file unreviewable — prune on re-record."""
    entries = json.loads(CASSETTE.read_text(encoding="utf-8"))
    assert len(entries) == 1, f"expected one live recording, found {list(entries)}"
