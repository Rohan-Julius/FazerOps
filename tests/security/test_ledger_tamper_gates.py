"""F1's point: a rewritten ledger cannot become signed evidence or generated code.

The chain only detects. These are the places that must act on it — the growth cycle before it
mines, `attest_bundle` before it signs, and CI's `evidence` check before it resolves.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from fazerops.actions.growth.job import run_cycle
from fazerops.actions.growth.pr import attest_bundle, main as pr_main
from fazerops.actions.growth.signals import GapSignalStore
from fazerops.config import EVIDENCE_KEY_ENV
from fazerops.ledger.chain import LedgerUntrusted
from fazerops.ledger.store import LedgerStore
from fazerops.models import Actor, ChangeEvent, NormalizedAction, ResourceRef, TimeWindow

KEY = b"gate-key"
T = datetime(2026, 9, 6, 14, 0, tzinfo=timezone.utc)
WINDOW = TimeWindow(start=T - timedelta(days=7), end=T)


def _event(event_id: str) -> ChangeEvent:
    return ChangeEvent(
        id=event_id,
        source="k8s_audit",
        occurred_at=T - timedelta(hours=1),
        actor=Actor(raw="dinesh"),
        action=NormalizedAction.UPDATE,
        resource=ResourceRef(kind="ConfigMap", name="c", namespace="billing"),
        in_band=False,
        raw_ref=f"k8s_audit:{event_id}",
    )


@pytest.fixture
def broken(tmp_path):
    path = tmp_path / "ledger.jsonl"
    LedgerStore(path, key=KEY).extend([_event("evt-1"), _event("evt-2")])
    rows = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(rows[0])
    row["record"]["actor"]["raw"] = "someone-else"
    path.write_text(json.dumps(row) + "\n" + rows[1] + "\n", encoding="utf-8")
    return path


@pytest.fixture
def bundle(tmp_path):
    directory = tmp_path / "bundle"
    directory.mkdir()
    (directory / "manifest.json").write_text(
        json.dumps({"candidate_id": "c", "action_id": "a", "cited_event_ids": ["evt-1", "evt-2"]}), encoding="utf-8"
    )
    return directory


async def test_a_broken_ledger_is_never_mined(broken, tmp_path):
    with pytest.raises(LedgerUntrusted, match="broken"):
        await run_cycle(LedgerStore(broken, key=KEY), GapSignalStore(), WINDOW, out_dir=tmp_path / "out", evidence_key=KEY)


async def test_an_unsigned_ledger_is_not_mined_where_a_key_could_have_signed_it(tmp_path):
    path = tmp_path / "ledger.jsonl"
    LedgerStore(path, key=None).record(_event("evt-1"))
    with pytest.raises(LedgerUntrusted, match="unsigned"):
        await run_cycle(LedgerStore(path, key=KEY), GapSignalStore(), WINDOW, out_dir=tmp_path / "out", evidence_key=KEY)


async def test_a_keyless_deployment_still_mines_its_unsigned_ledger(tmp_path):
    """Nothing is attested there, so nothing is vouched for — and no bundle it writes can be
    committed (CI rejects unattested evidence)."""
    path = tmp_path / "ledger.jsonl"
    LedgerStore(path, key=None).record(_event("evt-1"))
    assert await run_cycle(LedgerStore(path, key=None), GapSignalStore(), WINDOW, out_dir=tmp_path / "out") == []


def test_attest_refuses_a_broken_ledger(broken, bundle):
    with pytest.raises(LedgerUntrusted):
        attest_bundle(bundle, LedgerStore(broken, key=KEY), key=KEY)
    assert not (bundle / "evidence.json").exists()


def test_ci_evidence_check_rejects_a_broken_ledger(broken, bundle, monkeypatch, capsys):
    monkeypatch.setenv(EVIDENCE_KEY_ENV, KEY.decode())
    assert pr_main(["evidence", "--bundle", str(bundle), "--ledger", str(broken)]) == 1
    assert "broken" in capsys.readouterr().out


def test_ci_evidence_check_accepts_the_same_ledger_untouched(tmp_path, bundle, monkeypatch):
    path = tmp_path / "ledger.jsonl"
    LedgerStore(path, key=KEY).extend([_event("evt-1"), _event("evt-2")])
    monkeypatch.setenv(EVIDENCE_KEY_ENV, KEY.decode())
    assert pr_main(["evidence", "--bundle", str(bundle), "--ledger", str(path)]) == 0
