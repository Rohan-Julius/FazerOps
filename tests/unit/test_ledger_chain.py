"""F1 — the ledger's keyed hash chain (`ledger/chain.py`).

Every tamper shape the module claims to detect is performed here on a real file, and the two it
says it cannot detect are asserted as limits so nobody later reads the chain as more than it is.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from fazerops.ledger.chain import Integrity, LedgerIntegrityError, usable_as_evidence
from fazerops.ledger.store import LedgerStore
from fazerops.models import Actor, Alert, AlertClass, ChangeEvent, NormalizedAction, ResourceRef

KEY = b"ledger-test-key"
T = datetime(2026, 9, 6, 14, 0, tzinfo=timezone.utc)


def event(event_id: str, value: str = "20") -> ChangeEvent:
    return ChangeEvent(
        id=event_id,
        source="k8s_audit",
        occurred_at=T,
        actor=Actor(raw="dinesh"),
        action=NormalizedAction.UPDATE,
        resource=ResourceRef(kind="ConfigMap", name="billing-api-config", namespace="billing"),
        blast_radius_keys={"k8s:billing/configmap/billing-api-config"},
        in_band=False,
        raw_ref=f"k8s_audit:{event_id}",
        inverse_hint={"value": value},
    )


@pytest.fixture
def signed(tmp_path):
    path = tmp_path / "ledger.jsonl"
    LedgerStore(path, key=KEY).extend([event("e1"), event("e2"), event("e3")])
    return path


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def write(path, rows):
    path.write_text("".join(row + "\n" for row in rows), encoding="utf-8")


def test_a_signed_ledger_round_trips_verified(signed):
    reopened = LedgerStore(signed, key=KEY)
    assert reopened.integrity is Integrity.VERIFIED and reopened.integrity_detail is None
    assert len(reopened) == 3


def test_an_in_memory_ledger_has_no_file_to_tamper_with():
    assert LedgerStore().integrity is Integrity.IN_MEMORY


def test_an_edited_value_breaks_the_line_it_is_on(signed):
    rows = lines(signed)
    row = json.loads(rows[1])
    row["record"]["inverse_hint"]["value"] = "100"
    rows[1] = json.dumps(row)
    write(signed, rows)

    reopened = LedgerStore(signed, key=KEY)
    assert reopened.integrity is Integrity.BROKEN
    assert "line 2" in reopened.integrity_detail and "signature" in reopened.integrity_detail
    assert len(reopened) == 3, "a broken ledger still loads; its integrity says it is not evidence"


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param(lambda rows: [rows[0], rows[2]], id="removed"),
        pytest.param(lambda rows: [rows[1], rows[0], rows[2]], id="reordered"),
        pytest.param(lambda rows: [rows[0], rows[0], rows[1], rows[2]], id="duplicated"),
    ],
)
def test_structural_tampering_breaks_the_chain(signed, tamper):
    write(signed, tamper(lines(signed)))
    assert LedgerStore(signed, key=KEY).integrity is Integrity.BROKEN


def test_a_forged_line_resigned_with_another_key_is_caught(signed):
    forged = signed.with_name("forged.jsonl")
    LedgerStore(forged, key=b"attacker").extend([event("e1"), event("e2"), event("e3", value="999")])
    assert LedgerStore(forged, key=KEY).integrity is Integrity.BROKEN


def test_an_unsigned_line_slipped_into_a_signed_ledger_is_caught(signed):
    rows = lines(signed)
    rows.insert(1, event("planted").model_dump_json())
    write(signed, rows)
    reopened = LedgerStore(signed, key=KEY)
    assert reopened.integrity is Integrity.BROKEN and "unsigned" in reopened.integrity_detail


def test_a_garbled_middle_line_breaks_the_ledger_but_the_rest_still_loads(signed):
    rows = lines(signed)
    rows[1] = rows[1][: len(rows[1]) // 2]
    write(signed, rows)
    reopened = LedgerStore(signed, key=KEY)
    assert reopened.integrity is Integrity.BROKEN and "line 2" in reopened.integrity_detail
    assert set(reopened._events) == {"e1", "e3"}


def test_a_brief_still_posts_when_the_ledger_refuses_the_append(signed, tmp_path, monkeypatch):
    """A signed ledger and a server started without the key: the incident brief is Tier 0 and
    must not be lost to a bookkeeping refusal, which is reported instead."""
    import asyncio

    from fazerops.actions.runtime import Automation
    from fazerops.ingest.alerts import normalize_alert

    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    monkeypatch.delenv("FAZEROPS_EVIDENCE_KEY", raising=False)
    state = signed.parent
    automation = Automation.assemble(state_dir=state)
    alert = json.loads((__import__("pathlib").Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json").read_text())

    response = asyncio.run(automation.respond(normalize_alert(alert)))
    assert response.brief.candidates
    assert any("not recorded in the ledger" in reason for reason in response.refused)
    assert LedgerStore(signed, key=KEY).integrity is Integrity.VERIFIED


def test_a_signed_ledger_opened_without_the_key_is_unverified(signed):
    assert LedgerStore(signed, key=None).integrity is Integrity.UNVERIFIED


def test_a_ledger_written_without_a_key_is_unsigned(tmp_path):
    path = tmp_path / "ledger.jsonl"
    LedgerStore(path, key=None).record(event("e1"))
    assert LedgerStore(path, key=KEY).integrity is Integrity.UNSIGNED


def test_a_pre_chain_ledger_still_loads_and_reads_as_unsigned(tmp_path):
    path = tmp_path / "ledger.jsonl"
    write(path, [event("legacy-1").model_dump_json(), event("legacy-2").model_dump_json()])
    reopened = LedgerStore(path, key=KEY)
    assert reopened.integrity is Integrity.UNSIGNED and len(reopened) == 2


def test_an_unsigned_append_to_a_signed_ledger_is_refused(signed):
    with pytest.raises(LedgerIntegrityError):
        LedgerStore(signed, key=None).record(event("e4"))
    assert LedgerStore(signed, key=KEY).integrity is Integrity.VERIFIED


def test_a_torn_final_line_is_dropped_and_repaired_on_the_next_append(signed):
    with signed.open("a", encoding="utf-8") as handle:
        handle.write('{"prev": "abc", "mac": "de')
    torn = LedgerStore(signed, key=KEY)
    assert torn.integrity is Integrity.VERIFIED and len(torn) == 3

    torn.record(event("e4"))
    after = LedgerStore(signed, key=KEY)
    assert after.integrity is Integrity.VERIFIED and "e4" in after


def test_two_stores_appending_to_one_file_keep_one_chain(tmp_path):
    """The automation server and the growth job hold separate `LedgerStore`s over the same file.
    A mac remembered in memory would fork the chain on the first interleaving."""
    path = tmp_path / "ledger.jsonl"
    server, job = LedgerStore(path, key=KEY), LedgerStore(path, key=KEY)
    for index in range(5):
        server.record(event(f"server-{index}"))
        job.record(event(f"job-{index}"))
    reopened = LedgerStore(path, key=KEY)
    assert reopened.integrity is Integrity.VERIFIED and len(reopened) == 10


def test_concurrent_processes_keep_one_chain(tmp_path):
    path = tmp_path / "ledger.jsonl"
    script = f"""
import sys
sys.path.insert(0, {str(tmp_path.parent)!r})
from datetime import datetime, timezone
from fazerops.ledger.store import LedgerStore
from fazerops.models import Actor, ChangeEvent, NormalizedAction, ResourceRef
tag = sys.argv[1]
store = LedgerStore({str(path)!r}, key={KEY!r})
for i in range(40):
    store.record(ChangeEvent(id=f"{{tag}}-{{i}}", source="k8s_audit",
        occurred_at=datetime(2026, 9, 6, tzinfo=timezone.utc), actor=Actor(raw="x"),
        action=NormalizedAction.UPDATE, resource=ResourceRef(kind="ConfigMap", name="c", namespace="n"),
        in_band=False, raw_ref=f"k8s_audit:{{tag}}-{{i}}"))
"""
    procs = [subprocess.Popen([sys.executable, "-c", script, tag]) for tag in ("a", "b", "c")]
    assert all(proc.wait(timeout=60) == 0 for proc in procs)

    reopened = LedgerStore(path, key=KEY)
    assert reopened.integrity is Integrity.VERIFIED, reopened.integrity_detail
    assert len(reopened) == 120


def test_the_alert_history_has_its_own_chain(tmp_path):
    """Recurrence reads it: a planted past alert manufactures a precedent."""
    path = tmp_path / "ledger.jsonl"
    store = LedgerStore(path, key=KEY)
    store.record(event("e1"))
    store.record_alert(Alert(id="a1", service="billing-api", summary="s", fired_at=T, alert_class=AlertClass.LATENCY_SPIKE))

    alerts = path.with_name("ledger.alerts.jsonl")
    row = json.loads(lines(alerts)[0])
    row["record"]["fired_at"] = (T - timedelta(days=1)).isoformat()
    write(alerts, [json.dumps(row)])

    assert LedgerStore(path, key=KEY).integrity is Integrity.BROKEN


def test_known_limit_removing_lines_from_the_end_is_not_detected(signed):
    """Stated in `chain.py`: the head is not anchored off-host. Asserted so the limit cannot be
    quietly forgotten — if this ever fails, the docstring and README are out of date."""
    write(signed, lines(signed)[:2])
    assert LedgerStore(signed, key=KEY).integrity is Integrity.VERIFIED


def test_an_unsigned_ledger_can_be_signed_once_and_then_verifies(tmp_path, monkeypatch, capsys):
    from fazerops.actions.growth.__main__ import main

    path = tmp_path / "ledger.jsonl"
    store = LedgerStore(path, key=None)
    store.extend([event("e1"), event("e2")])
    store.record_alert(Alert(id="a1", service="billing-api", summary="s", fired_at=T, alert_class=AlertClass.LATENCY_SPIKE))
    monkeypatch.setenv("FAZEROPS_EVIDENCE_KEY", KEY.decode())

    assert main(["--state-dir", str(tmp_path), "sign-ledger"]) == 0
    reopened = LedgerStore(path, key=KEY)
    assert reopened.integrity is Integrity.VERIFIED and len(reopened) == 2 and reopened.prior_alerts is not None
    assert main(["--state-dir", str(tmp_path), "sign-ledger"]) == 0, "signing a verified ledger is a no-op"
    reopened.record(event("e3"))
    assert LedgerStore(path, key=KEY).integrity is Integrity.VERIFIED


def test_signing_refuses_to_launder_a_broken_ledger(signed, monkeypatch, capsys):
    from fazerops.actions.growth.__main__ import main

    rows = lines(signed)
    write(signed, [rows[1], rows[0], rows[2]])
    monkeypatch.setenv("FAZEROPS_EVIDENCE_KEY", KEY.decode())
    assert main(["--state-dir", str(signed.parent), "sign-ledger"]) == 1
    assert "only an unsigned ledger can be signed" in capsys.readouterr().out
    assert LedgerStore(signed, key=KEY).integrity is Integrity.BROKEN


def test_signing_needs_a_key(tmp_path, monkeypatch, capsys):
    from fazerops.actions.growth.__main__ import main

    monkeypatch.delenv("FAZEROPS_EVIDENCE_KEY", raising=False)
    assert main(["--state-dir", str(tmp_path), "sign-ledger"]) == 1


@pytest.mark.parametrize(
    ("integrity", "key_configured", "usable"),
    [
        (Integrity.IN_MEMORY, True, True),
        (Integrity.VERIFIED, True, True),
        (Integrity.UNSIGNED, False, True),
        (Integrity.UNSIGNED, True, False),
        (Integrity.UNVERIFIED, True, False),
        (Integrity.BROKEN, False, False),
        (Integrity.BROKEN, True, False),
    ],
)
def test_what_may_vouch_for_evidence(integrity, key_configured, usable):
    assert usable_as_evidence(integrity, key_configured=key_configured) is usable
