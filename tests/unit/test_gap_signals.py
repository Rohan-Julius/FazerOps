"""W40 — the five gap signals, and the demonstration corpus W42 replays against.

Plan §4 Phase G. Three properties matter more than the rest and each has its own test:

* **A decline is decided from the brief, not from model output** (§4). The model's vocabulary
  is untouched; Python reads the ranked #1 change.
* **The demonstration corpus is persisted with its values**, and survives a reload. W42's
  corpus-replay gate has nothing to replay against otherwise — a count is not a corpus.
* **Signals reach the store from the two existing decision points** — the proposer's decline
  and the gateway's recorded outcome — without either changing what it decides.
"""

from __future__ import annotations

import ast
import functools
import inspect
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _growth_events import (  # noqa: E402
    MULTI_AFTER,
    MULTI_BEFORE,
    T0,
    brief_for,
    configmap_change,
    multi_key_change,
)

from fazerops.actions.approval import ApprovalGateway, Approver, ApproverRole  # noqa: E402
from fazerops.actions.growth import signals as signals_module  # noqa: E402
from fazerops.actions.growth.miner import MinerThresholds, mine_history  # noqa: E402
from fazerops.actions.growth.signals import (  # noqa: E402
    FieldPath,
    GapSignalStore,
    ResourceKind,
    SignalKind,
    classify,
    decline_signal,
    find_remediations,
    ledger_signals,
    outcome_observer,
    signal_for,
)
from fazerops.actions.inverse import ActionRequest  # noqa: E402
from fazerops.ledger.store import LedgerStore  # noqa: E402
from fazerops.models import BlastRadius, TimeWindow  # noqa: E402

FIXTURE_ALERTS = Path(__file__).resolve().parents[2] / "fixtures" / "alerts"
SRC = Path(__file__).resolve().parents[2] / "src" / "fazerops"
CAUSE_AT = T0 - timedelta(minutes=38)
HISTORY = TimeWindow(start=T0 - timedelta(days=1), end=T0 + timedelta(days=1))


@pytest.fixture
async def demo_brief(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")

    from fazerops.ingest.alerts import normalize_alert
    from fazerops.pipeline import investigate

    payload = json.loads((FIXTURE_ALERTS / "alertmanager.json").read_text(encoding="utf-8"))
    return await investigate(normalize_alert(payload))


def _fix_of(cause, *, at, actor="dinesh", actor_kind="human", name="billing-api-config"):
    """A human putting the multi-key change back by hand."""
    return configmap_change(
        f"fix-{cause.id}",
        at=at,
        actor=actor,
        actor_kind=actor_kind,
        name=name,
        before=MULTI_AFTER,
        after=MULTI_BEFORE,
    )


# --------------------------------------------------------------------------------------
# Decline — §4, the deterministic trigger
# --------------------------------------------------------------------------------------


async def test_no_decline_is_recorded_when_the_catalog_can_revert_the_top_change(demo_brief):
    """The demo's rank 1 is the `pool.max` edit, which `revert_configmap_key` reverts. A model
    declining it is being cautious, and mining caution as missing capability is wrong."""
    assert decline_signal(demo_brief) is None


def test_a_decline_over_an_unrevertible_top_change_is_a_signal():
    brief = brief_for("INC-1", multi_key_change("evt-1", at=CAUSE_AT))
    signal = decline_signal(brief)

    assert signal.kind is SignalKind.DECLINE
    assert signal.incident_id == "INC-1"
    assert signal.event_id == "evt-1"
    assert signal.resource_kind is ResourceKind.CONFIGMAP
    assert signal.field_path is FieldPath.DATA
    assert signal.prior_value_recorded is True
    assert signal.observed_at == brief.alert.fired_at


def test_an_empty_brief_declines_nothing():
    assert decline_signal(brief_for("INC-1")) is None


def test_the_decline_reads_the_brief_and_never_the_models_vocabulary():
    """§4: the path fires off the decline without the model naming anything. Structural — the
    function takes only the brief, and the growth package never touches the proposer's enum."""
    assert list(inspect.signature(decline_signal).parameters) == ["brief"]

    forbidden = {"ACTION_IDS", "_ActionId", "ProposerOutput", "_WireOutput"}
    for path in (SRC / "actions" / "growth").glob("*.py"):
        names = {
            node.id if isinstance(node, ast.Name) else node.attr
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, (ast.Name, ast.Attribute))
        }
        assert not names & forbidden, f"{path.name} reaches into the proposer's schema"


# --------------------------------------------------------------------------------------
# Unactionable / inverse missing — against the recorded window
# --------------------------------------------------------------------------------------


async def test_the_recorded_demo_window_classifies_honestly(demo_brief):
    by_rank = {candidate.rank: candidate.event for candidate in demo_brief.candidates}

    assert classify(by_rank[1]) is None, "the pool.max edit is revertible"
    assert classify(by_rank[3]) is SignalKind.UNACTIONABLE, "the recorded two-key patch is not"

    secret = signal_for(SignalKind.UNACTIONABLE, by_rank[2], observed_at=T0)
    assert secret.prior_value_recorded is False, "a redacted prior is not a prior value"


def test_a_hint_with_no_current_value_is_an_inverse_missing():
    change = configmap_change("evt-1", at=CAUSE_AT, before={"pool.max": "100"}, after={"pool.max": "20"})
    broken = change.model_copy(
        update={"inverse_hint": {**change.inverse_hint, "current_value": None}}
    )
    assert classify(broken) is SignalKind.INVERSE_MISSING


def test_ledger_signals_are_scoped_to_the_radius():
    ledger = LedgerStore()
    ledger.extend(
        [
            multi_key_change("in-billing", at=CAUSE_AT),
            multi_key_change("in-auth", at=CAUSE_AT, namespace="auth", name="auth-service-config"),
        ]
    )
    billing = BlastRadius(service="billing-api", keys={"k8s:billing/configmap/billing-api-config"})

    found = ledger_signals(ledger, billing, HISTORY)
    assert [signal.event_id for signal in found] == ["in-billing"]
    assert found[0].incident_id is None, "history is a change class, not an incident"


# --------------------------------------------------------------------------------------
# The store
# --------------------------------------------------------------------------------------


def test_signals_persist_and_reload(tmp_path):
    path = tmp_path / "gap_signals.jsonl"
    signal = decline_signal(brief_for("INC-1", multi_key_change("evt-1", at=CAUSE_AT)))
    GapSignalStore(path).record(signal)

    assert GapSignalStore(path).signals() == [signal]


def test_recording_a_signal_twice_writes_it_once(tmp_path):
    path = tmp_path / "gap_signals.jsonl"
    store = GapSignalStore(path)
    signal = decline_signal(brief_for("INC-1", multi_key_change("evt-1", at=CAUSE_AT)))

    assert store.record(signal) is True
    assert store.record(signal) is False
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_a_truncated_final_line_does_not_lose_the_history(tmp_path):
    path = tmp_path / "gap_signals.jsonl"
    signal = decline_signal(brief_for("INC-1", multi_key_change("evt-1", at=CAUSE_AT)))
    GapSignalStore(path).record(signal)
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"kind": "decl')

    assert GapSignalStore(path).signals() == [signal]


# --------------------------------------------------------------------------------------
# The demonstration corpus — persisted, not counted
# --------------------------------------------------------------------------------------


def _anchor_and_ledger(fix):
    cause = multi_key_change("evt-1", at=CAUSE_AT)
    ledger = LedgerStore()
    ledger.extend([cause, fix(cause)])
    return decline_signal(brief_for("INC-1", cause)), ledger


def test_the_remediation_is_persisted_with_its_before_and_after(tmp_path):
    """The plan's dependency, asserted: W42 replays against these *values*, after a reload."""
    anchor, ledger = _anchor_and_ledger(lambda cause: _fix_of(cause, at=T0 + timedelta(minutes=12)))
    path = tmp_path / "gap_signals.jsonl"
    store = GapSignalStore(path)

    for _, demonstration in find_remediations(ledger, [anchor], window_minutes=60):
        store.record_demonstration(demonstration)

    [demonstration] = GapSignalStore(path).demonstrations(anchor.key)
    assert demonstration.before == MULTI_AFTER
    assert demonstration.after == MULTI_BEFORE
    assert demonstration.remediation_event_id == "fix-evt-1"
    assert demonstration.anchor_event_id == "evt-1"
    assert demonstration.actor == "dinesh"
    assert demonstration.lag_seconds == 12 * 60
    assert demonstration.resource.name == "billing-api-config"


@pytest.mark.parametrize(
    "fix",
    [
        pytest.param(lambda c: _fix_of(c, at=T0 + timedelta(minutes=61)), id="after-the-window"),
        pytest.param(lambda c: _fix_of(c, at=T0 - timedelta(minutes=1)), id="before-the-decline"),
        pytest.param(
            lambda c: _fix_of(c, at=T0 + timedelta(minutes=5), actor="ci", actor_kind="service_account"),
            id="not-a-human",
        ),
        pytest.param(
            lambda c: _fix_of(c, at=T0 + timedelta(minutes=5), name="other-config"),
            id="another-resource",
        ),
    ],
)
def test_changes_that_are_not_the_remediation_are_not_recorded_as_one(fix):
    anchor, ledger = _anchor_and_ledger(fix)
    assert list(find_remediations(ledger, [anchor], window_minutes=60)) == []


def test_mine_history_finds_the_gap_and_keeps_its_corpus(tmp_path):
    """The continuous job end to end: two incidents, two actors, each followed by a human fix."""
    ledger = LedgerStore()
    store = GapSignalStore(tmp_path / "gap_signals.jsonl")

    for number, actor, fired_at in ((1, "priya", T0), (2, "arun", T0 + timedelta(hours=6))):
        cause = multi_key_change(f"evt-{number}", at=fired_at - timedelta(minutes=38), actor=actor)
        ledger.extend([cause, _fix_of(cause, at=fired_at + timedelta(minutes=9))])
        # What the proposer node records at incident time, before the miner ever runs.
        store.record(decline_signal(brief_for(f"INC-{number}", cause, fired_at=fired_at)))

    gaps = mine_history(ledger, store, HISTORY, thresholds=MinerThresholds())
    eligible = [gap for gap in gaps if gap.eligible]

    assert len(eligible) == 1
    row = eligible[0].aggregate
    assert (row.incident_count, row.distinct_actors, row.remediation_count) == (2, 2, 2)
    assert len(store.demonstrations(eligible[0].key)) == 2

    again = mine_history(ledger, store, HISTORY, thresholds=MinerThresholds())
    assert again == gaps, "re-running the miner must record nothing new"


# --------------------------------------------------------------------------------------
# Wiring — the gateway and the proposer node
# --------------------------------------------------------------------------------------


class _Runner:
    def __init__(self) -> None:
        self.count = 0

    def __call__(self, request, credential, evidence):
        self.count += 1
        return {"action_id": request.action_id}


def _gateway_with_observer(store, *, observer=None):
    cause = configmap_change("evt-1", at=CAUSE_AT, before={"pool.max": "100"}, after={"pool.max": "20"})
    ledger = LedgerStore()
    ledger.record(cause)
    runner = _Runner()
    gateway = ApprovalGateway(
        runner=runner, observer=observer or outcome_observer(store, ledger)
    )
    request = ActionRequest.for_action(
        "revert_configmap_key",
        {"namespace": "billing", "name": "billing-api-config", "key": "pool.max", "target_value": "100"},
        inverse_hint=cause.inverse_hint,
    )
    gateway.register("INC-1", request, evidence_ids=[cause.id])
    return gateway, runner


ENGINEER = Approver(user_id="U_IC", role=ApproverRole.ENGINEER)


def test_a_rejection_is_recorded_as_a_signal():
    store = GapSignalStore()
    gateway, runner = _gateway_with_observer(store)

    gateway.decide(incident_id="INC-1", action_id="revert_configmap_key", approver=ENGINEER, kind="reject")

    [signal] = store.signals()
    assert signal.kind is SignalKind.REJECTED
    assert signal.action_id == "revert_configmap_key"
    assert signal.event_id == "evt-1"
    assert runner.count == 0


def test_an_execution_is_recorded_once_and_a_replay_adds_nothing():
    store = GapSignalStore()
    gateway, runner = _gateway_with_observer(store)

    for _ in range(2):
        gateway.decide(
            incident_id="INC-1", action_id="revert_configmap_key", approver=ENGINEER, kind="approve"
        )

    assert runner.count == 1
    assert [signal.kind for signal in store.signals()] == [SignalKind.EXECUTED]


def test_an_observer_that_raises_does_not_change_the_decision():
    def broken(pending, outcome):
        raise RuntimeError("disk full")

    gateway, runner = _gateway_with_observer(GapSignalStore(), observer=broken)
    outcome = gateway.decide(
        incident_id="INC-1", action_id="revert_configmap_key", approver=ENGINEER, kind="approve"
    )

    assert outcome.executed is True
    assert runner.count == 1


async def _run_graph_declining(monkeypatch, store):
    """The demo graph, with the proposer declining and the top change treated as unrevertible
    — the demo's own rank 1 is revertible, so the gap has to be induced to exercise the wire."""
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")

    import fazerops.agents.proposer as proposer_module
    from fazerops.agents.graph import investigate_via_graph
    from fazerops.ingest.alerts import normalize_alert

    async def declines(*args, **kwargs):
        return None

    monkeypatch.setattr(proposer_module, "propose", declines)
    monkeypatch.setattr(signals_module, "catalog_can_revert", lambda event: False)

    payload = json.loads((FIXTURE_ALERTS / "alertmanager.json").read_text(encoding="utf-8"))
    return await investigate_via_graph(
        normalize_alert(payload),
        proposer_node=functools.partial(proposer_module.proposer_node, signals=store),
    )


async def test_the_proposer_node_records_the_decline_it_observes(monkeypatch):
    store = GapSignalStore()
    brief, _ = await _run_graph_declining(monkeypatch, store)

    [signal] = store.signals()
    assert signal.kind is SignalKind.DECLINE
    assert signal.event_id == brief.top.event.id
    assert signal.incident_id == brief.incident_id


async def test_a_failing_signal_store_costs_the_brief_nothing(monkeypatch):
    class Broken(GapSignalStore):
        def record(self, signal):
            raise OSError("read-only filesystem")

    brief, result = await _run_graph_declining(monkeypatch, Broken())

    assert brief.candidates
    assert brief.degraded is False
    assert "proposer" in [node.node_id for node in result.execution_order]
