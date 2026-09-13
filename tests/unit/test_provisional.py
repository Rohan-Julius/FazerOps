"""W45 — the provisional lifecycle and tombstones. Plan §4 Phase G.

The plan's two assertions:

* **Provisional is a separate axis from tier, and no path demotes a declared tier.** A
  provisional action needs a manager approval without its tier changing; graduating it removes
  that approval and leaves the tier exactly where it was. "Born Tier 2, earns Tier 1" would be
  a demotion driven by a counter, which is what an attacker who can move the counter wants.
* **A tombstoned action stays resolvable for W28's record and is not proposable.**

And graduation's own rule (§7.8): N confirmed executions **and** no human remediation of the
same resource within T — the second half is the one that carries the weight.
"""

from __future__ import annotations

import ast
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _growth_events import MULTI_AFTER, MULTI_BEFORE, configmap_change, multi_key_change  # noqa: E402

from fazerops import keys  # noqa: E402
from fazerops.actions.approval import (  # noqa: E402
    ApprovalGateway,
    ApprovalRefused,
    Approver,
    ApproverNotPermitted,
    ApproverRole,
)
from fazerops.actions.catalog import DEFAULT_ACTIONS, Catalog, promote  # noqa: E402
from fazerops.actions.growth.lifecycle import (  # noqa: E402
    GraduationStatus,
    LifecycleConfig,
    graduation_progress,
    graduation_status,
    load_lifecycle,
    retirement_candidates,
)
from fazerops.actions.growth.signals import (  # noqa: E402
    GapSignalStore,
    SignalKind,
    outcome_observer,
    signal_for,
)
from fazerops.actions.inverse import ActionRequest  # noqa: E402
from fazerops.actions.preconditions import Evidence  # noqa: E402
from fazerops.actions.writers.registry import request_for_event  # noqa: E402
from fazerops.ledger.store import LedgerStore  # noqa: E402
from fazerops.models import Tier  # noqa: E402
from fazerops.slack.handlers import approval_card_for  # noqa: E402

SRC = Path(__file__).resolve().parents[2] / "src" / "fazerops"
ACTION = "revert_configmap_data"
IC = Approver(user_id="U_IC", role=ApproverRole.ENGINEER)
MANAGER = Approver(user_id="U_MGR", role=ApproverRole.MANAGER)
CONFIG = LifecycleConfig(graduation_approvals=2, quiet_minutes=60, retire_after_unused_incidents=3)
EVIDENCE = Evidence(
    resource_keys=frozenset({keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}),
    complete=True,
)
BASE = datetime(2026, 9, 20, 9, 0, tzinfo=timezone.utc)


def _catalog(tmp_path, *, tier: int = 1, provisional: bool = True, retired: bool = False) -> Catalog:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / f"actions-{tier}-{provisional}-{retired}.yaml"
    manager = "    requires_approval_from: manager\n" if tier == 2 else ""
    path.write_text(
        DEFAULT_ACTIONS.read_text(encoding="utf-8")
        + f"\n  - id: {ACTION}\n    tier: {tier}\n{manager}"
        "    description: generated from production evidence\n"
        "    writer: k8s/ConfigMap:data\n"
        f"    provisional: {str(provisional).lower()}\n"
        f"    retired: {str(retired).lower()}\n"
        "    params: {namespace: {type: str}, name: {type: str}}\n",
        encoding="utf-8",
    )
    return Catalog.load(path)


class _Runner:
    def __init__(self) -> None:
        self.count = 0

    def __call__(self, request, credential, evidence):
        self.count += 1
        return {"action_id": request.action_id}


def _world(tmp_path, *, clock=None, **catalog):
    world = SimpleNamespace(
        catalog=_catalog(tmp_path, **catalog), ledger=LedgerStore(), store=GapSignalStore(), runner=_Runner()
    )
    world.gateway = ApprovalGateway(
        catalog=world.catalog,
        runner=world.runner,
        observer=outcome_observer(world.store, world.ledger),
        graduation=graduation_progress(world.store, world.ledger, config=CONFIG, clock=clock),
    )
    return world


def _open(world, number: int):
    change = multi_key_change(f"evt-{number}", at=BASE + timedelta(hours=number))
    world.ledger.record(change)
    request = request_for_event(change, catalog=world.catalog)
    return world.gateway.register(f"INC-{number}", request, evidence=EVIDENCE, evidence_ids=[change.id])


def _execute(world, number: int):
    _open(world, number)
    outcome = world.gateway.decide(
        incident_id=f"INC-{number}", action_id=ACTION, approver=MANAGER, kind="approve"
    )
    assert outcome.executed, outcome.error
    return next(
        s for s in world.store.signals(kind=SignalKind.EXECUTED) if s.incident_id == f"INC-{number}"
    )


def _later() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=2)


# --------------------------------------------------------------------------------------
# Provisional is not a tier
# --------------------------------------------------------------------------------------


def test_provisional_requires_a_manager_without_changing_the_tier(tmp_path):
    pending = _open(_world(tmp_path), 1)

    assert pending.provisional is True
    assert pending.declared_tier is Tier.ENGINEER_APPROVAL
    assert pending.tier is Tier.ENGINEER_APPROVAL, "provisional must not raise the tier either"
    assert pending.escalated is False
    assert pending.requires_manager is True


def test_an_engineer_cannot_approve_a_provisional_action_and_a_manager_can(tmp_path):
    world = _world(tmp_path)
    _open(world, 1)

    with pytest.raises(ApproverNotPermitted, match="provisional"):
        world.gateway.decide(incident_id="INC-1", action_id=ACTION, approver=IC, kind="approve")
    assert world.runner.count == 0

    outcome = world.gateway.decide(incident_id="INC-1", action_id=ACTION, approver=MANAGER, kind="approve")
    assert outcome.executed and outcome.tier is Tier.ENGINEER_APPROVAL
    assert world.runner.count == 1


@pytest.mark.parametrize("tier", [1, 2])
def test_the_tier_is_identical_on_both_sides_of_graduation(tmp_path, tier):
    """No path demotes: the provisional and the graduated action present, record and route at the
    same tier. Graduation only removes the extra manager approval a Tier 1 action carried."""
    provisional = _open(_world(tmp_path / "p", tier=tier, provisional=True), 1)
    graduated = _open(_world(tmp_path / "g", tier=tier, provisional=False), 1)

    assert provisional.tier is graduated.tier is Tier(tier)
    assert provisional.tier >= provisional.declared_tier
    assert graduated.requires_manager is (tier == 2)

    spec = _catalog(tmp_path / "s", tier=tier).get(ACTION)
    assert promote(spec)[0] is Tier(tier)


def test_the_lifecycle_module_never_names_a_tier():
    """Structural. Graduation cannot demote a tier it has no way to refer to."""
    source = (SRC / "actions" / "growth" / "lifecycle.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and "tier" in n.attr.lower()]
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Name) and "tier" in n.id.lower()]
    assert not [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.lower() in {"tier", "requires_approval_from"}
    ]
    assert not {name for name in GraduationStatus.model_fields if "tier" in name}


# --------------------------------------------------------------------------------------
# The card
# --------------------------------------------------------------------------------------


def _card_text(pending) -> str:
    return str(approval_card_for(pending))


def test_the_card_says_generated_n_of_n(tmp_path):
    world = _world(tmp_path, clock=_later)
    assert "generated, 0/2" in _card_text(_open(world, 1))

    world.gateway.decide(incident_id="INC-1", action_id=ACTION, approver=MANAGER, kind="approve")
    assert "generated, 1/2" in _card_text(_open(world, 2))


def test_a_card_for_a_graduated_action_says_nothing_about_generation(tmp_path):
    assert "Provisional" not in _card_text(_open(_world(tmp_path, provisional=False), 1))


# --------------------------------------------------------------------------------------
# Graduation — N confirmed, and no human follow-up
# --------------------------------------------------------------------------------------


def test_graduation_needs_n_executions_with_their_quiet_period_elapsed(tmp_path):
    world = _world(tmp_path)
    _execute(world, 1)
    _execute(world, 2)

    now = graduation_status(ACTION, world.store, world.ledger, now=datetime.now(timezone.utc), config=CONFIG)
    assert (now.confirmed, now.awaiting_quiet_period, now.graduated) == (0, 2, False)

    later = graduation_status(ACTION, world.store, world.ledger, now=_later(), config=CONFIG)
    assert (later.confirmed, later.contested, later.graduated) == (2, 0, True)


def _executed_on_day(world, day: int):
    """An execution recorded at a controlled time, days apart.

    The gateway stamps `decided_at` from the real clock, so executions driven through it land
    milliseconds apart — and one hand-fix then sits inside every quiet window at once, which the
    check correctly reads as contesting all of them. Spacing them is what isolates one.
    """
    change = multi_key_change(f"evt-{day}", at=BASE + timedelta(days=day) - timedelta(minutes=38))
    world.ledger.record(change)
    executed = signal_for(
        SignalKind.EXECUTED,
        change,
        incident_id=f"INC-{day}",
        action_id=ACTION,
        observed_at=BASE + timedelta(days=day),
    )
    world.store.record(executed)
    return executed


def _hand_fix(world, name: str, at: datetime) -> None:
    world.ledger.record(configmap_change(name, at=at, before=MULTI_BEFORE, after=MULTI_AFTER))


def test_one_human_remediation_after_an_execution_blocks_graduation(tmp_path):
    """The negative signal outweighs any count: two confirmed do not outvote one contested."""
    world = _world(tmp_path)
    for day in (1, 2, 3):
        executed = _executed_on_day(world, day)
    _hand_fix(world, "hand-fix", executed.observed_at + timedelta(minutes=10))

    status = graduation_status(ACTION, world.store, world.ledger, now=BASE + timedelta(days=5), config=CONFIG)
    assert (status.confirmed, status.contested) == (2, 1)
    assert status.graduated is False


def test_a_change_after_the_quiet_period_does_not_contest(tmp_path):
    world = _world(tmp_path)
    _executed_on_day(world, 1)
    executed = _executed_on_day(world, 2)
    _hand_fix(world, "next-hour", executed.observed_at + timedelta(minutes=61))

    status = graduation_status(ACTION, world.store, world.ledger, now=BASE + timedelta(days=5), config=CONFIG)
    assert (status.confirmed, status.contested, status.graduated) == (2, 0, True)


def test_graduation_after_a_single_execution_cannot_be_configured():
    with pytest.raises(ValidationError):
        LifecycleConfig(graduation_approvals=1)


def test_the_shipped_lifecycle_config_loads():
    config = load_lifecycle()
    assert config.graduation_approvals >= 2
    assert config.quiet_minutes >= 1


# --------------------------------------------------------------------------------------
# Tombstones
# --------------------------------------------------------------------------------------


def test_a_retired_action_stays_resolvable_and_is_not_proposable(tmp_path):
    catalog = _catalog(tmp_path, retired=True)

    assert catalog.get(ACTION).retired is True, "W28's record must still resolve it"
    assert ACTION not in catalog.action_ids, "the proposer's enum is built from action_ids"
    assert request_for_event(multi_key_change("evt-1", at=BASE), catalog=catalog) is None


def test_a_retired_action_cannot_be_approved(tmp_path):
    catalog = _catalog(tmp_path, retired=True)
    change = multi_key_change("evt-1", at=BASE)
    request = ActionRequest.for_action(
        ACTION,
        {"namespace": "billing", "name": "billing-api-config"},
        inverse_hint={
            "action_id": ACTION,
            "writer": "k8s/ConfigMap:data",
            "ref": {"namespace": "billing", "name": "billing-api-config"},
            "prior": dict(change.diff.before),
            "current": dict(change.diff.after),
        },
        catalog=catalog,
    )

    with pytest.raises(ApprovalRefused, match="retired"):
        ApprovalGateway(catalog=catalog, runner=_Runner()).register("INC-1", request, evidence=EVIDENCE)


def test_retirement_recommends_only_generated_actions_unused_across_n_incidents(tmp_path):
    world = _world(tmp_path)
    _execute(world, 1)

    assert retirement_candidates(world.catalog, world.store, ["INC-1", "INC-2", "INC-3"], config=CONFIG) == []
    assert retirement_candidates(world.catalog, world.store, ["INC-4", "INC-5", "INC-6"], config=CONFIG) == [ACTION]
    assert retirement_candidates(world.catalog, world.store, ["INC-5", "INC-6"], config=CONFIG) == []


def test_the_handoff_actions_are_never_recommended_for_retirement(tmp_path):
    catalog = _catalog(tmp_path)
    recommended = retirement_candidates(catalog, GapSignalStore(), ["a", "b", "c"], config=CONFIG)
    assert recommended == [ACTION]
