"""W26 — tier promotion. Handoff §7, plan §4.

> *`thresholds.yaml` may only promote Tier 1 → Tier 2; nothing ever demotes.*

The plan's assertions are that promotion fires on cost and on a namespace crossing, and
that **nothing ever demotes**. The second is the one with teeth, so it is asserted by
sweeping every action against every combination of promotion inputs rather than by
checking the two cases someone thought of — a demotion introduced by a future rule would
be invisible to a test that only tries the inputs that promote.

The reason string is tested alongside the tier because W26b renders it on the card next to
the tier, and an escalation an operator cannot check the justification for is decoration.
"""

from __future__ import annotations

import itertools

import pytest

from fazerops.actions.catalog import Thresholds, default_catalog, effective_tier, promote
from fazerops.models import Tier

CATALOG = default_catalog()
ACTIONS = list(CATALOG)

# The thresholds `config/thresholds.yaml` actually ships. Read from the catalog rather than
# restated here: a test carrying its own copy of the config agrees with itself forever.
SHIPPED = CATALOG.thresholds


# --------------------------------------------------------------------------------------
# Declared, then promoted — never inferred
# --------------------------------------------------------------------------------------


def test_an_unpromoted_action_runs_at_its_declared_tier():
    for action in ACTIONS:
        tier, reason = promote(action, thresholds=SHIPPED)
        assert tier is action.tier, f"{action.id} moved with no promotion input"
        assert reason is None


def test_cost_delta_above_the_threshold_promotes_to_tier_2():
    action = CATALOG.get("revert_configmap_key")
    assert action.tier is Tier.ENGINEER_APPROVAL

    tier, reason = promote(
        action, estimated_cost_delta_usd=SHIPPED.estimated_cost_delta_usd + 1, thresholds=SHIPPED
    )
    assert tier is Tier.MANAGER_APPROVAL
    assert "cost delta" in reason


def test_cost_delta_exactly_at_the_threshold_does_not_promote():
    """`>` not `>=`, matching the config comment. Asserted because an off-by-one here means
    every action at exactly the limit escalates, and the demo's numbers sit on round
    figures."""
    action = CATALOG.get("revert_configmap_key")
    tier, reason = promote(
        action, estimated_cost_delta_usd=SHIPPED.estimated_cost_delta_usd, thresholds=SHIPPED
    )
    assert tier is Tier.ENGINEER_APPROVAL
    assert reason is None


def test_crossing_a_namespace_boundary_promotes_to_tier_2():
    action = CATALOG.get("revert_configmap_key")
    tier, reason = promote(action, crosses_namespace_boundary=True, thresholds=SHIPPED)
    assert tier is Tier.MANAGER_APPROVAL
    assert "namespace" in reason


def test_resource_count_above_the_threshold_promotes_to_tier_2():
    action = CATALOG.get("revert_configmap_key")
    tier, reason = promote(
        action, resource_count=SHIPPED.resource_count + 1, thresholds=SHIPPED
    )
    assert tier is Tier.MANAGER_APPROVAL
    assert str(SHIPPED.resource_count) in reason


def test_several_rules_firing_report_every_reason():
    """The card states why it escalated. When two rules fire, naming one of them would let
    an operator satisfy that one and expect the escalation to go away."""
    action = CATALOG.get("revert_configmap_key")
    tier, reason = promote(
        action,
        crosses_namespace_boundary=True,
        resource_count=SHIPPED.resource_count + 5,
        thresholds=SHIPPED,
    )
    assert tier is Tier.MANAGER_APPROVAL
    assert "namespace" in reason and "resources" in reason


def test_an_action_declared_tier_2_reports_no_escalation_reason():
    """Not an escalation — it was always Tier 2. Labelling the declaration as an escalation
    teaches an operator to read the word as decoration."""
    action = CATALOG.get("restore_db_parameter")
    assert action.tier is Tier.MANAGER_APPROVAL

    tier, reason = promote(action, crosses_namespace_boundary=True, thresholds=SHIPPED)
    assert tier is Tier.MANAGER_APPROVAL
    assert reason is None


# --------------------------------------------------------------------------------------
# Nothing ever demotes — the invariant, swept rather than sampled
# --------------------------------------------------------------------------------------

_COST = [None, -1_000_000.0, 0.0, 99.99, 100.0, 100.01, 1e9]
_COUNT = [None, -5, 0, 1, 10, 11, 10_000]
_CROSSES = [False, True]


@pytest.mark.parametrize("action", ACTIONS, ids=lambda a: a.id)
def test_no_combination_of_inputs_ever_lowers_a_declared_tier(action):
    for cost, count, crosses in itertools.product(_COST, _COUNT, _CROSSES):
        tier, _ = promote(
            action,
            estimated_cost_delta_usd=cost,
            resource_count=count,
            crosses_namespace_boundary=crosses,
            thresholds=SHIPPED,
        )
        assert tier >= action.tier, (
            f"{action.id} demoted from {action.tier} to {tier} on "
            f"cost={cost} count={count} crosses={crosses}"
        )


@pytest.mark.parametrize("action", ACTIONS, ids=lambda a: a.id)
def test_no_combination_of_thresholds_ever_lowers_a_declared_tier(action):
    """The sweep above varies the *inputs*; this one varies the *config*. A demotion
    configured by mistake is the failure `thresholds.yaml` has no field to express, and
    this is the assertion that keeps it that way when a field is added."""
    for cost, count, crosses in itertools.product([None, 0.0, 1e9], [None, 0, 10_000], _CROSSES):
        thresholds = Thresholds(
            estimated_cost_delta_usd=cost,
            resource_count=count,
            crosses_namespace_boundary=crosses,
        )
        tier, _ = promote(
            action,
            estimated_cost_delta_usd=1e6,
            resource_count=10_000,
            crosses_namespace_boundary=True,
            thresholds=thresholds,
        )
        assert tier >= action.tier, f"{action.id} demoted under thresholds {thresholds}"


def test_a_reason_is_reported_whenever_and_only_whenever_the_tier_moved():
    """Ties the two halves together. A reason without a movement is a card claiming an
    escalation that did not happen; a movement without a reason is one an operator cannot
    check."""
    for action in ACTIONS:
        for cost, count, crosses in itertools.product(_COST, _COUNT, _CROSSES):
            tier, reason = promote(
                action,
                estimated_cost_delta_usd=cost,
                resource_count=count,
                crosses_namespace_boundary=crosses,
                thresholds=SHIPPED,
            )
            assert (reason is not None) == (tier > action.tier), (
                f"{action.id}: tier {action.tier}->{tier} with reason {reason!r}"
            )


def test_effective_tier_agrees_with_promote():
    """Two entry points, one traversal. They are separate functions only because most
    callers do not want the reason, and they must never be able to disagree."""
    for action in ACTIONS:
        for cost, count, crosses in itertools.product(_COST, _COUNT, _CROSSES):
            kwargs = dict(
                estimated_cost_delta_usd=cost,
                resource_count=count,
                crosses_namespace_boundary=crosses,
                thresholds=SHIPPED,
            )
            assert effective_tier(action, **kwargs) is promote(action, **kwargs)[0]


def test_thresholds_has_no_field_that_could_express_a_demotion():
    """Structural. The one-way property above is checked behaviourally; this asserts the
    config schema cannot even *say* 'demote', so a future rule cannot be configured into
    existence without this test being deliberately changed."""
    fields = set(Thresholds.model_fields)
    assert fields == {
        "estimated_cost_delta_usd",
        "resource_count",
        "crosses_namespace_boundary",
    }, f"thresholds gained a field: {sorted(fields)}"
