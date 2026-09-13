"""W40 — the gap miner takes no free text. Plan §4 Phase G, `docs/catalog_self_extension.md` §7.1.

The ledger is built from attacker-influenceable data. A gap becomes a PR and a PR becomes a
catalog entry, so a miner that read narrative would be a path from one writable ConfigMap to a
new capability. Two properties close it, and both are asserted here:

1. **The miner's input model holds only scalars and enums**, read off its JSON **schema** — not
   a substring search over its source, which would have to be loosened until it guarded
   nothing, the same trap `test_scoring.py`'s AST check exists to avoid.
2. **A gap below the N-incident × M-actor threshold is ineligible**, and the threshold cannot be
   configured away.
"""

from __future__ import annotations

import inspect
import sys
import typing
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _growth_events import T0, brief_for, cloudtrail_change, configmap_change, multi_key_change  # noqa: E402
from _injection import CANONICAL, PAYLOADS  # noqa: E402

from fazerops.actions.growth.miner import (  # noqa: E402
    GapAggregate,
    IneligibleReason,
    MinerThresholds,
    aggregate,
    load_thresholds,
    mine,
)
from fazerops.actions.growth.signals import decline_signal  # noqa: E402

SCALAR_TYPES = {"integer", "number", "boolean"}
THRESHOLDS = MinerThresholds()


def _resolve(prop: dict, defs: dict) -> dict:
    if "$ref" in prop:
        return defs[prop["$ref"].rsplit("/", 1)[-1]]
    if len(prop.get("allOf", ())) == 1:
        return _resolve(prop["allOf"][0], defs)
    return prop


def _declines(*incidents: tuple[int, str]) -> list:
    """One decline per `(incident number, actor)`, each over the recorded multi-key shape."""
    signals = []
    for number, actor in incidents:
        change = multi_key_change(f"evt-{number}", at=T0 - timedelta(minutes=38), actor=actor)
        signals.append(decline_signal(brief_for(f"INC-{number}", change)))
    return signals


# --------------------------------------------------------------------------------------
# 1 — the input model, asserted against its schema
# --------------------------------------------------------------------------------------


def test_the_aggregate_schema_holds_only_scalars_and_enums():
    schema = GapAggregate.model_json_schema()
    defs = schema.get("$defs", {})
    assert schema["properties"], "an empty schema would pass this vacuously"

    for name, prop in schema["properties"].items():
        resolved = _resolve(prop, defs)
        # A union is how an optional string sneaks in — `str | None` is `anyOf`.
        assert "anyOf" not in resolved and "oneOf" not in resolved, f"{name} is a union"
        if "enum" in resolved or "const" in resolved:
            continue
        assert resolved.get("type") in SCALAR_TYPES, f"{name} can carry free text: {resolved}"


def test_the_aggregate_is_frozen_and_refuses_extra_fields():
    row = aggregate(_declines((1, "priya")))[0]

    with pytest.raises(ValidationError):
        row.decline_count = 99
    with pytest.raises(ValidationError):
        GapAggregate.model_validate({**row.model_dump(), "summary": CANONICAL})


def test_mine_is_typed_to_aggregates_and_nothing_else():
    assert list(inspect.signature(mine).parameters) == ["aggregates", "thresholds"]
    hints = typing.get_type_hints(mine)
    assert typing.get_args(hints["aggregates"]) == (GapAggregate,)


@pytest.mark.parametrize(
    "smuggled",
    [
        {"source": "k8s_audit", "resource_kind": "ConfigMap", "summary": CANONICAL},
        CANONICAL,
        "decline",
    ],
    ids=["dict", "payload", "bare-string"],
)
def test_mine_refuses_anything_that_is_not_an_aggregate(smuggled):
    """Refused at runtime, so the property does not depend on a type checker being run."""
    with pytest.raises(TypeError, match="GapAggregate"):
        mine([smuggled], THRESHOLDS)


def test_mine_refuses_a_raw_signal():
    """A signal carries ids and an actor name. It is the aggregate's input, never the miner's."""
    with pytest.raises(TypeError, match="GapAggregate"):
        mine(_declines((1, "priya")), THRESHOLDS)


@pytest.mark.parametrize("payload", sorted(PAYLOADS))
def test_hostile_text_in_a_change_never_reaches_the_aggregate(payload):
    """W27's payloads, written into both a value **and a key name** of the change.

    The key name is §10a's residual risk — a ConfigMap key is a string someone wrote — so it is
    asserted separately: the field path stops at the map.
    """
    hostile_key = PAYLOADS[payload][:60]
    signals = []
    for number, actor in ((1, "priya"), (2, "dinesh")):
        change = configmap_change(
            f"evt-{number}",
            at=T0 - timedelta(minutes=38),
            actor=actor,
            before={hostile_key: "a", "session.ttl": "3600"},
            after={hostile_key: PAYLOADS[payload], "session.ttl": "900"},
        )
        signals.append(decline_signal(brief_for(f"INC-{number}", change)))

    gaps = mine(aggregate(signals), THRESHOLDS)
    rendered = "".join(gap.model_dump_json() for gap in gaps)

    assert PAYLOADS[payload][:20] not in rendered
    assert hostile_key[:20] not in rendered
    assert {gap.aggregate.field_path.value for gap in gaps} == {"data"}


# --------------------------------------------------------------------------------------
# 2 — N incidents × M actors
# --------------------------------------------------------------------------------------


def test_a_single_incident_is_ineligible():
    [gap] = mine(aggregate(_declines((1, "priya"))), THRESHOLDS)

    assert not gap.eligible
    assert IneligibleReason.BELOW_INCIDENT_THRESHOLD in gap.reasons


def test_many_incidents_from_one_actor_are_ineligible():
    """§7.1's case exactly: one compromised identity cannot manufacture a gap by repetition."""
    [gap] = mine(aggregate(_declines(*((n, "mallory") for n in range(1, 9)))), THRESHOLDS)

    assert gap.aggregate.incident_count == 8
    assert gap.aggregate.distinct_actors == 1
    assert gap.reasons == (IneligibleReason.BELOW_ACTOR_THRESHOLD,)


def test_many_actors_in_one_incident_are_ineligible():
    change_a = multi_key_change("evt-a", at=T0 - timedelta(minutes=38), actor="priya")
    change_b = multi_key_change("evt-b", at=T0 - timedelta(minutes=30), actor="dinesh")
    signals = [
        decline_signal(brief_for("INC-1", change_a)),
        decline_signal(brief_for("INC-1", change_b)),
    ]

    [gap] = mine(aggregate(signals), THRESHOLDS)
    assert gap.reasons == (IneligibleReason.BELOW_INCIDENT_THRESHOLD,)


def test_n_incidents_across_m_actors_is_eligible():
    [gap] = mine(aggregate(_declines((1, "priya"), (2, "dinesh"))), THRESHOLDS)

    assert gap.eligible, gap.reasons
    assert gap.aggregate.resource_kind.value == "ConfigMap"


@pytest.mark.parametrize("field", ["min_incidents", "min_distinct_actors"])
def test_neither_threshold_can_be_configured_below_two(field):
    with pytest.raises(ValidationError):
        MinerThresholds(**{field: 1})


def test_the_shipped_thresholds_load_and_hold_the_floor():
    thresholds = load_thresholds()
    assert thresholds.min_incidents >= 2
    assert thresholds.min_distinct_actors >= 2


def test_a_cloudtrail_change_is_never_revert_shaped():
    """§6.1: `lookup_events` returns no prior value, so nothing from CloudTrail is eligible
    however often it recurs."""
    signals = [
        decline_signal(brief_for(f"INC-{n}", cloudtrail_change(f"ct-{n}", at=T0, actor=actor)))
        for n, actor in ((1, "priya"), (2, "dinesh"), (3, "arun"))
    ]
    [gap] = mine(aggregate(signals), THRESHOLDS)

    assert IneligibleReason.NOT_REVERT_SHAPED in gap.reasons


def test_an_unnamed_resource_kind_is_ineligible():
    signals = []
    for number, actor in ((1, "priya"), (2, "dinesh")):
        change = multi_key_change(f"evt-{number}", at=T0, actor=actor, kind="Widgetconfig")
        signals.append(decline_signal(brief_for(f"INC-{number}", change)))

    [gap] = mine(aggregate(signals), THRESHOLDS)
    assert IneligibleReason.UNKNOWN_RESOURCE_KIND in gap.reasons
