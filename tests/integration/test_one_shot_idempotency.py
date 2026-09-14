"""W44 — one-shot in-incident execution. Plan §4 Phase G, `docs/catalog_self_extension.md` §4, §7.5.

The plan's two assertions:

* **a regeneration returns the existing candidate** — the same object, with no second model call
  and no second sandbox, including when two regenerations race;
* **two approvals execute once** — through the real gateway and the real generic executor, for a
  human-written writer and for a generated one.

And the closure that makes the second one structural rather than lucky: the gateway keys on
`(incident_id, action_id)`, so the one-shot's id is a pure function of the resource and field it
restores, recomputed by the gateway before a card opens. Two generations for one resource —
across a restart — name one action, and the recorded outcome stops the second.

Plus the boundary §4 draws: the model never names a one-shot, a one-shot is offered only for an
`observed` recipe and only after containment, and its writer exists only inside its own context.
"""

from __future__ import annotations

import asyncio
import functools
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import _sandbox_fakes as fakes  # noqa: E402
from _growth_events import (  # noqa: E402
    BINARY_BEFORE,
    MULTI_BEFORE,
    T0,
    binary_data_change,
    brief_for,
    configmap_change,
    multi_key_change,
)

from fazerops.actions.approval import (  # noqa: E402
    AlreadyDecided,
    ApprovalGateway,
    ApprovalRefused,
    Approver,
    ApproverNotPermitted,
    ApproverRole,
)
from fazerops.actions.catalog import UnknownAction, default_catalog  # noqa: E402
from fazerops.actions.growth.one_shot import OneShotBook, Refusal, one_shot_action_id  # noqa: E402
from fazerops.actions.preconditions import Evidence  # noqa: E402
from fazerops.actions.writers import k8s_configmap, k8s_support  # noqa: E402
from fazerops.actions.writers.registry import default_registry  # noqa: E402
from fazerops.agents import writer_author  # noqa: E402
from fazerops.models import Tier  # noqa: E402

MANAGER = Approver(user_id="U_MGR", role=ApproverRole.MANAGER)
ENGINEER = Approver(user_id="U_IC", role=ApproverRole.ENGINEER)


class FakeCoreV1:
    def __init__(self) -> None:
        self.patches: list[tuple[str, str, dict]] = []

    def patch_namespaced_config_map(self, *, name, namespace, body):
        self.patches.append((namespace, name, body))
        [(field, values)] = body.items()
        attribute = "binary_data" if field == "binaryData" else "data"
        return SimpleNamespace(**{attribute: values}, metadata=SimpleNamespace(resource_version="7"))


@pytest.fixture
def cluster(monkeypatch):
    fake = FakeCoreV1()
    monkeypatch.setattr(k8s_configmap, "_core_v1", lambda credential=None: fake)
    monkeypatch.setattr(k8s_support, "api_for", lambda kind, credential=None: fake)
    return fake


@pytest.fixture
def author(monkeypatch):
    """The stub writer author, counted. Anything that re-authors on a regeneration fails here."""
    calls: list[dict] = []

    async def counted(contract, **kwargs):
        calls.append(contract)
        return writer_author.AuthoredWriter(**writer_author._stub(contract), model="stub")

    counted.calls = calls
    return counted


def _book(author, sandbox=None, **kwargs) -> OneShotBook:
    return OneShotBook(author=author, sandbox=sandbox or fakes.factory(), **kwargs)


def _evidence(brief) -> Evidence:
    return Evidence(resource_keys=frozenset({brief.top.event.resource.blast_radius_key()}), complete=True)


MULTI = brief_for("INC-1", multi_key_change("evt-multi", at=T0))
BINARY = brief_for("INC-1", binary_data_change("evt-binary", at=T0))


# --------------------------------------------------------------------------------------
# A regeneration returns the existing candidate
# --------------------------------------------------------------------------------------


async def test_a_regeneration_returns_the_existing_candidate(author):
    make = fakes.factory()
    book = _book(author, make)

    first = await book.offer(BINARY)
    again = await book.offer(BINARY)

    assert first.offered, first
    assert again is first
    assert len(author.calls) == 1, "no second model call"
    assert len(make.built) == 1, "no second sandbox"


async def test_racing_regenerations_build_one_candidate(author):
    make = fakes.factory()
    book = _book(author, make)

    outcomes = await asyncio.gather(*(book.offer(BINARY) for _ in range(5)))

    assert all(outcome is outcomes[0] for outcome in outcomes)
    assert len(author.calls) == 1 and len(make.built) == 1


async def test_a_refusal_is_remembered_as_well(author, monkeypatch):
    async def rejected(contract, **kwargs):
        author.calls.append(contract)
        return writer_author.AuthoredWriter(read_source="def read(params, *, client):\n    import os\n", write_source="x", model="m")

    book = _book(rejected)
    first = await book.offer(BINARY)
    again = await book.offer(BINARY)

    assert first.refusal is Refusal.WRITER_REJECTED
    assert again is first and len(author.calls) == 1


async def test_the_key_is_the_incident_the_resource_and_the_field(author):
    book = _book(author)
    other_resource = brief_for("INC-1", binary_data_change("evt-2", at=T0, name="billing-api-fonts"))
    other_incident = brief_for("INC-2", binary_data_change("evt-binary", at=T0))

    keys = {(await book.offer(brief)).key for brief in (BINARY, other_resource, other_incident)}
    assert len(keys) == 3


# --------------------------------------------------------------------------------------
# Two approvals execute once
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("brief, authored_by", [(MULTI, "human"), (BINARY, "agent")], ids=["human-writer", "generated-writer"])
async def test_two_approvals_execute_once(author, cluster, brief, authored_by):
    outcome = await _book(author).offer(brief)
    one_shot = outcome.one_shot
    assert one_shot.authored_by == authored_by

    gateway = ApprovalGateway()
    gateway.register_one_shot(one_shot, evidence=_evidence(brief))
    first = gateway.decide(incident_id="INC-1", action_id=one_shot.action_id, approver=MANAGER, kind="approve")
    second = gateway.decide(incident_id="INC-1", action_id=one_shot.action_id, approver=MANAGER, kind="approve")

    assert first.executed, first.error
    assert second.replay and second.executed
    assert len(cluster.patches) == 1
    [(namespace, name, body)] = cluster.patches
    field = "binaryData" if authored_by == "agent" else "data"
    assert body == {field: BINARY_BEFORE if authored_by == "agent" else MULTI_BEFORE}


async def test_two_generations_across_a_restart_name_one_action_and_execute_once(author, cluster):
    gateway = ApprovalGateway()
    first = (await _book(author).offer(BINARY)).one_shot
    gateway.register_one_shot(first, evidence=_evidence(BINARY))
    gateway.decide(incident_id="INC-1", action_id=first.action_id, approver=MANAGER, kind="approve")

    regenerated = (await _book(author).offer(BINARY)).one_shot  # a new book: the process restarted
    assert regenerated is not first and regenerated.action_id == first.action_id

    with pytest.raises(AlreadyDecided):
        gateway.register_one_shot(regenerated, evidence=_evidence(BINARY))
    assert len(cluster.patches) == 1


async def test_a_one_shot_whose_id_is_not_its_resource_and_field_is_refused(author):
    one_shot = (await _book(author).offer(BINARY)).one_shot
    minted = one_shot.model_copy(
        update={"request": one_shot.request.model_copy(update={"action_id": "one_shot:generation-7"})}
    )

    with pytest.raises(ApprovalRefused, match="keyed on"):
        ApprovalGateway().register_one_shot(minted)


def test_the_id_is_a_pure_function_of_resource_and_field():
    assert one_shot_action_id("k8s:billing/configmap/a", "data") == one_shot_action_id("k8s:billing/configmap/a", "data")
    assert one_shot_action_id("k8s:billing/configmap/a", "data") != one_shot_action_id("k8s:billing/configmap/a", "binaryData")


# --------------------------------------------------------------------------------------
# What reaches a human, and what never does
# --------------------------------------------------------------------------------------


async def test_a_one_shot_needs_a_manager_and_says_what_it_is(author):
    from fazerops.slack.handlers import approval_card_for

    one_shot = (await _book(author).offer(BINARY)).one_shot
    gateway = ApprovalGateway()
    pending = gateway.register_one_shot(one_shot, evidence=_evidence(BINARY))

    assert pending.tier is Tier.MANAGER_APPROVAL
    with pytest.raises(ApproverNotPermitted):
        gateway.decide(incident_id="INC-1", action_id=one_shot.action_id, approver=ENGINEER, kind="approve")

    card = json.dumps(approval_card_for(pending))
    assert "One-shot" in card and "generated writer" in card
    assert "iVBORw0KGgo" not in card or "favicon.ico" in card  # values render only as the dry run renders them


async def test_the_model_never_names_a_one_shot(author):
    from fazerops.agents.proposer import ACTION_IDS

    one_shot = (await _book(author).offer(BINARY)).one_shot

    assert one_shot.action_id not in ACTION_IDS
    assert one_shot.action_id not in default_catalog().action_ids
    with pytest.raises(UnknownAction):
        ApprovalGateway().register("INC-1", one_shot.request)


async def test_the_generated_writer_exists_only_inside_its_one_shot(author, cluster):
    one_shot = (await _book(author).offer(BINARY)).one_shot
    gateway = ApprovalGateway()
    gateway.register_one_shot(one_shot, evidence=_evidence(BINARY))
    gateway.decide(incident_id="INC-1", action_id=one_shot.action_id, approver=MANAGER, kind="approve")

    assert one_shot.writer.id not in default_registry()
    with one_shot.context():
        assert default_registry().get(one_shot.writer.id) is one_shot.writer


async def test_a_catalog_revertible_change_is_not_a_gap(author):
    single = brief_for("INC-1", configmap_change("evt-1", at=T0, before={"pool.max": "100"}, after={"pool.max": "20"}))
    make = fakes.factory()
    outcome = await _book(author, make).offer(single)

    assert outcome.refusal is Refusal.CATALOG_CAN_REVERT
    assert author.calls == [] and make.built == []


async def test_a_resource_type_without_an_observed_recipe_is_never_offered(author):
    deployment = brief_for(
        "INC-1", configmap_change("evt-d", at=T0, kind="Deployment", before={"replicas": "3"}, after={"replicas": "1"})
    )
    outcome = await _book(author, fakes.never()).offer(deployment)

    assert outcome.refusal is Refusal.NO_OBSERVED_RECIPE
    assert author.calls == []


async def test_an_uncontained_writer_never_reaches_a_card(author):
    outcome = await _book(author, fakes.factory(complete=False)).offer(BINARY)

    assert outcome.refusal is Refusal.NOT_CONTAINED and outcome.one_shot is None
    assert outcome.containment is not None and not outcome.containment.contained


async def test_a_containment_verdict_is_rechecked_by_the_gateway(author):
    from fazerops.actions.growth.sandbox import Verdict

    one_shot = (await _book(author).offer(BINARY)).one_shot
    uncontained = one_shot.model_copy(
        update={"containment": one_shot.containment.model_copy(update={"verdict": Verdict.MUTATED_OUTSIDE_DECLARED_REF})}
    )
    with pytest.raises(ApprovalRefused, match="not contained"):
        ApprovalGateway().register_one_shot(uncontained)


async def test_the_proposer_node_offers_a_one_shot_after_a_decline_and_only_then(author, monkeypatch):
    import fazerops.agents.graph as graph_module
    import fazerops.agents.proposer as proposer_module
    from fazerops.agents.graph import investigate_via_graph
    from fazerops.ingest.alerts import normalize_alert

    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json"
    monkeypatch.setattr(graph_module, "_brief_from", lambda state, narrative: BINARY)
    book = _book(author)

    async def declines(*args, **kwargs):
        return None

    monkeypatch.setattr(proposer_module, "propose", declines)
    await investigate_via_graph(
        normalize_alert(json.loads(fixture.read_text(encoding="utf-8"))),
        proposer_node=functools.partial(proposer_module.proposer_node, one_shots=book),
    )
    [outcome] = [book.get(key) for key in book._outcomes]
    assert outcome.offered

    async def proposes(*args, **kwargs):
        return SimpleNamespace(action_id="revert_configmap_key")

    quiet = _book(author)
    monkeypatch.setattr(proposer_module, "propose", proposes)
    await investigate_via_graph(
        normalize_alert(json.loads(fixture.read_text(encoding="utf-8"))),
        proposer_node=functools.partial(proposer_module.proposer_node, one_shots=quiet),
    )
    assert quiet._outcomes == {}, "a proposal is not a decline; nothing is offered"
