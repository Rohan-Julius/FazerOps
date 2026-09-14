"""W44 — one-shot in-incident execution. `docs/catalog_self_extension.md` §4, §6.1, §7.5.

The catalog grows through PRs, which take days. This is the other timescale: a gap met **during an
incident**, closed for that incident only, and never added to the catalog.

**The model never names the action, here least of all** (§4). The path is triggered by the
proposer's existing `"none"`, and everything after that is Python:

1. the ranked #1 change — ranked in code — is read off the brief;
2. if the catalog can revert it, the decline was about something else and nothing happens;
3. otherwise the writer registry is asked for a writer; a human-written one is used if it exists,
   and a writer is authored (W42 rung 3's gates) only if a contract exists for the change's map;
4. the writer is run against a sandbox and must be contained (W43);
5. the result goes **to the human** as an approval card, never back to the proposer.

**Only `observed` recipes** (§6.1), so in practice Kubernetes. A CloudTrail change is `delayed`
and gets the PR path, never a one-shot — the agent loses that incident, and says so.

**Keyed `(incident_id, resource_ref, field_path)`** (§7.5). The gateway keys on
`(incident_id, action_id)`, and an id minted per generation would not collide: a double approval
would execute twice. So the id is a pure function of the resource and field, the gateway
recomputes it from the request before accepting a one-shot, and `OneShotBook` holds one outcome
per triple — a regeneration returns it, refusal included, with no second model call or sandbox.

**What a human is approving.** A writer-backed action over human-written executor, inverse, dry
run, preconditions and credential gate. Its tier is fixed here, by a person, at manager approval:
nothing about a one-shot has been reviewed in a PR, so it takes the most senior approval every
time, and nothing generated chooses otherwise. Generated code runs in its own interpreter, pinned
to the one resource its parameters name (`authoring.run_generated_writer`).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict

from ...models import Brief, NormalizedAction, Tier
from .sandbox import ContainmentReport, RecipeClass, generated_subject, human_subject, recipe_for, resource_type_of, verify_containment
from .signals import FieldPath, field_path_of, prior_value_recorded

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..catalog import ActionSpec, Catalog
    from ..inverse import ActionRequest
    from ..writers.registry import WriterRegistry

__all__ = [
    "ONE_SHOT_TIER",
    "OneShot",
    "OneShotBook",
    "OneShotKey",
    "OneShotOutcome",
    "Refusal",
    "one_shot_action_id",
]

logger = logging.getLogger(__name__)

# Declared by a person, here. A one-shot is unreviewed by construction, so it always takes the
# manager path; `promote` can only keep it there.
ONE_SHOT_TIER = Tier.MANAGER_APPROVAL


def one_shot_action_id(resource_key: str, field_path: str) -> str:
    """A pure function of what is restored, so two generations for one resource cannot differ."""
    return f"one_shot:{field_path}:{resource_key}"


class OneShotKey(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: str
    resource_key: str
    field_path: FieldPath

    @property
    def action_id(self) -> str:
        return one_shot_action_id(self.resource_key, self.field_path.value)


class Refusal(str, Enum):
    NO_TOP_CANDIDATE = "no_top_candidate"
    CATALOG_CAN_REVERT = "catalog_can_revert"
    NOT_REVERT_SHAPED = "not_revert_shaped"
    NO_OBSERVED_RECIPE = "no_observed_recipe"
    NO_WRITER_CONTRACT = "no_writer_contract"
    WRITER_REJECTED = "writer_rejected"
    NOT_CONTAINED = "not_contained"


class OneShot(BaseModel):
    """A contained, writer-backed action for one resource in one incident. Not in the catalog."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    key: OneShotKey
    event_id: str
    spec: Any  # ActionSpec
    request: Any  # ActionRequest
    writer: Any  # WriterSpec — never registered process-wide
    containment: ContainmentReport
    authored_by_model: str | None = None

    @property
    def action_id(self) -> str:
        return self.spec.id

    @property
    def authored_by(self) -> str:
        return self.writer.authored_by

    def catalog(self, base: Catalog) -> Catalog:
        from ..catalog import Catalog

        return Catalog([*(a for a in base if a.id != self.spec.id), self.spec], base.thresholds)

    @contextmanager
    def context(self) -> Iterator[None]:
        """The writer resolvable for the length of a block — a dry run, an execution — and
        nowhere else, so a one-shot's writer never becomes one a catalog action could name."""
        from ..writers.registry import WriterRegistry, default_registry, registry_override

        base = default_registry()
        with registry_override(WriterRegistry([*(w for w in base if w.id != self.writer.id), self.writer])):
            yield


class OneShotOutcome(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    key: OneShotKey | None
    one_shot: OneShot | None = None
    refusal: Refusal | None = None
    detail: str | None = None
    containment: ContainmentReport | None = None

    @property
    def offered(self) -> bool:
        return self.one_shot is not None


Author = Callable[..., Any]


class OneShotBook:
    """One outcome per `(incident, resource, field)`, for the life of the process.

    In memory for the gateway's reason (`ApprovalGateway`): a restart forgets open cards, and a
    card whose pending approval is gone refuses. A regenerated one-shot after a restart names the
    same action id, so an outcome the gateway already recorded still stops a second execution.
    """

    def __init__(
        self,
        *,
        catalog: Catalog | None = None,
        registry: WriterRegistry | None = None,
        author: Author | None = None,
        sandbox: Callable[[], Any] | None = None,
        meter: Any | None = None,
        cassette_directory: Any | None = None,
    ) -> None:
        self._catalog = catalog
        self._registry = registry
        self._author = author
        self._sandbox = sandbox
        self._meter = meter
        self._cassette_directory = cassette_directory
        self._outcomes: dict[OneShotKey, OneShotOutcome] = {}
        self._locks: dict[OneShotKey, asyncio.Lock] = {}

    def get(self, key: OneShotKey) -> OneShotOutcome | None:
        return self._outcomes.get(key)

    async def offer(self, brief: Brief, *, meter: Any | None = None) -> OneShotOutcome:
        """§4 steps 2–5 for a brief whose proposal was `"none"`. The caller establishes that.

        `meter` is the offering investigation's own. A `TokenMeter` is one per run with per-run caps,
        so the book cannot hold one for the life of the server; without it, the writer authored
        here was the only model call on the server path missing from the token ledger (W31, 14 Sep).
        """
        from ..catalog import default_catalog
        from ..writers.registry import request_for_event

        catalog = self._catalog if self._catalog is not None else default_catalog()
        top = brief.top
        if top is None:
            return OneShotOutcome(key=None, refusal=Refusal.NO_TOP_CANDIDATE)

        event = top.event
        key = OneShotKey(
            incident_id=brief.incident_id,
            resource_key=event.resource.blast_radius_key(),
            field_path=field_path_of(event),
        )
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self._outcomes:
                return self._outcomes[key]
            if request_for_event(event, catalog) is not None:
                outcome = OneShotOutcome(key=key, refusal=Refusal.CATALOG_CAN_REVERT)
            else:
                outcome = await self._build(brief, key, catalog, meter=meter if meter is not None else self._meter)
            self._outcomes[key] = outcome
            return outcome

    async def _build(self, brief: Brief, key: OneShotKey, catalog: Catalog, *, meter: Any | None = None) -> OneShotOutcome:
        from ..catalog import ActionSpec, Catalog, UnknownAction, ValidationRejected
        from ..inverse import ActionRequest
        from ..writers.k8s_support import has_contract, writer_contract
        from ..writers.registry import WriterRegistry, default_registry, hint_for, registry_override
        from .authoring import accept_authored, generated_writer_spec

        event = brief.top.event  # type: ignore[union-attr]

        def refuse(refusal: Refusal, detail: str | None = None, containment: ContainmentReport | None = None) -> OneShotOutcome:
            return OneShotOutcome(key=key, refusal=refusal, detail=detail, containment=containment)

        if event.action is not NormalizedAction.UPDATE or not prior_value_recorded(event):
            return refuse(Refusal.NOT_REVERT_SHAPED, "a one-shot restores a recorded prior value of an update")

        recipe = recipe_for(resource_type_of(event))
        if recipe.recipe_class is not RecipeClass.OBSERVED:
            return refuse(Refusal.NO_OBSERVED_RECIPE, f"{recipe.recipe_class.value}: {recipe.why}")

        kind, field = event.resource.kind, key.field_path.value
        registry = self._registry if self._registry is not None else default_registry()
        writer = next(
            (w for w in registry if w.source == event.source and w.kind == kind and w.field_path == field), None
        )
        authored_by_model = None

        if writer is not None:
            subject = human_subject(writer)
        elif has_contract(kind, field):
            author = self._author
            if author is None:
                from ...agents.writer_author import author_writer as author
            authored = await author(
                writer_contract(kind, field), meter=meter, cassette_directory=self._cassette_directory
            )
            problems = accept_authored(kind, field, authored.read_source, authored.write_source)
            if problems:
                return refuse(Refusal.WRITER_REJECTED, "; ".join(problems)[:500])
            writer = generated_writer_spec(kind, field, authored.read_source, authored.write_source)
            subject = generated_subject(kind, field, authored.read_source, authored.write_source)
            authored_by_model = authored.model
        else:
            return refuse(Refusal.NO_WRITER_CONTRACT, f"no writer and no writer contract for {kind} {field}")

        spec = ActionSpec.model_validate(
            {
                "id": key.action_id,
                "tier": int(ONE_SHOT_TIER),
                "requires_approval_from": "manager",
                "description": f"One-shot: restore the recorded {field} of a {kind}, for this incident only",
                "writer": writer.id,
                "params": {name: {"type": "str", "required": True} for name in writer.ref_params},
            }
        )
        evaluation = Catalog([*(a for a in catalog if a.id != spec.id), spec], catalog.thresholds)

        with registry_override(WriterRegistry([*(w for w in registry if w.id != writer.id), writer])):
            hint = hint_for(event, spec)
            request: ActionRequest | None = None
            if hint is not None:
                try:
                    request = ActionRequest.for_action(spec.id, hint["ref"], inverse_hint=hint, catalog=evaluation)
                except (UnknownAction, ValidationRejected):
                    request = None
            if request is None or request.inverse(catalog=evaluation) is None:
                return refuse(Refusal.NOT_REVERT_SHAPED, "no inverse can be computed from the recorded values")

        report = await asyncio.to_thread(
            verify_containment,
            subject,
            declared=writer.resource(hint["ref"]),
            radius=brief.radius,
            prior=hint["prior"],
            current=hint["current"],
            sandbox=self._sandbox,
        )
        if not report.contained:
            return refuse(Refusal.NOT_CONTAINED, report.detail, containment=report)

        return OneShotOutcome(
            key=key,
            containment=report,
            one_shot=OneShot(
                key=key,
                event_id=event.id,
                spec=spec,
                request=request,
                writer=writer,
                containment=report,
                authored_by_model=authored_by_model,
            ),
        )


def authored_label(one_shot: OneShot) -> Literal["human-written", "generated"]:
    return "human-written" if one_shot.authored_by == "human" else "generated"
