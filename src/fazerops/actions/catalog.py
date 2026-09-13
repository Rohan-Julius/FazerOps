"""W20 — the action catalog. Handoff §7.

**This module is the structural barrier between model output and your cluster** (ground
rule #1). The model emits an `action_id` and a parameter dict. Everything else — the
executor, the tier, the dry-run renderer, the inverse — comes from `config/actions.yaml`,
which the model has never seen and cannot write to.

Three properties hold by construction rather than by care:

1. **An unknown `action_id` is refused.** There is no default action and no fallback to a
   generic executor.
2. **Parameters are validated before any client is constructed.** A proposal with a missing
   `namespace` fails here, not inside a kubectl call three frames later with a half-built
   client and an assumed default namespace.
3. **Tier is declared, never inferred.** `thresholds.yaml` may only promote; `effective_tier`
   has no code path that returns a lower tier than the catalog declares.

The catalog is loaded once and cached. An entry whose `executor` does not resolve raises at
load time — a declared-but-unimplemented action is a live path to an `ImportError` mid-demo,
which is why "declare three, implement one" was never an option.
"""

from __future__ import annotations

import functools
import importlib
from pathlib import Path
from typing import Any, Callable, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..models import Tier

__all__ = [
    "ActionSpec",
    "Catalog",
    "ParamSpec",
    "UnknownAction",
    "ValidationRejected",
    "default_catalog",
    "effective_tier",
    "promote",
    "resolve_executor",
    "validate_params",
]

CONFIG_ROOT = Path(__file__).resolve().parents[3] / "config"
DEFAULT_ACTIONS = CONFIG_ROOT / "actions.yaml"
DEFAULT_THRESHOLDS = CONFIG_ROOT / "thresholds.yaml"

_PY_TYPES: dict[str, type] = {"str": str, "int": int, "float": float, "bool": bool, "list[str]": list}

# What every writer-backed entry runs through (W41). Fixed, not declarable: the executor, the
# dry run and the inverse are the generic layer's, and a writer never supplies its own.
WRITER_EXECUTOR = "fazerops.actions.executors.writer:execute"
WRITER_DRY_RUN = "writer_diff"
WRITER_PRECONDITIONS = ("writer_resource_observed", "writer_prior_value_known")


class UnknownAction(KeyError):
    """The proposal named an action that is not in the catalog. There is no fallback."""


class ValidationRejected(ValueError):
    """The parameters did not match the action's schema. Raised **before** any client is
    constructed — that ordering is the point, not an implementation detail."""


class ParamSpec(BaseModel):
    """One parameter's declared shape, as written in `actions.yaml`."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # `list[str]` exists for W42's rung-1 widening (a key → the keys a change touched). No
    # shipped action declares one; the type is here so a reviewed widening can.
    type: Literal["str", "int", "float", "bool", "list[str]"]
    required: bool = True
    enum: list[Any] | None = None

    @property
    def python_type(self) -> type:
        return _PY_TYPES[self.type]

    @property
    def annotation(self) -> Any:
        """The type a response schema should declare. A bare `list` would emit an array of
        anything, and a provider schema with untyped items admits values we then reject."""
        return list[str] if self.type == "list[str]" else self.python_type


class ActionSpec(BaseModel):
    """One catalog entry. Every field the plan's schema test demands is required here, so
    an incomplete entry fails at load rather than at execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    tier: Tier
    description: str
    params: dict[str, ParamSpec]
    preconditions: list[str] = Field(default_factory=list)
    dry_run: str
    inverse: str
    executor: str = Field(description="`module.path:callable`, resolved at load time")
    requires_approval_from: Literal["engineer", "manager"] | None = None
    writer: str | None = Field(
        default=None,
        description="`resource_type:field_path` of a registered writer (W41). An entry with a "
        "writer is declarative: its executor, dry run and inverse are the generic layer's.",
    )
    provisional: bool = Field(
        default=False,
        description="A merged generated action (W45). A separate axis from `tier`: it never "
        "changes the declared tier, it only adds a manager approval on top of it.",
    )
    retired: bool = Field(
        default=False,
        description="A tombstone (W45, §7.6). Still resolvable by `Catalog.get` for the incident "
        "records that cite it; never proposable and never approvable.",
    )

    @model_validator(mode="before")
    @classmethod
    def _writer_backed_entries_use_the_generic_layer(cls, data: Any) -> Any:
        """Fill a writer-backed entry's executor, dry run and inverse — and refuse any other.

        This is W41's "a writer cannot supply its own inverse or dry-run renderer" at the
        catalog: an entry that names a writer *and* its own renderer is refused at load, so the
        generated half of an action can never also be the half that describes it to a human.
        """
        if not isinstance(data, dict) or not data.get("writer"):
            return data

        action_id = data.get("id")
        fixed = {"executor": WRITER_EXECUTOR, "dry_run": WRITER_DRY_RUN, "inverse": action_id}
        for field, value in fixed.items():
            given = data.get(field)
            if given is not None and given != value:
                raise ValueError(
                    f"{action_id}: a writer-backed action cannot declare its own {field} "
                    f"({given!r}) — the inverse, the dry run and the credential gate belong to "
                    "the generic layer, never to the writer (W41)"
                )

        declared = list(data.get("preconditions") or [])
        preconditions = declared + [name for name in WRITER_PRECONDITIONS if name not in declared]
        return {**data, **fixed, "preconditions": preconditions}

    @model_validator(mode="after")
    def _tier_two_requires_a_manager(self) -> ActionSpec:
        """Handoff §7 pairs Tier 2 with `requires_approval_from: manager`. Keeping the two
        in step here means W26b's routing cannot be handed a Tier 2 action with nobody to
        route it to — a Tier 2 that silently accepts an IC approval is worse than no tier
        system at all."""
        if self.tier is Tier.MANAGER_APPROVAL and self.requires_approval_from != "manager":
            raise ValueError(
                f"{self.id}: tier 2 must declare `requires_approval_from: manager`"
            )
        if self.tier is not Tier.MANAGER_APPROVAL and self.requires_approval_from == "manager":
            raise ValueError(
                f"{self.id}: `requires_approval_from: manager` without tier 2 would route "
                "an escalation the tier system does not know about"
            )
        return self

    @property
    def required_params(self) -> tuple[str, ...]:
        return tuple(sorted(n for n, spec in self.params.items() if spec.required))


class Thresholds(BaseModel):
    """`thresholds.yaml`, promotion-only by construction — there is no field here that
    could express a demotion, so a demotion cannot be configured by mistake."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    estimated_cost_delta_usd: float | None = None
    resource_count: int | None = None
    crosses_namespace_boundary: bool = False


class Catalog:
    """Loaded `actions.yaml`, with the lookups the automation layer needs."""

    def __init__(self, actions: list[ActionSpec], thresholds: Thresholds) -> None:
        self._actions = {action.id: action for action in actions}
        self.thresholds = thresholds
        if len(self._actions) != len(actions):
            raise ValueError("duplicate action id in the catalog")

    @classmethod
    def load(
        cls, actions_path: Path | str | None = None, thresholds_path: Path | str | None = None
    ) -> Catalog:
        raw = yaml.safe_load(Path(actions_path or DEFAULT_ACTIONS).read_text(encoding="utf-8"))
        actions = [ActionSpec.model_validate(entry) for entry in (raw or {}).get("actions") or []]

        raw_thresholds = yaml.safe_load(
            Path(thresholds_path or DEFAULT_THRESHOLDS).read_text(encoding="utf-8")
        )
        thresholds = Thresholds.model_validate((raw_thresholds or {}).get("promote_to_tier_2") or {})

        catalog = cls(actions, thresholds)
        # Resolve every executor at load time. Deferring it to execution would move the
        # failure from "the catalog is wrong" at startup to an ImportError mid-demo, with a
        # human already waiting on an approval card.
        for action in actions:
            resolve_executor(action)
            if action.writer is not None:
                from .writers.registry import default_registry

                default_registry().get(action.writer)  # UnknownWriter, at load
        return catalog

    @property
    def action_ids(self) -> tuple[str, ...]:
        """The proposer's `action_id` enum is drawn from this, so the model cannot name an
        action that does not exist (W22, same pattern as W19b's service enum).

        **Retired actions are excluded, and only here** (W45). A tombstone must stay resolvable
        through `get` — W28's record cites action ids — but a model must not be able to name it.
        """
        return tuple(sorted(a.id for a in self._actions.values() if not a.retired))

    def __contains__(self, action_id: object) -> bool:
        return action_id in self._actions

    def __iter__(self):
        return iter(self._actions.values())

    def __len__(self) -> int:
        return len(self._actions)

    def get(self, action_id: str) -> ActionSpec:
        try:
            return self._actions[action_id]
        except KeyError:
            raise UnknownAction(
                f"{action_id!r} is not in the action catalog; known actions: "
                f"{', '.join(self.action_ids)}"
            ) from None


@functools.lru_cache(maxsize=1)
def default_catalog() -> Catalog:
    return Catalog.load()


def resolve_executor(action: ActionSpec) -> Callable[..., Any]:
    """`module.path:callable` → the callable.

    Split on `:` rather than on the last dot, because `a.b.c` is ambiguous between a module
    attribute and a submodule and the ambiguity resolves differently depending on what has
    already been imported. Handoff §7 writes the paths with a colon; this honours that
    rather than being clever about it.
    """
    module_path, _, attribute = action.executor.partition(":")
    if not module_path or not attribute:
        raise ValueError(
            f"{action.id}: executor {action.executor!r} must be `module.path:callable`"
        )

    module = importlib.import_module(module_path)
    try:
        target = getattr(module, attribute)
    except AttributeError:
        raise ValueError(
            f"{action.id}: {module_path} has no attribute {attribute!r}"
        ) from None

    if not callable(target):
        raise ValueError(f"{action.id}: {action.executor} is not callable")
    return target


def validate_params(action: ActionSpec, params: dict[str, Any]) -> dict[str, Any]:
    """Check a proposal's parameters against the declared schema.

    Called **before anything constructs a client** — that is the ordering the plan's test
    asserts, and it is what keeps a malformed proposal from reaching a half-built kubectl
    call that quietly assumes the `default` namespace.

    Returns the validated parameters rather than `None` so a caller cannot accidentally use
    the unvalidated dict it passed in.
    """
    unknown = sorted(set(params) - set(action.params))
    if unknown:
        raise ValidationRejected(
            f"{action.id}: unknown parameter(s) {', '.join(unknown)}; "
            f"accepted: {', '.join(sorted(action.params))}"
        )

    missing = sorted(name for name in action.required_params if params.get(name) is None)
    if missing:
        raise ValidationRejected(f"{action.id}: missing required parameter(s) {', '.join(missing)}")

    validated: dict[str, Any] = {}
    for name, value in params.items():
        spec = action.params[name]
        if value is None:
            continue

        if spec.type == "list[str]":
            # Non-empty and free of duplicates: an empty key list is an action that restores
            # nothing while claiming to have run, and a duplicate is two writes to one key.
            if not isinstance(value, list) or not value:
                raise ValidationRejected(f"{action.id}.{name}: expected a non-empty list of strings")
            if not all(isinstance(item, str) and item for item in value):
                raise ValidationRejected(f"{action.id}.{name}: every item must be a non-empty string")
            if len(set(value)) != len(value):
                raise ValidationRejected(f"{action.id}.{name}: duplicate items")
            validated[name] = list(value)
            continue

        # `bool` is a subclass of `int` in Python, so an unguarded isinstance check accepts
        # `True` for an int parameter — and `target_revision=True` resolves to revision 1.
        if spec.python_type is int and isinstance(value, bool):
            raise ValidationRejected(f"{action.id}.{name}: expected int, got bool")
        if not isinstance(value, spec.python_type):
            raise ValidationRejected(
                f"{action.id}.{name}: expected {spec.type}, got {type(value).__name__}"
            )
        if spec.enum is not None and value not in spec.enum:
            raise ValidationRejected(
                f"{action.id}.{name}: {value!r} is not one of {spec.enum}"
            )
        validated[name] = value

    return validated


def promote(
    action: ActionSpec,
    *,
    estimated_cost_delta_usd: float | None = None,
    resource_count: int | None = None,
    crosses_namespace_boundary: bool = False,
    thresholds: Thresholds | None = None,
) -> tuple[Tier, str | None]:
    """The tier this action runs at after promotion, and *why* it was promoted.

    The tier and the reason come from one traversal of the rules because W26b renders the
    reason on the approval card next to the tier. Computing them separately would let a
    card state Tier 2 with an explanation drawn from a rule that did not actually fire —
    and the explanation is the only part of an escalation a human can check.

    **There is no path through this function that returns a tier below `action.tier`.** The
    only operator is `max`, and that is deliberate: a demotion rule would let an attacker
    who can influence a resource count lower the approval bar on a mutation.
    """
    thresholds = thresholds if thresholds is not None else default_catalog().thresholds
    reasons: list[str] = []

    cost_limit = thresholds.estimated_cost_delta_usd
    if (
        cost_limit is not None
        and estimated_cost_delta_usd is not None
        and estimated_cost_delta_usd > cost_limit
    ):
        reasons.append(
            f"estimated cost delta ${estimated_cost_delta_usd:,.2f} exceeds the "
            f"${cost_limit:,.2f} threshold"
        )

    count_limit = thresholds.resource_count
    if count_limit is not None and resource_count is not None and resource_count > count_limit:
        reasons.append(
            f"touches {resource_count} resources, above the {count_limit} threshold"
        )

    if thresholds.crosses_namespace_boundary and crosses_namespace_boundary:
        reasons.append("the blast radius crosses a namespace boundary")

    promoted = Tier.MANAGER_APPROVAL if reasons else action.tier
    tier = Tier(max(action.tier.value, promoted.value))

    # A reason is reported only when a rule actually *raised* the tier. An action already
    # declared Tier 2 is not an escalation, and labelling it as one on the card would teach
    # an operator to read "escalated" as decoration.
    if tier is action.tier or not reasons:
        return tier, None
    return tier, "; ".join(reasons)


def effective_tier(
    action: ActionSpec,
    *,
    estimated_cost_delta_usd: float | None = None,
    resource_count: int | None = None,
    crosses_namespace_boundary: bool = False,
    thresholds: Thresholds | None = None,
) -> Tier:
    """The tier this action runs at, after promotion. See `promote` for the reason."""
    tier, _ = promote(
        action,
        estimated_cost_delta_usd=estimated_cost_delta_usd,
        resource_count=resource_count,
        crosses_namespace_boundary=crosses_namespace_boundary,
        thresholds=thresholds,
    )
    return tier
