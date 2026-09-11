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
    "resolve_executor",
    "validate_params",
]

CONFIG_ROOT = Path(__file__).resolve().parents[3] / "config"
DEFAULT_ACTIONS = CONFIG_ROOT / "actions.yaml"
DEFAULT_THRESHOLDS = CONFIG_ROOT / "thresholds.yaml"

_PY_TYPES: dict[str, type] = {"str": str, "int": int, "float": float, "bool": bool}


class UnknownAction(KeyError):
    """The proposal named an action that is not in the catalog. There is no fallback."""


class ValidationRejected(ValueError):
    """The parameters did not match the action's schema. Raised **before** any client is
    constructed — that ordering is the point, not an implementation detail."""


class ParamSpec(BaseModel):
    """One parameter's declared shape, as written in `actions.yaml`."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: Literal["str", "int", "float", "bool"]
    required: bool = True
    enum: list[Any] | None = None

    @property
    def python_type(self) -> type:
        return _PY_TYPES[self.type]


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
        return catalog

    @property
    def action_ids(self) -> tuple[str, ...]:
        """The proposer's `action_id` enum is drawn from this, so the model cannot name an
        action that does not exist (W22, same pattern as W19b's service enum)."""
        return tuple(sorted(self._actions))

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


def effective_tier(
    action: ActionSpec,
    *,
    estimated_cost_delta_usd: float | None = None,
    resource_count: int | None = None,
    crosses_namespace_boundary: bool = False,
    thresholds: Thresholds | None = None,
) -> Tier:
    """The tier this action runs at, after promotion.

    **There is no path through this function that returns a tier below `action.tier`.** The
    only operator is `max`, and that is deliberate: a demotion rule would let an attacker
    who can influence a resource count lower the approval bar on a mutation.
    """
    thresholds = thresholds if thresholds is not None else default_catalog().thresholds
    promoted = action.tier

    cost_limit = thresholds.estimated_cost_delta_usd
    if (
        cost_limit is not None
        and estimated_cost_delta_usd is not None
        and estimated_cost_delta_usd > cost_limit
    ):
        promoted = Tier.MANAGER_APPROVAL

    count_limit = thresholds.resource_count
    if count_limit is not None and resource_count is not None and resource_count > count_limit:
        promoted = Tier.MANAGER_APPROVAL

    if thresholds.crosses_namespace_boundary and crosses_namespace_boundary:
        promoted = Tier.MANAGER_APPROVAL

    return Tier(max(action.tier.value, promoted.value))
