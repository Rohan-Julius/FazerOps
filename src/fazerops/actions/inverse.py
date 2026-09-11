"""W21 — inverse computation. Ground rule #4, Handoff §7.

> *Every mutating action computes its inverse before executing and refuses to run if it
> cannot.*

This module is the only thing that interprets an `inverse_hint` (plan §3.5 — the field is
opaque everywhere else). It turns a proposed action plus the hint the collector recorded
into a **fully-parameterized** inverse action, or into `None`.

**`None` is a first-class answer and the important one.** The failure this module exists to
prevent is not "the inverse was wrong" — it is an action executing while nobody can say how
to undo it, discovered at the moment someone needs to. `ActionRequest.execute()` refuses to
run when `inverse()` returns `None`, and the refusal is structural: `execute()` calls
`inverse()` itself rather than trusting a caller to have checked.

Two shapes of hint, and the difference is the whole design:

* **`revert_configmap_key` and `restore_db_parameter`** carry a prior value. The inverse is
  the same action aimed at the value that is current *now* — which the hint also records,
  because reading it back at execution time would race the very change being reverted.
* **`helm_rollback`** carries revisions. Handoff §5: rolling back to the currently-deployed
  revision restores exactly what the rollback replaced, so the inverse is free.

`execute()` also evaluates the catalog's declared `preconditions:` before any of this — see
`preconditions.py`, which answers them from collected evidence rather than by calling the
cluster.

Nothing here reads live state and nothing here mutates. A module that needed a cluster to
compute an inverse could not compute one during an outage, which is when it is needed.

**Inversion is relative to the recorded snapshot and does not compose.** A hint holds one
observation — the prior and current values as the collector saw them — so `inverse()` always
answers "restore what was recorded", and applying it twice is a fixed point rather than a
round trip. That is correct for the one thing the product does with it (an approval card
shows one action and its one inverse) and wrong for anything that chains inverses, which
nothing does. `test_inversion_is_relative_to_the_recorded_snapshot_and_does_not_compose`
pins it so the fixed point is not later read as a bug.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from ..models import Tier
from .catalog import ActionSpec, Catalog, default_catalog, validate_params

__all__ = [
    "ActionRequest",
    "InverseUnavailable",
    "inverse",
    "request_from_hint",
]


class InverseUnavailable(RuntimeError):
    """`execute()` was called on an action whose inverse could not be computed.

    Ground rule #4 makes this a refusal rather than a warning: an irreversible mutation
    dressed as a reversible one is worse than no automation, because the operator acted on
    a promise the system could not keep.
    """


class ActionRequest(BaseModel):
    """One catalog action with validated parameters, ready to dry-run or execute.

    Constructed only through `for_action`, which validates against the catalog schema — so
    an `ActionRequest` that exists is one whose parameters have already been checked, and
    there is no path that builds one from an unvalidated dict.
    """

    model_config = ConfigDict(frozen=True)

    action_id: str
    params: dict[str, Any]
    inverse_hint: dict[str, Any] | None = None

    @classmethod
    def for_action(
        cls,
        action_id: str,
        params: dict[str, Any],
        *,
        inverse_hint: dict[str, Any] | None = None,
        catalog: Catalog | None = None,
    ) -> ActionRequest:
        catalog = catalog if catalog is not None else default_catalog()
        spec = catalog.get(action_id)  # raises UnknownAction — there is no fallback
        return cls(
            action_id=action_id,
            params=validate_params(spec, params),
            inverse_hint=inverse_hint,
        )

    def spec(self, catalog: Catalog | None = None) -> ActionSpec:
        return (catalog if catalog is not None else default_catalog()).get(self.action_id)

    def tier(self, catalog: Catalog | None = None) -> Tier:
        return self.spec(catalog).tier

    def inverse(self, catalog: Catalog | None = None) -> ActionRequest | None:
        return inverse(self, catalog=catalog)

    def dry_run(self, *, evidence: Any = None, catalog: Catalog | None = None):
        from .dry_run import render

        return render(self, evidence=evidence, catalog=catalog)

    def execute(
        self,
        credential: Any = None,
        *,
        evidence: Any = None,
        catalog: Catalog | None = None,
    ) -> Any:
        """Run the action, after checking its preconditions and computing its inverse.

        Both guards are evaluated *here*, not asserted by the caller. A caller that forgot
        to check is the case they exist for, so trusting the caller to have checked would
        make them decorative.

        **Order is deliberate: ground rule #4 first, preconditions second.** The two
        overlap — `prior_value_known` and "the inverse is None" are the *same* condition for
        `revert_configmap_key` — so whichever runs first decides which exception a caller
        sees. Ground rule #4 is the named, non-negotiable rule and the one the plan asserts
        by name, so it must not be shadowed by a check that happens to notice the same thing
        a moment earlier. Preconditions then catch everything the inverse cannot: a release
        nobody collected, a revision absent from the recorded history.
        """
        undo = self.inverse(catalog=catalog)
        if undo is None:
            raise InverseUnavailable(
                f"{self.action_id}: refusing to execute — no inverse could be computed "
                f"from the available evidence (ground rule #4). Params: {sorted(self.params)}"
            )

        from .preconditions import check as check_preconditions

        check_preconditions(self, evidence, catalog=catalog)

        from .catalog import resolve_executor

        executor = resolve_executor(self.spec(catalog))
        return executor(self.params, credential=credential, undo=undo)


def request_from_hint(
    hint: dict[str, Any] | None, *, catalog: Catalog | None = None
) -> ActionRequest | None:
    """Build the *forward* action a `ChangeEvent`'s hint describes reverting.

    Returns `None` for a missing or unusable hint rather than raising: an event with no
    recorded prior value is the normal case for CloudTrail (`lookup_events` returns no
    prior value, so ground rule #4 forbids the reversible claim), not an error.
    """
    if not hint or "action_id" not in hint:
        return None

    catalog = catalog if catalog is not None else default_catalog()
    action_id = hint["action_id"]
    if action_id not in catalog:
        return None

    builder = _FORWARD_BUILDERS.get(action_id)
    if builder is None:
        return None

    params = builder(hint)
    if params is None:
        return None

    return ActionRequest.for_action(action_id, params, inverse_hint=hint, catalog=catalog)


def inverse(request: ActionRequest, *, catalog: Catalog | None = None) -> ActionRequest | None:
    """The fully-parameterized action that undoes `request`, or `None`.

    `None` whenever the evidence does not support one: no hint, a hint with no prior value,
    or an action with no inverse builder. Never a partially-parameterized action — an
    inverse missing its target value is indistinguishable at the call site from one that
    has it, and would fail at execution with the original change already applied.
    """
    catalog = catalog if catalog is not None else default_catalog()
    spec = catalog.get(request.action_id)

    builder = _INVERSE_BUILDERS.get(spec.inverse)
    if builder is None:
        return None

    params = builder(request)
    if params is None:
        return None

    try:
        return ActionRequest.for_action(
            spec.inverse, params, inverse_hint=request.inverse_hint, catalog=catalog
        )
    except Exception:
        # A builder that produced something the schema rejects is a bug here, not a reason
        # to execute. Ground rule #4 says refuse, so `None` — and `execute()` then raises
        # with the action id, which is what points at this function.
        return None


# --------------------------------------------------------------------------------------
# Per-action builders. Each returns the params of the *inverse*, or None.
# --------------------------------------------------------------------------------------


def _invert_configmap_key(request: ActionRequest) -> dict[str, Any] | None:
    """Restore the value that is current *now* — which the hint recorded at collection time.

    Reading the live ConfigMap here instead would race the change being reverted, and would
    make the inverse uncomputable during exactly the outage it is needed in.
    """
    hint = request.inverse_hint or {}
    current = hint.get("current_value")
    if current is None:
        return None

    return {
        "namespace": request.params["namespace"],
        "name": request.params["name"],
        "key": request.params["key"],
        "target_value": str(current),
    }


def _invert_helm_rollback(request: ActionRequest) -> dict[str, Any] | None:
    """Handoff §5: the inverse of rolling back to N−1 is rolling back to the revision that
    is deployed right now."""
    hint = request.inverse_hint or {}
    current = hint.get("current_revision")
    if current is None:
        return None

    return {
        "release": request.params["release"],
        "namespace": request.params["namespace"],
        "target_revision": int(current),
    }


def _invert_db_parameter(request: ActionRequest) -> dict[str, Any] | None:
    hint = request.inverse_hint or {}
    current = hint.get("current_value")
    if current is None:
        return None

    params: dict[str, Any] = {
        "parameter_group": request.params["parameter_group"],
        "parameter": request.params["parameter"],
        "target_value": str(current),
    }
    if "apply_method" in request.params:
        params["apply_method"] = request.params["apply_method"]
    return params


_INVERSE_BUILDERS = {
    "revert_configmap_key": _invert_configmap_key,
    "helm_rollback": _invert_helm_rollback,
    "restore_db_parameter": _invert_db_parameter,
}


# --------------------------------------------------------------------------------------
# Forward builders — a hint describes a change; these say what action reverts it.
# --------------------------------------------------------------------------------------


def _forward_configmap_key(hint: dict[str, Any]) -> dict[str, Any] | None:
    prior = hint.get("prior_value")
    if prior is None or not hint.get("namespace") or not hint.get("name") or not hint.get("key"):
        return None
    return {
        "namespace": hint["namespace"],
        "name": hint["name"],
        "key": hint["key"],
        "target_value": str(prior),
    }


def _forward_helm_rollback(hint: dict[str, Any]) -> dict[str, Any] | None:
    target = hint.get("target_revision")
    if target is None or not hint.get("release") or not hint.get("namespace"):
        return None
    return {
        "release": hint["release"],
        "namespace": hint["namespace"],
        "target_revision": int(target),
    }


def _forward_db_parameter(hint: dict[str, Any]) -> dict[str, Any] | None:
    prior = hint.get("prior_value")
    if prior is None or not hint.get("parameter_group") or not hint.get("parameter"):
        return None
    params: dict[str, Any] = {
        "parameter_group": hint["parameter_group"],
        "parameter": hint["parameter"],
        "target_value": str(prior),
    }
    if hint.get("apply_method"):
        params["apply_method"] = hint["apply_method"]
    return params


_FORWARD_BUILDERS = {
    "revert_configmap_key": _forward_configmap_key,
    "helm_rollback": _forward_helm_rollback,
    "restore_db_parameter": _forward_db_parameter,
}
