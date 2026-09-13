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
from .catalog import ActionSpec, Catalog, ValidationRejected, default_catalog, validate_params

__all__ = [
    "ActionRequest",
    "InverseUnavailable",
    "inverse",
    "recorded_keys",
    "request_from_hint",
    "writes",
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

        spec = self.spec(catalog)
        executor = resolve_executor(spec)
        if spec.writer is not None:
            # A writer-backed action's target is the recorded prior value, carried on the hint
            # rather than in its parameters, so its executor takes the whole request.
            return executor(self, credential=credential, undo=undo, catalog=catalog)
        import inspect

        if "recorded" in inspect.signature(executor).parameters:
            # The same reason, for an executor whose widened form restores recorded values.
            return executor(
                self.params, credential=credential, undo=undo, recorded=self.inverse_hint
            )
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

    if catalog.get(action_id).writer is not None:
        # A writer-backed hint names its resource directly (W41). The recorded values are
        # checked against those parameters when the inverse is built, not here.
        params = hint.get("ref") if isinstance(hint.get("ref"), dict) else None
    else:
        builder = _FORWARD_BUILDERS.get(action_id)
        params = builder(hint) if builder is not None else None
    if params is None:
        return None

    try:
        return ActionRequest.for_action(action_id, params, inverse_hint=hint, catalog=catalog)
    except ValidationRejected:
        # A hint the catalog's schema cannot accept is an unusable hint, not an error. The
        # audit collector records multi-key edits as `keys` hints whether or not a widened
        # `revert_configmap_key` has been merged (W42 rung 1); until it has, this is None.
        return None


def inverse(request: ActionRequest, *, catalog: Catalog | None = None) -> ActionRequest | None:
    """The fully-parameterized action that undoes `request`, or `None`.

    `None` whenever the evidence does not support one: no hint, a hint with no prior value,
    or an action with no inverse builder. Never a partially-parameterized action — an
    inverse missing its target value is indistinguishable at the call site from one that
    has it, and would fail at execution with the original change already applied.
    """
    catalog = catalog if catalog is not None else default_catalog()
    spec = catalog.get(request.action_id)

    if spec.writer is not None:
        # W41: the generic layer computes this, never the writer. Same action, recorded values
        # swapped, so the inverse restores exactly what the collector saw before it ran.
        from .writers.registry import invert

        inverted = invert(request, spec)
        if inverted is None:
            return None
        inverse_id, (params, hint) = spec.id, inverted
    else:
        builder = _INVERSE_BUILDERS.get(spec.inverse)
        built = builder(request) if builder is not None else None
        if built is None:
            return None
        # A builder returns params alone when the recorded snapshot stays valid for the
        # inverse, or `(params, hint)` when the inverse must carry it swapped — the multi-key
        # form, whose targets live on the hint rather than in its parameters.
        params, hint = built if isinstance(built, tuple) else (built, request.inverse_hint)
        inverse_id = spec.inverse

    try:
        return ActionRequest.for_action(inverse_id, params, inverse_hint=hint, catalog=catalog)
    except Exception:
        # A builder that produced something the schema rejects is a bug here, not a reason
        # to execute. Ground rule #4 says refuse, so `None` — and `execute()` then raises
        # with the action id, which is what points at this function.
        return None


# --------------------------------------------------------------------------------------
# Per-action builders. Each returns the params of the *inverse*, or None.
# --------------------------------------------------------------------------------------


def _invert_configmap_key(
    request: ActionRequest,
) -> dict[str, Any] | tuple[dict[str, Any], dict[str, Any]] | None:
    """Restore the value that is current *now* — which the hint recorded at collection time.

    Reading the live ConfigMap here instead would race the change being reverted, and would
    make the inverse uncomputable during exactly the outage it is needed in.

    The widened `keys` form (W42 rung 1) inverts by swapping the recorded values: it restores
    every key to what it held before this action ran.
    """
    if request.params.get("keys") is not None:
        recorded = recorded_keys(request.params, request.inverse_hint)
        if recorded is None:
            return None
        _, prior, current = recorded
        hint = {**(request.inverse_hint or {}), "prior_values": current, "current_values": prior}
        return dict(request.params), hint

    hint = request.inverse_hint or {}
    current = hint.get("current_value")
    if current is None or request.params.get("key") is None:
        return None
    if request.params.get("target_value") is None:
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
    if hint.get("keys"):
        # A multi-key edit. Only the keys are parameters; the values stay on the hint, where
        # `recorded_keys` checks them. Rejected by the schema until the widening is merged.
        if not hint.get("namespace") or not hint.get("name"):
            return None
        params = {"namespace": hint["namespace"], "name": hint["name"], "keys": sorted(hint["keys"])}
        return params if recorded_keys(params, hint) is not None else None

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


# --------------------------------------------------------------------------------------
# The widened multi-key form, and what a request writes
# --------------------------------------------------------------------------------------


def recorded_keys(
    params: dict[str, Any], hint: dict[str, Any] | None
) -> tuple[list[str], dict[str, Any], dict[str, Any]] | None:
    """`(keys, prior_values, current_values)` for a `keys` request, or `None` if they do not fit.

    Shared by the inverse, the dry run, the precondition and the executor, so the four cannot
    disagree about when the widened form is usable. It refuses:

    * a request that also names `key` or `target_value` — one form or the other, never both;
    * values recorded on a **different ConfigMap** than the parameters name (W41's lesson:
      without it, one resource's values could be written to another under an honest dry run);
    * **any key set other than exactly the recorded one**. A subset would be a partial revert
      the human never saw recorded as a unit, and a superset restores keys nobody observed.
    """
    hint = hint or {}
    keys = params.get("keys")
    if not keys or params.get("key") is not None or params.get("target_value") is not None:
        return None
    if hint.get("namespace") != params.get("namespace") or hint.get("name") != params.get("name"):
        return None
    prior, current = hint.get("prior_values"), hint.get("current_values")
    if not isinstance(prior, dict) or not isinstance(current, dict):
        return None
    if set(keys) != set(prior) or set(keys) != set(current):
        return None
    return sorted(keys), prior, current


def writes(
    request: ActionRequest, *, catalog: Catalog | None = None
) -> tuple[Any, dict[str, Any]] | None:
    """Where executing `request` writes, and what — from parameters and recorded values, with
    no I/O, exactly as the dry run renders it.

    This is what W42's corpus-replay gate compares to what a human actually did, so it exists
    once for every rung rather than being reconstructed per candidate. `None` for an action it
    cannot describe as field writes (a Helm rollback replaces a whole release).
    """
    from .. import keys as resource_keys

    catalog = catalog if catalog is not None else default_catalog()
    spec = catalog.get(request.action_id)

    if spec.writer is not None:
        from .writers.registry import recorded_values

        values = recorded_values(request, spec)
        return None if values is None else (values.writer.resource(request.params), values.prior)

    if request.action_id == "revert_configmap_key":
        ref = resource_keys.k8s_configmap(request.params["namespace"], request.params["name"])
        if request.params.get("keys") is not None:
            recorded = recorded_keys(request.params, request.inverse_hint)
            return None if recorded is None else (ref, {key: recorded[1][key] for key in recorded[0]})
        if request.params.get("key") is None or request.params.get("target_value") is None:
            return None
        return ref, {request.params["key"]: request.params["target_value"]}

    return None
