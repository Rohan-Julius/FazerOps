"""W20 — precondition checks. Handoff §7.

Each catalog entry declares `preconditions:` by name. This module is what those names mean,
and `ActionRequest.execute()` evaluates them before it does anything else.

**They are checked against evidence already in hand, never by calling the cluster.** That is
the same constraint `dry_run.py` runs under and it is load-bearing for the same reason:
W20b's test requires that a target revision absent from `helm history` fails its
precondition *before any client is constructed*. A check that phoned the API to answer could
not satisfy that, and would also fail during the outage it exists to guard.

The evidence is what the investigation already collected — the `inverse_hint` a collector
recorded, and the resources and revisions the ledger observed. So a precondition failure
means "nothing we collected supports this action", which is the honest claim. It is
deliberately **not** "we checked the cluster and it said no": `Evidence.complete` records
whether the caller supplied an inventory at all, and a check that cannot be evaluated fails
closed rather than passing by default.

Failing closed is the whole design. An unevaluated precondition that returns True is a
precondition that does nothing, and the first time anyone notices is when an action runs
against a resource that is not there.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .inverse import ActionRequest

__all__ = [
    "CHECKS",
    "Evidence",
    "PreconditionFailed",
    "check",
    "failures",
]


class PreconditionFailed(RuntimeError):
    """One or more declared preconditions were not satisfied by the collected evidence.

    Raised *before* the inverse is computed and long before an executor is resolved, so an
    action that should not run never reaches code that mutates.
    """


class Evidence(BaseModel):
    """What the investigation observed, in the shape the checks need.

    Built from a `Brief` by `from_brief`, or by hand in a test. Every field defaults to
    empty, and empty means **unknown, not absent** — which is why `complete` exists: a check
    over an empty inventory fails closed instead of silently passing.
    """

    model_config = ConfigDict(frozen=True)

    resource_keys: frozenset[str] = Field(
        default_factory=frozenset,
        description="`ResourceRef.blast_radius_key()` for everything the collectors saw.",
    )
    helm_revisions: dict[str, frozenset[int]] = Field(
        default_factory=dict,
        description="`namespace/release` → the revisions `helm history` reported.",
    )
    complete: bool = Field(
        default=False,
        description="Did the caller supply a real inventory? False makes existence checks "
        "fail closed — an action must not run because nobody looked.",
    )

    @classmethod
    def from_brief(cls, brief) -> Evidence:
        """The evidence one investigation produced.

        Takes a `Brief` rather than a ledger because the brief is what the automation layer
        is handed across the seam (plan §3.5) — the automation layer does not get to query
        the ledger for itself.
        """
        keys: set[str] = set()
        revisions: dict[str, set[int]] = {}

        for candidate in brief.candidates:
            resource = candidate.event.resource
            keys.add(resource.blast_radius_key())

            hint = candidate.event.inverse_hint or {}
            if hint.get("action_id") == "helm_rollback":
                release = f"{hint.get('namespace')}/{hint.get('release')}"
                seen = revisions.setdefault(release, set())
                for field in ("target_revision", "current_revision"):
                    if hint.get(field) is not None:
                        seen.add(int(hint[field]))

        return cls(
            resource_keys=frozenset(keys),
            helm_revisions={name: frozenset(values) for name, values in revisions.items()},
            complete=True,
        )


# --------------------------------------------------------------------------------------
# The named checks. Each returns None if satisfied, or a one-line reason if not.
# --------------------------------------------------------------------------------------


def _prior_value_known(request: ActionRequest, evidence: Evidence) -> str | None:
    """Ground rule #4's precondition, and the one that is true of most CloudTrail events.

    `lookup_events` returns no prior value, so an action derived from one cannot say what to
    restore. The hint is the only place a prior value can come from.
    """
    hint = request.inverse_hint or {}
    if request.params.get("keys") is not None:
        from .inverse import recorded_keys

        if recorded_keys(request.params, hint) is None:
            return "no prior values were captured for exactly these keys, so the change cannot be undone"
        return None
    if hint.get("current_value") is None:
        return "no prior value was captured for this resource, so the change cannot be undone"
    return None


def _configmap_exists(request: ActionRequest, evidence: Evidence) -> str | None:
    if not evidence.complete:
        return "no resource inventory was collected, so the ConfigMap cannot be confirmed"

    # Built by `keys.py`, never spelled out here. That module exists precisely because both
    # sides of the index must derive the key from the same function: a check that writes its
    # own key format silently stops matching the moment the format changes, and the symptom
    # is an action refusing for a resource that is plainly present.
    from .. import keys

    key = keys.k8s_configmap(request.params["namespace"], request.params["name"]).blast_radius_key()
    if key not in evidence.resource_keys:
        return f"no collected change touched {key}"
    return None


def _release_exists(request: ActionRequest, evidence: Evidence) -> str | None:
    if not evidence.complete:
        return "no release inventory was collected, so the release cannot be confirmed"

    name = f"{request.params['namespace']}/{request.params['release']}"
    if name not in evidence.helm_revisions:
        return f"no collected change touched Helm release {name}"
    return None


def _target_revision_exists(request: ActionRequest, evidence: Evidence) -> str | None:
    """W20b's assertion: a revision absent from `helm history` fails **before** a client is
    constructed. Answered from the revisions the collector already read."""
    if not evidence.complete:
        return "no release history was collected, so the target revision cannot be confirmed"

    name = f"{request.params['namespace']}/{request.params['release']}"
    known = evidence.helm_revisions.get(name)
    if not known:
        return f"no revision history was collected for {name}"

    target = int(request.params["target_revision"])
    if target not in known:
        return f"revision {target} is not in the collected history for {name} ({sorted(known)})"
    return None


def _parameter_group_exists(request: ActionRequest, evidence: Evidence) -> str | None:
    """Same rule as `_configmap_exists`, and it is here that guessing the format bit.

    An earlier version matched `:pg:<name>` and `/<name>` — plausible ARN-ish shapes, and
    both wrong. `keys.db_parameter_group()` produces `dbparametergroup:<name>`, which
    matches neither, so every RDS action would have refused against real evidence while
    passing against the hand-written evidence in its own test (found 12 Sep).
    """
    if not evidence.complete:
        return "no resource inventory was collected, so the parameter group cannot be confirmed"

    from .. import keys

    key = keys.db_parameter_group(request.params["parameter_group"]).blast_radius_key()
    if key not in evidence.resource_keys:
        return f"no collected change touched {key}"
    return None


def _writer_resource_observed(request: ActionRequest, evidence: Evidence) -> str | None:
    """`configmap_exists`, for any writer-backed action (W41). The key comes from the writer's
    own `resource()`, which goes through `keys.py` like every other check here."""
    if not evidence.complete:
        return "no resource inventory was collected, so the resource cannot be confirmed"

    from .writers.registry import default_registry

    writer_id = (request.inverse_hint or {}).get("writer")
    if writer_id not in default_registry():
        return f"no registered writer {writer_id!r} matches this action's recorded values"

    key = default_registry().get(writer_id).resource(request.params).blast_radius_key()
    if key not in evidence.resource_keys:
        return f"no collected change touched {key}"
    return None


def _writer_prior_value_known(request: ActionRequest, evidence: Evidence) -> str | None:
    prior = (request.inverse_hint or {}).get("prior")
    if not isinstance(prior, dict) or not prior:
        return "no prior values were captured for this resource, so the change cannot be undone"
    return None


CHECKS: dict[str, Callable[[ActionRequest, Evidence], str | None]] = {
    "writer_resource_observed": _writer_resource_observed,
    "writer_prior_value_known": _writer_prior_value_known,
    "prior_value_known": _prior_value_known,
    "configmap_exists": _configmap_exists,
    "release_exists": _release_exists,
    "target_revision_exists": _target_revision_exists,
    "parameter_group_exists": _parameter_group_exists,
}


# --------------------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------------------


def failures(request: ActionRequest, evidence: Evidence | None = None, *, catalog=None) -> list[str]:
    """Every declared precondition this request does not satisfy, as reasons.

    A precondition name with no registered check is itself a failure. The alternative —
    skipping unknown names — means a typo in `actions.yaml` silently disables a safety
    check, and `test_catalog_schema.py` would still pass because the entry *has* a
    precondition list.
    """
    from .catalog import default_catalog

    catalog = catalog if catalog is not None else default_catalog()
    evidence = evidence if evidence is not None else Evidence()

    reasons: list[str] = []
    for name in catalog.get(request.action_id).preconditions:
        checker = CHECKS.get(name)
        if checker is None:
            reasons.append(f"{name}: no such precondition check is registered")
            continue
        reason = checker(request, evidence)
        if reason is not None:
            reasons.append(f"{name}: {reason}")
    return reasons


def check(request: ActionRequest, evidence: Evidence | None = None, *, catalog=None) -> None:
    """Raise unless every declared precondition is satisfied."""
    reasons = failures(request, evidence, catalog=catalog)
    if reasons:
        raise PreconditionFailed(
            f"{request.action_id}: refusing to execute — "
            + "; ".join(reasons)
        )
