"""W21 — dry-run diff rendering. Handoff §7.

> *Every action implements `dry_run()` returning a renderable diff.*

The diff is what a human approves. It is the frame the demo lingers on and the only thing
standing between "the agent says it will fix it" and someone knowing what will change.

**Nothing in this module performs I/O.** Not a read, and certainly not a write. The diff is
rendered from the action's parameters and the collector's recorded hint — both already in
hand — so `dry_run()` is callable during the outage, from a laptop with no cluster access,
and `tests/unit/test_dry_run.py` can assert *zero* mutating calls by asserting there is no
client to make one with.

That is a deliberate constraint rather than a shortcut. A dry run that queries live state
to render its preview is a dry run that fails when the cluster is unreachable — which is
the condition under which someone is reading it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .catalog import Catalog
    from .inverse import ActionRequest

__all__ = ["DryRun", "DiffLine", "render"]

REDACTED = "<redacted>"

# Key fragments whose values never render. The ConfigMap path cannot reach a Secret today —
# the collector redacts those at normalization — but a dry run is the last surface before a
# value is shown to a human and echoed into an approval record, so it redacts again rather
# than relying on an upstream guarantee that a future collector might not make.
_SENSITIVE = ("password", "secret", "token", "key_id", "credential", "apikey", "api_key")


class DiffLine(BaseModel):
    """One field's before and after. `before is None` renders as "not captured", never as
    an empty string — Handoff §5 and plan §3.6 both insist the distinction survives to the
    screen, because "we set it to X" and "we changed it from nothing to X" are different
    claims."""

    model_config = ConfigDict(frozen=True)

    field: str
    before: str | None = None
    after: str | None = None
    prior_value_captured: bool = True
    changed: bool = True
    """Computed from the **raw** values, before masking.

    Found by test on 11 Sep: comparing the rendered strings marks a redacted secret
    `(unchanged)`, because two different secrets both render as `<redacted>`. That is a card
    telling an operator nothing will happen immediately before something does — the single
    most damaging thing a dry run can say."""


class DryRun(BaseModel):
    """What a human approves.

    `reversible` is computed from the inverse actually being constructible, not declared —
    ground rule #4 in the one place an operator reads it.
    """

    model_config = ConfigDict(frozen=True)

    action_id: str
    summary: str
    target: str
    lines: list[DiffLine] = Field(default_factory=list)
    reversible: bool = False
    inverse_summary: str | None = None
    unmet_preconditions: list[str] = Field(
        default_factory=list,
        description="Declared preconditions the collected evidence does not satisfy. "
        "Non-empty means `execute()` will refuse, and the card says so.",
    )
    notes: list[str] = Field(default_factory=list)

    def render(self) -> str:
        """Plain text, for stdout and for the markdown record. Slack's Block Kit version is
        W25's; both read the same `DryRun`, so the two surfaces cannot disagree."""
        out = [f"{self.summary}", f"  target: {self.target}"]
        for line in self.lines:
            if not line.prior_value_captured:
                out.append(f"  {line.field}: {line.after}  (prior value not captured)")
            elif not line.changed:
                out.append(f"  {line.field}: {line.after}  (unchanged)")
            else:
                out.append(f"  {line.field}: {line.before} → {line.after}")

        out.append(
            f"  reversible: {self.inverse_summary}"
            if self.reversible
            else "  reversible: NO — this action will refuse to execute (ground rule #4)"
        )
        out.extend(f"  note: {note}" for note in self.notes)
        return "\n".join(out)


def render(
    request: ActionRequest, *, evidence: Any = None, catalog: Catalog | None = None
) -> DryRun:
    """Render the diff for one action. No I/O — see the module docstring."""
    from .catalog import default_catalog

    catalog = catalog if catalog is not None else default_catalog()
    spec = catalog.get(request.action_id)

    undo = request.inverse(catalog=catalog)
    renderer = _RENDERERS.get(spec.dry_run)
    if renderer is None:
        # A catalog entry naming a dry-run renderer that does not exist. Caught by
        # `test_catalog_schema.py` at load, so reaching here means the catalog changed
        # without the test running — refuse rather than render a blank preview.
        raise ValueError(f"{spec.id}: no dry-run renderer named {spec.dry_run!r}")

    dry = renderer(request, spec)

    # An unmet precondition belongs on the card, not only in the exception `execute()` will
    # raise afterwards. The card is what a human approves; approving something that is
    # about to refuse is the same defect as approving something irreversible.
    from .preconditions import failures

    unmet = failures(request, evidence, catalog=catalog)

    return dry.model_copy(
        update={
            "reversible": undo is not None,
            "inverse_summary": _summarize(undo) if undo is not None else None,
            "unmet_preconditions": unmet,
            "notes": [*dry.notes, *(f"precondition not met — {reason}" for reason in unmet)],
        }
    )


# Which parameter carries a *value*, and which parameter names it. `target_value` tells you
# nothing about whether it holds a secret — `key` and `parameter` do. Masking on the
# parameter's own name (found by test, 11 Sep) printed a redacted ConfigMap value back out
# in full in the inverse summary one line below the redaction.
_VALUE_PARAMS = {
    "revert_configmap_key": ("target_value", "key"),
    "restore_db_parameter": ("target_value", "parameter"),
}


def _summarize(undo: ActionRequest) -> str:
    value_param, name_param = _VALUE_PARAMS.get(undo.action_id, (None, None))
    sensitive = (
        value_param is not None and _is_sensitive(str(undo.params.get(name_param, "")))
    )

    parts = ", ".join(
        f"{k}={REDACTED if sensitive and k == value_param else _mask(k, v)}"
        for k, v in sorted(undo.params.items())
    )
    return f"{undo.action_id}({parts})"


def _is_sensitive(field: str) -> bool:
    lowered = field.lower()
    return any(token in lowered for token in _SENSITIVE)


def _mask(field: str, value: Any) -> str:
    return REDACTED if _is_sensitive(field) else str(value)


# --------------------------------------------------------------------------------------
# Renderers, named by the catalog's `dry_run:` field
# --------------------------------------------------------------------------------------


def _kubectl_diff(request: ActionRequest, spec: Any) -> DryRun:
    params = request.params
    hint = request.inverse_hint or {}
    key = params["key"]
    current = hint.get("current_value")

    return DryRun(
        action_id=request.action_id,
        summary=f"Revert {key} in ConfigMap {params['name']}",
        target=f"{params['namespace']}/configmap/{params['name']}",
        lines=[
            DiffLine(
                field=key,
                before=None if current is None else _mask(key, current),
                after=_mask(key, params["target_value"]),
                prior_value_captured=current is not None,
                changed=str(current) != str(params["target_value"]),
            )
        ],
        notes=[
            "Pods do not reload a mounted ConfigMap automatically; a rollout may be "
            "required for this to take effect."
        ],
    )


def _helm_diff_revision(request: ActionRequest, spec: Any) -> DryRun:
    params = request.params
    hint = request.inverse_hint or {}
    current = hint.get("current_revision")

    return DryRun(
        action_id=request.action_id,
        summary=f"Roll {params['release']} back to revision {params['target_revision']}",
        target=f"{params['namespace']}/helm/{params['release']}",
        lines=[
            DiffLine(
                field="revision",
                before=None if current is None else str(current),
                after=str(params["target_revision"]),
                prior_value_captured=current is not None,
                changed=str(current) != str(params["target_revision"]),
            )
        ],
        notes=[
            "A rollback replaces the whole release manifest, not one value — changes made "
            "after the target revision are reverted with it."
        ],
    )


def _rds_parameter_diff(request: ActionRequest, spec: Any) -> DryRun:
    params = request.params
    hint = request.inverse_hint or {}
    current = hint.get("current_value")
    apply_method = params.get("apply_method", "pending-reboot")

    notes = [f"Tier {spec.tier.value}: requires {spec.requires_approval_from} approval."]
    if apply_method == "pending-reboot":
        notes.append("apply_method=pending-reboot: this takes effect on the next reboot.")

    return DryRun(
        action_id=request.action_id,
        summary=f"Restore {params['parameter']} in parameter group {params['parameter_group']}",
        target=f"rds/parameter-group/{params['parameter_group']}",
        lines=[
            DiffLine(
                field=params["parameter"],
                before=None if current is None else _mask(params["parameter"], current),
                after=_mask(params["parameter"], params["target_value"]),
                prior_value_captured=current is not None,
                changed=str(current) != str(params["target_value"]),
            )
        ],
        notes=notes,
    )


_RENDERERS = {
    "kubectl_diff": _kubectl_diff,
    "helm_diff_revision": _helm_diff_revision,
    "rds_parameter_diff": _rds_parameter_diff,
}
