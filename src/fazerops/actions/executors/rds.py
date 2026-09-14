"""`restore_db_parameter` — Handoff §7, **Tier 2**. W20c's executor.

Targets an RDS **parameter group**, never an instance. That is what makes the Tier 2 claim
honest without spending anything: a parameter group is a genuine managed-database mutation,
only instances bill, and it emits a real `ModifyDBParameterGroup` event that CloudTrail
records.

Tier is declared in the catalog and never inferred here (`config/actions.yaml`, `tier: 2`,
`requires_approval_from: manager`). W26b routes it; this executor's relationship to that
routing is indirect and structural — it demands a credential, and the only thing that mints
one is an approval that already cleared the tier. **There is deliberately no tier check in
this function.** A second, local tier check would be a second source of truth about tiers,
and the first time the two disagreed the one nobody audited would win.

The same four guards run upstream before anything here executes, exactly as for the other
two actions: schema, inverse (ground rule #4), preconditions from collected evidence, and
the approval-minted credential.

**`ApplyMethod` defaults to `pending-reboot`, not `immediate`.** RDS rejects `immediate`
for a static parameter, and the failure arrives mid-mutation after the approval has been
spent. `pending-reboot` is valid for every parameter, so the default is the one that cannot
fail on a property of the parameter that nobody looked up; a caller who knows the parameter
is dynamic passes `immediate` explicitly, and the catalog's enum is what constrains it.

**Nothing in this module has run against a live parameter group.** Creating one is resource
creation, which this build does not do without asking (`docs/session_state.md`). The boto3
call shapes below carry `# UNVERIFIED (W20c)` under plan §1.2's convention until a green
live test proves them.
"""

from __future__ import annotations

from typing import Any

from ...security.credentials import CredentialRefused, require_actor_credential

__all__ = ["restore_parameter"]

# Valid for every parameter, static or dynamic. See the module docstring on why this is not
# `immediate`.
DEFAULT_APPLY_METHOD = "pending-reboot"


def restore_parameter(
    params: dict[str, Any],
    *,
    credential: Any = None,
    undo: Any = None,
    client: Any = None,
) -> dict[str, Any]:
    """Set one parameter of one parameter group to `target_value`.

    `undo` arrives already computed — `ActionRequest.execute()` refuses to call this at all
    when the inverse is `None`. It is carried into the result for the incident record.

    `client` is injectable for the tests and for a caller that already holds a configured
    RDS client. When it is `None` one is built **after** the credential check, from the
    credential's own keys where it has them — an actor credential minted through STS is
    scoped to this one action by a session policy, and falling back to the ambient identity
    would silently execute the mutation as whoever the process happens to be.
    """
    parameter_group = params["parameter_group"]
    parameter = params["parameter"]
    target_value = params["target_value"]
    apply_method = params.get("apply_method") or DEFAULT_APPLY_METHOD

    # Before the client, always.
    credential = require_actor_credential(
        credential, action_id="restore_db_parameter", namespace=parameter_group
    )

    client = client if client is not None else _rds_client(credential)

    # One parameter per call. Modifying a list would let a partially-valid batch apply some
    # parameters and reject others, leaving a state no computed inverse describes.
    client.modify_db_parameter_group(
        DBParameterGroupName=parameter_group,
        Parameters=[
            {
                "ParameterName": parameter,
                "ParameterValue": target_value,
                "ApplyMethod": apply_method,
            }
        ],
    )

    return {
        "action_id": "restore_db_parameter",
        "parameter_group": parameter_group,
        "parameter": parameter,
        "apply_method": apply_method,
        "value": _value_after(client, parameter_group=parameter_group, parameter=parameter),
        "inverse": None if undo is None else {"action_id": undo.action_id, "params": undo.params},
    }


def _value_after(client: Any, *, parameter_group: str, parameter: str) -> str | None:
    """The value RDS reports after the modify, or `None` if it cannot be read.

    `None` rather than a raise, for the reason `helm.py` gives: the mutation has already
    happened, and failing here reports a completed action as an error and invites a retry.

    A `pending-reboot` change is *staged*, not applied, so the value read back can legally
    still be the old one — which is why this is reported as an observation rather than
    asserted as a confirmation.
    """
    try:
        paginator = client.get_paginator("describe_db_parameters")
        for page in paginator.paginate(DBParameterGroupName=parameter_group):
            for entry in page.get("Parameters", []):  # UNVERIFIED (W20c) — shape from typing
                if entry.get("ParameterName") == parameter:
                    return entry.get("ParameterValue")
    except Exception:
        return None
    return None


def _rds_client(credential: Any) -> Any:
    # Fail closed. This used to fall back to the ambient boto3 identity when the credential carried
    # no STS keys, which ran a Tier 2 mutation as the automation host rather than as the approved,
    # session-policy-scoped principal (14 Sep). The gateway refuses such a card before it opens;
    # this is the second barrier.
    if not getattr(credential, "access_key_id", ""):
        raise CredentialRefused(
            "restore_db_parameter needs an STS-backed actor credential; none was minted because "
            "FAZEROPS_ACTOR_ROLE_ARN is not set. Refusing to run as this process's own AWS identity."
        )

    from ...config import require_offline_capable

    require_offline_capable("restore_db_parameter")

    import boto3

    keys = {
        "aws_access_key_id": getattr(credential, "access_key_id", "") or None,
        "aws_secret_access_key": getattr(credential, "secret_access_key", "") or None,
        "aws_session_token": getattr(credential, "session_token", "") or None,
    }
    # A credential minted without STS carries empty keys (`mint_actor_credential`); there is
    # nothing to scope the client with, so the ambient identity is used and the scoping rests
    # on `require_actor_credential` above. `session_policy` documents the same split.
    return boto3.client("rds", region_name="us-east-1", **keys)
