"""W23 — reader and actor principals. Handoff §8.

> *The actor credential must be unobtainable on any code path that hasn't passed through
> an approval handler. Enforce it structurally — the executor takes a credential object
> that only the approval handler can mint — not by convention.*

"Structurally" is the whole unit, so it is worth being precise about what is structural
here and what cannot be:

* **`ActorCredential` cannot be constructed by anyone.** Its `__init__` refuses unless the
  caller is this module. There is no public constructor, no `model_validate` route in, and
  no path that builds one from a dict — so a caller cannot forge one by assembling the
  right fields.
* **`mint_actor_credential` refuses unless its immediate caller is an approval handler.**
  The permitted modules are a frozen allowlist checked against the calling frame, not a
  convention in a docstring. Import it from anywhere else and calling it raises.
* **The credential is bound to one incident, one action and one namespace, and is spent
  once.** A leaked credential is not a general-purpose key: it opens exactly the mutation
  a human already approved, and only until it expires.
* **TTL is 900 seconds and there is no parameter to raise it.** `DurationSeconds` is a
  module constant, not an argument, so there is no call site that can ask for longer.

What is *not* structural, stated plainly rather than implied: Python has no private
constructor and no memory isolation. A caller determined to forge a credential can reach
into this module's internals — `object.__new__`, a patched frame, a rewritten global. The
gate stops accidental coupling and any code path that did not deliberately subvert it,
which is what "unobtainable on any code path that hasn't passed through an approval
handler" can mean in this language. The credential is also the *second* barrier: the first
is that the model never emits a command string (ground rule #1).

**Two principals, two types, and the separation is what the types are for.** A
`ReaderCredential` has no field an executor can use and every mutating entry point demands
an `ActorCredential`, so "read and write are different principals" is checked by the type
system on every call rather than remembered by whoever wrote the executor.

**Automation layer** (plan §3.5). `tests/integration/test_layer_seam.py` blocks this module
by name from the investigation layer: a collector must not be able to obtain a credential
that can mutate anything.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ActorCredential",
    "CredentialRefused",
    "MINTING_MODULES",
    "SESSION_TTL_SECONDS",
    "ReaderCredential",
    "mint_actor_credential",
    "reader_credential",
    "require_actor_credential",
    "session_policy",
]

# Handoff §8: TTL 900s. A constant rather than a parameter — an argument would mean a call
# site could ask for eight hours, and the one that did would be the one nobody reviewed.
SESSION_TTL_SECONDS = 900

# The only modules permitted to mint. Checked against the calling frame, so importing
# `mint_actor_credential` elsewhere yields a function that raises when called.
#
# `slack.handlers` is the Socket Mode approval path (W25). `actions.approval` is W26's
# routing and idempotency layer, named here ahead of its arrival so that adding it is not
# also a change to this allowlist under time pressure on Sep 12.
MINTING_MODULES = frozenset(
    {
        "fazerops.slack.handlers",
        "fazerops.actions.approval",
    }
)

# The sentinel `ActorCredential.__init__` demands. Module-private and never exported; the
# frame check below is the real gate, and this closes the narrower hole of a caller inside
# an allowed module building a credential for an action nobody approved.
_MINT_TOKEN = object()


class CredentialRefused(PermissionError):
    """A credential was requested, forged or used outside the terms it was minted under.

    A `PermissionError` rather than a `ValueError` because every subclass of this failure
    is a security event: an unapproved mint, a replayed credential, an executor reaching
    for a namespace it was not granted.
    """


@dataclass(frozen=True)
class ReaderCredential:
    """The broad, long-lived, read-only principal every collector uses (Handoff §8).

    Deliberately carries **no** session token and no secret of its own: on this build the
    collectors use the ambient AWS chain and the local kubeconfig. Its job is to be a
    *type* — a value an executor cannot accept — so that "read and write are different
    principals" is enforced by signatures rather than by remembering.
    """

    profile: str | None = None
    region: str = "us-east-1"

    @property
    def can_mutate(self) -> bool:
        """Always False. Present so the answer is explicit at a call site rather than
        inferred from the absence of a field."""
        return False


@dataclass(frozen=True)
class ActorCredential:
    """A single-use, namespace-scoped, 900-second principal minted by an approval handler.

    Frozen, so the scope cannot be widened after the fact by the code that received it.
    `_spent` is the one piece of mutable state and it lives in a list precisely because the
    dataclass is frozen — spending must be visible to every holder of the same object, or
    two callers sharing one credential would each get a use out of it.
    """

    incident_id: str
    action_id: str
    namespace: str
    expires_at: float
    access_key_id: str = ""
    secret_access_key: str = field(default="", repr=False)
    session_token: str = field(default="", repr=False)
    _token: Any = None
    _spent: list[bool] = field(default_factory=lambda: [False], repr=False, compare=False)

    def __post_init__(self) -> None:
        # Not `__init__`: a frozen dataclass generates its own. `__post_init__` runs inside
        # it, which is the same guarantee — there is no way to build one of these without
        # passing through here.
        if self._token is not _MINT_TOKEN:
            raise CredentialRefused(
                "ActorCredential cannot be constructed directly; it is minted only by an "
                f"approval handler ({', '.join(sorted(MINTING_MODULES))}) — Handoff §8"
            )

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at

    @property
    def spent(self) -> bool:
        return self._spent[0]

    @property
    def ttl_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def spend(self) -> None:
        """Consume the credential. Handoff §8: one action per session.

        Raises on a second call rather than returning quietly, because the second call is
        either a replayed approval or a retry loop around a mutation that may already have
        landed — and both need to stop here, not proceed with a credential that looks fine.
        """
        if self._spent[0]:
            raise CredentialRefused(
                f"credential for {self.action_id} on {self.incident_id} has already been "
                "used; Handoff §8 allows one action per session"
            )
        self._spent[0] = True


def reader_credential(*, region: str = "us-east-1", profile: str | None = None) -> ReaderCredential:
    """The collectors' principal. Free to obtain from anywhere — it cannot mutate."""
    return ReaderCredential(profile=profile, region=region)


def session_policy(namespace: str, action_id: str) -> dict[str, Any]:
    """The STS session policy for one approved action.

    **Names exactly one namespace**, which is the plan's assertion and the reason the
    policy is built here rather than at the call site: a policy assembled next to the
    executor is one that grows a second namespace the first time someone needs two.

    Honest about its reach: the Kubernetes half of this build runs against k3d, which is
    not IAM-governed, so for `revert_configmap_key` this document is a *statement of the
    grant* rather than the thing enforcing it — `require_actor_credential` enforces that
    half at the executor boundary. For `restore_db_parameter` (W20c, Tier 2) the resource
    is RDS and the policy is enforced by AWS. Both scopes are carried on the credential and
    both are asserted, so neither half rests on the executor being careful.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "OneActionOneNamespace",
                "Effect": "Allow",
                "Action": _ACTIONS_FOR.get(action_id, []),
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:ResourceTag/fazerops:namespace": namespace}
                },
            }
        ],
    }


# The AWS API calls each catalog action needs, and nothing more. Written per action rather
# than as one union, so a new action cannot inherit another's permissions by omission.
_ACTIONS_FOR: dict[str, list[str]] = {
    "revert_configmap_key": [],  # k3d is not IAM-governed; see `session_policy`
    "helm_rollback": [],
    "restore_db_parameter": ["rds:ModifyDBParameterGroup", "rds:DescribeDBParameters"],
}


def mint_actor_credential(
    *,
    incident_id: str,
    action_id: str,
    namespace: str,
    sts_client: Any | None = None,
    role_arn: str | None = None,
) -> ActorCredential:
    """Mint the actor principal for one approved action.

    **Refuses unless the immediate caller is an approval handler.** That check is the unit:
    the plan's assertion is that this function is unreachable from any module except the
    approval handler, and a docstring saying so is what "by convention" means.

    `sts_client` is injectable so the gate can be tested without AWS, and because the
    fixture path must construct no client at all. When it is `None` and the process is
    offline, no STS call is made and the credential carries empty AWS keys — it still binds
    the incident, action, namespace, TTL and single use, which is what the Kubernetes
    executor checks.
    """
    caller = _calling_module(depth=2)
    if caller not in MINTING_MODULES:
        raise CredentialRefused(
            f"{caller or 'an unknown module'} may not mint an actor credential. Handoff §8: "
            "the actor credential is unobtainable on any code path that has not passed "
            f"through an approval handler ({', '.join(sorted(MINTING_MODULES))})."
        )

    expires_at = time.time() + SESSION_TTL_SECONDS
    keys = {"access_key_id": "", "secret_access_key": "", "session_token": ""}

    if sts_client is not None or role_arn is not None:
        keys = _assume(
            sts_client,
            role_arn=role_arn,
            namespace=namespace,
            action_id=action_id,
            incident_id=incident_id,
        )

    return ActorCredential(
        incident_id=incident_id,
        action_id=action_id,
        namespace=namespace,
        expires_at=expires_at,
        _token=_MINT_TOKEN,
        **keys,
    )


def require_actor_credential(
    credential: Any,
    *,
    incident_id: str | None = None,
    action_id: str,
    namespace: str,
) -> ActorCredential:
    """The executor's gate. Returns the credential or raises; never returns `None`.

    Called at the top of every mutating executor, **before** any client is constructed —
    the same ordering rule the catalog's parameter validation runs under, and for the same
    reason: a half-built client with an assumed default namespace is the thing that mutates
    the wrong resource.

    Checks the terms, not just the presence. A credential minted for another incident,
    another action or another namespace is a credential someone approved for something
    else, which is exactly as wrong as no credential at all.
    """
    if credential is None:
        raise CredentialRefused(
            f"{action_id} requires an actor credential minted by an approval handler; "
            "none was supplied. Handoff §8 — nothing mutates unattended (ground rule #5)."
        )
    if isinstance(credential, ReaderCredential):
        # The type split doing its job. A collector's principal reaching a mutating path
        # means the two were confused somewhere upstream, and that is worth naming.
        raise CredentialRefused(
            f"{action_id} was handed the read-only reader principal. Read and write are "
            "different principals (Handoff §8)."
        )
    if not isinstance(credential, ActorCredential):
        raise CredentialRefused(
            f"{action_id} was handed a {type(credential).__name__}, not an ActorCredential"
        )

    if credential.expired:
        raise CredentialRefused(
            f"credential for {action_id} expired {time.time() - credential.expires_at:.0f}s "
            f"ago (TTL {SESSION_TTL_SECONDS}s)"
        )
    if credential.action_id != action_id:
        raise CredentialRefused(
            f"credential was minted for {credential.action_id!r}, not {action_id!r}"
        )
    if credential.namespace != namespace:
        raise CredentialRefused(
            f"credential is scoped to namespace {credential.namespace!r}, not {namespace!r}"
        )
    if incident_id is not None and credential.incident_id != incident_id:
        raise CredentialRefused(
            f"credential was minted for incident {credential.incident_id!r}, not {incident_id!r}"
        )

    credential.spend()
    return credential


# --------------------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------------------


def _calling_module(*, depth: int) -> str | None:
    """The `__name__` of the frame `depth` levels up, or `None` if there is no such frame.

    `sys._getframe` rather than `inspect.stack()`: the latter builds a full `FrameInfo` for
    every frame on the stack, including reading source files off disk, which turns a
    security check into something a caller might be tempted to skip on a hot path.
    """
    try:
        frame = sys._getframe(depth)
    except ValueError:  # pragma: no cover - only at the very bottom of a stack
        return None
    return frame.f_globals.get("__name__")


def _assume(
    sts_client: Any | None,
    *,
    role_arn: str | None,
    namespace: str,
    action_id: str,
    incident_id: str,
) -> dict[str, str]:
    """The STS call. Session-policy scoped, 900 seconds, one namespace.

    **No live path in this build has ever executed this** — the demo's action runs against
    k3d, which is not IAM-governed, and W20c's RDS path is Sep 12's work. It compiles;
    that is not evidence it works, and the `# UNVERIFIED` convention (plan §1.2) applies to
    the response shape below until a green test proves it.
    """
    from ..config import require_offline_capable

    require_offline_capable("credentials")

    if sts_client is None:
        import boto3

        sts_client = boto3.client("sts", region_name="us-east-1")

    if not role_arn:
        raise CredentialRefused("an STS-backed credential needs a role_arn to assume")

    import json

    response = sts_client.assume_role(
        RoleArn=role_arn,
        # The session name is the audit trail on the AWS side: CloudTrail records it on
        # every call the session makes, so an operator reading CloudTrail sees which
        # incident and which approved action produced the mutation.
        RoleSessionName=f"fazerops-{incident_id}-{action_id}"[:64],
        Policy=json.dumps(session_policy(namespace, action_id)),
        DurationSeconds=SESSION_TTL_SECONDS,
    )
    credentials = response["Credentials"]  # UNVERIFIED (W23) — shape from boto3 typing
    return {
        "access_key_id": credentials["AccessKeyId"],
        "secret_access_key": credentials["SecretAccessKey"],
        "session_token": credentials["SessionToken"],
    }
