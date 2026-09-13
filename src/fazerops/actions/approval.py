"""W26 — approval routing, tier promotion and idempotency. Handoff §7 and §8.

This module is where a human's decision becomes a mutation, and it is the only such place.
`slack/handlers.py` parses a click into a `Decision` and hands the identifiers here; this
module re-derives everything else. **Nothing a Slack payload carried is used to name a
namespace, a resource or a target value** — those come from the `PendingApproval` this
module registered before the card was ever posted.

Four properties hold structurally rather than by care:

1. **A replay executes once.** Outcomes are keyed `(incident_id, action_id)`, first-write-
   wins, and the key is checked before a credential is minted. A double-clicked button, a
   Slack retry and a resent payload are all the same event to this module.
2. **Approval is unreachable without a dry run.** `decide()` resolves a `PendingApproval`
   or refuses, and `register()` is the only thing that builds one — rendering the dry run
   as it does. There is no path from a raw `ActionRequest` to `execute()` through here.
   Before W26 this ordering was true by flow, which is to say it was true until someone
   wrote a second call site.
3. **Tier is declared, then promoted, never inferred and never demoted.** `catalog.promote`
   supplies both the effective tier and the reason it escalated, from one traversal, so the
   card cannot state a tier drawn from one rule and a reason drawn from another.
4. **The credential is minted here and nowhere else reachable.** `security/credentials.py`
   allowlists this module by name; an executor called on any other path is handed nothing
   and refuses.

**Automation layer** (plan §3.5). The investigation layer imports nothing from here.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..models import Tier
from ..record.session import ApprovalRecord, ExecutionRecord
from ..security.credentials import mint_actor_credential
from .catalog import Catalog, default_catalog, promote
from .dry_run import DryRun
from .inverse import ActionRequest

__all__ = [
    "AlreadyDecided",
    "ApprovalGateway",
    "ApprovalRefused",
    "Approver",
    "ApproverNotPermitted",
    "ApproverRole",
    "NotAwaitingApproval",
    "Outcome",
    "PendingApproval",
    "scope_of",
]


class ApprovalRefused(RuntimeError):
    """Base for every refusal this module makes. Distinct from `CredentialRefused`: that one
    means the gate below rejected a credential; these mean it never minted one."""


class NotAwaitingApproval(ApprovalRefused):
    """A decision arrived for a pair this module never registered.

    This is the structural half of "the dry run is shown first": the only way to obtain a
    `PendingApproval` is `register()`, and `register()` renders the dry run. A decision with
    no pending entry is either a card from a previous process or a forged payload, and both
    are refusals rather than reasons to reconstruct an action from the click.
    """


class ApproverNotPermitted(ApprovalRefused):
    """The approver's role does not clear the action's effective tier (W26b, Handoff §7).

    **Deliberately does not record an outcome.** A Tier 2 action clicked by an IC must stay
    open for a manager; recording the refusal as a decision would let one wrong click
    permanently close an incident that nobody ever actually approved.
    """


class AlreadyDecided(ApprovalRefused):
    """Kept for callers that want the replay as an exception. `decide()` itself returns the
    first outcome instead — see its docstring on why refusing loudly is the wrong shape
    here."""

    def __init__(self, outcome: "Outcome") -> None:
        super().__init__(
            f"{outcome.action_id} on {outcome.incident_id} was already {outcome.decision} "
            f"by {outcome.approver}; Handoff §7 executes once per (incident, action)."
        )
        self.outcome = outcome


class ApproverRole(str, Enum):
    """Handoff §7's `requires_approval_from`. A manager clears Tier 1 as well as Tier 2 —
    the tiers are a floor on seniority, not a routing table that excludes the senior."""

    ENGINEER = "engineer"
    MANAGER = "manager"

    def clears(self, tier: Tier) -> bool:
        if tier is Tier.MANAGER_APPROVAL:
            return self is ApproverRole.MANAGER
        return True


class Approver(BaseModel):
    """Who clicked, and what they are allowed to clear.

    `user_id` is the Slack user id rather than a display name, for the reason
    `ApprovalRecord` gives: a name is re-assignable and an id is not, and this is the field
    an audit reads to answer who authorized a mutation.
    """

    model_config = ConfigDict(frozen=True)

    user_id: str
    role: ApproverRole


class PendingApproval(BaseModel):
    """One action awaiting a human, with everything the card and the executor will need.

    Built before the card is posted, so the dry run an operator reads and the action that
    runs on their click are the same object rather than two renderings that could disagree.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    incident_id: str
    request: ActionRequest
    declared_tier: Tier
    tier: Tier = Field(description="After `thresholds.yaml` promotion — what the card shows.")
    escalation_reason: str | None = None
    dry_run: DryRun
    evidence: Any = None
    registered_at: float = Field(default_factory=time.time)

    @property
    def action_id(self) -> str:
        return self.request.action_id

    @property
    def key(self) -> tuple[str, str]:
        return (self.incident_id, self.action_id)

    @property
    def scope(self) -> str:
        return scope_of(self.request)

    @property
    def escalated(self) -> bool:
        return self.tier > self.declared_tier


class Outcome(BaseModel):
    """What happened to one `(incident_id, action_id)` pair. Written once, returned forever.

    `replay` is the field that distinguishes the first call from every later one. It is on
    the outcome rather than signalled by an exception because a replayed approval is not an
    error — it is a human clicking twice, or Slack retrying a delivery, and the correct
    response is the result of the first click.
    """

    model_config = ConfigDict(frozen=True)

    incident_id: str
    action_id: str
    decision: Literal["approved", "rejected"]
    approver: str
    tier: Tier
    escalation_reason: str | None = None
    decided_at: datetime
    executed: bool = False
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    replay: bool = False

    def approval_record(self) -> ApprovalRecord:
        return ApprovalRecord(
            decision=self.decision,
            approver=self.approver,
            approved_at=self.decided_at,
            action_id=self.action_id,
            tier=int(self.tier),
            escalation_reason=self.escalation_reason,
        )

    def execution_record(self, *, inverse: dict[str, Any] | None = None) -> ExecutionRecord | None:
        """`None` when nothing ran — a rejection has no execution, and inventing an empty
        one would make `IncidentSession.stage` report an execution that never happened."""
        if not self.executed and self.error is None:
            return None
        return ExecutionRecord(
            action_id=self.action_id,
            succeeded=self.executed,
            executed_at=self.decided_at,
            result=self.result,
            inverse=inverse,
            error=self.error,
        )


def scope_of(request: ActionRequest) -> str:
    """The one scope the actor credential is bound to, per action.

    Kubernetes actions scope to a namespace; `restore_db_parameter` has no namespace and
    scopes to its parameter group, which is the resource `session_policy`'s tag condition
    names. Derived from the validated params rather than passed in, so a caller cannot widen
    the credential by supplying a scope broader than the action it is for.
    """
    for field in ("namespace", "parameter_group"):
        value = request.params.get(field)
        if value:
            return str(value)
    raise ApprovalRefused(
        f"{request.action_id}: no scope field among namespace/parameter_group; an actor "
        "credential cannot be bound to one resource (Handoff §8)."
    )


# What actually runs an approved action. Injectable so the gateway's own tests never touch a
# cluster, and so W27's injection suite can assert *which* executor was reached.
Runner = Callable[[ActionRequest, Any, Any], dict[str, Any]]


def _default_runner(request: ActionRequest, credential: Any, evidence: Any) -> dict[str, Any]:
    return request.execute(credential, evidence=evidence)


class ApprovalGateway:
    """Registers proposed actions, routes decisions by tier, and executes exactly once.

    In-memory by design. Handoff §10 persists the *record* of what happened
    (`IncidentSession`); this table is the live state of one process's open cards, and a
    restart correctly forgets them — a card whose pending entry is gone refuses rather than
    reconstructing an action from a click, which is `NotAwaitingApproval`.
    """

    def __init__(
        self,
        *,
        catalog: Catalog | None = None,
        runner: Runner | None = None,
        sts_client: Any | None = None,
        role_arn: str | None = None,
    ) -> None:
        self._catalog = catalog if catalog is not None else default_catalog()
        self._runner = runner if runner is not None else _default_runner
        self._sts_client = sts_client
        self._role_arn = role_arn
        self._pending: dict[tuple[str, str], PendingApproval] = {}
        self._outcomes: dict[tuple[str, str], Outcome] = {}

    # -- registration ------------------------------------------------------------------

    def register(
        self,
        incident_id: str,
        request: ActionRequest,
        *,
        evidence: Any = None,
        estimated_cost_delta_usd: float | None = None,
        resource_count: int | None = None,
        crosses_namespace_boundary: bool = False,
    ) -> PendingApproval:
        """Compute the effective tier, render the dry run, and open the card.

        The promotion inputs are arguments rather than read from the request, because they
        are properties of the *incident* — how many resources this blast radius touches,
        whether it crosses a namespace — and the request only knows about one resource.
        """
        spec = self._catalog.get(request.action_id)  # UnknownAction; there is no fallback
        tier, reason = promote(
            spec,
            estimated_cost_delta_usd=estimated_cost_delta_usd,
            resource_count=resource_count,
            crosses_namespace_boundary=crosses_namespace_boundary,
            thresholds=self._catalog.thresholds,
        )
        if tier is Tier.READ_ONLY:
            raise ApprovalRefused(
                f"{request.action_id} is Tier 0 (read-only) and has nothing to approve; "
                "Tier 0 is autonomous by definition (ground rule #5)."
            )

        pending = PendingApproval(
            incident_id=incident_id,
            request=request,
            declared_tier=spec.tier,
            tier=tier,
            escalation_reason=reason,
            dry_run=request.dry_run(evidence=evidence, catalog=self._catalog),
            evidence=evidence,
        )
        # Re-registering an incident/action that has already been decided would post a fresh
        # card for a mutation that already ran. The idempotency table is the authority.
        if pending.key in self._outcomes:
            raise AlreadyDecided(self._outcomes[pending.key])

        self._pending[pending.key] = pending
        return pending

    def pending(self, incident_id: str, action_id: str) -> PendingApproval:
        try:
            return self._pending[(incident_id, action_id)]
        except KeyError:
            raise NotAwaitingApproval(
                f"no approval is open for {action_id!r} on {incident_id!r}. The card was "
                "either built by another process or not built by this application at all; "
                "the action is not reconstructed from the callback (Handoff §9)."
            ) from None

    def outcome(self, incident_id: str, action_id: str) -> Outcome | None:
        return self._outcomes.get((incident_id, action_id))

    # -- decision ----------------------------------------------------------------------

    def decide(
        self,
        *,
        incident_id: str,
        action_id: str,
        approver: Approver,
        kind: Literal["approve", "reject"],
    ) -> Outcome:
        """Route one human decision, and execute at most once.

        Order is the unit. Idempotency is checked **before** the role check and before a
        credential is minted, so a replay cannot mint a second credential even if the
        approver, the roster or the thresholds changed between the two clicks. The role
        check then runs **before** minting, so a refused approver never causes a credential
        to exist at all.
        """
        key = (incident_id, action_id)

        # 1. Replay. Returned rather than raised: a second click is a human being human,
        #    and the useful answer is what the first click did.
        decided = self._outcomes.get(key)
        if decided is not None:
            return decided.model_copy(update={"replay": True})

        pending = self.pending(incident_id, action_id)

        if kind == "reject":
            return self._record(pending, approver, decision="rejected")

        # 2. Tier routing (W26b). Raises rather than recording — see `ApproverNotPermitted`.
        if not approver.role.clears(pending.tier):
            raise ApproverNotPermitted(
                f"{action_id} runs at tier {int(pending.tier)} and requires a "
                f"{ApproverRole.MANAGER.value} approval; {approver.user_id} is "
                f"{approver.role.value}."
                + (f" It escalated because {pending.escalation_reason}." if pending.escalation_reason else "")
            )

        # 3. Mint. This module is allowlisted in `credentials.MINTING_MODULES`; the call is
        #    direct rather than wrapped because the gate reads the *immediate* caller's
        #    frame, and a helper here would put that helper's module in the check instead.
        credential = mint_actor_credential(
            incident_id=incident_id,
            action_id=action_id,
            namespace=pending.scope,
            sts_client=self._sts_client,
            role_arn=self._role_arn,
        )

        try:
            result = self._runner(pending.request, credential, pending.evidence)
        except Exception as exc:
            # Recorded as a decision even though it failed, so a retry does not re-run a
            # mutation that may have partially landed. A failed mutation that has to be
            # retried by hand is recoverable; a silently doubled one is not.
            return self._record(
                pending, approver, decision="approved", error=f"{type(exc).__name__}: {exc}"
            )

        return self._record(pending, approver, decision="approved", result=result)

    # -- internals ---------------------------------------------------------------------

    def _record(
        self,
        pending: PendingApproval,
        approver: Approver,
        *,
        decision: Literal["approved", "rejected"],
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> Outcome:
        outcome = Outcome(
            incident_id=pending.incident_id,
            action_id=pending.action_id,
            decision=decision,
            approver=approver.user_id,
            tier=pending.tier,
            escalation_reason=pending.escalation_reason,
            decided_at=datetime.now(timezone.utc),
            executed=decision == "approved" and error is None,
            result=result or {},
            error=error,
        )
        self._outcomes[pending.key] = outcome
        # The card is closed either way. Leaving it pending after a decision would let a
        # later click find an open approval for an action that has already run.
        self._pending.pop(pending.key, None)
        return outcome
