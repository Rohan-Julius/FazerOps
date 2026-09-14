"""W26 — approval routing, tier promotion and idempotency. Handoff §7 and §8.

This module is where a human's decision becomes a mutation, and it is the only such place.
`slack/handlers.py` parses a click into a `Decision` and hands the identifiers here; this
module re-derives everything else. **Nothing a Slack payload carried is used to name a
namespace, a resource or a target value** — those come from the `PendingApproval` this
module registered before the card was ever posted.

Four properties hold structurally rather than by care:

1. **A replay executes once.** Outcomes are keyed `(incident_id, action_id)`, first-write-
   wins, and the key is checked and **claimed under a lock** before a credential is minted.
   A double-clicked button, a Slack retry and a resent payload are all the same event to this
   module — including when they arrive at the same moment on two listener threads.
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

import logging
import threading
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..models import Tier
from ..record.session import ApprovalRecord, ExecutionRecord
from ..security.credentials import mint_actor_credential, requires_aws
from .catalog import Catalog, default_catalog, promote
from .dry_run import DryRun
from .inverse import ActionRequest

__all__ = [
    "AlreadyDecided",
    "ApprovalExpired",
    "ApprovalGateway",
    "ApprovalRefused",
    "Approver",
    "ApproverNotPermitted",
    "ApproverRole",
    "NotAwaitingApproval",
    "Outcome",
    "PendingApproval",
    "StaleCard",
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


class StaleCard(ApprovalRefused):
    """The clicked card showed a different dry run from the one this module now holds.

    A re-registration for the same `(incident, action)` replaces the pending entry — newer
    evidence wins — and the older card must not approve the newer diff (drift log, 14 Sep, D1).
    **Records no outcome**, like `ApproverNotPermitted`: the current card stays approvable.
    """


class ApprovalExpired(ApprovalRefused):
    """The card has been open longer than `thresholds.yaml`'s `approval.expires_after_seconds`.

    Preconditions are evaluated against the evidence the investigation collected, never the live
    cluster, so a late approval would execute against stale evidence. **Records no outcome**:
    re-investigating opens a fresh card for the same key.
    """


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
    provisional: bool = Field(
        default=False,
        description="A merged generated action (W45). A separate axis from `tier`: it requires "
        "a manager approval and never changes the tier shown or recorded.",
    )
    graduation: tuple[int, int] | None = Field(
        default=None,
        description="`(confirmed, required)` for a provisional action — the card's `generated, n/N`.",
    )
    one_shot: Any = Field(
        default=None,
        description="A W44 `OneShot`: an action built for this incident and not in the catalog. "
        "Its writer is resolvable only inside `one_shot.context()`.",
    )
    dry_run: DryRun
    evidence: Any = None
    evidence_ids: tuple[str, ...] = Field(
        default=(),
        description="The ledger events the proposal cited. Read only by an outcome observer "
        "(W40), never to decide what executes.",
    )
    registered_at: float = Field(default_factory=time.time)
    expires_at: float | None = Field(
        default=None, description="Epoch seconds after which `decide()` refuses; `None` never expires."
    )

    @property
    def action_id(self) -> str:
        return self.request.action_id

    @property
    def digest(self) -> str:
        """The dry run's digest — what the card carries and `decide()` compares."""
        return self.dry_run.digest

    @property
    def key(self) -> tuple[str, str]:
        return (self.incident_id, self.action_id)

    @property
    def scope(self) -> str:
        return scope_of(self.request)

    @property
    def escalated(self) -> bool:
        return self.tier > self.declared_tier

    @property
    def requires_manager(self) -> bool:
        return self.tier is Tier.MANAGER_APPROVAL or self.provisional


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

# Told about each decision once it is recorded — never about a replay, which never reaches
# `_record`. Phase G's gap miner listens here (W40): a rejection is the only signal of a gap
# the model papered over instead of declining (`docs/catalog_self_extension.md` §2).
OutcomeObserver = Callable[["PendingApproval", "Outcome"], None]

logger = logging.getLogger(__name__)


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
        observer: OutcomeObserver | None = None,
        graduation: Callable[[str], tuple[int, int]] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._catalog = catalog if catalog is not None else default_catalog()
        self._clock = clock if clock is not None else time.time
        self._runner = runner if runner is not None else _default_runner
        self._sts_client = sts_client
        self._role_arn = role_arn
        self._observer = observer
        # W45's `growth.lifecycle.graduation_progress`. Read for the card only: whether an
        # action is provisional comes from the catalog, never from this count.
        self._graduation = graduation
        self._pending: dict[tuple[str, str], PendingApproval] = {}
        self._outcomes: dict[tuple[str, str], Outcome] = {}
        # Keys a `decide()` is running for right now. The outcome table alone cannot stop a double
        # execution: nothing is written to it until the mutation has finished, and Slack's Socket
        # Mode client hands two deliveries of one click to two pool threads at once. The condition
        # lets a second caller wait for the first's outcome instead of polling for it.
        self._deciding: set[tuple[str, str]] = set()
        self._decided = threading.Condition()

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
        evidence_ids: Iterable[str] = (),
    ) -> PendingApproval:
        """Compute the effective tier, render the dry run, and open the card.

        The promotion inputs are arguments rather than read from the request, because they
        are properties of the *incident* — how many resources this blast radius touches,
        whether it crosses a namespace — and the request only knows about one resource.
        """
        spec = self._catalog.get(request.action_id)  # UnknownAction; there is no fallback
        if spec.retired:
            raise ApprovalRefused(
                f"{request.action_id} is retired. It stays resolvable for the incident records "
                "that cite it, and is never proposed or run again (§7.6)."
            )
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
        if requires_aws(request.action_id) and self._runner is _default_runner and self._sts_client is None and self._role_arn is None:
            # Refused before a card exists rather than after a click. The executor refuses too, but by
            # then the approval is spent; a card that can only fail should never reach a human.
            raise ApprovalRefused(
                f"{request.action_id} calls AWS and no actor role is configured (FAZEROPS_ACTOR_ROLE_ARN), "
                "so it could only run as this process's own AWS identity. No card was opened."
            )

        registered_at = self._clock()
        pending = PendingApproval(
            incident_id=incident_id,
            request=request,
            declared_tier=spec.tier,
            tier=tier,
            registered_at=registered_at,
            expires_at=self._expiry(registered_at),
            escalation_reason=reason,
            dry_run=request.dry_run(evidence=evidence, catalog=self._catalog),
            evidence=evidence,
            evidence_ids=tuple(evidence_ids),
            provisional=spec.provisional,
            graduation=(
                self._graduation(spec.id)
                if spec.provisional and self._graduation is not None
                else None
            ),
        )
        return self._open(pending)

    def register_one_shot(
        self,
        one_shot: Any,
        *,
        evidence: Any = None,
        evidence_ids: Iterable[str] = (),
    ) -> PendingApproval:
        """Open the card for a W44 one-shot, keyed on `(incident, resource, field)`.

        The idempotency key is `(incident_id, action_id)` as for every action, and that is only
        the triple §7.5 requires because the id is **recomputed here** from the resource the
        request names and the writer's field — a one-shot whose id was minted any other way is
        refused, so two generations for one resource cannot open two cards that each execute.
        """
        from .growth.one_shot import one_shot_action_id

        request = one_shot.request
        if request.action_id in self._catalog:
            raise ApprovalRefused(f"{request.action_id} is a catalog action; a one-shot may not shadow one")
        expected = one_shot_action_id(
            one_shot.writer.resource(request.params).blast_radius_key(), one_shot.writer.field_path
        )
        if request.action_id != expected or one_shot.key.action_id != expected:
            raise ApprovalRefused(
                f"{request.action_id} is not keyed on the resource and field it restores; a one-shot "
                "is keyed on (incident, resource, field), never on a per-generation id (§7.5)"
            )
        if not one_shot.containment.contained:
            raise ApprovalRefused(
                f"{request.action_id} was not contained in its sandbox ({one_shot.containment.verdict.value}); "
                "only a contained one-shot reaches a human (§6)"
            )

        catalog = one_shot.catalog(self._catalog)
        spec = catalog.get(request.action_id)
        with one_shot.context():
            dry_run = request.dry_run(evidence=evidence, catalog=catalog)

        registered_at = self._clock()
        pending = PendingApproval(
            incident_id=one_shot.key.incident_id,
            request=request,
            declared_tier=spec.tier,
            tier=spec.tier,
            registered_at=registered_at,
            expires_at=self._expiry(registered_at),
            dry_run=dry_run,
            evidence=evidence,
            evidence_ids=tuple(evidence_ids),
            one_shot=one_shot,
        )
        return self._open(pending)

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

    def open_cards(self, incident_id: str) -> list[PendingApproval]:
        """Every undecided card for one incident — for `/fazerops status`, which only reads."""
        return [pending for key, pending in self._pending.items() if key[0] == incident_id]

    def outcomes_for(self, incident_id: str) -> list[Outcome]:
        return [outcome for key, outcome in self._outcomes.items() if key[0] == incident_id]

    def is_expired(self, pending: PendingApproval) -> bool:
        return self._expired(pending)

    # -- decision ----------------------------------------------------------------------

    def decide(
        self,
        *,
        incident_id: str,
        action_id: str,
        approver: Approver,
        kind: Literal["approve", "reject"],
        dry_run_digest: str | None = None,
    ) -> Outcome:
        """Route one human decision, and execute at most once.

        Order is the unit. Idempotency is checked **before** the role check and before a
        credential is minted, so a replay cannot mint a second credential even if the
        approver, the roster or the thresholds changed between the two clicks. The role
        check then runs **before** minting, so a refused approver never causes a credential
        to exist at all.

        `dry_run_digest` is what the clicked card carried. The Slack sink always passes it
        (`parse_decision` refuses an Approve or Reject without one); `None` is for an in-process
        caller holding the `PendingApproval` itself, which cannot have seen a stale card. The
        digest and expiry checks run after the replay check — a replay answers with the first
        outcome whatever card it came from — and before either decision is recorded, so a stale
        or expired click changes nothing.

        **Concurrent calls for one key run one at a time.** The key is claimed under a lock before
        anything else; a second caller waits for the claim to be released and then answers from
        the outcome as a replay. A call that records nothing — a refusal, or a mint that raised —
        releases the claim with no outcome, and the waiter then decides for itself, so a failure
        that ran nothing never blocks the retry.
        """
        key = (incident_id, action_id)

        # 1. Replay, and the claim. Returned rather than raised: a second click is a human being
        #    human, and the useful answer is what the first click did — so a click that arrives
        #    while the first is still executing waits for that answer rather than being refused.
        with self._decided:
            while True:
                decided = self._outcomes.get(key)
                if decided is not None:
                    return decided.model_copy(update={"replay": True})
                if key not in self._deciding:
                    self._deciding.add(key)
                    break
                self._decided.wait()

        try:
            return self._decide_claimed(
                incident_id=incident_id,
                action_id=action_id,
                approver=approver,
                kind=kind,
                dry_run_digest=dry_run_digest,
            )
        finally:
            # Released whatever happened. The outcome, if any, is already in the table, so a waiter
            # woken here returns it as a replay; with none, the waiter takes the claim itself.
            with self._decided:
                self._deciding.discard(key)
                self._decided.notify_all()

    def _decide_claimed(
        self,
        *,
        incident_id: str,
        action_id: str,
        approver: Approver,
        kind: Literal["approve", "reject"],
        dry_run_digest: str | None,
    ) -> Outcome:
        """`decide()` past the replay check, with the key claimed by this call alone."""
        pending = self.pending(incident_id, action_id)

        if dry_run_digest is not None and dry_run_digest != pending.digest:
            raise StaleCard(
                f"this card shows an older dry run for {action_id} on {incident_id}; a newer card "
                "replaced it. Nothing was recorded — decide on the newest card."
            )
        if self._expired(pending):
            raise ApprovalExpired(
                f"the approval for {action_id} on {incident_id} expired "
                f"{self._clock() - (pending.expires_at or 0):.0f}s ago; its evidence is too old to act "
                "on. Nothing was recorded — re-investigate to open a fresh card."
            )

        if kind == "reject":
            return self._record(pending, approver, decision="rejected")

        # 2. Tier routing (W26b). Raises rather than recording — see `ApproverNotPermitted`.
        #    A provisional action (W45) routes here too, without its tier changing.
        if pending.requires_manager and approver.role is not ApproverRole.MANAGER:
            if pending.provisional and pending.tier is not Tier.MANAGER_APPROVAL:
                why = (
                    " It is a provisional generated action, which needs a manager approval "
                    "every time until it graduates (W45)."
                )
            elif pending.escalation_reason:
                why = f" It escalated because {pending.escalation_reason}."
            else:
                why = ""
            refusal = ApproverNotPermitted(
                f"{action_id} runs at tier {int(pending.tier)} and requires a "
                f"{ApproverRole.MANAGER.value} approval; {approver.user_id} is "
                f"{approver.role.value}." + why
            )
            # The message is for the decision log; these let Slack say the same thing in words
            # (`slack.handlers._refusal`) without parsing it.
            refusal.escalation_reason = pending.escalation_reason
            refusal.provisional = pending.provisional and pending.tier is not Tier.MANAGER_APPROVAL
            refusal.one_shot = pending.one_shot is not None
            raise refusal

        # 3. Mint. This module is allowlisted in `credentials.MINTING_MODULES`; the call is
        #    direct rather than wrapped because the gate reads the *immediate* caller's
        #    frame, and a helper elsewhere would put that helper's module in the check instead.
        credential = mint_actor_credential(
            incident_id=incident_id,
            action_id=action_id,
            namespace=pending.scope,
            sts_client=self._sts_client,
            role_arn=self._role_arn,
            approver=approver.user_id,
        )

        try:
            result = self._run(pending, credential)
        except Exception as exc:
            # Recorded as a decision even though it failed, so a retry does not re-run a
            # mutation that may have partially landed. A failed mutation that has to be
            # retried by hand is recoverable; a silently doubled one is not.
            return self._record(
                pending, approver, decision="approved", error=f"{type(exc).__name__}: {exc}"
            )

        return self._record(pending, approver, decision="approved", result=result)

    # -- internals ---------------------------------------------------------------------

    def _open(self, pending: PendingApproval) -> PendingApproval:
        """Put a card in the table, or say why not.

        Re-registering a pair that has already been decided would post a fresh card for a
        mutation that already ran, so the idempotency table is checked first. An identical,
        unexpired dry run is the same card and is returned as it is. A *different* one replaces
        the entry: the newer evidence is what a human should decide on, and the older card's
        digest no longer matches, so `decide()` refuses it as `StaleCard` instead of executing a
        diff nobody read on it.
        """
        if pending.key in self._outcomes:
            raise AlreadyDecided(self._outcomes[pending.key])
        open_card = self._pending.get(pending.key)
        if open_card is not None and open_card.digest == pending.digest and not self._expired(open_card):
            return open_card
        self._pending[pending.key] = pending
        return pending

    def _expiry(self, registered_at: float) -> float | None:
        limit = self._catalog.approval.expires_after_seconds
        return None if limit is None else registered_at + limit

    def _expired(self, pending: PendingApproval) -> bool:
        return pending.expires_at is not None and self._clock() >= pending.expires_at

    def _run(self, pending: PendingApproval, credential: Any) -> dict[str, Any]:
        if pending.one_shot is None:
            return self._runner(pending.request, credential, pending.evidence)
        # A one-shot's action and writer exist only for this block.
        with pending.one_shot.context():
            if self._runner is not _default_runner:
                return self._runner(pending.request, credential, pending.evidence)
            return pending.request.execute(
                credential, evidence=pending.evidence, catalog=pending.one_shot.catalog(self._catalog)
            )

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
        self._notify(pending, outcome)
        return outcome

    def _notify(self, pending: PendingApproval, outcome: Outcome) -> None:
        """Tell the observer, and never let it change the answer.

        The outcome is already recorded when this runs. An observer that raised through
        `decide()` would make an executed mutation look like a failed call — and a failed
        call is what a caller retries.
        """
        if self._observer is None:
            return
        try:
            self._observer(pending, outcome)
        except Exception:
            logger.exception(
                "outcome observer failed for %s on %s; the decision stands",
                outcome.action_id,
                outcome.incident_id,
            )
