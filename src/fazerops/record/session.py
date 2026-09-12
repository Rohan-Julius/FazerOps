"""W29 — the session state AgentCore persists. Handoff §10.

> *State to persist: incident id, alert, resolved blast radius, collected events, scored
> candidates, proposal, approval decision and approver, execution result. **That state is
> exactly the incident record's input.***

That last sentence is why this module lives in `record/` rather than next to the AgentCore
entrypoint: the session state and the incident record's input are the same object, and
building two would guarantee they drift. W28 reads `IncidentSession` to generate the
markdown; AgentCore reads it to persist a run.

**Every field is optional after `incident_id` and `alert`, on purpose.** A session is
written at each stage, not once at the end, so a run that failed during collection still
persists what it knew — the state exists to survive the run, and one that only serializes
on success is a state that is never there when it is wanted.

**The session is a record, not a channel.** Nothing reads it back to make a decision: the
approval handler re-derives an action from the catalog rather than from a stored proposal,
so a tampered stored session cannot cause a mutation. It is written and read by humans and
by `record/generate.py`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from ..models import Alert, BlastRadius, Brief, Candidate, ChangeEvent, Proposal, TimeWindow

__all__ = ["ApprovalRecord", "ExecutionRecord", "IncidentSession"]


class ApprovalRecord(BaseModel):
    """Who decided what, and when. Handoff §10's "approval decision and approver".

    `approver` is the Slack user id rather than a display name: a name is re-assignable and
    an id is not, and this is the field an audit reads to answer who authorized a mutation.
    `tier` records what the approval was *sought at*, so a Tier 2 escalation stays legible
    in the record after the fact (W26b).
    """

    model_config = ConfigDict(frozen=True)

    decision: Literal["approved", "rejected"]
    approver: str
    approved_at: AwareDatetime
    action_id: str
    tier: int
    escalation_reason: str | None = None


class ExecutionRecord(BaseModel):
    """What actually happened when the action ran. Handoff §10's "execution result".

    `inverse` is stored alongside the result because the moment someone reads this record
    is the moment they may want to undo it, and recomputing an inverse from state that has
    since moved on is how you undo the wrong thing.
    """

    model_config = ConfigDict(frozen=True)

    action_id: str
    succeeded: bool
    executed_at: AwareDatetime
    result: dict[str, Any] = Field(default_factory=dict)
    inverse: dict[str, Any] | None = None
    error: str | None = None


class IncidentSession(BaseModel):
    """One incident, end to end. Handoff §10's persisted state, in its order.

    JSON-serializable throughout — AgentCore requires a JSON-serializable response
    (plan §1.1), and `tests/integration/test_layer_seam.py` already asserts a `Brief` is.
    """

    model_config = ConfigDict(frozen=True)

    incident_id: str
    alert: Alert
    radius: BlastRadius | None = None
    window: TimeWindow | None = None
    events: list[ChangeEvent] = Field(
        default_factory=list,
        description="Everything the collectors returned, before scoring. Kept separate "
        "from `candidates` because the record has to be able to show what was *looked at* "
        "and not only what ranked — 'nothing else changed' is a claim that needs evidence.",
    )
    candidates: list[Candidate] = Field(default_factory=list)
    narrative: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    proposal: Proposal | None = None
    approval: ApprovalRecord | None = None
    execution: ExecutionRecord | None = None
    degraded: bool = False
    created_at: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_brief(
        cls,
        brief: Brief,
        *,
        events: list[ChangeEvent] | None = None,
        proposal: Proposal | None = None,
    ) -> IncidentSession:
        """Build the session a completed investigation produced.

        Takes the `Brief` — the seam's contract (plan §3.5) — plus the optional automation
        results, so an investigation-only run persists a complete session with the
        automation fields simply empty. That is the Tier 0 product, and it must be
        recordable without the automation layer having run at all.
        """
        return cls(
            incident_id=brief.incident_id,
            alert=brief.alert,
            radius=brief.radius,
            window=brief.window,
            events=list(events or [candidate.event for candidate in brief.candidates]),
            candidates=list(brief.candidates),
            narrative=brief.narrative,
            evidence_ids=list(brief.evidence_ids),
            proposal=proposal,
            degraded=brief.degraded,
        )

    @property
    def stage(self) -> str:
        """How far this incident got, for a human scanning a list of sessions.

        Derived rather than stored: a stored stage is a second source of truth that goes
        stale the moment a field is set without it being updated.
        """
        if self.execution is not None:
            return "executed" if self.execution.succeeded else "execution_failed"
        if self.approval is not None:
            return self.approval.decision
        if self.proposal is not None:
            return "proposed"
        if self.candidates:
            return "investigated"
        return "opened"

    def with_approval(self, approval: ApprovalRecord) -> IncidentSession:
        return self.model_copy(update={"approval": approval})

    def with_execution(self, execution: ExecutionRecord) -> IncidentSession:
        return self.model_copy(update={"execution": execution})
