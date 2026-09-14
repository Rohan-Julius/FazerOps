"""The automation layer, assembled — one object, and one path from an alert to a human's approval.

Every piece of the automation layer was built, tested and injected by tests: the proposer node,
the approval gateway, the Slack sink — and Phase G's hooks into them, the decline recorder
(W40), the outcome observer (W40), the graduation count (W45) and the one-shot book (W44).
Nothing in production put them together, so a proposal never reached the gateway outside a test
and nothing was ever mined. `Automation` puts them together once, and its two entrypoints are
`actions/server.py` (alerts in, cards out, clicks back) and `python -m fazerops.actions.growth`
(the continuous job).

**State that must outlive the process is on disk** under one directory: the ledger, which the
miner reads and the outcome observer resolves evidence ids against, and the gap signal store
with its demonstration corpus. **State that must not outlive it stays in memory**: the gateway's
open cards and the one-shot book, for `ApprovalGateway`'s reason — a card from a dead process
refuses rather than being reconstructed from a click.

**Automation layer** (plan §3.5). `main.py` and `agentcore_app.py` are Tier 0 and import none of
this; `tests/integration/test_layer_seam.py` holds them to it.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..ledger.chain import LedgerIntegrityError
from ..ledger.store import LedgerStore
from ..models import Alert, Brief
from .approval import ApprovalGateway, ApprovalRefused, PendingApproval
from .decision_log import DecisionLog
from .growth.lifecycle import graduation_progress
from .growth.one_shot import OneShotBook, OneShotOutcome
from .growth.signals import GapSignalStore, outcome_observer

__all__ = ["Automation", "DEFAULT_STATE_DIR", "Response", "STATE_DIR_ENV"]

STATE_DIR_ENV = "FAZEROPS_STATE_DIR"

logger = logging.getLogger(__name__)
DEFAULT_STATE_DIR = Path(".fazerops")


@dataclass
class Response:
    """What one alert produced. `pending` holds every card that opened; `refused` every one the
    gateway would not open, in its own words — an alert that re-fires after its action ran is
    refused, and that is worth saying rather than dropping."""

    brief: Brief
    proposal: Any | None = None
    one_shot: OneShotOutcome | None = None
    pending: list[PendingApproval] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)


@dataclass
class Automation:
    ledger: LedgerStore
    signals: GapSignalStore
    gateway: ApprovalGateway
    one_shots: OneShotBook
    state_dir: Path
    # B1: every click and `/fazerops` command, refusals included (`decision_log.py`).
    decisions: DecisionLog | None = None
    # In memory for the gateway's reason: open cards die with the process, and so does what they
    # were drafted from. `/fazerops` reads these (B2); the incident record is built from them (B3).
    briefs: dict[str, Brief] = field(default_factory=dict)
    proposals: dict[str, Any] = field(default_factory=dict)
    threads: dict[str, tuple[str, str]] = field(default_factory=dict)
    cards: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)
    # Called with `(pending, outcome)` after the gateway records a decision — never on a replay.
    decided_hooks: list[Callable[[PendingApproval, Any], Any]] = field(default_factory=list)

    @classmethod
    def assemble(
        cls,
        *,
        state_dir: Path | str | None = None,
        catalog: Any | None = None,
        runner: Callable[..., Any] | None = None,
        sandbox: Callable[[], Any] | None = None,
        meter: Any | None = None,
        cassette_directory: Any | None = None,
        sts_client: Any | None = None,
        role_arn: str | None = None,
    ) -> Automation:
        root = Path(state_dir or os.environ.get(STATE_DIR_ENV) or DEFAULT_STATE_DIR)
        ledger = LedgerStore(root / "ledger.jsonl")
        signals = GapSignalStore(root / "gap_signals.jsonl")
        hooks: list[Callable[[PendingApproval, Any], Any]] = []
        gateway = ApprovalGateway(
            catalog=catalog,
            runner=runner,
            sts_client=sts_client,
            role_arn=role_arn,
            observer=_observers(outcome_observer(signals, ledger), hooks),
            graduation=graduation_progress(signals, ledger),
        )
        one_shots = OneShotBook(catalog=catalog, sandbox=sandbox, meter=meter, cassette_directory=cassette_directory)
        return cls(
            ledger=ledger,
            signals=signals,
            gateway=gateway,
            one_shots=one_shots,
            state_dir=root,
            decisions=DecisionLog(root / "decisions.jsonl"),
            decided_hooks=hooks,
        )

    def proposer_node(self, state: Any) -> Any:
        from ..agents.proposer import proposer_node

        return proposer_node(state, signals=self.signals, one_shots=self.one_shots)

    async def respond(self, alert: Alert, *, collectors: list[Any] | None = None) -> Response:
        """Investigate, propose, and open whatever card the result calls for.

        The proposal and the one-shot are exclusive by construction: a one-shot is offered only
        after the proposer declined (W44, `docs/catalog_self_extension.md` §4).
        """
        from ..agents.graph import investigate_via_graph
        from .preconditions import Evidence

        states: list[Any] = []

        def node(state: Any) -> Any:
            states.append(state)
            return self.proposer_node(state)

        brief, _ = await investigate_via_graph(alert, collectors=collectors, proposer_node=node)

        state = states[0] if states else None
        response = Response(
            brief=brief,
            proposal=getattr(state, "proposal", None),
            one_shot=getattr(state, "one_shot", None),
        )
        try:
            self.ledger.extend(candidate.event for candidate in brief.candidates)
        except LedgerIntegrityError as exc:
            # The brief is Tier 0 and still posts. A ledger that cannot be appended to honestly
            # (signed, and this process lacks the key) is refused loudly, not silently unsigned.
            response.refused.append(f"not recorded in the ledger: {exc}")
        self._remember(brief, response.proposal)
        evidence = Evidence.from_brief(brief)

        if response.proposal is not None:
            try:
                response.pending.append(
                    self.gateway.register(
                        brief.incident_id,
                        _request_for(response.proposal, brief),
                        evidence=evidence,
                        evidence_ids=response.proposal.evidence_ids,
                    )
                )
            except ApprovalRefused as exc:
                response.refused.append(str(exc))

        if response.one_shot is not None and response.one_shot.offered:
            one_shot = response.one_shot.one_shot
            try:
                response.pending.append(
                    self.gateway.register_one_shot(one_shot, evidence=evidence, evidence_ids=(one_shot.event_id,))
                )
            except ApprovalRefused as exc:
                response.refused.append(str(exc))

        return response

    async def follow_coverage(
        self,
        brief: Brief,
        on_update: Callable[[Any], Any],
        *,
        collectors: list[Any] | None = None,
        poll_seconds: float | None = None,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        now: Callable[[], datetime] | None = None,
    ) -> Brief:
        """Follow the brief's open coverage gaps to their close (`coverage.watch_coverage`),
        recording every late change in the durable ledger and handing each update to `on_update`.

        The brief was already posted; nothing here holds it. Returns the last brief — the one it
        started with when nothing changed.
        """
        from ..coverage import POLL_SECONDS, watch_coverage

        latest = brief
        async for update in watch_coverage(
            brief, collectors=collectors, poll_seconds=poll_seconds or POLL_SECONDS, sleep=sleep, now=now
        ):
            if update.late_event_ids:
                late = set(update.late_event_ids)
                try:
                    self.ledger.extend(c.event for c in update.brief.candidates if c.event.id in late)
                except LedgerIntegrityError:
                    logger.exception("late changes for %s were not recorded in the ledger", brief.incident_id)
            self.briefs[update.brief.incident_id] = update.brief
            on_update(update)
            latest = update.brief
        return latest

    def incident_session(self, pending: PendingApproval, outcome: Any) -> Any:
        """The `IncidentSession` for a recorded decision (B3), or `None` for an incident this process
        did not investigate. Built from what the process holds, never from the Slack payload."""
        from ..models import Proposal
        from ..record.session import IncidentSession

        brief = self.briefs.get(outcome.incident_id)
        if brief is None:
            return None
        proposal = self.proposals.get(outcome.incident_id)
        session = IncidentSession.from_brief(brief, proposal=proposal if isinstance(proposal, Proposal) else None)
        session = session.with_approval(outcome.approval_record())
        inverse = outcome.result.get("inverse") if isinstance(outcome.result, dict) else None
        execution = outcome.execution_record(inverse=inverse if isinstance(inverse, dict) else None)
        return session if execution is None else session.with_execution(execution)

    def _remember(self, brief: Brief, proposal: Any) -> None:
        self.briefs[brief.incident_id] = brief
        if proposal is not None:
            self.proposals[brief.incident_id] = proposal
        # Bounded: a long-running server sees many incidents, and only recent ones are ever asked about.
        for store in (self.briefs, self.proposals):
            while len(store) > MAX_REMEMBERED:
                store.pop(next(iter(store)))


MAX_REMEMBERED = 500


def _observers(first: Callable[[PendingApproval, Any], Any], hooks: list[Callable[[PendingApproval, Any], Any]]):
    """One gateway observer that tells the growth observer and then every hook. Each is isolated: a
    record upload that fails must not stop the gap miner hearing about the outcome, or vice versa."""

    def observe(pending: PendingApproval, outcome: Any) -> None:
        for hook in (first, *hooks):
            try:
                hook(pending, outcome)
            except Exception:  # noqa: BLE001 - the decision is already recorded
                logger.exception("an outcome hook failed for %s on %s", outcome.action_id, outcome.incident_id)

    return observe


def _request_for(proposal: Any, brief: Brief) -> Any:
    """The proposal as an executable request (`inverse.request_for_proposal`)."""
    from .inverse import request_for_proposal

    return request_for_proposal(proposal, brief.candidates)
