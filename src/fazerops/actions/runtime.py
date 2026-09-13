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

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..ledger.store import LedgerStore
from ..models import Alert, Brief
from .approval import ApprovalGateway, ApprovalRefused, PendingApproval
from .growth.lifecycle import graduation_progress
from .growth.one_shot import OneShotBook, OneShotOutcome
from .growth.signals import GapSignalStore, outcome_observer

__all__ = ["Automation", "DEFAULT_STATE_DIR", "Response", "STATE_DIR_ENV"]

STATE_DIR_ENV = "FAZEROPS_STATE_DIR"
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
        gateway = ApprovalGateway(
            catalog=catalog,
            runner=runner,
            sts_client=sts_client,
            role_arn=role_arn,
            observer=outcome_observer(signals, ledger),
            graduation=graduation_progress(signals, ledger),
        )
        one_shots = OneShotBook(catalog=catalog, sandbox=sandbox, meter=meter, cassette_directory=cassette_directory)
        return cls(ledger=ledger, signals=signals, gateway=gateway, one_shots=one_shots, state_dir=root)

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
        self.ledger.extend(candidate.event for candidate in brief.candidates)

        state = states[0] if states else None
        response = Response(
            brief=brief,
            proposal=getattr(state, "proposal", None),
            one_shot=getattr(state, "one_shot", None),
        )
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


def _request_for(proposal: Any, brief: Brief) -> Any:
    """The proposal as an executable request, carrying the hint its cited change recorded.

    The hint is taken from the ledger's event, never from the proposal: it holds the prior and
    current values the inverse and the dry run are computed from.
    """
    from .inverse import ActionRequest

    events = {candidate.event.id: candidate.event for candidate in brief.candidates}
    hint = next(
        (
            events[event_id].inverse_hint
            for event_id in proposal.evidence_ids
            if event_id in events and (events[event_id].inverse_hint or {}).get("action_id") == proposal.action_id
        ),
        None,
    )
    return ActionRequest.for_action(proposal.action_id, dict(proposal.params), inverse_hint=hint)
