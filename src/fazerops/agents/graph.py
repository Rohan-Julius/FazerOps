"""W19 — the Strands `Graph` topology, and the reusable `FunctionNode` adapter. Plan §3.2.

```
orchestrator (Agent) ──▶ ┌ cloudtrail  (FunctionNode) ┐
                         │ k8s_audit   (FunctionNode) │ one batch,
                         │ helm        (FunctionNode) │ concurrent
                         └ github      (FunctionNode) ┘
                                     │
                                     ▼
                         correlator (Agent) ──▶ proposer (Agent)
```

**Why a state object rather than the task string.** A Strands Graph passes a *task* between
nodes — text. The collectors need a `BlastRadius` and a `TimeWindow`, and serializing those
into the task and re-parsing them downstream would put a parser between the orchestrator's
typed decision and the query that acts on it. That parser is precisely what ground rule #1
forbids: a resource identifier reconstructed from text in the model's conversation. So the
graph carries control flow and `InvestigationState` carries the typed objects, exactly as
`OrchestrationSession` carries the handles inside W19b.

**Why the collectors are not agents** is settled in plan §3.2a and not re-argued here: it
would 6× the token bill, make W15's golden ranking test capable of flaking, and put a model
in the normalization path where a mistyped timestamp surfaces three layers away. Every node
below is a Strands object scheduled by the Strands Graph; only some of them call a model.

**Known limitation, accepted** (§3.2): Python's Graph runs independent nodes in discrete
batches with a barrier — the batch does not retire until its slowest node does, so a
rate-limited CloudTrail call gates correlation even after the K8s collector returned in
milliseconds. `set_node_timeout()` bounds the pathological case. TypeScript has
`maxConcurrency`; Python has no such knob.

Investigation layer: imports nothing from `actions/`, `slack/handlers.py` or
`security/credentials.py` (plan §3.5).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from strands.agent.agent_result import AgentResult
from strands.multiagent.base import MultiAgentBase, MultiAgentResult, NodeResult, Status
from strands.telemetry.metrics import EventLoopMetrics

from ..collectors.base import Collector, CollectorResult
from ..models import Alert, Brief, CIStatus, incident_id_for
from .orchestrator import OrchestrationSession, Plan

__all__ = [
    "COLLECTOR_NODES",
    "GRAPH_TIMEOUT_MULTIPLE",
    "NODE_TIMEOUT_SECONDS",
    "ORCHESTRATOR_TIMEOUT_SECONDS",
    "FunctionNode",
    "InvestigationState",
    "build_investigation_graph",
    "investigate_via_graph",
]

# One slow source must not hold the barrier open indefinitely (§3.2). Generous rather than
# tight: this is a stop for a hung socket, not a latency budget, and a collector killed
# mid-flight costs the brief a whole source.
NODE_TIMEOUT_SECONDS = 30.0

# **The graph's own timeout is a backstop, not the mechanism** — discovered 11 Sep by
# writing the test before believing the docs. `set_node_timeout()` does not degrade a node:
# Strands raises `Node 'github' execution timed out`, cancels every sibling task and fails
# the whole graph, which is the exact opposite of plan §4's requirement that one dead source
# degrade the brief. So each `FunctionNode` enforces its own, strictly shorter, timeout and
# absorbs it like any other failure. The graph's remains set, at this multiple, for the case
# the inner one cannot cover: work that never yields to the event loop and so cannot be
# cancelled by `asyncio.wait_for`.
#
# At 2.0 (60 s) a slow Gemini two-turn loop tripped it on 14 Sep and the whole investigation
# failed with no brief, while the orchestrator was a bare `Agent` this was the only bound on.
GRAPH_TIMEOUT_MULTIPLE = 4.0

# **The live orchestrator's own bound** (14 Sep, night — reverses that day's decision to raise the
# backstop rather than wrap the Agent, at the user's request). A throttled Gemini orchestrator
# retried for 124 s, past the backstop, and a 429 that escaped the Agent failed the graph with an
# HTTP 500 and no brief. Inside the node, a timeout or a failure costs the model's choice of scope
# and nothing else: the collectors run on the alert's own service over the default window, and the
# brief says it is degraded. Longer than the 60 s a slow but healthy two-turn loop overran;
# strictly shorter than the graph's backstop, so the node's timeout is always the one that fires.
ORCHESTRATOR_TIMEOUT_SECONDS = 90.0

COLLECTOR_NODES = ("cloudtrail", "k8s_audit", "helm", "github")


class InvestigationState:
    """The typed objects the graph's nodes read and write. See the module docstring for
    why they travel beside the graph rather than inside its task string."""

    def __init__(self, alert: Alert) -> None:
        self.alert = alert
        self.session = OrchestrationSession(alert)
        self.plan: Plan | None = None
        self.results: list[CollectorResult] = []
        self.narrative: Any | None = None
        self.proposal: Any | None = None
        # Set by an injected proposer node after a decline (Phase G, W44). Opaque here, like the
        # proposal: the investigation layer carries it and never reads it.
        self.one_shot: Any | None = None
        self.node_errors: dict[str, str] = {}
        # A `TokenMeter` for a run that calls a model (plan §5), `None` otherwise.
        self.meter: Any | None = None

    @property
    def degraded(self) -> bool:
        return (
            bool(self.node_errors)
            or any(not result.ok for result in self.results)
            or (self.plan is not None and self.plan.degraded)
        )


class FunctionNode(MultiAgentBase):
    """Deterministic Python as a real graph node — the docs' `FunctionNode` pattern
    (plan §1.1), written once and reused for every non-model node in the graph.

    **It never raises.** A node that throws inside a Graph surfaces as an opaque graph
    failure and takes the whole brief down; plan §4's requirement is the opposite — a
    single failing collector must *degrade* the brief. So the exception is caught here,
    recorded by name on the state, and the node retires COMPLETED with a message saying
    what broke. The brief then renders three sources and says the fourth was unavailable,
    which is the honest answer and the one the product exists to give.
    """

    def __init__(
        self,
        name: str,
        fn: Callable[[], Awaitable[str]],
        state: InvestigationState,
        timeout: float | None = None,
    ) -> None:
        super().__init__()
        self.name = name
        self._fn = fn
        self._state = state
        self._timeout = timeout

    async def invoke_async(self, task, invocation_state=None, **kwargs) -> MultiAgentResult:
        try:
            if self._timeout is None:
                summary = await self._fn()
            else:
                # Inside the node on purpose — see GRAPH_TIMEOUT_MULTIPLE. A timeout the
                # graph raises kills the run; one the node catches costs a single source.
                summary = await asyncio.wait_for(self._fn(), timeout=self._timeout)
        except asyncio.TimeoutError:
            self._state.node_errors[self.name] = f"timed out after {self._timeout}s"
            summary = f"{self.name} timed out"
        except Exception as exc:  # noqa: BLE001 - see this class's docstring
            self._state.node_errors[self.name] = f"{type(exc).__name__}: {exc}"
            summary = f"{self.name} failed: {type(exc).__name__}"

        result = AgentResult(
            stop_reason="end_turn",
            message={"role": "assistant", "content": [{"text": summary}]},
            metrics=EventLoopMetrics(),
            state={},
        )
        return MultiAgentResult(
            status=Status.COMPLETED,
            results={self.name: NodeResult(result=result, status=Status.COMPLETED)},
        )


# --------------------------------------------------------------------------------------
# The nodes
# --------------------------------------------------------------------------------------


def _orchestrator_node(state: InvestigationState) -> Any:
    """The orchestrator agent, run through `orchestrate()` inside a bounded `FunctionNode`.

    In a live mode `orchestrate()` builds a real `strands.Agent` with the three typed tools and
    runs it under `Limits(turns=MAX_TURNS)`; in `stub` and `cassette` it builds none. It is the
    correlator's shape — an Agent constructed inside its node — for the same reason: the node
    is where a failure can be absorbed. A bare `Agent` node had no turn cap, no fallback and no
    timeout of its own, so a throttled model failed the whole graph (14 Sep).

    Three bounds, each owned by exactly one layer: the turn cap and the fallback plan by
    `orchestrate()`, which never raises on a model failure; the wall clock by this node's
    `ORCHESTRATOR_TIMEOUT_SECONDS`. A timeout leaves `state.plan` unset, and `_require_plan`
    then builds the plan from whatever the tools had already dispatched, or the fallback scope.
    """
    return FunctionNode(
        "orchestrator", lambda: _run_orchestrator(state), state, timeout=ORCHESTRATOR_TIMEOUT_SECONDS
    )


async def _run_orchestrator(state: InvestigationState) -> str:
    from .orchestrator import orchestrate

    state.plan = await orchestrate(state.alert, session=state.session, meter=state.meter)
    return f"scope: {state.plan.service}, window: {state.plan.window.hours:.0f}h"


def _collector_node(
    collector: Collector, state: InvestigationState, timeout: float | None = None
) -> Any:
    async def run() -> str:
        plan = _require_plan(state)
        result = await collector.fetch(plan.radius, plan.window)
        state.results.append(result)
        return f"{result.source}: {len(result.events)} events"

    return FunctionNode(collector.source, run, state, timeout=timeout)


def _correlator_node(state: InvestigationState) -> Any:
    """The narrative agent. `correlate()` owns the mode switch and the citation validator,
    so the node is a thin wrapper on every path — including the live one, where
    `correlate()` constructs the `Agent` itself in order to reach `structured_output`."""

    async def run() -> str:
        from .correlator import NarrativeRejected, correlate

        brief = _brief_from(state, narrative=None)
        try:
            state.narrative = await correlate(brief, meter=state.meter)
        except NarrativeRejected as exc:
            # Handoff §6: a brief with no explanation is still a ranked, cited list of what
            # changed, which is the product. A wrong explanation is not.
            state.node_errors["correlator"] = str(exc)
            return "narrative rejected"
        return f"narrative: {len(state.narrative.claims)} claims"

    return FunctionNode("correlator", run, state)


def _require_plan(state: InvestigationState) -> Plan:
    """The plan the collectors query against.

    If the orchestrator node was a live `Agent`, its tools wrote handles into the session
    and nothing assembled them into a `Plan` — so that is done here, from the session, by
    the same fallback W19b uses when the turn cap fires. The collectors always have a
    radius and a window; the only question is whether a model chose them.
    """
    if state.plan is not None:
        return state.plan

    from .orchestrator import _fallback_plan

    session = state.session
    if session.dispatched and session.last_radius is not None:
        radius_id, window_id = session.dispatched[-1]
        state.plan = Plan(
            service=session.radii[radius_id].service,
            radius=session.radii[radius_id],
            window=session.windows[window_id],
            dispatched=True,
        )
    else:
        state.plan = _fallback_plan(
            session, note="orchestrator never dispatched; default scope used"
        )
    return state.plan


# --------------------------------------------------------------------------------------
# The graph
# --------------------------------------------------------------------------------------


def build_investigation_graph(
    state: InvestigationState,
    *,
    collectors: list[Collector] | None = None,
    node_timeout: float = NODE_TIMEOUT_SECONDS,
    proposer_node: Callable[[InvestigationState], Any] | None = None,
) -> Any:
    """Assemble the topology of plan §3.2.

    **W22's proposer arrives by injection, not by import, and that is the seam** (plan
    §3.5). The proposer reads the action catalog, so a graph module that imported it would
    be an investigation-layer module importing `actions/` — exactly what the seam forbids,
    and what `tests/integration/test_layer_seam.py` exists to catch. Passing a node factory
    keeps this module automation-free while still building the diagram's full topology when
    the automation layer is present: `correlator → proposer`, one edge.

    With no factory the graph is the investigation alone, which is the Tier 0 product and
    must keep working with the automation layer deleted.
    """
    from strands.multiagent import GraphBuilder

    from ..pipeline import build_collectors

    collectors = collectors if collectors is not None else build_collectors()

    builder = GraphBuilder()
    builder.add_node(_orchestrator_node(state), "orchestrator")

    correlator = _correlator_node(state)
    builder.add_node(correlator, "correlator")

    for collector in collectors:
        node = _collector_node(collector, state, timeout=node_timeout)
        builder.add_node(node, collector.source)
        # Every collector hangs off the orchestrator and feeds the correlator, with no edges
        # between them. That is what puts all four in one batch rather than in a chain.
        builder.add_edge("orchestrator", collector.source)
        builder.add_edge(collector.source, "correlator")

    if proposer_node is not None:
        builder.add_node(proposer_node(state), "proposer")
        builder.add_edge("correlator", "proposer")

    builder.set_entry_point("orchestrator")
    builder.set_node_timeout(node_timeout * GRAPH_TIMEOUT_MULTIPLE)
    # One execution per node plus headroom. Bounds a cycle if an edge is ever added that
    # creates one — the graph is a DAG today, and this is what keeps it cheap to keep so.
    builder.set_max_node_executions(len(collectors) + 4)
    return builder.build()


async def investigate_via_graph(
    alert: Alert,
    *,
    collectors: list[Collector] | None = None,
    node_timeout: float = NODE_TIMEOUT_SECONDS,
    proposer_node: Callable[[InvestigationState], Any] | None = None,
    state: InvestigationState | None = None,
) -> tuple[Brief, Any]:
    """Run one investigation through the Strands Graph. Returns the brief and the graph
    result, so a caller (and `test_graph_topology.py`) can inspect `execution_order`.

    Any proposal the injected proposer node produced is left on `state.proposal` rather
    than returned. The `Brief` is the seam's contract and a `Proposal` is not part of it
    (plan §3.5); a caller on the automation side holds the state and reads it from there.
    A caller that wants to say *why* a brief is degraded passes its own `state` and reads
    `state.node_errors` afterwards — the `Brief` carries only the flag.
    """
    from .budget import meter_for_mode

    state = state if state is not None else InvestigationState(alert)
    state.meter = meter_for_mode()
    graph = build_investigation_graph(
        state,
        collectors=collectors,
        node_timeout=node_timeout,
        proposer_node=proposer_node,
    )

    result = await graph.invoke_async(
        f"Investigate alert {alert.id} on {alert.service}."
    )
    return _brief_from(state, narrative=state.narrative), result


def _brief_from(state: InvestigationState, *, narrative: Any) -> Brief:
    """Assemble the `Brief` from whatever the graph managed to collect.

    Deliberately total: it produces a brief from an empty state as readily as from a full
    one. The degraded flag is what distinguishes them, and `Brief.degraded` is rendered —
    so a thin brief says it is thin instead of reading as a confident "nothing changed".
    """
    from ..collectors.github import ci_status_from
    from ..correlation.scoring import score_events
    from ..correlation.sensitivity import rank_stability
    from ..ledger.store import LedgerStore
    from ..pipeline import coverage_gaps_from

    plan = _require_plan(state)
    ledger = LedgerStore()
    for result in state.results:
        ledger.extend(result.events)

    candidates = score_events(
        ledger.query(plan.radius, plan.window), state.alert, plan.radius, plan.window, ledger
    )
    ledger.record_alert(state.alert)

    github = next((r for r in state.results if r.source == "github"), None)
    ci_status = (
        ci_status_from(github, plan.radius) if github is not None else CIStatus(merge_count=0)
    )

    narrative = narrative if narrative is not None else state.narrative
    return Brief(
        incident_id=incident_id_for(state.alert),
        alert=state.alert,
        radius=plan.radius,
        window=plan.window,
        candidates=candidates,
        ci_status=ci_status,
        narrative=narrative.text if narrative is not None else None,
        evidence_ids=list(narrative.evidence_ids) if narrative is not None else [],
        degraded=state.degraded or not plan.radius.keys,
        stability=rank_stability(candidates),
        coverage_gaps=coverage_gaps_from(state.results),
    )
