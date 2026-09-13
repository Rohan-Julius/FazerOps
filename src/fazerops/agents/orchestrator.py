"""W19b — the orchestrator agent. Plan §3.1.

The first node in the graph, and the one whose failure mode is total: everything
downstream investigates whatever scope this agent chose, so a wrong service produces an
empty candidate set and a brief that confidently reports nothing changed. It is also the
only agent that reads attacker-influenceable text *before* the radius is fixed.

**The design that makes that safe is structural, not textual** (ground rule #1):

* `resolve_blast_radius(service)` takes a `Literal` enum built from
  `config/service_manifest.yaml` **at import time**. A service that is not in the manifest
  is rejected by the tool schema — the model cannot name it, so there is no prompt to
  jailbreak past.
* `compute_window(hours)` takes a `Literal` of 1..24. There is no 90-day window to ask for.
* `dispatch_collectors(radius_id, window_id)` takes **handles**, not objects. The real
  `BlastRadius` and `TimeWindow` never enter model context and are never reconstructed
  from model output; they are looked up in the session that minted them. A model-authored
  id that was never minted is a `KeyError` the tool reports, not a query it executes.

So the agent decides *what* and *how far back* over a bounded, typed space, and never
constructs a query, a resource identifier or a command. That is plan §3.1's whole claim.

**Why the plan bought an agent here at all** is settled in §9.2 ("Settled, not open") and
is not re-argued: routing over three manifest-bounded tools is a judgment, the topology
is what earns the multi-agent claim, and the residual risk is handled by the enum, the
turn cap and `test_orchestrator_envelope.py`.

Investigation layer — this module imports nothing from `actions/`, `slack/handlers.py` or
`security/credentials.py` (plan §3.5).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..models import Alert, BlastRadius, TimeWindow
from ..radius import default_manifest

__all__ = [
    "MAX_TURNS",
    "OrchestrationSession",
    "Plan",
    "SERVICE_NAMES",
    "WINDOW_HOURS",
    "build_tools",
    "orchestrate",
]

# Plan §5's runaway-loop guardrail. Three tool calls plus one answer is the entire job, so
# four turns is the job's own shape rather than an arbitrary ceiling. Enforced by Strands'
# `Limits(turns=...)`, not by asking the model nicely in the prompt.
MAX_TURNS = 4

# Read at import time on purpose — this is the sentence that makes "rejected by the tool
# schema, not the prompt" literally true. `default_manifest()` is `lru_cache`d, so the
# enum and the resolver can never disagree about what services exist.
SERVICE_NAMES: tuple[str, ...] = default_manifest().service_names

# Handoff Q3's default is 4h; §3.1 bounds the parameter to [1, 24]. Strands' tool decorator
# rejects `Annotated[int, Field(ge=..., le=...)]` outright (verified 11 Sep against
# strands-agents==1.54.0), so the bound is expressed as the enum of permitted values. That
# is a stronger guarantee than a numeric range in prose would have been: 24 entries in the
# schema, and nothing else is expressible.
WINDOW_HOURS: tuple[int, ...] = tuple(range(1, 25))
DEFAULT_WINDOW_HOURS = 4

_ServiceName = Literal[SERVICE_NAMES]  # type: ignore[valid-type]
_WindowHours = Literal[WINDOW_HOURS]  # type: ignore[valid-type]


class Plan(BaseModel):
    """What the orchestrator decided, and whether it finished deciding it.

    Carries the *resolved* radius and window rather than the model's words about them, so
    a caller consumes typed objects the tools built and never re-parses model output.
    """

    model_config = ConfigDict(frozen=True)

    service: str
    radius: BlastRadius
    window: TimeWindow
    dispatched: bool = Field(
        default=False,
        description="Did the agent actually call `dispatch_collectors`? False means the "
        "turn cap or an error stopped it, and the caller fans out itself — a partial "
        "brief, marked degraded, rather than no brief.",
    )
    degraded: bool = False
    note: str | None = Field(
        default=None,
        description="Why the plan is degraded, in one line. Rendered on the brief; never "
        "fed back to a model.",
    )


class OrchestrationSession:
    """The side table the tools write to, and the reason the model never holds an object.

    Handles are minted here and resolved here. Nothing the model says is ever turned into
    a `BlastRadius` or a `TimeWindow` — it can only name one that a tool already built,
    and naming one that was not built is an error the tool reports rather than a query
    anything runs.
    """

    def __init__(self, alert: Alert) -> None:
        self.alert = alert
        self.radii: dict[str, BlastRadius] = {}
        self.windows: dict[str, TimeWindow] = {}
        self.dispatched: list[tuple[str, str]] = []
        self.calls: list[str] = []

    def put_radius(self, radius: BlastRadius) -> str:
        handle = f"radius-{len(self.radii) + 1}"
        self.radii[handle] = radius
        return handle

    def put_window(self, window: TimeWindow) -> str:
        handle = f"window-{len(self.windows) + 1}"
        self.windows[handle] = window
        return handle

    @property
    def last_radius(self) -> BlastRadius | None:
        return next(reversed(self.radii.values()), None) if self.radii else None

    @property
    def last_window(self) -> TimeWindow | None:
        return next(reversed(self.windows.values()), None) if self.windows else None


def build_tools(session: OrchestrationSession) -> list[Any]:
    """The three typed tools of plan §3.1, bound to one session.

    Built per-invocation rather than at module scope because the handles are per-incident:
    a module-level table would let one investigation resolve another's radius id, which is
    the isolation invariant this project states up front.
    """
    from strands import tool

    @tool
    def resolve_blast_radius(service: _ServiceName) -> dict[str, Any]:
        """Resolve which resources belong to a service, plus one hop of its dependencies.

        Args:
            service: The service the alert names. Only the listed services exist.

        Returns:
            A radius_id to pass to dispatch_collectors, and a summary of what it covers.
        """
        session.calls.append("resolve_blast_radius")
        radius = default_manifest().resolve(service)
        handle = session.put_radius(radius)
        return {
            "radius_id": handle,
            "service": service,
            "resource_count": len(radius.keys),
            "directly_owned": len(radius.direct_keys),
        }

    @tool
    def compute_window(hours: _WindowHours) -> dict[str, Any]:
        """Compute the time window to search, ending when the alert fired.

        Args:
            hours: How many hours before the alert to look. Default 4. Maximum 24.

        Returns:
            A window_id to pass to dispatch_collectors, and the window's bounds.
        """
        from datetime import timedelta

        session.calls.append("compute_window")
        window = TimeWindow(
            start=session.alert.fired_at - timedelta(hours=int(hours)),
            end=session.alert.fired_at,
        )
        handle = session.put_window(window)
        return {
            "window_id": handle,
            "hours": int(hours),
            "start": window.start.isoformat(),
            "end": window.end.isoformat(),
        }

    @tool
    def dispatch_collectors(radius_id: str, window_id: str) -> dict[str, Any]:
        """Start all change collectors over a resolved radius and window. Call once.

        Args:
            radius_id: An id returned by resolve_blast_radius.
            window_id: An id returned by compute_window.

        Returns:
            Confirmation of what was dispatched.
        """
        session.calls.append("dispatch_collectors")
        if radius_id not in session.radii:
            return {"error": f"no such radius_id {radius_id!r}; call resolve_blast_radius first"}
        if window_id not in session.windows:
            return {"error": f"no such window_id {window_id!r}; call compute_window first"}

        session.dispatched.append((radius_id, window_id))
        # The fan-out itself is not performed here. The tool records the decision and the
        # caller executes it — W19 turns that decision into four `FunctionNode`s in one
        # Strands batch, and a tool that blocked on four network collectors would burn the
        # agent's turn budget waiting for I/O it contributes nothing to.
        return {"dispatched": True, "sources": ["cloudtrail", "k8s_audit", "helm", "github"]}

    return [resolve_blast_radius, compute_window, dispatch_collectors]


def _fallback_plan(
    session: OrchestrationSession,
    note: str | None,
    hours: int = DEFAULT_WINDOW_HOURS,
) -> Plan:
    """What to do when the agent did not finish: resolve the alert's own service over the
    default window.

    This is the honest degraded answer rather than a silent one. The alternative — giving
    up — throws away a brief that would have been correct in every case except the one
    where the model had a better idea about scope, and `degraded` says on the brief that
    no model chose this scope.
    """
    from datetime import timedelta

    radius = session.last_radius or default_manifest().resolve(session.alert.service)
    window = session.last_window or TimeWindow(
        start=session.alert.fired_at - timedelta(hours=max(1, min(int(hours), 24))),
        end=session.alert.fired_at,
    )
    return Plan(
        service=session.alert.service,
        radius=radius,
        window=window,
        dispatched=False,
        degraded=note is not None,
        note=note,
    )


async def orchestrate(
    alert: Alert,
    *,
    hours: int = DEFAULT_WINDOW_HOURS,
    meter: Any | None = None,
    session: OrchestrationSession | None = None,
    model_client: Any | None = None,
) -> Plan:
    """Decide scope and window for one alert, under whichever mode is active.

    Never raises on a model failure. The orchestrator sits in front of everything else, so
    an exception here costs the whole investigation; a degraded `Plan` costs only the
    model's judgment about scope, which the deterministic fallback supplies.

    `model_client` substitutes the provider and **nothing else** — the mode check, the
    offline guard, the tool schemas, the turn cap and the session handles are all still the
    production ones. It exists because the orchestrator's risk lives in the agentic loop,
    and a test that mocks `Agent` would assert against the mock instead of the loop.
    """
    from ..config import LlmMode, llm_mode

    session = session if session is not None else OrchestrationSession(alert)
    mode = llm_mode()

    if mode is LlmMode.STUB:
        # Not a degraded plan: `stub` is a *chosen* deterministic path, and marking the CI
        # default and the judge's clean-machine default "degraded" would put a warning on
        # every brief anyone actually sees.
        plan = _fallback_plan(session, note=None, hours=hours)
        return plan.model_copy(update={"dispatched": True})

    if mode is LlmMode.CASSETTE:
        return _replay(session, hours=hours)

    return await _invoke(session, meter=meter, mode=mode, model_client=model_client)


def _replay(session: OrchestrationSession, *, hours: int = DEFAULT_WINDOW_HOURS) -> Plan:
    """Cassette mode replays the *decision* — service and hours — and re-derives the rest.

    The orchestrator's tape cannot be a transcript of a tool loop: the tools have side
    effects and mint fresh handles every run, so a replayed `radius-1` would refer to
    nothing. What the model actually contributes is two values, and those are what the
    cassette holds. Everything downstream of them is deterministic Python that replays
    exactly by being re-run.
    """
    from datetime import timedelta

    from .cassette import Cassette, request_key
    from .llm import recording_model_for
    from .prompts.orchestrator import SYSTEM_PROMPT

    from .cassette import CassetteMiss

    from ..config import LlmMode
    from .correlator import generation_params_for

    model = recording_model_for("orchestrator")
    key = request_key(
        "orchestrator",
        model,
        _decision_messages(session.alert),
        system=SYSTEM_PROMPT,
        **generation_params_for(LlmMode.CASSETTE),
    )
    try:
        recorded = Cassette("orchestrator").replay(key)
    except CassetteMiss as exc:
        # **Degraded, not fatal, and never silent.** A missing tape is a model failure like
        # any other, and `orchestrate` does not raise on those — the investigation is worth
        # more than the model's opinion about scope. But it must not read as success: the
        # note lands on `Brief.degraded` and says which tape is missing.
        #
        # There is no orchestrator cassette as of 12 Sep. W18's was recorded against a real
        # model; this one needs a `GEMINI_API_KEY`, and the key in `.env` is the one that
        # leaked and is awaiting rotation. Recording it is an outstanding item, not a
        # decision this function is entitled to make.
        return _fallback_plan(session, note=f"no orchestrator cassette ({exc})", hours=hours)

    service = recorded.get("service", session.alert.service)
    hours = int(recorded.get("window_hours", DEFAULT_WINDOW_HOURS))
    window = TimeWindow(
        start=session.alert.fired_at - timedelta(hours=hours), end=session.alert.fired_at
    )
    return Plan(
        service=service,
        radius=default_manifest().resolve(service),
        window=window,
        dispatched=True,
    )


def _decision_messages(alert: Alert) -> list[dict[str, Any]]:
    """The user turn, and the cassette key's basis.

    The alert reaches the model only inside W16's envelope — it is the first
    attacker-influenceable string in the pipeline, and this is the agent that reads it
    before the radius is fixed.
    """
    from ..security.envelope import render_alert_for_llm

    return [{"role": "user", "content": [{"text": render_alert_for_llm(alert)}]}]


async def _invoke(
    session: OrchestrationSession,
    *,
    meter: Any | None,
    mode: Any,
    model_client: Any | None = None,
) -> Plan:
    """One live agentic tool loop, capped at `MAX_TURNS`.

    **Not exercised by any test that runs in CI**, for the same reason W18's `_invoke` is
    not: Bedrock inference is blocked account-wide and the Gemini path needs a key CI does
    not have. It compiles; that is not evidence it works.
    """
    from strands import Agent
    from strands.types.agent import Limits

    from ..config import LlmMode, require_offline_capable
    from .llm import model_for, provider_for
    from .prompts.orchestrator import SYSTEM_PROMPT

    require_offline_capable("orchestrator")

    model_id = model_for("orchestrator", mode)
    client = model_client if model_client is not None else _client_for(provider_for(mode), model_id)

    agent = Agent(
        model=client,
        tools=build_tools(session),
        system_prompt=SYSTEM_PROMPT,
        callback_handler=None,
    )

    note: str | None = None
    try:
        result = await agent.invoke_async(
            _decision_messages(session.alert)[0]["content"],
            limits=Limits(turns=MAX_TURNS),
        )
    except Exception as exc:  # noqa: BLE001 - see this function's docstring
        # Includes the turn cap being hit. Strands raises rather than returning a partial
        # result, and the partial result is exactly what we want: whatever tools *did*
        # run left their answers in the session, so the fallback below is often the
        # model's own radius with only the dispatch missing.
        note = f"orchestrator did not finish ({type(exc).__name__}); default scope used"
        result = None

    if meter is not None and result is not None:
        usage = _usage_from(result)
        meter.record(
            "orchestrator",
            model_id,
            usage["in"],
            usage["out"],
            estimated=usage.get("estimated", False),
        )

    if session.dispatched and session.last_radius is not None:
        radius_id, window_id = session.dispatched[-1]
        plan = Plan(
            service=session.radii[radius_id].service,
            radius=session.radii[radius_id],
            window=session.windows[window_id],
            dispatched=True,
        )
        if mode is LlmMode.RECORD:
            _record(session, plan, model_id)
        return plan

    if mode is LlmMode.RECORD:
        # Deliberately not recorded. A cassette of a run that never dispatched would replay
        # a degraded plan forever and read in CI as the orchestrator working — the failure
        # this whole module is shaped around. Re-run the recording instead.
        note = note or "orchestrator never dispatched; nothing recorded"

    return _fallback_plan(
        session, note=note or "orchestrator never dispatched; default scope used"
    )


def _record(session: OrchestrationSession, plan: Plan, model_id: str) -> None:
    """Write the orchestrator's *decision* to its cassette — service and window hours.

    Not a transcript of the tool loop. The tools have side effects and mint fresh handles
    every run, so a replayed `radius-1` would refer to nothing; what the model actually
    contributes is these two values, and everything downstream of them is deterministic
    Python that replays exactly by being re-run. `_replay` reads precisely this shape.
    """
    from ..config import LlmMode
    from .cassette import Cassette, request_key
    from .correlator import generation_params_for
    from .prompts.orchestrator import SYSTEM_PROMPT

    key = request_key(
        "orchestrator",
        model_id,
        _decision_messages(session.alert),
        system=SYSTEM_PROMPT,
        **generation_params_for(LlmMode.RECORD),
    )
    Cassette("orchestrator").record(
        key,
        {"service": plan.service, "window_hours": int(plan.window.hours)},
        model=model_id,
    )


def _client_for(provider: Any, model_id: str) -> Any:
    """Same two-branch construction as W18's correlator, and the same reason it is two
    branches and not a rewrite: both providers implement Strands' `Model` interface, so
    only the constructor differs (plan §9.2)."""
    from .correlator import _bedrock_model, _gemini_model
    from .llm import Provider

    return _gemini_model(model_id) if provider is Provider.GEMINI else _bedrock_model(model_id)


def _usage_from(result: Any) -> dict[str, int]:
    """Real token counts off the `AgentResult` when the provider reported them.

    Unlike the correlator's structured-output path — where Strands' Gemini branch yields
    no usage event at all (U6a) — an agentic loop goes through the streaming path, which
    is where `_format_chunk` does emit metadata. So this is expected to return real counts
    here. `estimated` is still carried, because "expected to" is not "observed to" and a
    ledger that cannot tell a measurement from a guess is the thing W17 exists to prevent.
    """
    usage = getattr(getattr(result, "metrics", None), "accumulated_usage", None) or {}
    if usage.get("inputTokens") is not None:
        return {"in": int(usage["inputTokens"]), "out": int(usage.get("outputTokens", 0))}

    from ..security.envelope import estimate_tokens

    return {"in": estimate_tokens(str(result)), "out": 0, "estimated": True}
