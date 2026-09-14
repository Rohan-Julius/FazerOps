"""W29 — the AgentCore Runtime entrypoint. Handoff §10, plan §4.

    agentcore configure --entrypoint agentcore_app.py
    agentcore dev                 # local, creates nothing, costs nothing
    agentcore deploy              # creates ECR repo, IAM role, Runtime + endpoint
    agentcore invoke '{"alert": {...}}' --user-id <caller>
    agentcore invoke '{"get_session": "INC-..."}'
    agentcore destroy

At the repo root rather than under `src/` because `agentcore configure --entrypoint` takes
a path to a file it will containerize, and a root-level entrypoint is the shape every
example in the AWS docs uses. It is deliberately thin: it normalizes a payload, runs the
investigation, persists the session and returns it. Everything it calls is code the
Slack path already exercises, so a deployment failure is a deployment failure and not a
different code path that has to be debugged twice.

**It runs the Strands graph, not the bare pipeline** (14 Sep). `pipeline.investigate` is
the orchestrator and the deterministic collectors only — no correlator, so no narrative —
and a deployed agent that never called its model agents would make the AgentCore claim
hollow. `investigate_via_graph` is what the Slack path runs, minus the proposer node.

**Why this deploys at all while Bedrock inference is blocked** (plan §9.2, §4's state *(b)*):
AgentCore Runtime hosts a containerized agent and does not itself require a Bedrock model.
The agent deployed here is Strands throughout and Gemini-backed. **The Gemini key comes
from AgentCore Identity**, an API-key credential provider, so it never appears in the
Runtime's configuration. Identity hands a Runtime a workload token only when the caller
names a user (`--user-id`, `runtimeUserId`), so a Gemini run invoked without one is
refused with that hint rather than quietly falling back to the stub.

**Tier 0 only.** Nothing reachable from this entrypoint can mutate anything: the graph is
built without the proposer node, which is the only edge into the automation layer, and
approvals happen only through a Slack callback (plan §3.5). A deployed HTTP endpoint that
could execute an action would make ground rule #5 false the moment it was public.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from fazerops.agents.graph import InvestigationState, investigate_via_graph
from fazerops.ingest.alerts import UnrecognisedPayload, normalize_alert
from fazerops.record.session import IncidentSession
from fazerops.record.store import session_store_from_env
from fazerops.render.text import render_brief

logger = logging.getLogger(__name__)

app = BedrockAgentCoreApp()

GEMINI_KEY_PROVIDER_ENV = "FAZEROPS_GEMINI_KEY_PROVIDER"


class KeyUnavailable(RuntimeError):
    pass


def _calls_gemini() -> bool:
    from fazerops.agents.llm import PROVIDER, Provider
    from fazerops.config import llm_mode

    return PROVIDER.get(llm_mode()) is Provider.GEMINI


def _identity_client(region: str) -> Any:
    from bedrock_agentcore.services.identity import IdentityClient

    return IdentityClient(region)


def _workload_token() -> str | None:
    from bedrock_agentcore.runtime.context import BedrockAgentCoreContext

    return BedrockAgentCoreContext.get_workload_access_token()


async def _ensure_gemini_key() -> None:
    """Put the Gemini key where `agents/correlator._gemini_model` reads it, fetched from
    AgentCore Identity once per Runtime session.

    A no-op when the mode calls no Gemini model, when the key is already present, or when
    no provider is configured — in the last case `_gemini_model` raises its own error naming
    the missing key, which is the more useful message.
    """
    if not _calls_gemini() or os.environ.get("GEMINI_API_KEY"):
        return
    provider = os.environ.get(GEMINI_KEY_PROVIDER_ENV)
    if not provider:
        return
    token = _workload_token()
    if token is None:
        raise KeyUnavailable(
            "the Gemini key is held in AgentCore Identity, which issues it only to a request that "
            "names a user: invoke with --user-id (runtimeUserId)"
        )
    region = os.environ.get("AWS_REGION") or "sa-east-1"
    key = await _identity_client(region).get_api_key(provider_name=provider, agent_identity_token=token)
    os.environ["GEMINI_API_KEY"] = key


def _persist(session: IncidentSession) -> dict[str, Any]:
    """Write the session and report what happened. A failed write never costs the caller the brief:
    the brief is the product, and the record of it is reported missing rather than raised."""
    try:
        store = session_store_from_env()
        if store is None:
            return {"store": None}
        return {"store": store.name, "ok": True, "ref": store.save(session)}
    except Exception as exc:  # noqa: BLE001 - reported on the response, never raised past it
        logger.exception("persisting session %s failed", session.incident_id)
        return {"store": os.environ.get("FAZEROPS_SESSION_STORE"), "ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}


def _read_back(incident_id: str) -> dict[str, Any]:
    """A stored session and its history — every stage written, by the Runtime or by the
    automation server. Read-only, like everything else this endpoint reaches."""
    try:
        store = session_store_from_env()
    except ValueError as exc:
        return {"error": str(exc)}
    if store is None:
        return {"error": "no session store is configured (FAZEROPS_SESSION_STORE)"}
    session = store.load(incident_id)
    if session is None:
        return {"error": f"no session stored for {incident_id!r}", "store": store.name}
    return {
        "incident_id": session.incident_id,
        "stage": session.stage,
        "store": store.name,
        "history": [{"recorded_at": s.recorded_at, "stage": s.stage} for s in store.history(incident_id)],
        "session": session.model_dump(mode="json"),
    }


@app.entrypoint
async def invoke(payload: dict[str, Any]) -> dict[str, Any]:
    """Investigate one alert, or read a stored session back. Returns JSON-serializable state.

    `{"get_session": "<incident id>"}` reads back. Otherwise the payload is an alert, either
    `{"alert": {...}}` or bare, because the three payload shapes `ingest/alerts.py`
    normalizes are what a real caller sends and wrapping them is a convention only this file
    would know about.

    An unrecognised payload returns an error rather than guessing. A permissively-parsed
    alert yields the wrong service, and the brief then investigates the wrong blast radius
    with total confidence — the one failure mode this product must not have.
    """
    if isinstance(payload, dict) and isinstance(payload.get("get_session"), str):
        return _read_back(payload["get_session"])

    alert_payload = payload.get("alert") if isinstance(payload, dict) else None
    if not isinstance(alert_payload, dict):
        alert_payload = payload if isinstance(payload, dict) else {}

    try:
        alert = normalize_alert(alert_payload)
    except UnrecognisedPayload as exc:
        return {"error": str(exc), "hint": "send an Alertmanager, CloudWatch or PagerDuty payload"}

    try:
        await _ensure_gemini_key()
    except KeyUnavailable as exc:
        return {"error": str(exc)}

    state = InvestigationState(alert)
    brief, _ = await investigate_via_graph(alert, state=state)
    session = IncidentSession.from_brief(brief)
    # The brief says only *that* it is degraded; a deployed run's logs are the one place nobody is
    # watching, so the reason rides on the response. Node names and exception summaries, no payloads.
    node_errors = {name: reason[:300] for name, reason in state.node_errors.items()}
    if brief.degraded:
        logger.warning("investigation %s degraded: %s", brief.incident_id, node_errors or "the orchestrator's plan")

    return {
        # The rendered brief first: it is what a human invoking this endpoint wants, and
        # burying it under the state object would make the useful half the hard half.
        "brief": render_brief(brief),
        "incident_id": session.incident_id,
        "stage": session.stage,
        "degraded": session.degraded,
        "node_errors": node_errors,
        "plan_degraded": bool(state.plan is not None and state.plan.degraded),
        # Which configuration the container actually came up in, reported rather than
        # assumed. A container that silently defaulted to `fixture` when it was meant to be
        # `live` produces a brief that looks entirely normal and is about the wrong world.
        #
        # It rides on the invocation response because `BedrockAgentCoreApp` has exactly one
        # entrypoint — `@app.entrypoint` registers under the single key `"main"`, so a
        # second decorated function silently *replaces* the first rather than adding a
        # route (verified against the installed SDK, 12 Sep). Liveness is `/ping`, whose
        # handler takes no payload and returns a `PingStatus`; the framework's default is
        # correct here and a custom one would report nothing this does not.
        "runtime": {
            "mode": os.environ.get("FAZEROPS_MODE", "fixture"),
            "llm": os.environ.get("FAZEROPS_LLM", "stub"),
            "session_store": os.environ.get("FAZEROPS_SESSION_STORE") or "none",
        },
        "persisted": _persist(session),
        # Handoff §10's persisted state. `mode="json"` because the runtime serializes the
        # response and Python datetimes are not JSON — a failure that surfaces only once
        # deployed, which is the expensive place to find it.
        "session": session.model_dump(mode="json"),
    }


if __name__ == "__main__":  # pragma: no cover - the container's command
    # The Runtime ships stdout/stderr to CloudWatch, but nothing reaches them unless logging is
    # configured: on 14 Sep a degraded run left no trace of which node failed.
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s %(message)s")
    logging.getLogger("fazerops").setLevel(logging.INFO)
    app.run()
