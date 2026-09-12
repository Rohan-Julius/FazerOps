"""W29 — the AgentCore Runtime entrypoint. Handoff §10, plan §4.

    agentcore configure --entrypoint agentcore_app.py
    agentcore dev                 # local, creates nothing, costs nothing
    agentcore deploy              # creates ECR repo, IAM role, Runtime + endpoint
    agentcore invoke '{"alert": {...}}'
    agentcore destroy

At the repo root rather than under `src/` because `agentcore configure --entrypoint` takes
a path to a file it will containerize, and a root-level entrypoint is the shape every
example in the AWS docs uses. It is deliberately thin: it normalizes a payload, runs the
investigation, and returns a JSON-serializable session. Everything it calls is code the
fixture demo already exercises, so a deployment failure is a deployment failure and not a
different code path that has to be debugged twice.

**Why this deploys at all while Bedrock inference is blocked** (plan §9.2, §4's state *(b)*):
AgentCore Runtime hosts a containerized agent and does not itself require a Bedrock model.
The account-wide block is inference-only — `bedrock-agentcore-control list-agent-runtimes`
returns a clean empty list, which is what U1 established. So the agent that deploys here is
Strands throughout and Gemini-backed, and the AWS deployment story survives the block.

**Tier 0 only.** Nothing reachable from this entrypoint can mutate anything: it calls
`pipeline.investigate`, which is the investigation layer, and the automation layer is
entered only through a Slack approval callback (plan §3.5). A deployed HTTP endpoint that
could execute an action would make ground rule #5 false the moment it was public.
"""

from __future__ import annotations

import os
from typing import Any

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from fazerops.ingest.alerts import UnrecognisedPayload, normalize_alert
from fazerops.pipeline import investigate
from fazerops.record.session import IncidentSession
from fazerops.render.text import render_brief

app = BedrockAgentCoreApp()


@app.entrypoint
async def invoke(payload: dict[str, Any]) -> dict[str, Any]:
    """Investigate one alert. Returns Handoff §10's session state, JSON-serializable.

    Accepts either `{"alert": {...}}` or a bare alert payload, because the three payload
    shapes `ingest/alerts.py` normalizes are what a real caller sends and wrapping them is
    a convention only this file would know about.

    An unrecognised payload returns an error rather than guessing. A permissively-parsed
    alert yields the wrong service, and the brief then investigates the wrong blast radius
    with total confidence — the one failure mode this product must not have.
    """
    alert_payload = payload.get("alert") if isinstance(payload, dict) else None
    if not isinstance(alert_payload, dict):
        alert_payload = payload if isinstance(payload, dict) else {}

    try:
        alert = normalize_alert(alert_payload)
    except UnrecognisedPayload as exc:
        return {"error": str(exc), "hint": "send an Alertmanager, CloudWatch or PagerDuty payload"}

    brief = await investigate(alert, hours=int(payload.get("window_hours") or 4))
    session = IncidentSession.from_brief(brief)

    return {
        # The rendered brief first: it is what a human invoking this endpoint wants, and
        # burying it under the state object would make the useful half the hard half.
        "brief": render_brief(brief),
        "incident_id": session.incident_id,
        "stage": session.stage,
        "degraded": session.degraded,
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
        },
        # Handoff §10's persisted state. `mode="json"` because the runtime serializes the
        # response and Python datetimes are not JSON — a failure that surfaces only once
        # deployed, which is the expensive place to find it.
        "session": session.model_dump(mode="json"),
    }


if __name__ == "__main__":  # pragma: no cover - the container's command
    app.run()
