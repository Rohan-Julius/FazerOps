"""The automation server — alerts in, a brief and approval cards out, clicks back, in one process.

    .venv/bin/python -m fazerops.actions.server

`main.py` is Tier 0, and it stays that way: nothing reachable from it can mutate anything, and a
webhook there that opened approval cards would make that false. This is the other entrypoint, for
a deployment that runs the automation layer. One process on purpose: the gateway's open cards
live in memory (`ApprovalGateway`), so the alert that opens a card and the click that decides it
must reach the same process — the Socket Mode listener runs beside the HTTP server, sharing one
`Automation`.

Not deployed to AgentCore, which is Tier 0 by the same argument (`agentcore_app.py`). Posting to
Slack happens only when this is run with Slack credentials; the tests post to a fake.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# At module level on purpose: FastAPI resolves a route's annotations by name, and a `Request`
# imported inside `build_app` is invisible to it under postponed annotations — the handler then
# reads `request` as a body field and every alert is a 422.
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .runtime import Automation, Response

__all__ = ["build_app", "messages_for", "serve"]

Post = Callable[..., Any]


def messages_for(response: Response) -> list[tuple[list[dict[str, Any]], str]]:
    """The brief, then one card per opened approval, each with its notification text."""
    from ..slack.blocks import change_brief
    from ..slack.handlers import approval_card_for

    brief = response.brief
    proposal = response.proposal
    catalog_card = next((p for p in response.pending if p.one_shot is None), None)
    messages = [
        (
            change_brief(
                brief,
                proposal_summary=catalog_card.dry_run.summary if catalog_card is not None else None,
                action_id=proposal.action_id if proposal is not None else None,
            ),
            f"{brief.incident_id}: {len(brief.candidates)} change(s) in the {brief.alert.service} blast radius",
        )
    ]
    for pending in response.pending:
        messages.append((approval_card_for(pending), f"Approval required: {pending.action_id} for {pending.incident_id}"))
    return messages


def build_app(automation: Automation, *, post: Post | None = None) -> FastAPI:
    from ..ingest.alerts import UnrecognisedPayload, normalize_alert

    app = FastAPI(title="FazerOps automation", version="0.1.0")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/alerts")
    async def alerts(request: Request) -> JSONResponse:
        try:
            alert = normalize_alert(await request.json())
        except UnrecognisedPayload as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        response = await automation.respond(alert)
        messages = messages_for(response)
        if post is not None:
            for blocks, text in messages:
                post(blocks, text=text)

        one_shot = response.one_shot
        return JSONResponse(
            {
                "incident_id": response.brief.incident_id,
                "proposal": response.proposal.action_id if response.proposal is not None else None,
                "one_shot": None if one_shot is None else (one_shot.one_shot.action_id if one_shot.offered else one_shot.refusal.value),
                "pending": [pending.action_id for pending in response.pending],
                "refused": response.refused,
                "posted": len(messages) if post is not None else 0,
            }
        )

    return app


GROWTH_EVERY_ENV = "FAZEROPS_GROWTH_EVERY_MINUTES"
GROWTH_REPO_ENV = "FAZEROPS_GROWTH_REPO"
GROWTH_BASE_ENV = "FAZEROPS_GROWTH_BASE"
GROWTH_OPEN_PR_ENV = "FAZEROPS_GROWTH_OPEN_PR"


def growth_schedule_from_env(automation: Automation) -> dict[str, Any] | None:
    """The catalog-growth schedule the server runs beside the incident path, or `None` when
    `FAZEROPS_GROWTH_EVERY_MINUTES` is `0`. Hourly by default; commits only if a repository is named,
    and pushes and opens pull requests only if `FAZEROPS_GROWTH_OPEN_PR` is set as well."""
    import os

    from .growth.pr import evidence_key_from_env

    every = float(os.environ.get(GROWTH_EVERY_ENV) or 60)
    if every <= 0:
        return None
    repo = os.environ.get(GROWTH_REPO_ENV) or None
    open_prs = (os.environ.get(GROWTH_OPEN_PR_ENV) or "").strip().lower() in {"1", "true", "yes"}
    if open_prs and repo is None:
        raise ValueError(f"{GROWTH_OPEN_PR_ENV} is set but {GROWTH_REPO_ENV} is not: a PR is opened from a committed branch")
    return {
        "state_dir": automation.state_dir,
        "every_minutes": every,
        "evidence_key": evidence_key_from_env(),
        "repo": repo,
        "base": os.environ.get(GROWTH_BASE_ENV) or ("main" if open_prs else "HEAD"),
        "open_prs": open_prs,
    }


def serve(*, host: str = "127.0.0.1", port: int = 8081) -> None:  # pragma: no cover - a process
    import logging
    import threading

    import uvicorn

    from ..slack.handlers import approval_sink, post_brief, run_socket_mode
    from .growth.job import run_on_schedule
    from .roster import default_roster

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    automation = Automation.assemble()
    sink = approval_sink(automation.gateway, resolve_approver=lambda user_id: default_roster().resolve(user_id))
    threading.Thread(target=run_socket_mode, kwargs={"sink": sink}, daemon=True, name="slack-socket-mode").start()

    schedule = growth_schedule_from_env(automation)
    if schedule is not None:
        threading.Thread(target=run_on_schedule, kwargs=schedule, daemon=True, name="catalog-growth").start()

    uvicorn.run(build_app(automation, post=post_brief), host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    serve()
