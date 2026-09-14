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

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

# At module level on purpose: FastAPI resolves a route's annotations by name, and a `Request`
# imported inside `build_app` is invisible to it under postponed annotations — the handler then
# reads `request` as a body field and every alert is a 422.
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .runtime import Automation, Response

__all__ = ["build_app", "messages_for", "serve"]

Post = Callable[..., Any]
Update = Callable[..., Any]
Sleep = Callable[[float], Awaitable[Any]]

logger = logging.getLogger(__name__)


def messages_for(response: Response) -> list[tuple[list[dict[str, Any]], str]]:
    """The brief, then one card per opened approval, each with its notification text."""
    from ..render.text import approval_card_note
    from ..slack.handlers import approval_card_for

    note = approval_card_note(response.brief)
    messages = [_brief_message(response, response.brief)]
    for pending in response.pending:
        messages.append((approval_card_for(pending, coverage_note=note), _card_text(pending)))
    return messages


def _brief_message(response: Response, brief: Any) -> tuple[list[dict[str, Any]], str]:
    from ..slack.blocks import change_brief

    catalog_card = next((p for p in response.pending if p.one_shot is None), None)
    blocks = change_brief(
        brief,
        proposal_summary=catalog_card.dry_run.summary if catalog_card is not None else None,
        action_id=response.proposal.action_id if response.proposal is not None else None,
    )
    return blocks, f"{brief.incident_id}: {len(brief.candidates)} change(s) in the {brief.alert.service} blast radius"


def _card_text(pending: Any) -> str:
    return f"Approval required: {pending.action_id} for {pending.incident_id}"


def _handle(posted: Any) -> tuple[str, str] | None:
    """The `(channel, ts)` a posted message is edited by. Slack's response supports item access; a
    poster that returns nothing leaves nothing to edit."""
    try:
        return str(posted["channel"]), str(posted["ts"])
    except (KeyError, TypeError):
        return None


async def _follow_coverage(
    automation: Automation, response: Response, handles: list[tuple[str, str] | None], update: Update, sleep: Sleep
) -> None:
    """Edit the posted brief — and every card drafted from it — as late changes arrive and when the
    gap closes. In place, so the message a person opens is the current one."""
    from ..render.text import approval_card_note
    from ..slack.handlers import approval_card_for

    brief_handle, card_handles = handles[0], handles[1:]
    notes = [approval_card_note(response.brief)] * len(response.pending)

    def on_update(change: Any) -> None:
        if brief_handle is not None:
            blocks, text = _brief_message(response, change.brief)
            update(brief_handle[0], brief_handle[1], blocks, text=text)
        note = approval_card_note(change.brief)
        for index, (pending, handle) in enumerate(zip(response.pending, card_handles)):
            if handle is not None and note != notes[index]:
                update(handle[0], handle[1], approval_card_for(pending, coverage_note=note), text=_card_text(pending))
                notes[index] = note

    try:
        await automation.follow_coverage(response.brief, on_update, sleep=sleep)
    except Exception:  # following a gap must never surface as a crash in the incident path
        logger.exception("following coverage for %s failed", response.brief.incident_id)


def build_app(
    automation: Automation,
    *,
    post: Post | None = None,
    update: Update | None = None,
    sleep: Sleep = asyncio.sleep,
) -> FastAPI:
    from ..ingest.alerts import UnrecognisedPayload, normalize_alert

    app = FastAPI(title="FazerOps automation", version="0.1.0")
    # Held so a pending follow-up is not garbage-collected mid-sleep (asyncio keeps only a weak
    # reference to a task).
    app.state.follow_ups = set()

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
        handles = [_handle(post(blocks, text=text)) for blocks, text in messages] if post is not None else []

        # The brief has already posted; this only follows it. Without a way to edit it in place
        # there is nothing to follow into.
        follow_up = (
            update is not None
            and bool(handles)
            and handles[0] is not None
            and any(gap.status == "open" for gap in response.brief.coverage_gaps)
        )
        if follow_up:
            task = asyncio.create_task(_follow_coverage(automation, response, handles, update, sleep))
            app.state.follow_ups.add(task)
            task.add_done_callback(app.state.follow_ups.discard)

        one_shot = response.one_shot
        return JSONResponse(
            {
                "incident_id": response.brief.incident_id,
                "proposal": response.proposal.action_id if response.proposal is not None else None,
                "one_shot": None if one_shot is None else (one_shot.one_shot.action_id if one_shot.offered else one_shot.refusal.value),
                "pending": [pending.action_id for pending in response.pending],
                "refused": response.refused,
                "posted": len(messages) if post is not None else 0,
                "coverage_follow_up": follow_up,
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

    from ..slack.handlers import approval_sink, post_brief, run_socket_mode, update_message
    from .growth.job import run_on_schedule
    from .roster import default_roster

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    automation = Automation.assemble()
    sink = approval_sink(automation.gateway, resolve_approver=lambda user_id: default_roster().resolve(user_id))
    threading.Thread(target=run_socket_mode, kwargs={"sink": sink}, daemon=True, name="slack-socket-mode").start()

    schedule = growth_schedule_from_env(automation)
    if schedule is not None:
        threading.Thread(target=run_on_schedule, kwargs=schedule, daemon=True, name="catalog-growth").start()

    uvicorn.run(build_app(automation, post=post_brief, update=update_message), host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    serve()
