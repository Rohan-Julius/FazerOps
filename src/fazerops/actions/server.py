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

__all__ = ["ACTOR_ROLE_ENV", "assemble_from_env", "build_app", "decision_closer", "messages_for", "record_poster", "serve"]

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
        messages.append((approval_card_for(pending, coverage_note=note, brief=response.brief), _card_text(pending)))
    return messages


def _brief_message(response: Response, brief: Any, automation: Any = None) -> tuple[list[dict[str, Any]], str]:
    """The brief's blocks. The decision is made on the approval card (plan §9.2, 14 Sep); once
    `automation` shows it decided, the brief says what was decided in place of pointing to the card."""
    from ..slack.blocks import change_brief

    catalog_card = next((p for p in response.pending if p.one_shot is None), None)
    blocks = change_brief(
        brief,
        proposal_summary=catalog_card.dry_run.summary if catalog_card is not None else None,
        action_id=response.proposal.action_id if response.proposal is not None else None,
        dry_run_digest=catalog_card.digest if catalog_card is not None else None,
        decided_line=_decided_line_for(automation, catalog_card) if catalog_card is not None else None,
    )
    return blocks, f"{brief.alert.service}: {len(brief.candidates)} recent change(s) found for this alert"


def _decided_line_for(automation: Any, pending: Any) -> str | None:
    """The outcome line for a decided card, or `None` while it is open (or with no gateway to ask)."""
    gateway = getattr(automation, "gateway", None)
    outcome = gateway.outcome(pending.incident_id, pending.action_id) if gateway is not None else None
    if outcome is None:
        return None
    from ..slack.handlers import _decided_line

    return _decided_line(outcome)


def _card_text(pending: Any) -> str:
    return f"Approval required: {pending.dry_run.summary}"


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
            blocks, text = _brief_message(response, change.brief, automation)
            update(brief_handle[0], brief_handle[1], blocks, text=text)
        note = approval_card_note(change.brief)
        for index, (pending, handle) in enumerate(zip(response.pending, card_handles)):
            # A decided card was closed by its click (A3); re-rendering it would restore live buttons.
            if _decided_line_for(automation, pending) is not None:
                continue
            if handle is not None and note != notes[index]:
                update(
                    handle[0],
                    handle[1],
                    approval_card_for(pending, coverage_note=note, brief=change.brief),
                    text=_card_text(pending),
                )
                notes[index] = note

    try:
        await automation.follow_coverage(response.brief, on_update, sleep=sleep)
    except Exception:  # following a gap must never surface as a crash in the incident path
        logger.exception("following coverage for %s failed", response.brief.incident_id)


def decision_closer(automation: Automation, update: Update, *, background: bool = True) -> Callable[..., None]:
    """A decided hook that brings *every* message about the decision up to date, not only the one clicked.

    The decision is made on the approval card (plan §9.2, 14 Sep), and the brief names the proposal and
    points to that card. This closes the card, re-rendered with its Approve and Reject replaced by the
    outcome line, and rewrites the brief's pointer as that same line. Runs for every recorded decision —
    never a replay.
    """
    import threading

    def hook(pending: Any, outcome: Any) -> None:
        from ..slack.blocks import change_brief, close_decision
        from ..slack.handlers import _decided_line, approval_card_for

        line = _decided_line(outcome)
        edits: list[tuple[tuple[str, str], list[dict[str, Any]]]] = []
        brief = automation.briefs.get(outcome.incident_id)

        card = automation.cards.get((outcome.incident_id, outcome.action_id))
        if card is not None:
            closed = close_decision(approval_card_for(pending, brief=brief), action_id=outcome.action_id, line=line)
            if closed is not None:
                edits.append((card, closed))

        thread = automation.threads.get(outcome.incident_id)
        # A one-shot is named on its card only; the brief's proposal line belongs to the catalog proposal.
        if brief is not None and thread is not None and pending.one_shot is None:
            edits.append(
                (
                    thread,
                    change_brief(
                        brief,
                        proposal_summary=pending.dry_run.summary,
                        action_id=pending.action_id,
                        dry_run_digest=pending.digest,
                        decided_line=line,
                    ),
                )
            )

        def send() -> None:
            for (channel, ts), blocks in edits:
                try:
                    update(channel, ts, blocks, text=line)
                except Exception:  # noqa: BLE001 - an unclosed message is cosmetic; the decision stands
                    logger.exception("could not close a decided message for %s", outcome.incident_id)

        if background:
            threading.Thread(target=send, daemon=True, name="close-decided").start()
        else:
            send()

    return hook


ACTOR_ROLE_ENV = "FAZEROPS_ACTOR_ROLE_ARN"


def assemble_from_env() -> Automation:
    """The production `Automation`, with the actor role the credential mint assumes for AWS actions.

    Without `FAZEROPS_ACTOR_ROLE_ARN`, an action that calls AWS (`restore_db_parameter`) is refused
    before its card opens: the only identity left to run it as is this process's own, and a mutation
    attributed to the automation host rather than its approver is the thing A4 exists to prevent.
    """
    import os

    role_arn = os.environ.get(ACTOR_ROLE_ENV) or None
    if role_arn is None:
        logger.warning(
            "%s is not set: actions that call AWS will be refused rather than run as this process's own identity",
            ACTOR_ROLE_ENV,
        )
    return Automation.assemble(role_arn=role_arn)


def record_poster(automation: Automation, upload: Callable[..., Any], *, background: bool = True) -> Callable[..., None]:
    """B3 — a decided hook that posts the incident record into the brief's thread.

    Runs off the Slack listener's thread by default: the gateway calls hooks inside `decide()`, and an
    upload must not hold the click's reply. Posts nothing for an incident whose brief was never
    posted by this process — there is no thread to put it in.
    """
    import re
    import threading

    from ..record.markdown import render_record

    def hook(pending: Any, outcome: Any) -> None:
        thread = automation.threads.get(outcome.incident_id)
        session = automation.incident_session(pending, outcome)
        if thread is None or session is None:
            return
        markdown = render_record(session)
        # The id carries the alert's own identifier, which the alert source controls.
        filename = re.sub(r"[^A-Za-z0-9._-]", "-", outcome.incident_id)[:120] + ".md"

        def send() -> None:
            try:
                upload(thread[0], thread[1], markdown, filename=filename, title=f"Incident record · {outcome.incident_id}")
            except Exception:  # noqa: BLE001 - a missing record is reported, never raised into a decision
                logger.exception("could not post the incident record for %s", outcome.incident_id)

        if background:
            threading.Thread(target=send, daemon=True, name="incident-record").start()
        else:
            send()

    return hook


def _save_quietly(store: Any, session: Any) -> None:
    try:
        store.save(session)
    except Exception:  # noqa: BLE001 - a missing stage is logged, never raised into the incident path
        logger.exception("could not persist session %s to %s", session.incident_id, getattr(store, "name", store))


def _investigated_session(response: Response) -> Any:
    from ..models import Proposal
    from ..record.session import IncidentSession

    proposal = response.proposal if isinstance(response.proposal, Proposal) else None
    return IncidentSession.from_brief(response.brief, proposal=proposal)


def session_persister(automation: Automation, store: Any, *, background: bool = True) -> Callable[..., None]:
    """W29 — a decided hook that appends the decided session to the session store (Handoff §10).

    The AgentCore Runtime writes the stages it sees; approval and execution happen here, so this is
    the only process that can write them. Appends, never overwrites (`record/store.py`), and runs off
    the Slack listener's thread for the same reason `record_poster` does. Writes nothing for an
    incident this process did not investigate — it has no brief to build the session from.
    """
    import threading

    def hook(pending: Any, outcome: Any) -> None:
        session = automation.incident_session(pending, outcome)
        if session is None:
            return
        if background:
            threading.Thread(target=_save_quietly, args=(store, session), daemon=True, name="session-store").start()
        else:
            _save_quietly(store, session)

    return hook


def build_app(
    automation: Automation,
    *,
    post: Post | None = None,
    update: Update | None = None,
    sleep: Sleep = asyncio.sleep,
    dedupe: Any | None = None,
    sessions: Any | None = None,
) -> FastAPI:
    from ..ingest.alerts import UnrecognisedPayload, normalize_alert
    from ..ingest.dedupe import AlertDeduper
    from ..models import incident_id_for

    app = FastAPI(title="FazerOps automation", version="0.1.0")
    # A re-delivered firing is answered with the first delivery's result and posts nothing: no second
    # brief, no second card, no re-registration behind a card someone is reading (D1, D2, A1).
    dedupe = dedupe if dedupe is not None else AlertDeduper()
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

        key = incident_id_for(alert)
        seen = dedupe.claim(key)
        if seen is not None:
            if seen.response is None:
                return JSONResponse({"incident_id": key, "deduplicated": True, "in_progress": True}, status_code=202)
            return JSONResponse({**seen.response, "posted": 0, "coverage_follow_up": False, "deduplicated": True})

        try:
            response = await automation.respond(alert)
        except BaseException:
            dedupe.abandon(key)
            raise
        messages = messages_for(response)
        handles = [_handle(post(blocks, text=text)) for blocks, text in messages] if post is not None else []
        # Where the incident record goes once a decision is recorded (B3): the brief's own thread.
        threads = getattr(automation, "threads", None)
        if threads is not None and handles and handles[0] is not None:
            threads[response.brief.incident_id] = handles[0]
        # Each card's own message, so a decision made on the brief can close the card too.
        cards = getattr(automation, "cards", None)
        if cards is not None:
            for pending, handle in zip(response.pending, handles[1:]):
                if handle is not None:
                    cards[pending.key] = handle

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

        # The investigated stage, off the request path: a slow store must not hold the webhook's reply.
        if sessions is not None:
            task = asyncio.create_task(asyncio.to_thread(_save_quietly, sessions, _investigated_session(response)))
            app.state.follow_ups.add(task)
            task.add_done_callback(app.state.follow_ups.discard)

        one_shot = response.one_shot
        body = {
            "incident_id": response.brief.incident_id,
            "proposal": response.proposal.action_id if response.proposal is not None else None,
            "one_shot": None if one_shot is None else (one_shot.one_shot.action_id if one_shot.offered else one_shot.refusal.value),
            "pending": [pending.action_id for pending in response.pending],
            "refused": response.refused,
            "posted": len(messages) if post is not None else 0,
            "coverage_follow_up": follow_up,
        }
        dedupe.finish(key, body)
        return JSONResponse({**body, "deduplicated": False})

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

    from ..slack.commands import command_handler
    from ..slack.handlers import approval_sink, post_brief, run_socket_mode, update_message, upload_record
    from .growth.job import run_on_schedule
    from .roster import default_roster

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    automation = assemble_from_env()

    def member(user_id: str) -> Any:
        return default_roster().resolve(user_id)

    automation.decided_hooks.append(decision_closer(automation, update_message))
    automation.decided_hooks.append(record_poster(automation, upload_record))
    from ..record.store import session_store_from_env

    sessions = session_store_from_env()
    if sessions is not None:
        automation.decided_hooks.append(session_persister(automation, sessions))
    sink = approval_sink(automation.gateway, resolve_approver=member, decisions=automation.decisions)
    command = command_handler(automation, resolve_member=member, decisions=automation.decisions)
    malformed = automation.decisions.record_malformed if automation.decisions is not None else None
    threading.Thread(
        target=run_socket_mode,
        kwargs={"sink": sink, "command": command, "on_malformed": malformed},
        daemon=True,
        name="slack-socket-mode",
    ).start()

    schedule = growth_schedule_from_env(automation)
    if schedule is not None:
        threading.Thread(target=run_on_schedule, kwargs=schedule, daemon=True, name="catalog-growth").start()

    uvicorn.run(build_app(automation, post=post_brief, update=update_message, sessions=sessions), host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    serve()
