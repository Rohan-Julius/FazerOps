"""B2 — `/fazerops`: read an incident's state from Slack, with no model in the loop.

    /fazerops status <incident>          the brief's #1, open cards and what was decided
    /fazerops brief <incident>           the brief again, as text
    /fazerops changes <service> [4h]     recorded changes touching a service's blast radius
    /fazerops help

**Read-only by construction.** There is no subcommand that decides or runs anything, and there must
never be one: a mutation reaches an executor only through a card `ApprovalGateway.register` opened,
with its dry run shown first. A `/fazerops approve` would be a second path around that.

**Parsed, not interpreted.** The text is split on whitespace and matched against four fixed shapes;
anything else is refused with the usage. A service must be one `config/service_manifest.yaml`
names, and a window is bounded to 24h, so a command cannot widen a ledger query past what an
investigation could have asked for (`LedgerStore.query` has no unscoped variant).

**Who may ask.** People on the approver roster — the same fail-closed list that may approve, so an
empty roster answers nobody. Replies are ephemeral: an incident's state is shown to the person who
asked, not re-posted into a channel.

**What it can see.** Briefs and open cards live in this process's memory (`Automation`), so a
restart forgets them and `status` says so. `changes` reads the durable ledger — what investigations
have collected — not the live sources.

The Slack app needs the `/fazerops` slash command configured and the `commands` scope; in Socket
Mode no request URL is required.

**Automation layer** (plan §3.5).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict

__all__ = [
    "COMMAND",
    "Command",
    "MalformedCommand",
    "USAGE",
    "answer",
    "command_handler",
    "parse_command",
]

COMMAND = "/fazerops"

DEFAULT_CHANGES_WINDOW = timedelta(hours=4)
MAX_CHANGES_WINDOW = timedelta(hours=24)  # the orchestrator's own bound on an investigation window
MAX_CHANGES_LISTED = 15
# Slack truncates a message's text well above this, but a code block this long is already a scroll.
_BRIEF_LIMIT = 2800

_DURATION = re.compile(r"^(\d{1,4})([mh])$")
_INCIDENT = re.compile(r"^INC-[A-Za-z0-9._:-]{1,200}$")

USAGE = "\n".join(
    [
        f"*`{COMMAND}`* — read an incident's state. Nothing here changes anything.",
        f"• `{COMMAND} status <incident>` — the #1 change, open approval cards, and what was decided",
        f"• `{COMMAND} brief <incident>` — the change brief again",
        f"• `{COMMAND} changes <service> [30m|4h]` — recorded changes in a service's blast radius (max 24h)",
        f"• `{COMMAND} help`",
    ]
)


class MalformedCommand(ValueError):
    """The text matched none of the four shapes. Refused with the usage, never guessed at."""


class Command(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: Literal["help", "status", "brief", "changes"]
    incident_id: str | None = None
    service: str | None = None
    window: timedelta | None = None


def parse_command(text: str) -> Command:
    parts = (text or "").split()
    if not parts or parts[0].lower() == "help":
        return Command(name="help")

    name, args = parts[0].lower(), parts[1:]

    if name in ("status", "brief"):
        if len(args) != 1:
            raise MalformedCommand(f"usage: `{COMMAND} {name} <incident id>`")
        if not _INCIDENT.match(args[0]):
            raise MalformedCommand(f"`{_code(args[0])}` is not an incident id (they look like `INC-…`)")
        return Command(name=name, incident_id=args[0])

    if name == "changes":
        if not 1 <= len(args) <= 2:
            raise MalformedCommand(f"usage: `{COMMAND} changes <service> [30m|4h]`")
        window = DEFAULT_CHANGES_WINDOW
        if len(args) == 2:
            match = _DURATION.match(args[1].lower())
            if match is None:
                raise MalformedCommand(f"`{_code(args[1])}` is not a window — use minutes or hours, like `30m` or `4h`")
            amount = int(match[1])
            window = timedelta(minutes=amount) if match[2] == "m" else timedelta(hours=amount)
            if not timedelta(0) < window <= MAX_CHANGES_WINDOW:
                raise MalformedCommand("the window must be more than 0 and at most 24h")
        return Command(name="changes", service=args[0], window=window)

    raise MalformedCommand(f"unknown subcommand `{_code(name)}`")


def answer(command: Command, automation: Any, *, now: datetime | None = None) -> str:
    """The reply to one parsed command. Pure over `automation`'s state; performs no Slack I/O."""
    if command.name == "help":
        return USAGE
    if command.name == "status":
        return _status(command.incident_id or "", automation)
    if command.name == "brief":
        return _brief(command.incident_id or "", automation)
    return _changes(command.service or "", command.window or DEFAULT_CHANGES_WINDOW, automation, now=now)


def command_handler(
    automation: Any,
    *,
    resolve_member: Callable[[str], Any],
    decisions: Any = None,
) -> Callable[..., None]:
    """The Bolt listener for `/fazerops`. `resolve_member` is `Roster.resolve`: it raises for anyone
    not on the roster, and that refusal is the access check."""
    from ..actions.approval import ApprovalRefused

    def log(user_id: str, kind: str, result: str, reason: str | None = None, role: str | None = None) -> None:
        if decisions is None:
            return
        try:
            decisions.record(result=result, user_id=user_id, kind=kind, reason=reason, role=role)
        except Exception:  # noqa: BLE001 - an audit write never changes the reply
            pass

    def handle(ack, command, respond, logger=None, **_: Any) -> None:
        ack()  # first, always — Slack gives a slash command 3 seconds
        user_id = str((command or {}).get("user_id") or "")
        text = str((command or {}).get("text") or "")

        try:
            member = resolve_member(user_id)
        except ApprovalRefused as exc:
            log(user_id, "command", "refused", reason=f"{type(exc).__name__}: {exc}")
            respond(text=f"`{COMMAND}` is available to people on the approver roster.", response_type="ephemeral")
            return

        role = getattr(getattr(member, "role", None), "value", None)
        try:
            parsed = parse_command(text)
        except MalformedCommand as exc:
            log(user_id, "command", "malformed", reason=str(exc), role=role)
            respond(text=f"{exc}\n{USAGE}", response_type="ephemeral")
            return

        try:
            reply = answer(parsed, automation)
        except Exception:  # noqa: BLE001 - a failed read is reported, never raised through Bolt
            if logger is not None:
                logger.exception("%s %s failed", COMMAND, parsed.name)
            reply = "That lookup failed. Nothing was changed."

        log(user_id, f"command:{parsed.name}", "read", role=role)
        respond(text=reply, response_type="ephemeral")

    return handle


# --------------------------------------------------------------------------------------
# The answers
# --------------------------------------------------------------------------------------


def _not_found(incident_id: str) -> str:
    return (
        f"No incident `{_code(incident_id)}` in this process. Briefs and open cards "
        "are kept in memory, so a restart forgets them."
    )


def _status(incident_id: str, automation: Any) -> str:
    brief = automation.briefs.get(incident_id)
    gateway = automation.gateway
    cards = gateway.open_cards(incident_id)
    outcomes = gateway.outcomes_for(incident_id)
    if brief is None and not cards and not outcomes:
        return _not_found(incident_id)

    lines = [f"*{_plain(incident_id)}*"]
    if brief is not None:
        count = len(brief.candidates)
        lines.append(
            f"{_plain(brief.alert.service)} · {count} change{'' if count == 1 else 's'} in the blast radius"
            + (" · degraded" if brief.degraded else "")
        )
        if brief.candidates:
            top = brief.candidates[0]
            lines.append(
                f"#1 {_plain(top.event.resource.kind)} `{_code(top.event.resource.name)}` — score {top.score:.2f}, "
                f"{_plain(top.event.action.value)} by {_plain(top.event.actor.display)}"
            )

    for card in cards:
        if gateway.is_expired(card):
            state = "expired — re-investigate for a fresh card"
        elif card.expires_at is not None:
            state = f"open until {datetime.fromtimestamp(card.expires_at, timezone.utc):%H:%M} UTC"
        else:
            state = "open"
        lines.append(f"• `{_code(card.action_id)}` — tier {int(card.tier)} — {state}")

    for outcome in outcomes:
        ran = "failed" if outcome.error else ("executed once" if outcome.executed else "nothing ran")
        lines.append(f"• `{_code(outcome.action_id)}` — {outcome.decision} by {_mention(outcome.approver)} — {ran}")

    if not cards and not outcomes:
        lines.append("No approval card was opened for this incident.")
    return "\n".join(lines)


def _brief(incident_id: str, automation: Any) -> str:
    brief = automation.briefs.get(incident_id)
    if brief is None:
        return _not_found(incident_id)

    from ..render.text import render_brief

    text = render_brief(brief)
    if len(text) > _BRIEF_LIMIT:
        text = text[:_BRIEF_LIMIT] + "\n… (truncated)"
    # The brief quotes alert text and change values, both attacker-influenceable: a fence inside
    # them must not close the block, and `<!channel>` must not become a mention.
    return f"```{_plain(text).replace('```', chr(39) * 3)}```"


def _changes(service: str, window: timedelta, automation: Any, *, now: datetime | None) -> str:
    from ..models import TimeWindow
    from ..radius import default_manifest

    manifest = default_manifest()
    if not manifest.knows(service):
        known = ", ".join(f"`{name}`" for name in sorted(manifest.service_names))
        return f"`{_code(service)}` is not in `config/service_manifest.yaml`. Known services: {known}."

    end = now or datetime.now(timezone.utc)
    events = automation.ledger.query(manifest.resolve(service), TimeWindow(start=end - window, end=end))
    span = _span(window)
    if not events:
        return (
            f"No recorded changes touching `{_code(service)}`'s blast radius in the last {span}. "
            "This reads FazerOps's ledger — what investigations collected — not the live sources."
        )

    lines = [
        f"*{len(events)} recorded change{'' if len(events) == 1 else 's'} touching `{_code(service)}`'s "
        f"blast radius in the last {span}* — newest first, from the ledger, not live"
    ]
    for event in list(reversed(events))[:MAX_CHANGES_LISTED]:
        where = f"{event.resource.namespace}/{event.resource.name}" if event.resource.namespace else event.resource.name
        lines.append(
            f"• `{event.occurred_at:%m-%d %H:%M}` {_plain(event.source)} · {_plain(event.action.value)} "
            f"{_plain(event.resource.kind)} `{_code(where)}` by {_plain(event.actor.display)}"
            + ("" if event.actor.resolved else " (unresolved)")
            + (" · in band" if event.in_band else "")
        )
    if len(events) > MAX_CHANGES_LISTED:
        lines.append(f"…and {len(events) - MAX_CHANGES_LISTED} more.")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Escaping — every string below came from an alert, a change or a command's own text
# --------------------------------------------------------------------------------------


def _plain(text: Any) -> str:
    """Slack's three control characters, escaped as its API documentation requires. Without it a
    ConfigMap named `<!channel>` pings everyone the moment someone asks about it."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _code(text: Any) -> str:
    return _plain(text).replace("`", "'")


def _mention(user_id: str) -> str:
    """A mention only for an id shaped like Slack's own. Anything else is shown, escaped, as it is —
    stripping characters to make it fit would mention a different person."""
    text = str(user_id)
    return f"<@{text}>" if re.fullmatch(r"[UW][A-Z0-9]{2,}", text) else f"`{_code(text)}`"


def _span(window: timedelta) -> str:
    minutes = int(window.total_seconds() // 60)
    return f"{minutes // 60}h" if minutes % 60 == 0 else f"{minutes}m"
