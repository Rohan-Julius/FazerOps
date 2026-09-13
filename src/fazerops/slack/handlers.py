"""W25 — the Slack app: posting briefs and receiving button callbacks. Handoff §9.

Socket Mode, so there is no tunnel to maintain during the demo and no Request URL that
stops working when the laptop changes network.

**This module is the only one in the package that talks to Slack.** `blocks.py` and
`signature.py` are pure, which is what lets their tests run in the CI default with no
token and no socket. The split is also the seam W26 builds against: the decision handler
below parses and validates a callback and then hands a typed `Decision` to a sink. W26
replaces the sink with approval routing, idempotency and execution; it does not have to
touch parsing, acking or the socket.

**Automation layer** (plan §3.5). The investigation layer imports nothing from here, and
`tests/integration/test_layer_seam.py` makes that structural.

`slack_bolt` is an optional dependency (`pip install 'fazerops[slack]'`) and every import
of it is deliberately inside a function. A judge running the fixture quickstart has no
Slack workspace, and a module-level import would make the whole package unimportable for
a dependency the demo path never uses.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "Decision",
    "DecisionSink",
    "MalformedCallback",
    "approval_card_for",
    "approval_sink",
    "SlackNotConfigured",
    "build_app",
    "parse_decision",
    "post_brief",
    "run_socket_mode",
    "slack_config",
]

ACTION_IDS = ("approve", "reject", "show_all")


class SlackNotConfigured(RuntimeError):
    """A Slack surface was asked for without the tokens to build it.

    Raised rather than defaulted, because the failure mode of a missing token is a demo
    that appears to run and silently posts nothing.
    """


class MalformedCallback(ValueError):
    """An interaction payload did not carry the identifiers this app minted.

    Distinct from a Slack-level authentication failure: the connection is authentic, the
    *payload* is not one `blocks.py` produced. Treated as a refusal, never as a reason to
    guess what was meant.
    """


class SlackConfig(BaseModel):
    """The four values `.env` supplies. Read at call time, never at import."""

    model_config = ConfigDict(frozen=True)

    bot_token: str
    app_token: str
    channel_id: str
    signing_secret: str | None = None


class Decision(BaseModel):
    """One button press, parsed and identified — the automation layer's input event.

    Carries identifiers only. The parameters of the action are re-derived from the
    incident by whoever consumes this; nothing a human's Slack client sent is allowed to
    name a namespace or a target value (`blocks._payload`).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["approve", "reject", "show_all"]
    incident_id: str
    action_id: str | None = None
    user_id: str = Field(description="The Slack user who clicked. W26b's approver identity.")
    channel_id: str | None = None
    message_ts: str | None = None


# What to do with a parsed decision. W25 records it; W26 routes, checks idempotency and
# executes. Typed as a plain callable so W26 substitutes a function rather than subclassing
# anything — the seam is the `Decision`, not a class hierarchy.
DecisionSink = Callable[[Decision], "str | None"]


def slack_config() -> SlackConfig:
    """Build the config from the environment, or say exactly which variable is missing."""
    values = {
        "bot_token": os.environ.get("SLACK_BOT_TOKEN", ""),
        "app_token": os.environ.get("SLACK_APP_TOKEN", ""),
        "channel_id": os.environ.get("SLACK_CHANNEL_ID", ""),
    }
    missing = sorted(f"SLACK_{name.upper()}" for name, value in values.items() if not value)
    if missing:
        raise SlackNotConfigured(
            f"missing {', '.join(missing)}. See .env.example; the values live in .env, "
            "which is gitignored and never committed."
        )
    return SlackConfig(**values, signing_secret=os.environ.get("SLACK_SIGNING_SECRET") or None)


def parse_decision(payload: dict[str, Any]) -> Decision:
    """Turn a Slack interaction payload into a `Decision`, or refuse it.

    Pure, and separated from the Bolt handler on purpose: this is where every hostile
    input lands, and a test for it should not need a socket. The Bolt handler below is
    then three lines that cannot be got wrong.
    """
    actions = payload.get("actions") or []
    if not actions:
        raise MalformedCallback("interaction payload carried no actions")

    action = actions[0]
    kind = action.get("action_id")
    if kind not in ACTION_IDS:
        raise MalformedCallback(f"unknown action_id {kind!r}; expected one of {ACTION_IDS}")

    try:
        value = json.loads(action.get("value") or "")
    except json.JSONDecodeError as exc:
        raise MalformedCallback(f"button value was not JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise MalformedCallback(f"button value was {type(value).__name__}, expected an object")

    incident_id = value.get("incident_id")
    if not incident_id or not isinstance(incident_id, str):
        raise MalformedCallback("button value carried no incident_id")

    action_id = value.get("action_id")
    if action_id is not None and not isinstance(action_id, str):
        raise MalformedCallback("button value carried a non-string action_id")

    # Approve and Reject without an action are refused rather than treated as a no-op. A
    # payload in that shape is either a card this app did not build or one edited in
    # transit, and both are the case the refusal exists for.
    if kind in ("approve", "reject") and not action_id:
        raise MalformedCallback(f"{kind} callback carried no action_id")

    return Decision(
        kind=kind,
        incident_id=incident_id,
        action_id=action_id,
        user_id=(payload.get("user") or {}).get("id", ""),
        channel_id=(payload.get("channel") or {}).get("id"),
        message_ts=(payload.get("message") or {}).get("ts"),
    )


def build_app(
    *,
    config: SlackConfig | None = None,
    sink: DecisionSink | None = None,
    client: Any | None = None,
) -> Any:
    """A Bolt app with the three button handlers registered.

    `client` is injectable so a test can drive real handler registration offline. It has
    to be a `slack_sdk.WebClient` — Bolt type-checks it — so the test subclasses one and
    removes the network rather than passing a duck type.

    **`token_verification_enabled` stays on**, including under the injected client. Bolt
    authorizes every inbound interaction, and with no cached `auth.test` result it makes
    that call inline, inside the 3-second budget Slack gives an ack. Verifying once at
    construction caches it: a bad token then fails when the process starts rather than on
    the first click of an incident, and the interaction path never waits on Slack to find
    out who we are.
    """
    from slack_bolt import App

    config = config if config is not None else slack_config()
    sink = sink if sink is not None else _record_only

    app = App(
        token=config.bot_token,
        signing_secret=config.signing_secret,
        token_verification_enabled=True,
        client=client,
        raise_error_for_unhandled_request=False,
    )

    for kind in ACTION_IDS:
        app.action(kind)(_make_handler(sink))

    return app


def _make_handler(sink: DecisionSink):
    """One handler for all three buttons — the branch is the `Decision.kind`.

    **`ack()` comes first, always.** Slack times out an interaction at 3 seconds and then
    shows the operator a failure, so anything the sink does slowly must not delay it.
    """

    def handle(ack, body, say=None, logger=None, **_: Any) -> None:
        ack()
        try:
            decision = parse_decision(body)
        except MalformedCallback as exc:
            # Refused, and visibly. A silently dropped callback looks to the operator
            # exactly like an approval that worked.
            if logger is not None:
                logger.warning("refused a malformed Slack callback: %s", exc)
            if say is not None:
                say(":no_entry: That button did not carry a valid incident reference.")
            return

        response = sink(decision)
        if response and say is not None:
            say(response)

    return handle


def _record_only(decision: Decision) -> str:
    """W25's sink: acknowledge the click and say what would happen next.

    **Deliberately does not execute anything.** W26 owns approval routing and idempotency,
    and an executing sink written a day early is one written without the idempotency key
    that keeps a double-click from being a double mutation.
    """
    if decision.kind == "show_all":
        return f"Full change list for {decision.incident_id} — see the incident record."
    verb = "approved" if decision.kind == "approve" else "rejected"
    return (
        f"<@{decision.user_id}> {verb} `{decision.action_id}` for {decision.incident_id}. "
        "Routing and execution land with W26; nothing has run."
    )


def approval_card_for(pending: Any) -> list[dict[str, Any]]:
    """Render the approval card for a `PendingApproval`. W26b.

    The one mapping from gateway state to card, so a caller cannot hand `approval_card` the
    *declared* tier by mistake — which would understate an escalation on precisely the
    action that escalated, and is the reason `blocks.approval_card` takes the tier as an
    argument rather than reading the catalog itself.
    """
    from .blocks import approval_card

    return approval_card(
        pending.dry_run,
        incident_id=pending.incident_id,
        tier=pending.tier,
        escalation_reason=pending.escalation_reason,
        provisional=pending.provisional,
        graduation=pending.graduation,
        one_shot=(
            None
            if pending.one_shot is None
            else ("human-written" if pending.one_shot.authored_by == "human" else "generated")
        ),
    )


def approval_sink(
    gateway: Any,
    *,
    resolve_approver: Callable[[str], Any],
) -> DecisionSink:
    """W26 — the sink that routes a click to the approval gateway.

    This is the seam W25 left open, filled without touching parsing, acking or the socket.
    It is deliberately thin: every decision this function could get wrong — the tier, the
    scope, whether it already ran — is made by `actions/approval.py`, which is the module
    the credential gate allowlists. **Nothing here re-derives an action from the payload.**

    `resolve_approver` maps a Slack user id to an `Approver` and is injected rather than
    read from a roster here, because W26b owns the roster and this function must not grow a
    default that treats an unknown clicker as an engineer.

    Returns the line Slack shows. **It never renders an executed result's values** — the
    inverse summary printed a redacted value back out in full once already (12 Sep,
    `docs/drift_log.md`), and the result of a ConfigMap patch is exactly the kind of value
    that was redacted on the card two messages earlier.
    """
    from ..actions.approval import ApprovalRefused, ApproverNotPermitted, NotAwaitingApproval

    def sink(decision: Decision) -> str | None:
        if decision.kind == "show_all":
            return f"Full change list for {decision.incident_id} — see the incident record."

        try:
            # Inside the guard on purpose: `roster.UnknownApprover` is an `ApprovalRefused`,
            # and resolving outside the try would let an unlisted clicker raise through the
            # Bolt listener instead of being told they are not on the roster.
            approver = resolve_approver(decision.user_id)
            outcome = gateway.decide(
                incident_id=decision.incident_id,
                action_id=decision.action_id,
                approver=approver,
                kind=decision.kind,
            )
        except ApproverNotPermitted as exc:
            # Visible, and it names the escalation. A silently ignored click looks to the
            # operator exactly like an approval that worked.
            return f":lock: {exc}"
        except NotAwaitingApproval:
            return (
                f":no_entry: No approval is open for `{decision.action_id}` on "
                f"{decision.incident_id}. Nothing has run."
            )
        except ApprovalRefused as exc:
            return f":no_entry: {exc}"

        if outcome.replay:
            return (
                f":repeat: `{outcome.action_id}` on {outcome.incident_id} was already "
                f"{outcome.decision} by <@{outcome.approver}>. Nothing was re-run."
            )
        if outcome.decision == "rejected":
            return (
                f":x: <@{outcome.approver}> rejected `{outcome.action_id}` for "
                f"{outcome.incident_id}. Nothing has run."
            )
        if outcome.error:
            return (
                f":warning: `{outcome.action_id}` was approved by <@{outcome.approver}> but "
                f"failed: {outcome.error}. Check the resource before retrying — the "
                "approval will not run again."
            )
        return (
            f":white_check_mark: <@{outcome.approver}> approved `{outcome.action_id}` for "
            f"{outcome.incident_id} (tier {int(outcome.tier)}); it executed once."
        )

    return sink


def post_brief(
    blocks: list[dict[str, Any]],
    *,
    text: str,
    config: SlackConfig | None = None,
    client: Any | None = None,
) -> dict[str, Any]:
    """Post a rendered message to the demo channel.

    Takes rendered blocks rather than a `Brief`, so the one function that opens a socket
    has no opinion about rendering and `blocks.py` stays free of I/O.

    `text` is the notification fallback. Slack shows it in the sidebar and in push
    notifications, and a message without one arrives titled with the app's name and
    nothing else — on a phone, at 2am, that is the whole of what an on-call sees.
    """
    from slack_sdk import WebClient

    config = config if config is not None else slack_config()
    client = client if client is not None else WebClient(token=config.bot_token)
    return client.chat_postMessage(channel=config.channel_id, blocks=blocks, text=text)


def run_socket_mode(*, sink: DecisionSink | None = None) -> None:  # pragma: no cover - a loop
    """Open the socket and block. The demo's listener process."""
    from slack_bolt.adapter.socket_mode import SocketModeHandler

    config = slack_config()
    SocketModeHandler(build_app(config=config, sink=sink), config.app_token).start()
