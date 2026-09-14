"""W25 — the Slack app's callback path. Handoff §9, plan §6's Sep 11 gate.

The gate's first signal is *"a Block Kit message posts and a button callback returns"*.
Both halves are asserted here without a workspace: `post_brief` against a fake WebClient,
and the button callback against Bolt's real handler registration driven by a synthetic
interaction payload.

**`parse_decision` is where every hostile input lands**, which is why it is a pure
function separated from the Bolt handler — the tests that matter need no socket. The rule
it enforces is `blocks._payload`'s: a button carries *identifiers only*. A payload edited
in transit names an incident and an action id, both of which are checked downstream; it
cannot smuggle a namespace or a target value into an executor.
"""

from __future__ import annotations

import json

import pytest
from slack_sdk import WebClient
from slack_sdk.web import SlackResponse

from fazerops.slack.handlers import (
    Decision,
    MalformedCallback,
    SlackConfig,
    SlackNotConfigured,
    build_app,
    parse_decision,
    post_brief,
    slack_config,
)

SYNTHETIC = SlackConfig(
    bot_token="xoxb-synthetic-not-a-credential",
    app_token="xapp-synthetic-not-a-credential",
    channel_id="C0SYNTHETIC",
    signing_secret="synthetic-signing-secret",
)


def _interaction(action_id: str = "approve", value: dict | str | None = None) -> dict:
    """A Slack `block_actions` payload, in the shape Bolt hands a handler."""
    if value is None:
        value = {"incident_id": "INC-1", "action_id": "revert_configmap_key", "dry_run": "0123456789abcdef"}
    return {
        "type": "block_actions",
        "user": {"id": "U0IC"},
        "channel": {"id": "C0SYNTHETIC"},
        "message": {"ts": "1789000000.000100"},
        "actions": [
            {
                "type": "button",
                "action_id": action_id,
                "value": value if isinstance(value, str) else json.dumps(value),
            }
        ],
    }


class FakeWebClient(WebClient):
    """Slack's own client with the network removed, rather than a stand-in for it.

    A subclass, not a duck type, because Bolt type-checks `client` and refuses anything
    that is not a `WebClient` — and because a fake that does not satisfy the same check the
    production path does is a fake that can drift away from it silently.
    """

    def __init__(self) -> None:
        super().__init__(token="xoxb-synthetic-not-a-credential")
        self.posted: list[dict] = []

    def chat_postMessage(self, **kwargs):  # type: ignore[override]
        self.posted.append(kwargs)
        return self._response({"ok": True, "ts": "1789000000.000200"})

    def auth_test(self, **kwargs):  # type: ignore[override]
        """Bolt authorizes **every** inbound request, not just startup, so a fake that
        only stubs `chat.postMessage` never reaches a listener — the request is refused by
        middleware and the handler silently does not run. That failure returns HTTP 200,
        which is why the test asserts on the decisions the sink saw and not on the status.
        """
        return self._response(
            {
                "ok": True,
                "url": "https://synthetic.slack.com/",
                "team": "synthetic",
                "user": "fazerops",
                "team_id": "T0SYNTHETIC",
                "user_id": "U0BOT",
                "bot_id": "B0SYNTHETIC",
            }
        )

    def _response(self, data: dict) -> SlackResponse:
        return SlackResponse(
            client=self,
            http_verb="POST",
            api_url="https://slack.com/api/synthetic",
            req_args={},
            data=data,
            headers={},
            status_code=200,
        )


# --------------------------------------------------------------------------------------
# Parsing — where hostile input lands
# --------------------------------------------------------------------------------------


def test_an_approve_click_parses_into_a_decision():
    decision = parse_decision(_interaction())

    assert decision == Decision(
        kind="approve",
        incident_id="INC-1",
        action_id="revert_configmap_key",
        user_id="U0IC",
        channel_id="C0SYNTHETIC",
        message_ts="1789000000.000100",
        dry_run_digest="0123456789abcdef",
    )


def test_the_clicking_user_is_carried_because_w26b_routes_on_it():
    """Tier 2 needs a different approver principal, so the identity of the clicker is not
    decoration — it is the input to the routing decision."""
    assert parse_decision(_interaction()).user_id == "U0IC"


def test_show_all_parses_without_an_action_id():
    decision = parse_decision(_interaction("show_all", {"incident_id": "INC-1", "action_id": None}))
    assert decision.kind == "show_all"
    assert decision.action_id is None


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ({"actions": []}, "no actions"),
        (_interaction("delete_namespace"), "unknown action_id"),
        (_interaction(value="not json at all"), "not JSON"),
        (_interaction(value="[1, 2, 3]"), "expected an object"),
        (_interaction(value={"action_id": "revert_configmap_key"}), "no incident_id"),
        (_interaction(value={"incident_id": "INC-1"}), "no action_id"),
        (_interaction(value={"incident_id": "INC-1", "action_id": 7}), "non-string action_id"),
    ],
)
def test_a_malformed_callback_is_refused_rather_than_guessed(payload, match):
    """Every one of these is a payload this app did not build, or one edited in transit.
    A handler that guessed what was meant would be acting on an attacker's intent."""
    with pytest.raises(MalformedCallback, match=match):
        parse_decision(payload)


def test_a_button_payload_carries_identifiers_and_nothing_executable():
    """The rule `blocks._payload` states: identifiers only.

    Extra keys in the payload are ignored rather than surfaced — there is nowhere for them
    to go. `Decision` forbids extras and is built field by field from the three keys this
    parser reads, so a `namespace` planted in a button value reaches no executor.
    """
    smuggled = _interaction(
        value={
            "incident_id": "INC-1",
            "action_id": "revert_configmap_key",
            "dry_run": "0123456789abcdef",
            "namespace": "kube-system",
            "target_value": "0",
        }
    )
    decision = parse_decision(smuggled)

    assert not hasattr(decision, "namespace")
    assert set(decision.model_dump()) == {
        "kind",
        "incident_id",
        "action_id",
        "user_id",
        "channel_id",
        "message_ts",
        "dry_run_digest",
    }


# --------------------------------------------------------------------------------------
# The gate's signal: a message posts and a button callback returns
# --------------------------------------------------------------------------------------


def test_a_block_kit_message_posts():
    client = FakeWebClient()
    post_brief(
        [{"type": "section", "text": {"type": "mrkdwn", "text": "hello"}}],
        text="FazerOps brief",
        config=SYNTHETIC,
        client=client,
    )

    assert len(client.posted) == 1
    posted = client.posted[0]
    assert posted["channel"] == "C0SYNTHETIC"
    assert posted["blocks"][0]["type"] == "section"
    # Without a fallback, a phone notification shows the app name and nothing else.
    assert posted["text"] == "FazerOps brief"


def test_a_button_callback_returns_through_bolts_real_handler():
    """Driven through Bolt's own dispatch rather than by calling the handler directly —
    the registration is the part that silently does nothing when it is wrong."""
    from slack_bolt.request import BoltRequest

    seen: list[Decision] = []

    def sink(decision: Decision) -> None:
        """Returns `None` so the handler does not call `say`.

        Bolt builds a *fresh* `WebClient` for every request from the app's token, so the
        injected fake cannot intercept `say` — only the construction-time `auth.test`.
        The reply path is covered with an injected `say` in
        `test_a_malformed_callback_tells_the_operator_rather_than_disappearing`.
        """
        seen.append(decision)

    app = build_app(config=SYNTHETIC, sink=sink, client=FakeWebClient())

    body = f"payload={json.dumps(_interaction())}"
    response = app.dispatch(
        BoltRequest(
            body=body,
            headers={"content-type": ["application/x-www-form-urlencoded"]},
            mode="socket_mode",  # Socket Mode skips signature verification — see below.
        )
    )

    assert response.status == 200, "Slack shows the operator a failure on anything else"
    assert [d.kind for d in seen] == ["approve"]
    assert seen[0].action_id == "revert_configmap_key"


def test_w25s_sink_acknowledges_and_executes_nothing():
    """W26 owns routing, idempotency and execution. A sink that executed a day early would
    be one written without the idempotency key that keeps a double-click from being a
    double mutation."""
    from fazerops.slack.handlers import _record_only

    response = _record_only(parse_decision(_interaction()))

    assert "approved" in response
    assert "nothing has run" in response


def test_a_malformed_callback_tells_the_operator_rather_than_disappearing():
    """A silently dropped callback looks to the person who clicked exactly like an
    approval that worked."""
    from fazerops.slack.handlers import _make_handler

    said: list[str] = []
    acked: list[bool] = []
    handler = _make_handler(lambda decision: "should not be reached")

    handler(
        ack=lambda: acked.append(True),
        body=_interaction(value="not json"),
        say=said.append,
        logger=None,
    )

    assert acked == [True], "ack comes first — Slack times an interaction out at 3s"
    assert said and "did not carry a valid incident reference" in said[0]


# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------


def test_missing_slack_configuration_names_the_variable_rather_than_defaulting(monkeypatch):
    """A missing token must not produce a demo that appears to run and posts nothing."""
    for name in ("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "SLACK_CHANNEL_ID"):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(SlackNotConfigured) as excinfo:
        slack_config()

    message = str(excinfo.value)
    for name in ("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "SLACK_CHANNEL_ID"):
        assert name in message


def test_the_signing_secret_is_optional_on_the_socket_path(monkeypatch):
    """Socket Mode authenticates the connection with the app token, so no inbound HTTP
    request arrives to verify. The secret is still read when present — Handoff §9 requires
    the HTTP path to verify, and `test_signature.py` covers it."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-synthetic")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-synthetic")
    monkeypatch.setenv("SLACK_CHANNEL_ID", "C0SYNTHETIC")
    monkeypatch.delenv("SLACK_SIGNING_SECRET", raising=False)

    assert slack_config().signing_secret is None
