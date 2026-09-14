"""W26 — the Slack callback wired to the approval gateway. Handoff §7 and §9.

W25 left a `DecisionSink` seam and a sink that executed nothing. This asserts the seam was
filled without changing parsing, acking or the socket: the same synthetic payload W25's
tests drive through **Bolt's own dispatch** now reaches the gateway, and a double delivery
— Slack retries, and humans double-click — patches the cluster once.

The gateway's runner is injected, so nothing here touches a cluster. What is *not* faked
is Bolt's registration or the credential mint; both are the parts that silently do nothing
when they are wrong.
"""

from __future__ import annotations

import json

import pytest
from slack_sdk import WebClient
from slack_sdk.web import SlackResponse

from fazerops import keys
from fazerops.actions.approval import ApprovalGateway, Approver, ApproverRole
from fazerops.actions.inverse import ActionRequest
from fazerops.actions.preconditions import Evidence
from fazerops.slack.handlers import Decision, SlackConfig, approval_sink, build_app

SYNTHETIC = SlackConfig(
    bot_token="xoxb-synthetic-not-a-credential",
    app_token="xapp-synthetic-not-a-credential",
    channel_id="C0SYNTHETIC",
    signing_secret="synthetic-signing-secret",
)

INCIDENT = "INC-1"
HINT = {
    "action_id": "revert_configmap_key",
    "namespace": "billing",
    "name": "billing-api-config",
    "key": "pool.max",
    "prior_value": "100",
    "current_value": "20",
}
EVIDENCE = Evidence(
    resource_keys=frozenset(
        {keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}
    ),
    complete=True,
)

ROSTER = {
    "U0IC": Approver(user_id="U0IC", role=ApproverRole.ENGINEER),
    "U0MGR": Approver(user_id="U0MGR", role=ApproverRole.MANAGER),
}


def _resolve(user_id: str) -> Approver:
    return ROSTER[user_id]


def _request() -> ActionRequest:
    return ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
        inverse_hint=HINT,
    )


def _interaction(action_id: str = "approve", user: str = "U0IC") -> dict:
    return {
        "type": "block_actions",
        "user": {"id": user},
        "channel": {"id": "C0SYNTHETIC"},
        "message": {"ts": "1789000000.000100"},
        "actions": [
            {
                "type": "button",
                "action_id": action_id,
                "value": json.dumps(
                    {
                        "incident_id": INCIDENT,
                        "action_id": "revert_configmap_key",
                        # What the rendered card carries (D1): the digest of the dry run it shows.
                        "dry_run": _request().dry_run(evidence=EVIDENCE).digest,
                    }
                ),
            }
        ],
    }


class FakeWebClient(WebClient):
    """Slack's client with the network removed — a subclass because Bolt type-checks it."""

    def __init__(self) -> None:
        super().__init__(token="xoxb-synthetic-not-a-credential")

    def auth_test(self, **kwargs):  # type: ignore[override]
        return SlackResponse(
            client=self,
            http_verb="POST",
            api_url="https://slack.com/api/auth.test",
            req_args={},
            data={"ok": True, "user_id": "U0BOT", "bot_id": "B0BOT", "team_id": "T0TEAM"},
            headers={},
            status_code=200,
        )


class Runner:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, request, credential, evidence):
        self.calls.append(request.action_id)
        return {"action_id": request.action_id}


@pytest.fixture
def wired():
    runner = Runner()
    gateway = ApprovalGateway(runner=runner)
    gateway.register(INCIDENT, _request(), evidence=EVIDENCE)
    sink = approval_sink(gateway, resolve_approver=_resolve)
    return gateway, runner, sink


def _dispatch(sink, payload: dict):
    """Drive one payload through Bolt's real registration.

    The sink is wrapped to return `None`. Bolt builds a **fresh `WebClient` per request**
    from the app's token (`handlers.build_app`), so the injected fake cannot intercept
    `say` — a sink returning a string here makes a real call to slack.com. That is not a
    production defect; it is why the reply text is asserted by calling the sink directly
    below, and why this helper asserts the *effect* on the gateway instead.
    """
    from slack_bolt.request import BoltRequest

    def silent(decision):
        sink(decision)
        return None

    app = build_app(config=SYNTHETIC, sink=silent, client=FakeWebClient())
    return app.dispatch(
        BoltRequest(
            body=f"payload={json.dumps(payload)}",
            headers={"content-type": ["application/x-www-form-urlencoded"]},
            mode="socket_mode",
        )
    )


def test_an_approval_click_reaches_the_gateway_through_bolts_real_dispatch(wired):
    _, runner, sink = wired

    response = _dispatch(sink, _interaction())

    assert response.status == 200, "Slack shows the operator a failure on anything else"
    assert runner.calls == ["revert_configmap_key"]


def test_a_redelivered_click_executes_once(wired):
    """Slack retries an interaction it thinks was not acked, and operators double-click.
    Both arrive here as two identical payloads."""
    _, runner, sink = wired

    _dispatch(sink, _interaction())
    _dispatch(sink, _interaction())

    assert runner.calls == ["revert_configmap_key"], "a redelivery executed a second mutation"


def test_a_rejection_click_executes_nothing(wired):
    _, runner, sink = wired

    _dispatch(sink, _interaction(action_id="reject"))

    assert runner.calls == []


# --------------------------------------------------------------------------------------
# What the sink says back — called directly, because Bolt builds a fresh client per
# request and the injected fake cannot intercept `say` (W25, `handlers.build_app`).
# --------------------------------------------------------------------------------------


def test_the_reply_names_the_approver_and_says_it_executed_once(wired):
    _, _, sink = wired

    reply = sink(
        Decision(
            kind="approve",
            incident_id=INCIDENT,
            action_id="revert_configmap_key",
            user_id="U0IC",
        )
    )
    assert "<@U0IC>" in reply and "executed once" in reply


def test_the_replay_reply_says_nothing_was_re_run(wired):
    _, _, sink = wired
    decision = Decision(
        kind="approve",
        incident_id=INCIDENT,
        action_id="revert_configmap_key",
        user_id="U0IC",
    )

    sink(decision)
    reply = sink(decision)

    assert "already" in reply and "re-run" in reply


def test_an_ic_clicking_an_escalated_action_is_told_why():
    runner = Runner()
    gateway = ApprovalGateway(runner=runner)
    gateway.register(INCIDENT, _request(), evidence=EVIDENCE, crosses_namespace_boundary=True)
    sink = approval_sink(gateway, resolve_approver=_resolve)

    reply = sink(
        Decision(
            kind="approve",
            incident_id=INCIDENT,
            action_id="revert_configmap_key",
            user_id="U0IC",
        )
    )

    assert runner.calls == []
    assert "namespace" in reply, "the operator is not told why it escalated"

    # The card stayed open for the manager it escalated to.
    assert "executed once" in sink(
        Decision(
            kind="approve",
            incident_id=INCIDENT,
            action_id="revert_configmap_key",
            user_id="U0MGR",
        )
    )
    assert runner.calls == ["revert_configmap_key"]


def test_a_click_on_a_card_this_process_never_opened_is_refused():
    """A card from a previous process, or a forged payload. Either way the action is not
    reconstructed from the click."""
    runner = Runner()
    sink = approval_sink(ApprovalGateway(runner=runner), resolve_approver=_resolve)

    reply = sink(
        Decision(
            kind="approve",
            incident_id="INC-NEVER-REGISTERED",
            action_id="revert_configmap_key",
            user_id="U0IC",
        )
    )

    assert runner.calls == []
    assert "Nothing has run" in reply


def test_the_reply_never_renders_the_value_that_was_written():
    """The inverse summary printed a redacted value back out in full once already
    (12 Sep, `docs/drift_log.md`). A ConfigMap patch's result is exactly that kind of
    value, and the card two messages earlier may have masked it."""

    class LeakyRunner:
        def __call__(self, request, credential, evidence):
            return {"action_id": request.action_id, "value": "s3cret-connection-string"}

    gateway = ApprovalGateway(runner=LeakyRunner())
    gateway.register(INCIDENT, _request(), evidence=EVIDENCE)
    sink = approval_sink(gateway, resolve_approver=_resolve)

    reply = sink(
        Decision(
            kind="approve",
            incident_id=INCIDENT,
            action_id="revert_configmap_key",
            user_id="U0IC",
        )
    )

    assert "s3cret-connection-string" not in reply
