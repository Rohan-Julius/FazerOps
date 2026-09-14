"""D2 and A1 (drift log, 14 Sep) — one incident id per firing, and one investigation per firing.

**D2.** `INC-{alert.id}` reused the alert rule's own identifier, stable across every firing, so the
second incident on an alarm hit the first incident's `(incident_id, action_id)` idempotency key and
its action was refused as already decided.

**A1.** Re-deliveries of one firing each ran a full investigation. Both webhooks now answer a
re-delivery from the first delivery's result.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fazerops.ingest.alerts import normalize_alert
from fazerops.ingest.dedupe import AlertDeduper
from fazerops.models import incident_id_for

FIXTURE_ALERTS = Path(__file__).resolve().parents[2] / "fixtures" / "alerts"


def _payload(name: str = "alertmanager.json") -> dict:
    return json.loads((FIXTURE_ALERTS / name).read_text(encoding="utf-8"))


def _refired(payload: dict, *, later: timedelta) -> dict:
    """The same Alertmanager rule firing again: same fingerprint, a later `startsAt`."""
    copy = json.loads(json.dumps(payload))
    started = datetime.fromisoformat(copy["alerts"][0]["startsAt"].replace("Z", "+00:00"))
    copy["alerts"][0]["startsAt"] = (started + later).isoformat().replace("+00:00", "Z")
    return copy


@pytest.fixture(autouse=True)
def fixture_mode(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


# --------------------------------------------------------------------------------------
# D2
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("shape", ["alertmanager.json", "cloudwatch.json", "pagerduty.json"])
def test_a_re_delivery_of_one_firing_keeps_its_incident_id(shape):
    assert incident_id_for(normalize_alert(_payload(shape))) == incident_id_for(normalize_alert(_payload(shape)))


def test_a_new_firing_of_the_same_rule_is_a_new_incident():
    this_week = normalize_alert(_payload())
    next_week = normalize_alert(_refired(_payload(), later=timedelta(days=7)))

    assert this_week.id == next_week.id, "the premise: the rule's fingerprint does not change"
    assert incident_id_for(this_week) != incident_id_for(next_week)


def test_the_incident_id_is_utc_regardless_of_the_source_offset():
    alert = normalize_alert(_payload("cloudwatch.json"))
    shifted = alert.model_copy(update={"fired_at": alert.fired_at.astimezone(timezone(timedelta(hours=-7)))})

    assert shifted.fired_at.utcoffset() == timedelta(hours=-7), "model_copy skipped the UTC validator"
    assert incident_id_for(alert) == incident_id_for(shifted)
    assert incident_id_for(alert).endswith("Z")


def test_the_next_firing_can_run_the_action_the_last_one_ran():
    """The consequence D2 broke, asserted at the gateway."""
    from fazerops import keys
    from fazerops.actions.approval import ApprovalGateway, Approver, ApproverRole
    from fazerops.actions.inverse import ActionRequest
    from fazerops.actions.preconditions import Evidence

    evidence = Evidence(
        resource_keys=frozenset({keys.k8s_configmap("billing", "billing-api-config").blast_radius_key()}),
        complete=True,
    )
    hint = {
        "action_id": "revert_configmap_key",
        "namespace": "billing",
        "name": "billing-api-config",
        "key": "pool.max",
        "prior_value": "100",
        "current_value": "20",
    }
    params = {"namespace": "billing", "name": "billing-api-config", "key": "pool.max", "target_value": "100"}
    calls: list[str] = []
    gateway = ApprovalGateway(runner=lambda request, credential, evidence: calls.append(request.action_id) or {})
    ic = Approver(user_id="U_IC_01", role=ApproverRole.ENGINEER)

    for later in (timedelta(0), timedelta(days=7)):
        incident = incident_id_for(normalize_alert(_refired(_payload(), later=later)))
        pending = gateway.register(incident, ActionRequest.for_action(hint["action_id"], params, inverse_hint=hint), evidence=evidence)
        gateway.decide(incident_id=incident, action_id=pending.action_id, approver=ic, kind="approve", dry_run_digest=pending.digest)

    assert calls == ["revert_configmap_key", "revert_configmap_key"]


# --------------------------------------------------------------------------------------
# A1 — the deduper
# --------------------------------------------------------------------------------------


def test_the_first_delivery_proceeds_and_later_ones_are_answered_from_it():
    dedupe = AlertDeduper()

    assert dedupe.claim("INC-a") is None
    assert dedupe.claim("INC-a").response is None, "still being investigated"
    dedupe.finish("INC-a", {"incident_id": "INC-a"})
    assert dedupe.claim("INC-a").response == {"incident_id": "INC-a"}
    assert dedupe.claim("INC-b") is None, "a different firing is never deduplicated"


def test_a_failed_investigation_is_retried_rather_than_answered_with_nothing():
    dedupe = AlertDeduper()
    dedupe.claim("INC-a")
    dedupe.abandon("INC-a")

    assert dedupe.claim("INC-a") is None


def test_a_claim_lapses_after_its_ttl():
    now = [0.0]
    dedupe = AlertDeduper(ttl_seconds=60, clock=lambda: now[0])
    dedupe.claim("INC-a")
    dedupe.finish("INC-a", {})
    now[0] = 61

    assert dedupe.claim("INC-a") is None


def test_memory_is_bounded():
    dedupe = AlertDeduper(max_entries=3)
    for index in range(10):
        dedupe.claim(f"INC-{index}")

    assert len(dedupe._entries) == 3
    assert dedupe.claim("INC-9") is not None, "the newest claims survive the prune"


# --------------------------------------------------------------------------------------
# A1 — both webhooks
# --------------------------------------------------------------------------------------


def test_the_tier0_webhook_investigates_a_firing_once(monkeypatch):
    from fastapi.testclient import TestClient

    import fazerops.main as main
    from fazerops.ingest.dedupe import AlertDeduper

    real = main.investigate
    calls: list[str] = []

    async def counting(alert):
        calls.append(alert.id)
        return await real(alert)

    monkeypatch.setattr(main, "investigate", counting)
    monkeypatch.setattr(main.app.state, "dedupe", AlertDeduper())
    client = TestClient(main.app)

    first = client.post("/webhook", json=_payload()).json()
    second = client.post("/webhook", json=_payload()).json()
    refired = client.post("/webhook", json=_refired(_payload(), later=timedelta(days=7))).json()

    assert len(calls) == 2, "the re-delivery was not investigated; the new firing was"
    assert first["deduplicated"] is False and second["deduplicated"] is True
    assert second["incident_id"] == first["incident_id"] != refired["incident_id"]
    assert second["brief"] == first["brief"]


def test_the_automation_webhook_posts_nothing_for_a_re_delivery(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from fazerops.actions.runtime import Response
    from fazerops.actions.server import build_app
    from fazerops.pipeline import investigate

    class Automation:
        state_dir = tmp_path

        def __init__(self) -> None:
            self.responded = 0

        async def respond(self, alert, *, collectors=None):
            self.responded += 1
            return Response(brief=await investigate(alert))

    automation = Automation()
    posted: list[str] = []
    client = TestClient(build_app(automation, post=lambda blocks, text: posted.append(text) or None))

    first = client.post("/alerts", json=_payload()).json()
    second = client.post("/alerts", json=_payload()).json()

    assert automation.responded == 1
    assert len(posted) == 1, "one brief, not two"
    assert first["posted"] == 1 and second["posted"] == 0
    assert second["deduplicated"] is True and second["incident_id"] == first["incident_id"]


def _automation_app(tmp_path, post, **attributes):
    from fastapi.testclient import TestClient

    from fazerops.actions.runtime import Response
    from fazerops.actions.server import build_app
    from fazerops.pipeline import investigate

    class Automation:
        state_dir = tmp_path
        responded = 0

        async def respond(self, alert, *, collectors=None):
            Automation.responded += 1
            return Response(brief=await investigate(alert))

    automation = Automation()
    for name, value in attributes.items():
        setattr(automation, name, value)
    return automation, TestClient(build_app(automation, post=post), raise_server_exceptions=False)


def test_a_failed_post_releases_the_claim_so_the_re_delivery_posts(tmp_path):
    """Regression: only a failed investigation released the claim. A Slack rate limit on the post
    left it "in progress" for the 24h TTL, and every re-delivery was answered 202 with nothing
    ever posted."""
    posted: list[str] = []
    failures = [RuntimeError("slack: ratelimited")]

    def post(blocks, text):
        if failures:
            raise failures.pop()
        posted.append(text)

    automation, client = _automation_app(tmp_path, post)

    assert client.post("/alerts", json=_payload()).status_code == 500
    retry = client.post("/alerts", json=_payload())

    assert retry.status_code == 200, retry.text
    assert retry.json()["deduplicated"] is False and retry.json()["posted"] == 1
    assert automation.responded == 2 and len(posted) == 1


def test_a_failure_after_everything_posted_does_not_post_a_second_brief(tmp_path):
    """The other half: once the brief is in the channel, a re-delivery is answered from it even if
    bookkeeping after the post raised — releasing the claim there would post the brief twice."""

    class Threads(dict):
        def __setitem__(self, key, value):
            raise RuntimeError("bookkeeping failed")

    posted: list[str] = []
    automation, client = _automation_app(
        tmp_path, lambda blocks, text: posted.append(text) or {"channel": "C1", "ts": "1.0"}, threads=Threads()
    )

    assert client.post("/alerts", json=_payload()).status_code == 500
    retry = client.post("/alerts", json=_payload()).json()

    assert retry["deduplicated"] is True and retry.get("in_progress") is None
    assert automation.responded == 1 and len(posted) == 1


def test_the_text_webhook_investigates_a_firing_once(monkeypatch):
    """Gap 4 (14 Sep): `/webhook/text` was the one endpoint that still investigated every delivery."""
    from fastapi.testclient import TestClient

    import fazerops.main as main
    from fazerops.ingest.dedupe import AlertDeduper

    real = main.investigate
    calls: list[str] = []

    async def counting(alert):
        calls.append(alert.id)
        return await real(alert)

    monkeypatch.setattr(main, "investigate", counting)
    monkeypatch.setattr(main.app.state, "dedupe", AlertDeduper())
    client = TestClient(main.app)

    first = client.post("/webhook/text", json=_payload())
    second = client.post("/webhook/text", json=_payload())
    as_json = client.post("/webhook", json=_payload())

    assert len(calls) == 2, "the text re-delivery was answered from cache; the JSON endpoint has its own"
    assert second.status_code == 200 and second.text == first.text
    assert as_json.json()["deduplicated"] is False, "one endpoint never answers with the other's shape"
