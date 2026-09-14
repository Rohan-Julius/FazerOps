"""Ingest's two promises to a webhook sender.

* **A payload it cannot use is a 400, never a 500.** Every caller maps `UnrecognisedPayload` to a
  client error and nothing else. A malformed body that escaped as a pydantic `ValidationError` or
  an `AttributeError` became a 500 instead — and Alertmanager retries a 5xx, re-sending a payload
  that can never succeed.
* **A grouped Alertmanager notification is investigated for an alert that is still firing.**
  Resolved alerts ride along in the same `alerts[]`, in no promised order.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from fazerops.ingest.alerts import NothingFiring, UnrecognisedPayload, normalize_alert

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "alerts"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _alertmanager_without_starts_at() -> dict:
    payload = _load("alertmanager")
    del payload["alerts"][0]["startsAt"]
    return payload


def _alertmanager_with_list_labels() -> dict:
    payload = _load("alertmanager")
    payload["alerts"][0]["labels"] = ["service", "billing-api"]
    return payload


def _cloudwatch_without_state_change_time() -> dict:
    payload = _load("cloudwatch")
    payload.pop("StateChangeTime", None)
    return payload


def _cloudwatch_with_numeric_state_change_time() -> dict:
    payload = _load("cloudwatch")
    payload["StateChangeTime"] = 1757169660
    return payload


def _pagerduty_without_timestamps() -> dict:
    payload = _load("pagerduty")
    payload["event"].pop("occurred_at", None)
    payload["event"]["data"].pop("created_at", None)
    return payload


MALFORMED = {
    "a JSON array": lambda: [1, 2],
    "a JSON string": lambda: "billing-api is down",
    "alertmanager without startsAt": _alertmanager_without_starts_at,
    "alertmanager with list labels": _alertmanager_with_list_labels,
    "cloudwatch without StateChangeTime": _cloudwatch_without_state_change_time,
    "cloudwatch with a numeric StateChangeTime": _cloudwatch_with_numeric_state_change_time,
    "pagerduty without a timestamp": _pagerduty_without_timestamps,
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")
    from fastapi.testclient import TestClient

    from fazerops.main import app

    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_a_malformed_payload_is_unrecognised_rather_than_a_crash(name):
    with pytest.raises(UnrecognisedPayload):
        normalize_alert(MALFORMED[name]())


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_a_malformed_payload_is_a_400_at_the_webhook(client, name):
    assert client.post("/webhook", json=MALFORMED[name]()).status_code == 400


def test_the_rejection_names_the_field_without_echoing_its_value():
    """The message goes back to the sender and into logs; the payload's values are untrusted."""
    payload = _load("cloudwatch")
    payload["StateChangeTime"] = "<script>not a time</script>"
    with pytest.raises(UnrecognisedPayload) as raised:
        normalize_alert(payload)
    assert "fired_at" in str(raised.value)
    assert "script" not in str(raised.value)


def test_the_first_firing_alert_is_investigated_not_the_first_listed():
    payload = _load("alertmanager")
    firing = payload["alerts"][0]
    resolved = copy.deepcopy(firing)
    resolved["status"] = "resolved"
    resolved["fingerprint"] = "00000000resolved"
    resolved["labels"]["service"] = "session-store"
    payload["alerts"] = [resolved, firing]

    alert = normalize_alert(payload)

    assert alert.id == firing["fingerprint"]
    assert alert.service == "billing-api"


def test_a_notification_with_only_resolved_alerts_starts_no_investigation(client):
    """Nothing is wrong any more. Investigating would post a brief for an incident that is over."""
    payload = _load("alertmanager")
    payload["status"] = "resolved"
    payload["alerts"][0]["status"] = "resolved"

    with pytest.raises(NothingFiring):
        normalize_alert(payload)
    assert client.post("/webhook", json=payload).status_code == 400


def test_the_demo_alert_still_normalizes():
    assert normalize_alert(_load("alertmanager")).service == "billing-api"
