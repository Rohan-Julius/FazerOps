"""W29 — the session store behind the AgentCore deployment (Handoff §10, `record/store.py`).

Both stores run against fakes that enforce what the real services would refuse: DynamoDB's conditional
put and its reserved word `session`, and AgentCore Memory's session-id pattern. A fake that accepted
anything would pass a store that the service rejects on the first live write.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fazerops.record import store as store_module
from fazerops.record.session import ApprovalRecord, ExecutionRecord, IncidentSession
from fazerops.record.store import (
    MAX_SESSION_BYTES,
    DynamoSessionStore,
    MemorySessionStore,
    SessionTooLarge,
    session_store_from_env,
)

ALERT = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json").read_text(encoding="utf-8"))
DYNAMO_RESERVED = {"session"}


class ConditionalCheckFailed(Exception):
    pass


class FakeDynamo:
    """Items keyed by (incident_id, recorded_at); query sorts, pages and projects like the service."""

    def __init__(self, page_size: int = 100) -> None:
        self.items: dict[tuple[str, str], dict] = {}
        self.page_size = page_size

    def put_item(self, *, TableName, Item, ConditionExpression=None):
        key = (Item["incident_id"]["S"], Item["recorded_at"]["S"])
        if ConditionExpression == "attribute_not_exists(recorded_at)" and key in self.items:
            raise ConditionalCheckFailed(key)
        self.items[key] = Item

    def query(self, *, TableName, KeyConditionExpression, ExpressionAttributeValues, ScanIndexForward=True,
              ProjectionExpression=None, ExpressionAttributeNames=None, ConsistentRead=False, Limit=None,
              ExclusiveStartKey=None):
        names = ExpressionAttributeNames or {}
        wanted = [names.get(part.strip(), part.strip()) for part in ProjectionExpression.split(",")]
        for part in ProjectionExpression.split(","):
            assert part.strip() not in DYNAMO_RESERVED, f"reserved word {part.strip()!r} used in a projection"
        incident = ExpressionAttributeValues[":id"]["S"]
        keys = sorted((k for k in self.items if k[0] == incident), key=lambda k: k[1], reverse=not ScanIndexForward)
        if ExclusiveStartKey is not None:
            start = (ExclusiveStartKey["incident_id"]["S"], ExclusiveStartKey["recorded_at"]["S"])
            keys = keys[keys.index(start) + 1:]
        size = min(self.page_size, Limit or self.page_size)
        page = keys[:size]
        result = {"Items": [{name: self.items[k][name] for name in wanted} for k in page]}
        if len(keys) > size:
            last = page[-1]
            result["LastEvaluatedKey"] = {"incident_id": {"S": last[0]}, "recorded_at": {"S": last[1]}}
        return result


class FakeMemory:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def create_event(self, *, memoryId, actorId, sessionId, eventTimestamp, payload, metadata=None):
        assert store_module._MEMORY_SESSION_ID.fullmatch(sessionId)
        event = {
            "eventId": f"ev-{len(self.events)}",
            "memoryId": memoryId,
            "actorId": actorId,
            "sessionId": sessionId,
            # The service orders by this timestamp, and two writes can share a clock tick.
            "eventTimestamp": eventTimestamp + timedelta(microseconds=len(self.events)),
            "payload": payload,
            "metadata": metadata or {},
        }
        self.events.append(event)
        return {"event": event}

    def list_events(self, *, memoryId, actorId, sessionId, includePayloads, maxResults, nextToken=None):
        matching = [e for e in self.events if (e["memoryId"], e["actorId"], e["sessionId"]) == (memoryId, actorId, sessionId)]
        start = int(nextToken or 0)
        page = matching[start:start + 2]
        result = {"events": list(reversed(page))}  # the service does not promise an order
        if start + 2 < len(matching):
            result["nextToken"] = str(start + 2)
        return result


@pytest.fixture
def session() -> IncidentSession:
    from fazerops.ingest.alerts import normalize_alert
    from fazerops.models import incident_id_for

    alert = normalize_alert(ALERT)
    return IncidentSession(incident_id=incident_id_for(alert), alert=alert)


def _decided(session: IncidentSession) -> IncidentSession:
    at = datetime(2026, 9, 6, 14, 45, tzinfo=timezone.utc)
    approved = session.with_approval(
        ApprovalRecord(decision="approved", approver="U_IC", approved_at=at, action_id="revert_configmap_key", tier=1)
    )
    return approved.with_execution(ExecutionRecord(action_id="revert_configmap_key", succeeded=True, executed_at=at))


@pytest.fixture(params=["dynamodb", "agentcore-memory"])
def store(request):
    if request.param == "dynamodb":
        return DynamoSessionStore("sessions", FakeDynamo(page_size=1))
    return MemorySessionStore("mem-1", FakeMemory())


def test_a_saved_session_loads_back_whole(store, session):
    store.save(session)

    assert store.load(session.incident_id) == session


def test_nothing_stored_loads_as_none(store):
    assert store.load("INC-never-seen") is None
    assert store.history("INC-never-seen") == []


def test_stages_append_and_the_latest_is_what_loads(store, session):
    """Each stage is its own write, so the history survives and the latest state is what a reader sees."""
    store.save(session)
    store.save(_decided(session))

    assert store.load(session.incident_id).stage == "executed"
    assert [s.stage for s in store.history(session.incident_id)] == ["opened", "executed"]


def test_two_incidents_never_share_a_history(store, session):
    other = session.model_copy(update={"incident_id": session.incident_id + "-other"})
    store.save(session)
    store.save(_decided(other))

    assert store.load(session.incident_id).stage == "opened"
    assert [s.stage for s in store.history(other.incident_id)] == ["executed"]


def test_an_oversize_session_is_refused_with_its_name(store, session, monkeypatch):
    monkeypatch.setattr(store_module, "MAX_SESSION_BYTES", 100)

    with pytest.raises(SessionTooLarge, match=session.incident_id):
        store.save(session)
    assert MAX_SESSION_BYTES < 400_000, "DynamoDB's item limit, with room for the key"


def test_dynamo_writes_in_the_same_instant_both_land(session, monkeypatch):
    """The conditional put is what stops a same-microsecond write from overwriting a stage."""
    monkeypatch.setattr(store_module, "_now", lambda: "2026-09-06T14:45:00.000000+00:00")
    fake = FakeDynamo()
    dynamo = DynamoSessionStore("sessions", fake)

    dynamo.save(session)
    dynamo.save(_decided(session))

    assert len(fake.items) == 2


def test_memory_refuses_an_incident_id_it_cannot_hold_rather_than_rewriting_it(session):
    """Rewriting an id can map two incidents onto one Memory session and interleave their histories."""
    memory = MemorySessionStore("mem-1", FakeMemory())
    hostile = session.model_copy(update={"incident_id": "INC-a:b/../c"})

    with pytest.raises(ValueError, match="not a valid AgentCore Memory session id"):
        memory.save(hostile)


# --------------------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------------------


def test_no_store_is_configured_by_default(monkeypatch):
    """The zero-credential path stays zero-network: nothing is built unless asked for."""
    monkeypatch.delenv("FAZEROPS_SESSION_STORE", raising=False)

    assert session_store_from_env() is None


def test_dynamodb_is_selected_with_its_table_and_region(monkeypatch):
    monkeypatch.setenv("FAZEROPS_SESSION_STORE", "dynamodb")
    monkeypatch.setenv("FAZEROPS_SESSION_REGION", "sa-east-1")
    monkeypatch.delenv("FAZEROPS_SESSION_TABLE", raising=False)

    chosen = session_store_from_env()

    assert isinstance(chosen, DynamoSessionStore)
    assert chosen.table == "fazerops-incident-sessions"
    assert chosen._client.meta.region_name == "sa-east-1"


def test_memory_needs_its_id(monkeypatch):
    monkeypatch.setenv("FAZEROPS_SESSION_STORE", "agentcore-memory")
    monkeypatch.setenv("FAZEROPS_SESSION_REGION", "sa-east-1")
    monkeypatch.delenv("FAZEROPS_SESSION_MEMORY_ID", raising=False)

    with pytest.raises(ValueError, match="FAZEROPS_SESSION_MEMORY_ID"):
        session_store_from_env()


def test_an_unknown_store_is_refused_rather_than_treated_as_none(monkeypatch):
    """A deployment that believes it is persisting and silently is not is the failure to prevent."""
    monkeypatch.setenv("FAZEROPS_SESSION_STORE", "dynamo")

    with pytest.raises(ValueError, match="expected none, dynamodb or agentcore-memory"):
        session_store_from_env()


def test_a_store_without_a_region_says_which_variable_to_set(monkeypatch):
    monkeypatch.setenv("FAZEROPS_SESSION_STORE", "dynamodb")
    for name in ("FAZEROPS_SESSION_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ValueError, match="FAZEROPS_SESSION_REGION"):
        session_store_from_env()
