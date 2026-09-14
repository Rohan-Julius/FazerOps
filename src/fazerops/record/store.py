"""W29 — where an `IncidentSession` persists. Handoff §10: *"AgentCore for deployment and session state."*

**AgentCore Memory is the Handoff's store, and on this account it cannot be created** (14 Sep): the
`Memories` quota (`L-81002DCC`) is 0 in every region AgentCore runs in, and an increase has to ask for
at least the default of 150, which routes to AWS Support rather than approving. So two stores sit behind
one interface and an environment variable picks between them (plan §9.2, approved 14 Sep):

* `DynamoSessionStore` — the one that runs. One table, written by the AgentCore Runtime when an
  investigation finishes and by the automation server when a decision is recorded.
* `MemorySessionStore` — AgentCore Memory's short-term events, written against the service model and
  tested against a fake. `# UNVERIFIED (U10)` until a live quota lets it run. Short-term only, with no
  strategies: a strategy extracts long-term records **with a Bedrock model**, and Bedrock inference is
  blocked on this account too.

**Append-only.** Each stage is its own write and nothing is overwritten, so a session's history —
investigated, then approved, then executed — is readable after the fact and a later write cannot erase
an earlier one. `load` returns the latest.

**The store is a record, not a channel** (`record/session.py`). Nothing reads a stored session to decide
anything: the approval path re-derives every action from the catalog and from what its own process
holds, so a tampered row cannot cause a mutation.

Nothing here touches the network unless `FAZEROPS_SESSION_STORE` names a store — the default is none,
which is what keeps the zero-credential path zero-network (`tests/integration/test_no_network.py`).
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .session import IncidentSession

__all__ = [
    "DynamoSessionStore",
    "MemorySessionStore",
    "SessionStore",
    "SessionTooLarge",
    "StoredStage",
    "session_store_from_env",
]

STORE_ENV = "FAZEROPS_SESSION_STORE"
TABLE_ENV = "FAZEROPS_SESSION_TABLE"
MEMORY_ID_ENV = "FAZEROPS_SESSION_MEMORY_ID"
REGION_ENV = "FAZEROPS_SESSION_REGION"
DEFAULT_TABLE = "fazerops-incident-sessions"

# DynamoDB refuses an item over 400 KB. Refused here, with headroom for the key and attributes, so the
# failure names the session rather than arriving as a ValidationException about an item.
MAX_SESSION_BYTES = 350_000

# AgentCore Memory's sessionId pattern and length. The incident id carries the alert's own id, which the
# alert source controls; an id that does not fit is refused rather than rewritten, because rewriting can
# map two incidents onto one session and interleave their histories.
_MEMORY_SESSION_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,99}")
MEMORY_ACTOR = "fazerops"


class SessionTooLarge(ValueError):
    pass


@dataclass(frozen=True)
class StoredStage:
    """One write in a session's history: when, and how far the incident had got."""

    recorded_at: str
    stage: str


class SessionStore(Protocol):
    name: str

    def save(self, session: IncidentSession) -> str:
        """Append this state of the session. Returns the write's reference."""

    def load(self, incident_id: str) -> IncidentSession | None:
        """The latest state written for this incident, or `None` if nothing was."""

    def history(self, incident_id: str) -> list[StoredStage]:
        """Every write for this incident, oldest first."""


def _encoded(session: IncidentSession) -> str:
    text = session.model_dump_json()
    if len(text.encode("utf-8")) > MAX_SESSION_BYTES:
        raise SessionTooLarge(
            f"session {session.incident_id} is {len(text.encode('utf-8'))} bytes; the store takes "
            f"at most {MAX_SESSION_BYTES}"
        )
    return text


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class DynamoSessionStore:
    """One item per write: partition key `incident_id`, sort key `recorded_at`.

    The sort key carries a random suffix after the timestamp, and the put is conditional on the key
    being new, so two writes in the same microsecond append two items instead of one overwriting the
    other — the only way this table could lose a stage.
    """

    name = "dynamodb"

    def __init__(self, table: str, client: Any) -> None:
        self.table = table
        self._client = client

    def save(self, session: IncidentSession) -> str:
        sort_key = f"{_now()}#{uuid.uuid4().hex[:8]}"
        self._client.put_item(
            TableName=self.table,
            Item={
                "incident_id": {"S": session.incident_id},
                "recorded_at": {"S": sort_key},
                "stage": {"S": session.stage},
                "session": {"S": _encoded(session)},
            },
            ConditionExpression="attribute_not_exists(recorded_at)",
        )
        return sort_key

    def _query(self, incident_id: str, *, newest_first: bool, limit: int | None, attributes: str) -> list[dict]:
        items: list[dict] = []
        params: dict[str, Any] = {
            "TableName": self.table,
            "KeyConditionExpression": "incident_id = :id",
            "ExpressionAttributeValues": {":id": {"S": incident_id}},
            "ScanIndexForward": not newest_first,
            "ProjectionExpression": attributes,
            "ConsistentRead": True,
        }
        if "#s" in attributes:
            # `session` is a DynamoDB reserved word, so its projection goes through a placeholder.
            params["ExpressionAttributeNames"] = {"#s": "session"}
        while True:
            if limit is not None:
                params["Limit"] = limit - len(items)
            page = self._client.query(**params)
            items.extend(page.get("Items", []))
            start = page.get("LastEvaluatedKey")
            if start is None or (limit is not None and len(items) >= limit):
                return items
            params["ExclusiveStartKey"] = start

    def load(self, incident_id: str) -> IncidentSession | None:
        items = self._query(incident_id, newest_first=True, limit=1, attributes="#s")
        if not items:
            return None
        return IncidentSession.model_validate_json(items[0]["session"]["S"])

    def history(self, incident_id: str) -> list[StoredStage]:
        items = self._query(incident_id, newest_first=False, limit=None, attributes="recorded_at, stage")
        return [StoredStage(recorded_at=i["recorded_at"]["S"].split("#")[0], stage=i["stage"]["S"]) for i in items]


class MemorySessionStore:
    """AgentCore Memory short-term events: actor `fazerops`, one Memory session per incident, one blob
    event per write. `# UNVERIFIED (U10)` — the shapes are the service model's, not a live response."""

    name = "agentcore-memory"

    def __init__(self, memory_id: str, client: Any) -> None:
        self.memory_id = memory_id
        self._client = client

    @staticmethod
    def _session_id(incident_id: str) -> str:
        if not _MEMORY_SESSION_ID.fullmatch(incident_id):
            raise ValueError(f"incident id {incident_id!r} is not a valid AgentCore Memory session id")
        return incident_id

    def save(self, session: IncidentSession) -> str:
        response = self._client.create_event(
            memoryId=self.memory_id,
            actorId=MEMORY_ACTOR,
            sessionId=self._session_id(session.incident_id),
            eventTimestamp=datetime.now(timezone.utc),
            payload=[{"blob": _encoded(session)}],
            metadata={"stage": {"stringValue": session.stage}},
        )
        return response["event"]["eventId"]

    def _events(self, incident_id: str) -> list[dict]:
        events: list[dict] = []
        params: dict[str, Any] = {
            "memoryId": self.memory_id,
            "actorId": MEMORY_ACTOR,
            "sessionId": self._session_id(incident_id),
            "includePayloads": True,
            "maxResults": 100,
        }
        while True:
            page = self._client.list_events(**params)
            events.extend(page.get("events", []))
            token = page.get("nextToken")
            if not token:
                break
            params["nextToken"] = token
        return sorted(events, key=lambda event: event["eventTimestamp"])

    @staticmethod
    def _blob(event: dict) -> str | None:
        for part in event.get("payload", []):
            if "blob" in part:
                blob = part["blob"]
                return blob if isinstance(blob, str) else json.dumps(blob)
        return None

    def load(self, incident_id: str) -> IncidentSession | None:
        for event in reversed(self._events(incident_id)):
            blob = self._blob(event)
            if blob is not None:
                return IncidentSession.model_validate_json(blob)
        return None

    def history(self, incident_id: str) -> list[StoredStage]:
        stages = []
        for event in self._events(incident_id):
            stage = (event.get("metadata") or {}).get("stage", {}).get("stringValue", "unknown")
            stamp = event["eventTimestamp"]
            stages.append(StoredStage(recorded_at=stamp.isoformat() if hasattr(stamp, "isoformat") else str(stamp), stage=stage))
        return stages


def _region() -> str:
    region = os.environ.get(REGION_ENV) or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if not region:
        raise ValueError(f"{STORE_ENV} is set but no region is: set {REGION_ENV} (the store's region, sa-east-1)")
    return region


def session_store_from_env() -> SessionStore | None:
    """The configured store, or `None` when `FAZEROPS_SESSION_STORE` is unset or `none`.

    An unknown value raises rather than falling back to none: a deployment that believes it is
    persisting and silently is not is the failure this function exists to prevent.
    """
    choice = (os.environ.get(STORE_ENV) or "none").strip().lower()
    if choice == "none":
        return None

    import boto3

    if choice == "dynamodb":
        table = os.environ.get(TABLE_ENV) or DEFAULT_TABLE
        return DynamoSessionStore(table, boto3.client("dynamodb", region_name=_region()))
    if choice == "agentcore-memory":
        memory_id = os.environ.get(MEMORY_ID_ENV)
        if not memory_id:
            raise ValueError(f"{STORE_ENV}=agentcore-memory needs {MEMORY_ID_ENV}")
        return MemorySessionStore(memory_id, boto3.client("bedrock-agentcore", region_name=_region()))
    raise ValueError(f"{STORE_ENV}={choice!r}: expected none, dynamodb or agentcore-memory")
