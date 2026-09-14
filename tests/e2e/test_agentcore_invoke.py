"""W29 — the deployed AgentCore endpoint, invoked for real. Plan §4's acceptance test:
*"deployed endpoint returns a JSON-serializable brief for a fixture alert."*

**Not free, unlike the other live markers.** One run is one live investigation — orchestrator and
correlator on Gemini, billed to GCP credits — plus a few seconds of Runtime compute and two DynamoDB
writes. So it runs only when `-m agentcore` is selected **explicitly** and the Runtime's ARN is set;
the default suite's `-m "not cluster and not aws and not github"` would otherwise select it.

    FAZEROPS_AGENTCORE_RUNTIME_ARN=arn:aws:bedrock-agentcore:sa-east-1:…:runtime/fazerops-… \
        pytest -m agentcore tests/e2e/test_agentcore_invoke.py

One investigation serves every assertion (a module-scoped fixture): the read-back costs no model call.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.agentcore

RUNTIME_ARN_ENV = "FAZEROPS_AGENTCORE_RUNTIME_ARN"
ALERT = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json").read_text(encoding="utf-8"))
INCIDENT_ID = "INC-7c1f9a2e4b6d8033-20260906T144100Z"
# Identity issues the Gemini key only to a request that names a user (agentcore_app.py).
RUNTIME_USER = "fazerops-e2e"


@pytest.fixture(scope="module")
def endpoint(request):
    if "agentcore" not in (request.config.getoption("markexpr") or ""):
        pytest.skip("spends GCP credits: select it explicitly with -m agentcore")
    arn = os.environ.get(RUNTIME_ARN_ENV)
    if not arn:
        pytest.skip(f"{RUNTIME_ARN_ENV} is not set")

    import boto3
    from botocore.config import Config

    # The graph's backstop is 120 s; the default 60 s read timeout would abandon a brief mid-flight.
    client = boto3.client(
        "bedrock-agentcore",
        region_name=arn.split(":")[3],
        config=Config(read_timeout=300, retries={"max_attempts": 1}),
    )

    def call(payload: dict, *, user: str | None = None) -> dict:
        kwargs = {
            "agentRuntimeArn": arn,
            "runtimeSessionId": f"fazerops-e2e-{uuid.uuid4().hex}",  # the service wants ≥ 33 chars
            "payload": json.dumps(payload).encode("utf-8"),
            "contentType": "application/json",
            "accept": "application/json",
        }
        if user is not None:
            kwargs["runtimeUserId"] = user
        return json.loads(client.invoke_agent_runtime(**kwargs)["response"].read())

    return call


@pytest.fixture(scope="module")
def investigated(endpoint):
    return endpoint({"alert": ALERT}, user=RUNTIME_USER)


def test_the_endpoint_returns_the_demo_brief(investigated):
    assert "error" not in investigated, investigated.get("error")
    assert investigated["incident_id"] == INCIDENT_ID
    assert investigated["stage"] == "investigated"
    assert investigated["degraded"] is False
    assert "billing-api-config" in investigated["brief"]


def test_it_came_up_gemini_backed_on_the_fixture_world(investigated):
    """Reported by the container, never assumed: a Runtime that defaulted to the stub answers with
    a brief that looks entirely normal."""
    assert investigated["runtime"]["llm"] == "gemini"
    assert investigated["runtime"]["mode"] == "fixture"


def test_the_ranking_is_the_golden_one(investigated):
    candidates = investigated["session"]["candidates"]
    assert candidates[0]["event"]["resource"]["name"] == "billing-api-config"
    assert candidates[0]["score"] - candidates[1]["score"] >= 0.15, "the golden test's margin floor"


def test_the_narrative_is_the_models_and_cites_only_real_evidence(investigated):
    """Handoff §6: an uncited or fabricated claim is dropped, so what survives cites real ids."""
    session = investigated["session"]
    assert session["narrative"]
    cited = set(session["evidence_ids"])
    assert cited and cited <= {candidate["event"]["id"] for candidate in session["candidates"]}


def test_the_session_was_persisted(investigated):
    assert investigated["persisted"]["ok"] is True, investigated["persisted"]
    assert investigated["persisted"]["store"] == "dynamodb"


def test_the_session_reads_back_from_the_store(endpoint, investigated):
    read = endpoint({"get_session": INCIDENT_ID})

    assert "error" not in read, read.get("error")
    assert "investigated" in [stage["stage"] for stage in read["history"]]
    assert read["session"]["candidates"] == investigated["session"]["candidates"]
