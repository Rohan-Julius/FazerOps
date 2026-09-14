"""`_gemini_model`'s `structured_output` override, against a fake client — no network.

The override exists because Strands' own version drops usage and turns a truncated
response into a Pydantic error. Both only show on a thinking model, which CI never calls,
so the shape of the response is faked here rather than left to the next live recording.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from fazerops.agents.correlator import _WireOutput, _gemini_model, _usage_from


def _response(*, parsed, thoughts=2449, answer=291, prompt=1634):
    return SimpleNamespace(
        parsed=parsed,
        usage_metadata=SimpleNamespace(
            prompt_token_count=prompt,
            candidates_token_count=answer,
            thoughts_token_count=thoughts,
        ),
    )


def _events(monkeypatch, response):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    model = _gemini_model("gemini-3.1-pro-preview")

    async def generate_content(**_):
        return response

    fake = SimpleNamespace(aio=SimpleNamespace(models=SimpleNamespace(generate_content=generate_content)))
    monkeypatch.setattr(model, "_get_client", lambda: fake)

    async def collect():
        messages = [{"role": "user", "content": [{"text": "x"}]}]
        return [event async for event in model.structured_output(_WireOutput, messages, "sys")]

    return asyncio.run(collect())


def test_thought_tokens_are_metered_as_output(monkeypatch):
    """They are billed as output. A meter that saw only the 291-token answer would record
    a tenth of what 3.1 Pro actually charged."""
    events = _events(monkeypatch, _response(parsed={"primary_cause_event_id": "e1", "confidence": "high"}))

    usage = next(u for u in map(_usage_from, events) if u is not None)
    assert usage == {"in": 1634, "out": 291 + 2449}


def test_a_truncated_response_yields_no_output_rather_than_raising(monkeypatch):
    """MAX_TOKENS leaves `parsed=None`. Upstream raises a `ValidationError` about
    `NoneType`; the correlator and proposer each have a named rejection for this case."""
    events = _events(monkeypatch, _response(parsed=None, thoughts=1150, answer=36))

    assert not any("output" in event for event in events)
    assert any(_usage_from(event) for event in events), "a failed call still spent tokens"


def test_a_parsed_response_is_validated_into_the_wire_model(monkeypatch):
    events = _events(monkeypatch, _response(parsed={"primary_cause_event_id": "e1", "confidence": "low"}))

    (output,) = [event["output"] for event in events if "output" in event]
    assert isinstance(output, _WireOutput)
    assert output.confidence == "low"


@pytest.mark.parametrize("parsed", [{"confidence": "high"}])
def test_a_schema_violation_still_raises(monkeypatch, parsed):
    """The override only stops treating *absence* as an error — a wrong shape is still one."""
    with pytest.raises(ValueError):
        _events(monkeypatch, _response(parsed=parsed))


# --- transient errors -----------------------------------------------------------------


def _api_error(code: int):
    from google.genai import errors

    cls = errors.ServerError if code >= 500 else errors.ClientError
    return cls(code, {"error": {"code": code, "status": "TEST", "message": "fake"}})


def _events_after(monkeypatch, outcomes):
    """Like `_events`, but the fake client plays `outcomes` in order — an exception is raised,
    anything else returned — and the number of calls it received comes back too."""
    monkeypatch.setattr("fazerops.agents.correlator.TRANSIENT_RETRY_DELAYS_SECONDS", (0.0, 0.0))
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    model = _gemini_model("gemini-3.1-pro-preview")
    calls = []

    async def generate_content(**_):
        outcome = outcomes[len(calls)]
        calls.append(outcome)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    fake = SimpleNamespace(aio=SimpleNamespace(models=SimpleNamespace(generate_content=generate_content)))
    monkeypatch.setattr(model, "_get_client", lambda: fake)

    async def collect():
        messages = [{"role": "user", "content": [{"text": "x"}]}]
        return [event async for event in model.structured_output(_WireOutput, messages, "sys")]

    try:
        return asyncio.run(collect()), len(calls)
    except Exception as exc:
        exc.calls = len(calls)
        raise


OK = {"primary_cause_event_id": "e1", "confidence": "high"}


def test_a_throttled_call_is_retried_and_its_answer_kept(monkeypatch):
    """The 14 Sep degraded brief: one 429 on the correlator's call, no retry, no narrative."""
    events, calls = _events_after(monkeypatch, [_api_error(429), _response(parsed=OK)])

    assert calls == 2
    assert any("output" in event for event in events)


def test_a_server_error_is_retried_too(monkeypatch):
    events, calls = _events_after(
        monkeypatch, [_api_error(503), _api_error(500), _response(parsed=OK)]
    )

    assert calls == 3
    assert any("output" in event for event in events)


def test_retries_are_bounded(monkeypatch):
    """A real outage must still degrade the brief, not hold it past the graph's backstop."""
    from google.genai import errors

    with pytest.raises(errors.ClientError) as raised:
        _events_after(monkeypatch, [_api_error(429)] * 3 + [_response(parsed=OK)])

    assert raised.value.calls == 3


def test_a_request_error_is_not_retried(monkeypatch):
    """A 400 is our request, not the provider's weather; sending it again cannot help."""
    from google.genai import errors

    with pytest.raises(errors.ClientError) as raised:
        _events_after(monkeypatch, [_api_error(400), _response(parsed=OK)])

    assert raised.value.calls == 1


def test_the_retry_waits_are_short():
    from fazerops.agents.correlator import TRANSIENT_RETRY_DELAYS_SECONDS

    assert len(TRANSIENT_RETRY_DELAYS_SECONDS) == 2
    assert sum(TRANSIENT_RETRY_DELAYS_SECONDS) <= 10
