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
