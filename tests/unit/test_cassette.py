"""W17 — record once, replay forever. Plan §5's `cassette` mode.

The point of a cassette is that CI can assert agent behaviour with no credentials and no
network. So the two claims worth proving are that a round-trip preserves the response
exactly, and that replay cannot reach the network even when it fails.

The second is the one that would rot silently: a cassette layer that falls back to a live
call on a miss still passes every happy-path test, and only breaks on a judge's machine.
"""

from __future__ import annotations

import json
import socket

import pytest

from fazerops.agents.cassette import Cassette, CassetteMiss, request_key

MESSAGES = [{"role": "user", "content": [{"text": "rank these changes"}]}]

RESPONSE = {
    "narrative": "The ConfigMap change reduced the connection pool from 100 to 20.",
    "evidence_ids": ["65a6f2b9-9a21-4c85-94bd-641b40bb50e6"],
    "confidence": "high",
}


@pytest.fixture
def cassette(tmp_path):
    return Cassette("correlator", directory=tmp_path)


# --------------------------------------------------------------------------------------
# Round trip
# --------------------------------------------------------------------------------------


def test_record_then_replay_returns_the_response_unchanged(cassette):
    key = request_key("correlator", "amazon.nova-pro-v1:0", MESSAGES)
    cassette.record(key, RESPONSE, model="amazon.nova-pro-v1:0")

    assert cassette.replay(key) == RESPONSE


def test_a_replay_survives_a_new_process(tmp_path):
    """Recording and replaying in one object proves a dict works. The cassette's whole
    job is to outlive the process that recorded it."""
    key = request_key("correlator", "amazon.nova-pro-v1:0", MESSAGES)
    Cassette("correlator", directory=tmp_path).record(
        key, RESPONSE, model="amazon.nova-pro-v1:0"
    )

    assert Cassette("correlator", directory=tmp_path).replay(key) == RESPONSE


def test_recording_a_second_prompt_keeps_the_first(cassette):
    """Read-modify-write, not overwrite. Re-recording one prompt must not silently drop
    every other recording for that agent."""
    first = request_key("correlator", "amazon.nova-pro-v1:0", MESSAGES)
    second = request_key("correlator", "amazon.nova-pro-v1:0", [{"role": "user", "x": 1}])

    cassette.record(first, RESPONSE, model="amazon.nova-pro-v1:0")
    cassette.record(second, {"narrative": "other"}, model="amazon.nova-pro-v1:0")

    assert cassette.replay(first) == RESPONSE
    assert cassette.replay(second) == {"narrative": "other"}


def test_re_recording_the_same_key_replaces_it(cassette):
    key = request_key("correlator", "amazon.nova-pro-v1:0", MESSAGES)
    cassette.record(key, RESPONSE, model="amazon.nova-pro-v1:0")
    cassette.record(key, {"narrative": "re-recorded"}, model="amazon.nova-pro-v1:0")

    assert cassette.replay(key) == {"narrative": "re-recorded"}


def test_each_agent_gets_its_own_file(tmp_path):
    """Recording the orchestrator must not clobber the correlator's cassette."""
    key = request_key("orchestrator", "amazon.nova-lite-v1:0", MESSAGES)
    Cassette("orchestrator", directory=tmp_path).record(
        key, {"service": "billing-api"}, model="amazon.nova-lite-v1:0"
    )
    Cassette("correlator", directory=tmp_path).record(
        key, RESPONSE, model="amazon.nova-pro-v1:0"
    )

    assert (tmp_path / "orchestrator.json").is_file()
    assert (tmp_path / "correlator.json").is_file()
    assert Cassette("orchestrator", directory=tmp_path).replay(key) != RESPONSE


# --------------------------------------------------------------------------------------
# A miss is a failure, never a network call
# --------------------------------------------------------------------------------------


def test_a_missing_recording_raises_rather_than_returning_none(cassette):
    with pytest.raises(CassetteMiss):
        cassette.replay("nosuchkey")


def test_replay_opens_no_socket_even_on_a_miss(cassette, monkeypatch):
    """The guarantee CI rests on. A cassette layer that fell back to a live call would
    pass every happy-path test and break on a machine with no credentials — which is every
    machine a judge runs this on."""

    def forbidden(*args, **kwargs):
        raise AssertionError("cassette mode opened a socket")

    monkeypatch.setattr(socket, "socket", forbidden)

    key = request_key("correlator", "amazon.nova-pro-v1:0", MESSAGES)
    cassette.record(key, RESPONSE, model="amazon.nova-pro-v1:0")
    assert cassette.replay(key) == RESPONSE

    with pytest.raises(CassetteMiss):
        cassette.replay("nosuchkey")


def test_the_miss_message_says_how_to_fix_it(cassette):
    """A prompt edit invalidates every key for that agent, and it will happen constantly
    during the build. The error has to name the remedy or it reads as a broken test."""
    with pytest.raises(CassetteMiss, match="FAZEROPS_LLM=record"):
        cassette.replay("nosuchkey")


# --------------------------------------------------------------------------------------
# The key
# --------------------------------------------------------------------------------------


def test_the_same_request_hashes_the_same_way():
    assert request_key("correlator", "m", MESSAGES) == request_key("correlator", "m", MESSAGES)


def test_dict_ordering_does_not_change_the_key():
    """Without `sort_keys` the same request hashes differently between runs and every
    replay is a miss — a failure that looks like a broken cassette file."""
    a = request_key("correlator", "m", [{"role": "user", "content": "x"}])
    b = request_key("correlator", "m", [{"content": "x", "role": "user"}])
    assert a == b


@pytest.mark.parametrize(
    "kwargs",
    [
        {"agent": "proposer"},
        {"model": "amazon.nova-lite-v1:0"},
        {"messages": [{"role": "user", "content": [{"text": "different"}]}]},
    ],
)
def test_anything_that_could_change_the_response_changes_the_key(kwargs):
    """A changed prompt must *miss*, not replay the answer to a question nobody asked any
    more. Otherwise W18's citation validator gets tested against a response the current
    prompt can no longer produce."""
    base = {"agent": "correlator", "model": "amazon.nova-pro-v1:0", "messages": MESSAGES}
    assert request_key(**base) != request_key(**{**base, **kwargs})


def test_inference_params_are_part_of_the_key():
    base = request_key("correlator", "m", MESSAGES, temperature=0.0)
    assert base != request_key("correlator", "m", MESSAGES, temperature=1.0)


def test_a_non_json_value_does_not_break_the_key():
    """`default=str` — messages carry datetimes and enums in practice, and a key function
    that raises on one takes the whole run down for a hashing detail."""
    from datetime import datetime, timezone

    assert request_key("correlator", "m", [{"at": datetime.now(timezone.utc)}])


def test_the_cassette_file_is_readable_json(cassette):
    """These are committed fixtures a judge may open, and a re-record that reordered every
    key would make the diff unreviewable."""
    key = request_key("correlator", "amazon.nova-pro-v1:0", MESSAGES)
    cassette.record(key, RESPONSE, model="amazon.nova-pro-v1:0")

    raw = cassette.path.read_text()
    assert json.loads(raw)[key]["model"] == "amazon.nova-pro-v1:0"
    assert raw.endswith("\n")
    assert "\n  " in raw, "indented, not one line"
