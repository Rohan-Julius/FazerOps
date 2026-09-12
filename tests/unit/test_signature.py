"""W25 — Slack request signature verification. Handoff §9, plan §4.

The plan's two assertions: a tampered signature is rejected, and a stale timestamp (over
five minutes) is rejected.

Runs against a **synthetic secret**, offline. That is what makes it a CI test rather than
a thing that only works on the machine with the workspace — and the synthetic secret is
why the golden signature below can be a literal: it is computed here from a key nobody
holds, so it is not a credential.

The staleness case is the one worth stating plainly: a valid Slack signature never
expires, so without a time bound, a captured approval callback can be replayed at any
future moment and will verify perfectly.
"""

from __future__ import annotations

import time

import pytest

from fazerops.slack.signature import (
    MAX_SKEW_SECONDS,
    SignatureInvalid,
    expected_signature,
    verify,
)

SECRET = "synthetic-signing-secret-not-a-credential"
BODY = "payload=%7B%22type%22%3A%22block_actions%22%7D"
NOW = 1_789_000_000.0
TIMESTAMP = str(int(NOW))


def _signed(body: str = BODY, timestamp: str = TIMESTAMP) -> str:
    return expected_signature(SECRET, timestamp, body)


def test_a_genuine_request_verifies():
    verify(SECRET, timestamp=TIMESTAMP, body=BODY, signature=_signed(), now=NOW)


def test_a_tampered_signature_is_rejected():
    """One flipped character. `compare_digest` is what keeps the rejection constant-time —
    the timing difference on `==` is small and it is measurable, and what a forged
    approval buys is a cluster mutation."""
    genuine = _signed()
    tampered = genuine[:-1] + ("0" if genuine[-1] != "0" else "1")

    with pytest.raises(SignatureInvalid, match="does not match"):
        verify(SECRET, timestamp=TIMESTAMP, body=BODY, signature=tampered, now=NOW)


def test_a_tampered_body_is_rejected():
    """The signature covers the body, so editing the approved action invalidates it. This
    is the attack the whole scheme exists to stop: a genuine signature from a genuine
    Reject, replayed over an Approve."""
    with pytest.raises(SignatureInvalid, match="does not match"):
        verify(
            SECRET,
            timestamp=TIMESTAMP,
            body=BODY.replace("block_actions", "block_actions_evil"),
            signature=_signed(),
            now=NOW,
        )


def test_a_stale_timestamp_is_rejected_even_with_a_perfect_signature():
    """Over five minutes old. The signature below is genuine for its timestamp — which is
    exactly the point, because a captured request stays genuine forever."""
    old = str(int(NOW - MAX_SKEW_SECONDS - 1))

    with pytest.raises(SignatureInvalid, match="replay window"):
        verify(SECRET, timestamp=old, body=BODY, signature=_signed(timestamp=old), now=NOW)


def test_a_request_just_inside_the_window_is_accepted():
    """The boundary, so the bound is not quietly off by one in the strict direction — a
    verifier that rejects four-minute-old requests fails real approvals."""
    recent = str(int(NOW - MAX_SKEW_SECONDS + 1))
    verify(SECRET, timestamp=recent, body=BODY, signature=_signed(timestamp=recent), now=NOW)


def test_a_future_timestamp_is_rejected():
    """Absolute skew, not just "too old". A timestamp from the future is a badly skewed
    clock or an attempt to mint a request that stays fresh for hours."""
    future = str(int(NOW + MAX_SKEW_SECONDS + 1))

    with pytest.raises(SignatureInvalid, match="replay window"):
        verify(SECRET, timestamp=future, body=BODY, signature=_signed(timestamp=future), now=NOW)


@pytest.mark.parametrize(
    ("timestamp", "signature", "match"),
    [
        (None, "v0=abc", "missing"),
        (TIMESTAMP, None, "missing"),
        ("not-a-number", "v0=abc", "not an integer"),
    ],
)
def test_a_malformed_request_is_rejected_rather_than_crashing(timestamp, signature, match):
    """Each of these is a `ValueError` or a `TypeError` away from being a 500 that an
    attacker can distinguish from a rejection."""
    with pytest.raises(SignatureInvalid, match=match):
        verify(SECRET, timestamp=timestamp, body=BODY, signature=signature, now=NOW)


def test_an_empty_signing_secret_refuses_rather_than_verifying_under_an_empty_key():
    """HMAC under an empty key produces a perfectly valid digest that authenticates
    nobody. An unconfigured verifier must refuse, not accept."""
    with pytest.raises(SignatureInvalid, match="no signing secret"):
        verify("", timestamp=TIMESTAMP, body=BODY, signature=_signed(), now=NOW)


def test_verify_returns_none_so_a_discarded_result_cannot_read_as_success():
    """`if verify(...)` and a call whose result is ignored look identical, and the second
    accepts everything. Returning `None` means there is no boolean to misuse."""
    assert verify(SECRET, timestamp=TIMESTAMP, body=BODY, signature=_signed(), now=NOW) is None


def test_the_signature_matches_slacks_documented_scheme():
    """`v0:{timestamp}:{body}` under HMAC-SHA256, hex, prefixed `v0=`.

    Pinned against an independently-computed digest rather than against
    `expected_signature` itself, which would assert the function equals itself.
    """
    import hashlib
    import hmac

    digest = hmac.new(
        SECRET.encode(), f"v0:{TIMESTAMP}:{BODY}".encode(), hashlib.sha256
    ).hexdigest()
    assert _signed() == f"v0={digest}"


def test_the_default_clock_is_the_real_one():
    """`now` is injectable for the staleness tests; the production path must not depend on
    a caller passing it."""
    timestamp = str(int(time.time()))
    verify(SECRET, timestamp=timestamp, body=BODY, signature=_signed(timestamp=timestamp))
