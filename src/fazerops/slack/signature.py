"""W25 — Slack request signature verification. Handoff §9.

> *Verify signatures on every inbound request even in the demo build; a judge may look.*

**On the Socket Mode path this code is not on the critical path, and it is still required.**
Socket Mode authenticates the *connection* with the app-level token, so no inbound HTTP
request arrives to verify and `SLACK_SIGNING_SECRET` goes unused. That makes this module
look like dead weight. It is not, for two reasons:

1. The HTTP path exists — `main.py` is a FastAPI app — and the moment anyone runs this
   behind a Request URL instead of a socket, the signature is the only thing standing
   between the approval handler and anybody who learned the endpoint. Writing it after
   that switch means writing it while it is already needed.
2. Handoff §9 asks for it explicitly, on the grounds that a judge may look.

Verified against a synthetic secret in `tests/unit/test_signature.py`, which needs no
workspace and no network.

The scheme, from Slack's own documentation: sign `v0:{timestamp}:{body}` with HMAC-SHA256
under the signing secret, hex-encode, and compare to the `X-Slack-Signature` header, which
is that digest prefixed with `v0=`.
"""

from __future__ import annotations

import hashlib
import hmac
import time

__all__ = [
    "MAX_SKEW_SECONDS",
    "SignatureInvalid",
    "expected_signature",
    "verify",
]

# Slack's documented replay window. A request older than this is refused even if its
# signature is perfect: a valid signature stays valid forever, so without a time bound a
# captured approval callback can be replayed at any point in the future.
#
# W26's idempotency key is the other half of that defence and neither replaces the other —
# this one bounds *any* replayed request, including ones for incidents this process has
# never seen and therefore has no idempotency record for.
MAX_SKEW_SECONDS = 60 * 5

_VERSION = "v0"


class SignatureInvalid(ValueError):
    """The request did not carry a valid, fresh Slack signature.

    One exception type for every failure — bad digest, stale timestamp, missing header,
    malformed timestamp — because distinguishing them in the *response* tells an attacker
    which half of the check to work on. The message says which; the caller must not
    forward it.
    """


def expected_signature(signing_secret: str, timestamp: str, body: str) -> str:
    """The signature Slack would have sent for this exact request."""
    basestring = f"{_VERSION}:{timestamp}:{body}".encode()
    digest = hmac.new(signing_secret.encode(), basestring, hashlib.sha256).hexdigest()
    return f"{_VERSION}={digest}"


def verify(
    signing_secret: str,
    *,
    timestamp: str | None,
    body: str,
    signature: str | None,
    now: float | None = None,
) -> None:
    """Raise `SignatureInvalid` unless this request is authentically Slack's and fresh.

    Returns `None` on success rather than `True`. A boolean return is the shape that gets
    misused — `if verify(...)` reads identically to a call whose result was discarded, and
    the discarded-result version silently accepts everything.

    `now` is injectable so the staleness test does not have to sleep for five minutes.
    """
    if not signing_secret:
        # Refusing here rather than computing an HMAC under an empty key, which would
        # produce a digest that verifies fine and authenticates nobody.
        raise SignatureInvalid("no signing secret is configured; refusing to verify")
    if not signature or not timestamp:
        raise SignatureInvalid("request is missing its Slack signature or timestamp headers")

    try:
        sent_at = int(timestamp)
    except ValueError:
        raise SignatureInvalid(f"timestamp {timestamp!r} is not an integer") from None

    now = time.time() if now is None else now
    # Absolute, so a timestamp from the future is refused too. A future timestamp is either
    # a badly skewed clock or an attempt to mint a request that stays fresh for hours.
    if abs(now - sent_at) > MAX_SKEW_SECONDS:
        raise SignatureInvalid(
            f"timestamp is {abs(now - sent_at):.0f}s from now, outside the "
            f"{MAX_SKEW_SECONDS}s replay window"
        )

    if not hmac.compare_digest(expected_signature(signing_secret, timestamp, body), signature):
        # `compare_digest`, not `==`. The timing difference on a string comparison is
        # small and it is measurable, and a forged approval is a cluster mutation.
        raise SignatureInvalid("signature does not match")
