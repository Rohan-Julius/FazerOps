"""W17 — record once, replay forever. Plan §5's `cassette` mode.

Agent behaviour has to be asserted in CI, and CI has no credentials and no network
(`tests/integration/test_no_network.py` patches `socket.socket` to raise). A cassette is
how a real model response becomes a test fixture: recorded once against Bedrock, replayed
deterministically thereafter at zero cost.

**Keyed on a hash of the request — the system prompt included**, so a changed prompt
misses the cassette rather than silently replaying the answer to a question nobody asked
any more. The system prompt was *not* in the key until 12 Sep, which made this paragraph
false for the only prompt that carries the instructions; `request_key` now demands it. That miss is the point:
prompts change constantly during a build, and a cassette layer that tolerates drift would
let W18's citation validator be tested against a response the current prompt cannot
produce.

Cassettes live in `tests/cassettes/` and are **committed** — they are test fixtures, not
cache. `.fazerops/` is gitignored and is for the token ledger; cassettes are not.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

__all__ = ["Cassette", "CassetteMiss", "request_key"]

CASSETTE_DIR = Path("tests") / "cassettes"


class CassetteMiss(LookupError):
    """No recording for this request.

    A hard failure, never a silent passthrough to the network. In `cassette` mode the
    whole guarantee is that no socket opens; falling back to a live call would break that
    quietly, on a machine that may not even have credentials.
    """


def request_key(
    agent: str, model: str, messages: Any, *, system: str, **params: Any
) -> str:
    """A stable hash over everything that could change the response.

    `sort_keys` and `default=str` make the digest independent of dict ordering and of
    types JSON does not know — without them the same request hashes differently between
    runs and every replay is a miss.

    **`system` is required, and has no default, because omitting it silently broke this
    module's central promise.** Until 12 Sep the key covered only the user turn: every
    agent passes its `SYSTEM_PROMPT` separately to `structured_output`, so editing the
    prompt — the substantive half — left every tape replaying, and the docstring above
    claiming a changed prompt misses was false for the prompt that matters. A default of
    `None` would have made the same omission possible one call site at a time; a required
    keyword makes forgetting it a `TypeError` at the call rather than a stale replay
    discovered on camera.
    """
    payload = json.dumps(
        {
            "agent": agent,
            "model": model,
            "messages": messages,
            "system": system,
            "params": params,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


class Cassette:
    """One JSON file per agent, mapping request key → recorded response."""

    def __init__(self, agent: str, *, directory: Path | str | None = None) -> None:
        self.agent = agent
        self.directory = Path(directory) if directory is not None else CASSETTE_DIR
        self.path = self.directory / f"{agent}.json"

    # ----------------------------------------------------------------------------------

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def replay(self, key: str) -> dict[str, Any]:
        entries = self._load()
        if key not in entries:
            raise CassetteMiss(
                f"no recording for {self.agent}/{key} in {self.path}. "
                "Re-record with FAZEROPS_LLM=record — a prompt change invalidates the key."
            )
        return entries[key]["response"]

    def record(self, key: str, response: dict[str, Any], *, model: str) -> None:
        """Write one interaction, merging into whatever is already there.

        Read-modify-write rather than append: recording the orchestrator must not discard
        the correlator's cassette, and re-recording one prompt must not drop the others.
        """
        entries = self._load()
        entries[key] = {"model": model, "response": response}

        self.directory.mkdir(parents=True, exist_ok=True)
        # Sorted and indented because these are committed fixtures — a judge may read one,
        # and a diff that reorders every key on each re-record is unreviewable.
        self.path.write_text(
            json.dumps(entries, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def __contains__(self, key: str) -> bool:
        return key in self._load()
