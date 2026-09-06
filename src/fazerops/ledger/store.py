"""W9 — the ledger itself: durable `ChangeEvent` storage behind a blast-radius index.

Handoff §3 says `blast_radius_keys` is what makes the ledger queryable, and that the keys
are populated at *normalization* time from the service manifest rather than joined at
query time. This module is the other half of that sentence: it indexes on those keys as
the event arrives, so a query is a set lookup against the manifest as it stood when the
change happened, not as it stands now.

Two properties are enforced here rather than left to callers, because both fail silently:

* **Every query is scoped to a blast radius.** `query()` takes a `BlastRadius` and there
  is no unscoped read. The project-isolation invariant is that events outside the radius
  are never returned; a convenience `all()` that skipped the filter would be the obvious
  thing to reach for at 2am on demo day, and nothing would go red when someone did.
* **Windows are half-open `[start, end)`**, matching `TimeWindow.contains` and the
  collectors. An inclusive end double-counts a change landing exactly on the alert
  timestamp — and that change is the *most* suspicious one in the set, so the duplicate
  lands at rank 1 and rank 2 of the brief.

Persistence is an append-only JSONL file. It is not a database and does not pretend to be
one: the ledger in this build is small, single-writer and reconstructed on load. The
append-only shape is chosen because a change ledger that can be rewritten in place is not
evidence, and because a crashed write costs the last line rather than the file.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from ..models import BlastRadius, ChangeEvent, TimeWindow

DEFAULT_LEDGER_PATH = Path(".fazerops") / "ledger.jsonl"


class LedgerStore:
    """Change events, indexed by blast-radius key.

    Construct with a `path` for a durable ledger, or without one for an in-memory ledger —
    the tests and the fixture demo use the latter, and the two behave identically apart
    from surviving the process.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._events: dict[str, ChangeEvent] = {}
        self._by_key: dict[str, set[str]] = {}

        if self._path is not None and self._path.exists():
            self._load()

    # ----------------------------------------------------------------------------------
    # Writing
    # ----------------------------------------------------------------------------------

    def record(self, event: ChangeEvent) -> None:
        """Add one event. Idempotent on `event.id`.

        Collectors overlap by design — a Helm rollout appears in the K8s audit log too —
        and the same window may be investigated twice when an alert re-fires. Re-recording
        an id replaces the stored event and rebuilds its index entries, so a corrected
        payload cannot leave the old event reachable under a key it no longer claims.
        """
        self._deindex(event.id)
        self._events[event.id] = event
        for key in event.blast_radius_keys:
            self._by_key.setdefault(key, set()).add(event.id)

        if self._path is not None:
            self._append([event])

    def extend(self, events: Iterable[ChangeEvent]) -> int:
        """Record many, one file open. Returns the number of events now in the ledger that
        were not there before — duplicates from an overlapping collector run count zero."""
        events = list(events)
        before = len(self._events)

        for event in events:
            self._deindex(event.id)
            self._events[event.id] = event
            for key in event.blast_radius_keys:
                self._by_key.setdefault(key, set()).add(event.id)

        if self._path is not None and events:
            self._append(events)

        return len(self._events) - before

    # ----------------------------------------------------------------------------------
    # Reading
    # ----------------------------------------------------------------------------------

    def query(self, radius: BlastRadius, window: TimeWindow | None = None) -> list[ChangeEvent]:
        """Events touching `radius`, optionally inside `window`, oldest first.

        The radius argument is not optional and there is no unscoped variant — see the
        module docstring. An event whose `blast_radius_keys` is empty is unreachable by
        construction, which is the correct answer: a change nothing can attribute to a
        service cannot be evidence about that service.
        """
        ids: set[str] = set()
        for key in radius.keys:
            ids |= self._by_key.get(key, frozenset())

        found = [self._events[event_id] for event_id in ids]
        if window is not None:
            found = [event for event in found if window.contains(event.occurred_at)]

        # Ties on timestamp break on id so two events recorded in the same millisecond
        # always render in the same order — the golden ranking test depends on it.
        found.sort(key=lambda event: (event.occurred_at, event.id))
        return found

    def get(self, event_id: str) -> ChangeEvent | None:
        """By-id lookup, for resolving the evidence ids a brief cites. Not radius-scoped
        because the caller already holds an id the radius handed it."""
        return self._events.get(event_id)

    def keys_indexed(self) -> set[str]:
        """Every blast-radius key the ledger currently knows. Diagnostics: an empty
        candidate set is almost always a key that was written in one shape and queried in
        another, and this is how you see that without a debugger."""
        return {key for key, ids in self._by_key.items() if ids}

    def __len__(self) -> int:
        return len(self._events)

    def __contains__(self, event_id: object) -> bool:
        return event_id in self._events

    # ----------------------------------------------------------------------------------
    # Persistence
    # ----------------------------------------------------------------------------------

    def _append(self, events: list[ChangeEvent]) -> None:
        assert self._path is not None
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            for event in events:
                handle.write(event.model_dump_json() + "\n")

    def _load(self) -> None:
        """Replay the file. Later lines win, which is what makes `record` idempotent across
        restarts as well as within a process.

        A truncated final line — the shape a crash mid-append leaves — is dropped rather
        than raised on. Refusing to open a ledger because its last write was interrupted
        would lose the whole history to protect one event.
        """
        assert self._path is not None
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = ChangeEvent.model_validate_json(line)
                except (ValueError, json.JSONDecodeError):
                    continue
                self._deindex(event.id)
                self._events[event.id] = event
                for key in event.blast_radius_keys:
                    self._by_key.setdefault(key, set()).add(event.id)

    def _deindex(self, event_id: str) -> None:
        existing = self._events.get(event_id)
        if existing is None:
            return
        for key in existing.blast_radius_keys:
            holders = self._by_key.get(key)
            if holders is not None:
                holders.discard(event_id)
                if not holders:
                    del self._by_key[key]
