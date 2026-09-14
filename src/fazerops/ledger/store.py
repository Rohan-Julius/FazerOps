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

from collections.abc import Iterable
from pathlib import Path

from ..config import evidence_key
from ..models import Alert, AlertClass, BlastRadius, ChangeEvent, TimeWindow
from .chain import ChainedLog, Integrity, worst

DEFAULT_LEDGER_PATH = Path(".fazerops") / "ledger.jsonl"

_FROM_ENV = object()


class LedgerStore:
    """Change events, indexed by blast-radius key.

    Construct with a `path` for a durable ledger, or without one for an in-memory ledger —
    the tests and the fixture demo use the latter, and the two behave identically apart
    from surviving the process.
    """

    def __init__(self, path: Path | str | None = None, *, key: bytes | None | object = _FROM_ENV) -> None:
        """`key` signs and verifies the file's chain (`chain.py`); by default it is
        `FAZEROPS_EVIDENCE_KEY`. An in-memory ledger has no file and ignores it."""
        self._path = Path(path) if path is not None else None
        self._key: bytes | None = evidence_key() if key is _FROM_ENV else key  # type: ignore[assignment]
        self._events: dict[str, ChangeEvent] = {}
        self._by_key: dict[str, set[str]] = {}
        self._alerts: dict[str, Alert] = {}
        self._integrity: tuple[Integrity, str | None] = (Integrity.IN_MEMORY, None)

        if self._path is not None:
            self._integrity = worst(self._load(), self._load_alerts())

    @property
    def integrity(self) -> Integrity:
        """What the files on disk could vouch for when this store opened them. Appends made
        through this store keep the chain intact, so they do not change it."""
        return self._integrity[0]

    @property
    def integrity_detail(self) -> str | None:
        return self._integrity[1]

    @property
    def _alerts_path(self) -> Path | None:
        """Alerts live beside the changes, not among them. Two record types in one
        append-only file would make `_load`'s tolerance for a truncated final line into a
        guess about which type the truncated line was."""
        if self._path is None:
            return None
        return self._path.with_name(f"{self._path.stem}.alerts.jsonl")

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

    def record_alert(self, alert: Alert) -> None:
        """Remember that an alert fired. Idempotent on one *firing* — `alert.id` and `fired_at`.

        Keyed on `alert.id` alone until 14 Sep: the id is the rule's own identifier (a fingerprint,
        an alarm name), so every later firing of a rule overwrote the first and `prior_alerts` never
        counted a re-fire of the same rule — the one case `recurrence` most exists for.

        This is the whole memory W14b's `recurrence` needs: the ledger already holds every
        change, so the only fact missing from a "has this shape preceded this signature
        before?" query is that a signature occurred at all. Recording briefs, or the
        rankings they contained, would make the feature depend on what a past scorer
        concluded — and a scoring change would then rewrite history.
        """
        key = _alert_key(alert)
        first_time = key not in self._alerts
        self._alerts[key] = alert

        if self._alerts_path is not None and first_time:
            ChainedLog(self._alerts_path, self._key).append([alert.model_dump(mode="json")])

    # ----------------------------------------------------------------------------------
    # Reading
    # ----------------------------------------------------------------------------------

    def prior_alerts(self, alert: Alert) -> list[Alert]:
        """Earlier alerts of the same signature — same service, same class — oldest first.

        Strictly earlier: an alert never counts as its own precedent, so recording the
        current alert before or after scoring it gives the same answer. An `unclassified`
        alert has no signature to match on and returns nothing rather than matching every
        other unclassified alert, which would make the feature fire on the absence of a
        classification.
        """
        if alert.alert_class is AlertClass.UNCLASSIFIED:
            return []

        found = [
            past
            for past in self._alerts.values()
            if _alert_key(past) != _alert_key(alert)
            and past.service == alert.service
            and past.alert_class is alert.alert_class
            and past.fired_at < alert.fired_at
        ]
        found.sort(key=lambda past: (past.fired_at, past.id))
        return found

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
        ChainedLog(self._path, self._key).append([event.model_dump(mode="json") for event in events])

    def _load(self) -> tuple[Integrity, str | None]:
        """Replay the file. Later lines win, which is what makes `record` idempotent across
        restarts as well as within a process.

        A truncated final line — the shape a crash mid-append leaves — is dropped rather
        than raised on. Refusing to open a ledger because its last write was interrupted
        would lose the whole history to protect one event. Anything else wrong with the file
        is not refused either: the events still load, and `integrity` says the file is not
        evidence — the reader decides what that costs (the growth job refuses to mine it).
        """
        assert self._path is not None
        records, *state = ChainedLog(self._path, self._key).read()
        for record in records:
            try:
                event = ChangeEvent.model_validate(record)
            except ValueError:
                continue
            self._deindex(event.id)
            self._events[event.id] = event
            for key in event.blast_radius_keys:
                self._by_key.setdefault(key, set()).add(event.id)
        return state[0], state[1]

    def _load_alerts(self) -> tuple[Integrity, str | None]:
        """Replay the alert history. Its own chain, with the same tolerances as `_load`."""
        assert self._alerts_path is not None
        records, *state = ChainedLog(self._alerts_path, self._key).read()
        for record in records:
            try:
                alert = Alert.model_validate(record)
            except ValueError:
                continue
            self._alerts[_alert_key(alert)] = alert
        return state[0], state[1]

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


def _alert_key(alert: Alert) -> str:
    """One firing of one rule. The same key a re-delivered webhook produces, so recording it twice is
    still a no-op."""
    return f"{alert.id}@{alert.fired_at.isoformat()}"
