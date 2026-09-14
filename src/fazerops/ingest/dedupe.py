"""Drop repeat deliveries of one alert firing.

Alertmanager re-sends a firing alert on every `repeat_interval`, CloudWatch and PagerDuty retry a
webhook that answered slowly, and an investigation takes longer than most retry timers. Each
delivery used to run a full investigation: another brief, another card, another model bill — and,
before the dry-run digest, a fresh registration that silently replaced the dry run behind a card
someone was already reading (drift log, 14 Sep, D1).

Keyed on `models.incident_id_for`, which is stable across re-deliveries of one firing and differs
between firings, so next week's alert on the same rule is never mistaken for this week's.

**In memory, per process, on purpose.** The approval gateway's open cards are in memory too
(`actions/approval.py`): after a restart they are gone, and a re-delivered alert *should* open a
fresh card. A durable dedupe store would suppress exactly that.

A claim is released if the investigation raises, so a retry of a failed investigation runs rather
than being answered with nothing — failing open, because every mutation is still approval-gated.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

__all__ = ["AlertDeduper", "Seen"]

# Alertmanager's default `repeat_interval` is 4h; a day covers a firing that stays open overnight.
DEFAULT_TTL_SECONDS = 24 * 3600
DEFAULT_MAX_ENTRIES = 10_000


@dataclass(frozen=True)
class Seen:
    """An earlier delivery of this firing. `response` is `None` while it is still being investigated."""

    response: dict[str, Any] | None


class AlertDeduper:
    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[float, dict[str, Any] | None]] = {}

    def claim(self, key: str) -> Seen | None:
        """Claim `key` for this delivery. `None` means proceed; a `Seen` means answer from it."""
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and now - entry[0] <= self._ttl:
                return Seen(response=entry[1])
            self._entries[key] = (now, None)
            self._prune(now)
            return None

    def finish(self, key: str, response: dict[str, Any]) -> None:
        """Record what the claimed delivery produced, for later deliveries to be answered with."""
        with self._lock:
            claimed_at = self._entries.get(key, (self._clock(), None))[0]
            self._entries[key] = (claimed_at, dict(response))

    def abandon(self, key: str) -> None:
        """Release a claim whose investigation failed, so a retry is investigated."""
        with self._lock:
            self._entries.pop(key, None)

    def _prune(self, now: float) -> None:
        for key in [k for k, (at, _) in self._entries.items() if now - at > self._ttl]:
            del self._entries[key]
        if len(self._entries) > self._max:
            for key in sorted(self._entries, key=lambda k: self._entries[k][0])[: len(self._entries) - self._max]:
                del self._entries[key]
