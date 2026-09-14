"""W5 — the collector contract, and the fixture/live switch.

The switch lives in exactly one method: `_fetch_raw`. Fixture mode reads recorded source
payloads off disk; live mode calls the API. Both then feed the *same* normalizer, the same
window filter and the same radius filter.

That is what makes fixture parity structural rather than aspirational. If the two paths
had separate normalizers, fixture mode would drift from live mode and the demo would pass
on data the production path could never produce — the classic way a fixture-backed demo
becomes a lie without anyone deciding to lie.
"""

from __future__ import annotations

import abc
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ..config import Mode, mode
from ..models import BlastRadius, ChangeEvent, ChangeSource, CoverageGap, TimeWindow

FIXTURE_ROOT = Path(__file__).resolve().parents[3] / "fixtures"


class CollectorResult:
    """What a collector hands back. Carries failures rather than raising them.

    A collector runs as a node inside a Strands Graph batch (plan §3.2). An exception
    there surfaces as an opaque graph failure and takes the whole brief with it, so a
    dead source degrades the brief instead: `Brief.degraded` goes true and the message
    says which source was unavailable.
    """

    __slots__ = ("source", "events", "error", "coverage_gap")

    def __init__(
        self,
        source: ChangeSource,
        events: list[ChangeEvent],
        error: str | None = None,
        coverage_gap: CoverageGap | None = None,
    ) -> None:
        self.source = source
        self.events = events
        self.error = error
        self.coverage_gap = coverage_gap

    @property
    def ok(self) -> bool:
        return self.error is None

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        state = "ok" if self.ok else f"error={self.error!r}"
        return f"CollectorResult({self.source}, {len(self.events)} events, {state})"


@runtime_checkable
class Collector(Protocol):
    """Handoff §5. Every source satisfies this, in both fixture and live mode."""

    source: ChangeSource

    async def fetch(self, radius: BlastRadius, window: TimeWindow) -> CollectorResult: ...


class BaseCollector(abc.ABC):
    """Template method shared by all four collectors.

    Subclasses supply three things and inherit the rest: how to read raw payloads in each
    mode, and how to turn one raw payload into a `ChangeEvent`.
    """

    source: ChangeSource
    fixture_dir: str

    delivery_lag: timedelta = timedelta(0)
    """How long after a change this source can take to report it. Non-zero only where the
    source says so (CloudTrail); a query at alert time cannot see the last `delivery_lag` of
    the window, and `fetch` reports that stretch as a `CoverageGap` rather than as silence."""

    async def fetch(self, radius: BlastRadius, window: TimeWindow) -> CollectorResult:
        # Taken before the call: an event delivered while the call runs may or may not be in
        # the answer, so the earlier instant is the one the gap can be vouched for from.
        queried_at = self._now()
        try:
            raw_items = await self._fetch_raw(radius, window)
        except Exception as exc:  # noqa: BLE001 - see CollectorResult's docstring
            return CollectorResult(self.source, [], error=f"{type(exc).__name__}: {exc}")

        raw_items = self._prepare(raw_items)

        events: list[ChangeEvent] = []
        for item in raw_items:
            event = self._normalize(item)
            if event is None:
                continue  # filtered by the source's own rules (read verbs, noise, etc.)
            if not window.contains(event.occurred_at):
                continue
            if not radius.overlaps(event.blast_radius_keys):
                continue
            events.append(event)

        events.sort(key=lambda e: e.occurred_at)
        return CollectorResult(self.source, events, coverage_gap=self._coverage_gap(window, queried_at))

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _coverage_gap(self, window: TimeWindow, queried_at: datetime) -> CoverageGap | None:
        """The tail of `window` this query could not yet see. A fixture is a finished recording,
        so it has none — which is also what keeps the demo and the golden ranking unchanged."""
        if mode() is Mode.FIXTURE or self.delivery_lag <= timedelta(0):
            return None
        settled = queried_at - self.delivery_lag
        if settled >= window.end:
            return None
        return CoverageGap(
            source=self.source,
            unobserved=TimeWindow(start=max(window.start, settled), end=window.end),
            delivery_lag_minutes=self.delivery_lag.total_seconds() / 60.0,
        )

    async def _fetch_raw(self, radius: BlastRadius, window: TimeWindow) -> list[dict[str, Any]]:
        if mode() is Mode.FIXTURE:
            return self._load_fixtures()
        return await self._fetch_live(radius, window)

    def _load_fixtures(self) -> list[dict[str, Any]]:
        """Read every `*.json` under this collector's fixture directory.

        A file may hold a single payload object or a list of them. A missing directory is
        an empty source, not an error — a collector with no fixtures yet must not break
        the pipeline for the three that do.
        """
        directory = FIXTURE_ROOT / self.fixture_dir
        if not directory.is_dir():
            return []

        items: list[dict[str, Any]] = []
        for path in sorted(directory.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            items.extend(payload if isinstance(payload, list) else [payload])
        return items

    async def _fetch_live(
        self, radius: BlastRadius, window: TimeWindow
    ) -> list[dict[str, Any]]:
        raise NotImplementedError(
            f"{type(self).__name__} has no live mode; run with FAZEROPS_MODE=fixture"
        )

    def _prepare(self, raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Hook for cross-item context, run once before any item is normalized.

        The K8s audit collector needs it: an audit entry for an `update` carries only the
        *new* object, so `before` has to be reconstructed from the same object's previous
        entry — which may sit outside the correlation window. Window filtering happens
        after this, so the anchor can inform the diff without becoming a candidate.
        """
        return raw_items

    @abc.abstractmethod
    def _normalize(self, raw: dict[str, Any]) -> ChangeEvent | None:
        """One raw source payload into one `ChangeEvent`, or `None` to drop it.

        Shared by both modes by construction — see the module docstring.
        """
