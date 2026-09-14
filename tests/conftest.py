"""The suite reads a pinned copy of the action catalog, never `config/actions.yaml` directly.

The catalog is not only configuration here: the proposer's prompt embeds it, so every cassette key
depends on it, and the growth tests build their gaps against what it cannot yet revert. A catalog
change — a catalog-growth PR above all — failed 155 tests in 15 files on 14 Sep for that reason alone
(`docs/drift_log.md`). Pinned, such a change fails exactly one test, `test_catalog_pin.py`, which says
what a human must do before merging: re-pin, re-record the cassettes, and review the growth tests.

Set at import time, before any test module loads a catalog — one builds `default_catalog()` at module
level. Subprocesses a test starts load the real file.
"""

from __future__ import annotations

from pathlib import Path

from fazerops.actions import catalog as _catalog

PINNED_ACTIONS = Path(__file__).resolve().parent / "fixtures" / "catalog" / "actions.yaml"

_catalog.DEFAULT_ACTIONS = PINNED_ACTIONS
_catalog.default_catalog.cache_clear()
