"""`helm_rollback` — Handoff §7, Tier 1.

Roll a release back to an earlier revision. Handoff §5 notes revision N−1 gives the inverse
for free: rolling back to the revision deployed right now restores exactly what this action
replaces.

The mutating body is **W20b (Sep 12)**. Import path, parameter schema, dry run and inverse
are complete today — see `_pending.py`.
"""

from __future__ import annotations

from typing import Any

from ._pending import pending

__all__ = ["rollback"]


def rollback(params: dict[str, Any], *, credential: Any = None, undo: Any = None) -> Any:
    raise pending("helm_rollback", "W20b")
