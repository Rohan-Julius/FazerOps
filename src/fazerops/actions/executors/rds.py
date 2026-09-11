"""`restore_db_parameter` — Handoff §7, **Tier 2**.

Targets an RDS **parameter group**, never an instance. That is what makes the Tier 2 claim
honest without spending anything: a parameter group is a genuine managed-database mutation,
only instances bill, and it emits a real `ModifyDBParameterGroup` event that W10a's
recording already consumes.

Tier is declared in the catalog and never inferred here. The manager-approval routing is
W26b's; this executor's only relationship to it is that it will refuse a credential minted
for an IC approval.

The mutating body is **W20c (Sep 12)**. Import path, parameter schema, dry run and inverse
are complete today — see `_pending.py`.
"""

from __future__ import annotations

from typing import Any

from ._pending import pending

__all__ = ["restore_parameter"]


def restore_parameter(params: dict[str, Any], *, credential: Any = None, undo: Any = None) -> Any:
    raise pending("restore_db_parameter", "W20c")
