"""`revert_configmap_key` — Handoff §7, Tier 1.

The demo's action: restore one key of one ConfigMap to the value it held before an
out-of-band edit. Its inverse is itself, aimed at the value that is current now, which is
why ground rule #4 is cheap here (`actions/inverse.py`).

The mutating body is **W24 (Sep 11)**. Import path, parameter schema, dry run and inverse
are complete today — see `_pending.py` for why that boundary is drawn at the import.
"""

from __future__ import annotations

from typing import Any

from ._pending import pending

__all__ = ["revert_key"]


def revert_key(params: dict[str, Any], *, credential: Any = None, undo: Any = None) -> Any:
    """Patch one ConfigMap key.

    `undo` is passed in already computed — `ActionRequest.execute()` refuses to call this at
    all when the inverse is `None`, so an executor never has to decide whether it is safe to
    run. `credential` is the approval-minted actor principal (W23); a call without one will
    be refused there rather than here.
    """
    raise pending("revert_configmap_key", "W24")
