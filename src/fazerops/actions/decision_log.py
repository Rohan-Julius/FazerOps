"""B1 — every interaction with an approval card or `/fazerops`, written down, refusals included.

`IncidentSession` records the decision that went through. The events a security review asks for
first are the ones it never saw: a clicker not on the roster, an engineer clicking a Tier 2 card,
a stale or expired card, a button payload this app did not build. Before this they reached a
`logger.warning` at best. Each is now one line in `decisions.jsonl`, beside the ledger.

**Written through the ledger's `ChainedLog`**, so when `FAZEROPS_EVIDENCE_KEY` is set every line is
HMAC-chained and an edit, deletion or reorder reads back as `Integrity.BROKEN`. Without a key the
file is still append-only, and says it is unsigned.

**A record, never a channel.** Nothing reads this file to decide anything, and a failure to write it
never changes the answer a click gets — the decision has already been made by then, and a failed
audit write that surfaced as a failed approval is what someone would retry.

**Automation layer** (plan §3.5).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import evidence_key
from ..ledger.chain import ChainedLog, Integrity

__all__ = ["DecisionLog", "RESULTS"]

logger = logging.getLogger(__name__)

_FROM_ENV = object()

# `read` is a `show_all` click or a `/fazerops` command — nothing was decided, and who looked is
# still worth knowing during an incident review.
RESULTS = ("executed", "failed", "rejected", "replay", "refused", "malformed", "read")

# Reasons quote exception messages, which can quote payload content. Bounded so a hostile payload
# cannot turn the audit log into its own storage.
_TEXT_LIMIT = 300


class DecisionLog:
    def __init__(self, path: Path | str, *, key: bytes | None | object = _FROM_ENV) -> None:
        self.path = Path(path)
        self._log = ChainedLog(self.path, evidence_key() if key is _FROM_ENV else key)  # type: ignore[arg-type]

    def record(
        self,
        *,
        result: str,
        user_id: str,
        kind: str,
        incident_id: str | None = None,
        action_id: str | None = None,
        dry_run_digest: str | None = None,
        role: str | None = None,
        tier: int | None = None,
        reason: str | None = None,
        source: str = "slack",
    ) -> None:
        if result not in RESULTS:
            raise ValueError(f"unknown decision-log result {result!r}; expected one of {RESULTS}")
        entry = {
            "at": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "user_id": _bounded(user_id),
            "role": role,
            "kind": _bounded(kind),
            "incident_id": _bounded(incident_id),
            "action_id": _bounded(action_id),
            "dry_run_digest": _bounded(dry_run_digest),
            "tier": tier,
            "result": result,
            "reason": _bounded(reason),
        }
        try:
            self._log.append([entry])
        except Exception:  # noqa: BLE001 - see the module docstring: never changes the answer
            logger.exception("could not append to %s; the decision stands", self.path)

    def record_malformed(self, body: dict[str, Any], reason: str) -> None:
        """For `handlers.build_app(on_malformed=...)`: a payload that never became a `Decision`.

        The button's `value` is deliberately not stored — it is the part a forger controls.
        """
        actions = body.get("actions") or [{}]
        kind = actions[0].get("action_id") if isinstance(actions[0], dict) else None
        self.record(
            result="malformed",
            user_id=str((body.get("user") or {}).get("id") or ""),
            kind=str(kind) if isinstance(kind, str) else "unknown",
            reason=reason,
        )

    def entries(self) -> tuple[list[dict[str, Any]], Integrity, str | None]:
        """Every entry in order, and whether the file can vouch for them."""
        return self._log.read()


def _bounded(value: Any) -> Any:
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= _TEXT_LIMIT else text[:_TEXT_LIMIT] + "…"
