"""W26b — the approver roster. Handoff §7, Idea §3 and §4.

> *Tier 2 requires `requires_approval_from: manager`.*

A tier split is only real if the two principals are actually different people, so this is
the module that says who is which. It is small on purpose and **fails closed** on every
axis that could go wrong:

* an **unlisted** user is refused, never defaulted to engineer;
* an **empty** roster refuses everyone, so a misconfigured deployment approves nothing
  rather than approving everything;
* a user listed as **both** engineer and manager is an error, not a promotion. Idea §3's
  warning runs in both directions — managers approve risk and spend, not pod restarts — and
  one person holding both roles makes the split decorative while still looking configured.

Ids come from the environment first (`FAZEROPS_SLACK_ENGINEERS`, `FAZEROPS_SLACK_MANAGERS`,
comma-separated) and from `config/approvers.yaml` otherwise, so a workspace's real user ids
never need to be committed.

**Automation layer** (plan §3.5). The investigation layer imports nothing from here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

import yaml

from .approval import Approver, ApproverRole, ApprovalRefused

__all__ = ["Roster", "UnknownApprover", "default_roster"]

DEFAULT_ROSTER = Path(__file__).resolve().parents[3] / "config" / "approvers.yaml"

_ENV = {
    ApproverRole.ENGINEER: "FAZEROPS_SLACK_ENGINEERS",
    ApproverRole.MANAGER: "FAZEROPS_SLACK_MANAGERS",
}


class UnknownApprover(ApprovalRefused):
    """The clicker is not on the roster.

    A subclass of `ApprovalRefused` so `approval_sink` reports it the same way it reports
    every other refusal — visibly, to the operator, rather than as a dropped click.
    """


class Roster:
    """Slack user id → `Approver`. Constructed from a file, the environment, or directly."""

    def __init__(
        self,
        *,
        engineers: Iterable[str] = (),
        managers: Iterable[str] = (),
    ) -> None:
        self._engineers = {str(uid).strip() for uid in engineers if str(uid).strip()}
        self._managers = {str(uid).strip() for uid in managers if str(uid).strip()}

        both = sorted(self._engineers & self._managers)
        if both:
            raise ValueError(
                f"{', '.join(both)} listed as both engineer and manager. A person holding "
                "both roles makes the Tier 1/Tier 2 split decorative while still looking "
                "configured (Idea §3); list them once, under the role they approve as."
            )

    @classmethod
    def load(cls, path: Path | str | None = None) -> Roster:
        """The environment wins over the file, per role, so real ids stay out of the repo.

        A role set in the environment replaces that role's file list rather than extending
        it: a roster half from one source and half from another is one nobody can read off
        a single page, and an id someone thought they had removed is still in it.
        """
        raw = {}
        target = Path(path or DEFAULT_ROSTER)
        if target.exists():
            raw = (yaml.safe_load(target.read_text(encoding="utf-8")) or {}).get("approvers") or {}

        return cls(
            engineers=_from_env_or(_ENV[ApproverRole.ENGINEER], raw.get("engineers")),
            managers=_from_env_or(_ENV[ApproverRole.MANAGER], raw.get("managers")),
        )

    def __len__(self) -> int:
        return len(self._engineers) + len(self._managers)

    @property
    def empty(self) -> bool:
        return not self._engineers and not self._managers

    def resolve(self, user_id: str) -> Approver:
        """The approver for a Slack user id, or a refusal. **Never returns a default.**"""
        uid = (user_id or "").strip()
        if uid in self._managers:
            return Approver(user_id=uid, role=ApproverRole.MANAGER)
        if uid in self._engineers:
            return Approver(user_id=uid, role=ApproverRole.ENGINEER)

        if self.empty:
            raise UnknownApprover(
                "the approver roster is empty, so no approval can be authorized. Set "
                f"{_ENV[ApproverRole.ENGINEER]} and {_ENV[ApproverRole.MANAGER]} in .env, "
                "or fill config/approvers.yaml. Nothing has run."
            )
        raise UnknownApprover(
            f"{uid or 'an unidentified user'} is not on the approver roster and cannot "
            "authorize a mutation (Handoff §7). Nothing has run."
        )


def _from_env_or(variable: str, fallback: object) -> list[str]:
    value = os.environ.get(variable)
    if value is not None:
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(item) for item in (fallback or [])]


def default_roster() -> Roster:
    """Loaded per call, not cached: the roster changes when `.env` changes, and a process
    that cached it at import would keep approving under a roster someone had edited."""
    return Roster.load()
