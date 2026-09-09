"""W11 — the Helm collector. `helm history -o json` per release in the blast radius.

Thin on purpose (Handoff §5: "don't over-invest"). Helm's history is a small, honest
source: it says which releases changed and when, and it carries the one thing no other
source does for free — **revision N-1, which is the inverse of revision N**. W20b's
`helm_rollback` computes its inverse from exactly that, so this collector is what makes
ground rule #4 cheap for the Helm action rather than something to be reconstructed.

Two limitations are reported rather than papered over:

* **Helm history carries no principal.** There is no field naming who ran the upgrade, so
  the actor is unresolved. The attribution for a Helm-driven change comes from the K8s
  audit log, which records the API calls Helm made — the two collectors overlapping is by
  design, and the ledger deduplicates on event id.
* **A release is not automatically in-band.** Helm is run from CI *and* from laptops, and
  the history cannot tell them apart. `in_band` is therefore false — "not attributable to
  the pipeline" rather than "definitely not the pipeline". It is never scored (Handoff §3),
  so the cost is one honest line in the brief.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from typing import Any

from ..config import require_offline_capable
from ..keys import helm_release
from ..ledger.normalize import blast_radius_keys, normalize_action, normalize_actor
from ..models import BlastRadius, ChangeEvent, NormalizedAction, TimeWindow
from .base import BaseCollector

HELM_BIN = "helm"
HELM_TIMEOUT_SECONDS = 20

# `helm history` reports what happened in `description`, not in a verb field: "Install
# complete", "Upgrade complete", "Rollback to 2". The description is the only place the
# operation appears, so it is parsed rather than inferred from revision numbers.
_DESCRIPTION_VERBS = (
    ("install", "install"),
    ("upgrade", "upgrade"),
    ("rollback", "rollback"),
    ("uninstall", "uninstall"),
    ("deletion", "uninstall"),
)


class HelmCollector(BaseCollector):
    source = "helm"
    fixture_dir = "helm"

    async def _fetch_live(
        self, radius: BlastRadius, window: TimeWindow
    ) -> list[dict[str, Any]]:
        """`helm list -A` then `helm history` per release, in a worker thread.

        Every release is listed and the radius filter runs afterwards in the shared
        template, rather than the release names being read out of the manifest here. That
        keeps one filter for all four collectors: a release that the manifest has not been
        told about is dropped for the same reason and in the same place as an out-of-radius
        ConfigMap, instead of being invisible to a second, private filter.
        """
        require_offline_capable("HelmCollector")
        releases = json.loads(await self._helm("list", "-A", "-o", "json") or "[]")

        payloads: list[dict[str, Any]] = []
        for release in releases:
            name, namespace = release.get("name"), release.get("namespace")
            if not name or not namespace:
                continue
            history = await self._helm("history", name, "-n", namespace, "-o", "json")
            payloads.append(
                {"release": name, "namespace": namespace, "history": json.loads(history or "[]")}
            )
        return payloads

    async def _helm(self, *args: str) -> str:
        def call() -> str:
            result = subprocess.run(
                [HELM_BIN, *args],
                capture_output=True,
                text=True,
                timeout=HELM_TIMEOUT_SECONDS,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(f"helm {' '.join(args[:2])} failed: {result.stderr.strip()}")
            return result.stdout

        return await asyncio.to_thread(call)

    def _prepare(self, raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Flatten `{release, namespace, history: [...]}` into one item per revision.

        `helm history` output does not name its own release — the release is context the
        caller had and the output does not carry. Flattening here rather than in
        `_normalize` is what lets the fixture store Helm's output verbatim inside a wrapper
        that supplies that context, instead of a rewritten shape Helm never emits.

        The previous revision is attached to each item because it is this collector's
        reason for existing: Handoff §5 notes revision N-1 is `helm_rollback`'s inverse for
        free, and only the whole history knows what N-1 was.
        """
        flattened: list[dict[str, Any]] = []

        for payload in raw_items:
            release, namespace = payload.get("release"), payload.get("namespace")
            if not release or not namespace:
                continue

            history = sorted(payload.get("history") or [], key=lambda e: e.get("revision", 0))
            for index, entry in enumerate(history):
                previous = history[index - 1] if index > 0 else None
                flattened.append(
                    {
                        **entry,
                        "release": release,
                        "namespace": namespace,
                        "previous_revision": previous.get("revision") if previous else None,
                    }
                )

        return flattened

    def _normalize(self, raw: dict[str, Any]) -> ChangeEvent | None:
        revision = raw.get("revision")
        updated = raw.get("updated")
        if revision is None or not updated:
            return None

        action = normalize_action(_verb_from(raw.get("description", "")), "helm")
        if action is NormalizedAction.UNKNOWN:
            # A revision whose description this collector cannot read is dropped rather
            # than recorded with a guessed verb: a wrong verb feeds a wrong type_prior and
            # the failure then looks like a scoring bug (W14).
            return None

        resource = helm_release(raw["namespace"], raw["release"])
        previous = raw.get("previous_revision")

        return ChangeEvent(
            id=f"helm-{raw['namespace']}-{raw['release']}-{revision}",
            source="helm",
            occurred_at=updated,
            # No principal in the history — see the module docstring.
            actor=normalize_actor("helm", "helm"),
            action=action,
            resource=resource,
            blast_radius_keys=blast_radius_keys(resource),
            in_band=False,
            reversible=previous is not None,
            inverse_hint=(
                None
                if previous is None
                else {
                    "action_id": "helm_rollback",
                    "release": raw["release"],
                    "namespace": raw["namespace"],
                    "target_revision": previous,
                    "current_revision": revision,
                }
            ),
            raw_ref=f"helm:{raw['namespace']}/{raw['release']}@{revision}",
        )


def _verb_from(description: str) -> str:
    """Helm's `description` in the vocabulary `normalize_action` understands."""
    lowered = description.lower()
    for needle, verb in _DESCRIPTION_VERBS:
        if needle in lowered:
            return verb
    return description
