"""W8 — the Kubernetes audit collector. This produces the demo's single causal event.

Two things here are load-bearing and non-obvious:

**Reconstructing `before`.** An audit entry for an `update` carries `requestObject` (what
was sent) and `responseObject` (what was stored). Both hold the *new* value. The prior
value is only available from the same object's previous audit entry, which is frequently
outside the correlation window — so `_prepare` indexes the whole log by object first, and
window filtering happens afterwards. Without this the diff is a claim rather than a
screenshot, and the diff is the most convincing frame in the video.

**Excluding the control plane.** kube-system service accounts mutate objects constantly.
Left in, they dominate every brief. They are excluded by principal, not by heuristics on
the object.

**Live mode reads a file, not an API.** The audit log is not exposed through the
Kubernetes API — the API server writes it to disk on the control-plane node (or ships it
to a webhook). For k3d that file is bind-mounted onto the host by `scripts/setup_k3d.sh`,
so live mode reads it directly. A production cluster ships the same JSON to a log sink and
the collector would read it from there; that is a swap of `_fetch_live`, not a redesign,
and it is disclosed in the README rather than half-built.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..ledger.normalize import (
    blast_radius_keys,
    default_identity_map,
    normalize_action,
    normalize_actor,
    parse_timestamp,
)
from ..models import BlastRadius, ChangeEvent, Diff, NormalizedAction, ResourceRef, TimeWindow
from .base import BaseCollector

# k3d writes the audit log here via the bind mount in `scripts/setup_k3d.sh`. Overridable
# because a cluster created with a different `FAZEROPS_AUDIT_DIR` puts it elsewhere, and
# because a production deployment reads it from a log sink entirely.
AUDIT_LOG_ENV = "FAZEROPS_K8S_AUDIT_LOG"
DEFAULT_AUDIT_LOG = Path(__file__).resolve().parents[3] / ".k3d" / "audit" / "audit.log"

# Handoff §5: a change ledger records mutations. A ledger that records reads is a log.
MUTATING_VERBS = frozenset({"create", "update", "patch", "delete", "deletecollection"})

# The audit policy emits an entry per stage; ResponseComplete is the only one carrying the
# stored object. Counting the others would double-count every change.
TERMINAL_STAGE = "ResponseComplete"

CONTROL_PLANE_PREFIXES = (
    "system:serviceaccount:kube-system:",
    "system:kube-",
    "system:node:",
)

# `objectRef.resource` is the lowercase plural; ResourceRef.kind is the singular Kind, and
# it must match what `config/service_manifest.yaml` produces via keys.py or the event will
# not be retrievable by its own blast-radius key.
RESOURCE_KINDS = {
    "configmaps": "ConfigMap",
    "secrets": "Secret",
    "deployments": "Deployment",
    "statefulsets": "StatefulSet",
    "daemonsets": "DaemonSet",
    "services": "Service",
    "ingresses": "Ingress",
}

REDACTED = "<redacted>"


class K8sAuditCollector(BaseCollector):
    source = "k8s_audit"
    fixture_dir = "k8s_audit"

    def __init__(self) -> None:
        # objectRef key -> the `data` block of that object's most recent prior entry.
        self._prior_state: dict[tuple[str, str, str], dict[str, Any]] = {}

    async def _fetch_live(
        self, radius: BlastRadius, window: TimeWindow
    ) -> list[dict[str, Any]]:
        """Read the API server's audit log off disk.

        A missing log is raised rather than swallowed: `BaseCollector.fetch` turns it into
        a degraded brief naming this source, which is honest. Returning `[]` would render
        as "nothing changed in this window" — the one wrong answer this product can give.
        """
        path = audit_log_path()
        if not path.is_file():
            raise FileNotFoundError(
                f"no Kubernetes audit log at {path}. Run scripts/setup_k3d.sh, or set "
                f"{AUDIT_LOG_ENV} to the log's location."
            )
        return list(self._read_log(path, window))

    def _read_log(self, path: Path, window: TimeWindow) -> Iterator[dict[str, Any]]:
        """Everything `_prepare` needs, and nothing else.

        The audit log is every request the cluster served, capped at 64MB by the flags in
        `setup_k3d.sh` — parsing all of it on every alert would be slow and pointless.
        Two classes of entry matter: anything up to the window's end, and — from before
        the window — the latest entry per object that actually carries an object body,
        because that is what seeds the prior-state index and makes a real diff possible.

        The filter reuses `_is_recordable` and `_object_data` rather than restating them,
        so it cannot drift from what `_prepare` will later count as prior state.
        """
        anchors: dict[tuple[str, str, str], dict[str, Any]] = {}
        in_window: list[dict[str, Any]] = []

        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    # The API server appends as it goes; the final line can be half
                    # written. A torn line is not corruption and must not kill the brief.
                    continue

                raw_time = entry.get("requestReceivedTimestamp")
                if not isinstance(raw_time, str):
                    continue
                try:
                    occurred = parse_timestamp(raw_time)
                except ValueError:
                    continue

                if occurred >= window.end:
                    continue  # nothing after the alert can have caused it

                if occurred >= window.start:
                    in_window.append(entry)
                    continue

                key = _object_key(entry)
                if key and self._is_recordable(entry) and _object_data(entry.get("responseObject")):
                    anchors[key] = entry

        yield from anchors.values()
        yield from in_window

    def _prepare(self, raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sort by time and build the prior-state index. See the module docstring."""
        ordered = sorted(raw_items, key=lambda item: item.get("requestReceivedTimestamp", ""))

        self._prior_state = {}
        seen_state: dict[tuple[str, str, str], dict[str, Any]] = {}

        for item in ordered:
            if not self._is_recordable(item):
                continue
            key = _object_key(item)
            if key is None:
                continue
            if key in seen_state:
                # Snapshot what this object looked like *before* the current entry.
                item["_prior_data"] = seen_state[key]
            stored = _object_data(item.get("responseObject"))
            if stored is not None:
                seen_state[key] = stored

        return ordered

    def _is_recordable(self, raw: dict[str, Any]) -> bool:
        if raw.get("stage") != TERMINAL_STAGE:
            return False
        if raw.get("verb", "").lower() not in MUTATING_VERBS:
            return False

        username = (raw.get("user") or {}).get("username", "")
        if username.startswith(CONTROL_PLANE_PREFIXES):
            return False

        # A denied request changed nothing. Recording it would put a change in the ledger
        # that never happened, and the revert would then have nothing to revert.
        code = (raw.get("responseStatus") or {}).get("code", 200)
        return 200 <= int(code) < 300

    def _normalize(self, raw: dict[str, Any]) -> ChangeEvent | None:
        if not self._is_recordable(raw):
            return None

        object_ref = raw.get("objectRef") or {}
        resource_plural = object_ref.get("resource", "")
        namespace = object_ref.get("namespace")
        name = object_ref.get("name")
        if not name or not namespace:
            return None  # cluster-scoped objects are out of scope for this build

        resource = ResourceRef(
            kind=RESOURCE_KINDS.get(resource_plural, resource_plural.rstrip("s").title()),
            name=name,
            namespace=namespace,
        )

        actor = normalize_actor((raw.get("user") or {}).get("username", ""), "k8s_audit")
        action = normalize_action(raw.get("verb", ""), "k8s_audit")
        diff = self._build_diff(raw, resource.kind)

        reversible, inverse_hint = self._inverse_for(resource, action, diff)

        return ChangeEvent(
            id=raw["auditID"],
            source="k8s_audit",
            occurred_at=parse_timestamp(raw["requestReceivedTimestamp"]),
            actor=actor,
            action=action,
            resource=resource,
            diff=diff,
            blast_radius_keys=blast_radius_keys(resource),
            in_band=default_identity_map().is_in_band(actor),
            reversible=reversible,
            inverse_hint=inverse_hint,
            raw_ref=f"k8s_audit:{raw['auditID']}",
        )

    def _build_diff(self, raw: dict[str, Any], kind: str) -> Diff | None:
        after = _object_data(raw.get("responseObject"))
        before = raw.get("_prior_data")

        if after is None and before is None:
            return None  # a Metadata-level entry; the policy did not capture bodies

        if kind == "Secret":
            # Never put secret material in a Slack message, a markdown record, or a model
            # prompt. The fact that a key rotated is the evidence; the value is not.
            before = {k: REDACTED for k in (before or {})} or None
            after = {k: REDACTED for k in (after or {})} or None

        return Diff(
            before=before,
            after=after,
            prior_value_captured=before is not None,
        )

    def _inverse_for(
        self, resource: ResourceRef, action: NormalizedAction, diff: Diff | None
    ) -> tuple[bool, dict[str, Any] | None]:
        """Ground rule #4: claim reversibility only when the undo can actually be built.

        The hint is opaque data — only `actions/inverse.py` interprets it (plan §3.5).
        Restricted to ConfigMap key edits, because that is the one action the catalog
        ships (§3.5) and a hint for an action with no executor is a live ImportError.
        """
        if resource.kind != "ConfigMap" or action is not NormalizedAction.UPDATE:
            return False, None
        if diff is None or not diff.prior_value_captured or not diff.fields_changed:
            return False, None

        changed = diff.fields_changed
        if len(changed) != 1:
            return False, None  # multi-key edits are out of scope for the single action

        key = changed[0]
        return True, {
            "action_id": "revert_configmap_key",
            "namespace": resource.namespace,
            "name": resource.name,
            "key": key,
            "prior_value": (diff.before or {}).get(key),
            "current_value": (diff.after or {}).get(key),
        }


def audit_log_path() -> Path:
    override = os.environ.get(AUDIT_LOG_ENV)
    return Path(override) if override else DEFAULT_AUDIT_LOG


def _object_key(raw: dict[str, Any]) -> tuple[str, str, str] | None:
    ref = raw.get("objectRef") or {}
    resource, namespace, name = ref.get("resource"), ref.get("namespace"), ref.get("name")
    if not (resource and namespace and name):
        return None
    return (resource, namespace, name)


def _object_data(obj: Any) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None
    data = obj.get("data")
    return data if isinstance(data, dict) else None
