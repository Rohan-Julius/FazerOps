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
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
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
        # The API server rotates the log at 64MB and keeps one backup (`setup_k3d.sh`). An object's
        # last body before a rotation lives only in the backup, and so does any in-window change
        # made before it: read without the backup, the first edit after a rotation has no prior
        # value and nothing to revert. Found live 14 Sep, when a revert card never appeared.
        return list(self._read_log([*rotated_logs(path), path], window))

    def _read_log(self, paths: Sequence[Path], window: TimeWindow) -> Iterator[dict[str, Any]]:
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

        with _joined(paths) as handle:
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
                stored = entry.get("responseObject")
                # A body with no maps still replaces an anchor that had them: the API server omits
                # an emptied `data`, so that entry is the object's latest state, and keeping the
                # older one would seed a prior value the object no longer held.
                if key and self._is_recordable(entry) and (
                    _object_data(stored)
                    or _object_map(stored, "binaryData")
                    or (key in anchors and isinstance(stored, dict))
                ):
                    anchors[key] = entry

        yield from anchors.values()
        yield from in_window

    def _prepare(self, raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sort by time and build the prior-state index. See the module docstring."""
        ordered = sorted(raw_items, key=lambda item: item.get("requestReceivedTimestamp", ""))

        self._prior_state = {}
        seen_state: dict[tuple[str, str, str], dict[str, Any]] = {}
        seen_binary: dict[tuple[str, str, str], dict[str, Any]] = {}

        for item in ordered:
            if not self._is_recordable(item):
                continue
            key = _object_key(item)
            if key is None:
                continue
            if key in seen_state:
                # Snapshot what this object looked like *before* the current entry.
                item["_prior_data"] = seen_state[key]
            if key in seen_binary:
                item["_prior_binary_data"] = seen_binary[key]
            body = item.get("responseObject")
            # Kubernetes serializes both maps `omitempty`: an update that removes every key stores
            # an object with no `data` at all. So a stored body without the map, for an object
            # already seen with one, is that map emptied — not "no information". Left as it was,
            # the next edit's `before` would be the stale map, and its revert hint would restore
            # a value deleted on purpose. An object never seen with the map (a Deployment) stays
            # out of the index, so its entries still carry no diff.
            stored = _object_data(body)
            if stored is not None:
                seen_state[key] = stored
            elif key in seen_state and isinstance(body, dict):
                seen_state[key] = {}
            binary = _object_map(body, "binaryData")
            if binary is not None:
                seen_binary[key] = binary
            elif key in seen_binary and isinstance(body, dict):
                seen_binary[key] = {}

        return ordered

    def normalize_entries(self, raw_items: list[dict[str, Any]]) -> list[tuple[dict[str, Any], ChangeEvent]]:
        """Prepare and normalize raw audit entries, pairing each event with its entry.

        The live and fixture paths reach this through `fetch`, which is radius-scoped. W43's
        containment check needs the same normalization over entries it selected itself — every
        request one sandbox principal made, wherever it landed — so it is exposed here rather
        than restated there, where it could drift from what this collector records.
        """
        pairs = []
        for item in self._prepare(list(raw_items)):
            event = self._normalize(item)
            if event is not None:
                pairs.append((item, event))
        return pairs

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

        # An impersonated request is attributed to the identity it acted as: `user` is only the
        # principal that was allowed to impersonate — for every FazerOps execution, the
        # kubeconfig's `system:admin`, which named nobody (drift log, 14 Sep, D3).
        principal = (raw.get("impersonatedUser") or {}).get("username") or (raw.get("user") or {}).get(
            "username", ""
        )
        actor = normalize_actor(principal, "k8s_audit")
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

        if kind == "ConfigMap":
            binary = _binary_data_diff(raw, data_before=before, data_after=after)
            if binary is not None:
                return binary

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
        if diff.field_path == "binaryData":
            # No shipped action restores a binary map, so there is nothing to hint at. The
            # recorded before and after are what Phase G mines this change class from.
            return False, None

        changed = diff.fields_changed
        if len(changed) != 1:
            # Several keys at once. The hint records every changed key's prior and current
            # value, so an action that restores them together can be built from it — but the
            # shipped `revert_configmap_key` takes one key, so `reversible` stays False. It
            # reaches the model and the brief, and must not claim what the shipped catalog
            # cannot do. Whether any action consumes this hint is `actions/inverse.py`'s call
            # (plan §3.5), which is how W42's rung-1 widening becomes usable once merged
            # without this collector changing again.
            return False, {
                "action_id": "revert_configmap_key",
                "namespace": resource.namespace,
                "name": resource.name,
                "keys": changed,
                "prior_values": {name: (diff.before or {}).get(name) for name in changed},
                "current_values": {name: (diff.after or {}).get(name) for name in changed},
            }

        key = changed[0]
        return True, {
            "action_id": "revert_configmap_key",
            "namespace": resource.namespace,
            "name": resource.name,
            "key": key,
            "prior_value": (diff.before or {}).get(key),
            "current_value": (diff.after or {}).get(key),
        }


def rotated_logs(path: Path) -> list[Path]:
    """The API server's rotated backups of `path`, oldest first.

    The server names a backup `<stem>-<UTC timestamp><suffix>`, so name order is time order.
    """
    return sorted(candidate for candidate in path.parent.glob(f"{path.stem}-*{path.suffix}") if candidate.is_file())


@contextmanager
def _joined(paths: Sequence[Path]) -> Iterator[Iterator[str]]:
    """The lines of every log in order, as one stream. A backup deleted mid-read (the server keeps
    only one) is skipped: what it held is gone either way, and the live file still reads."""

    def lines() -> Iterator[str]:
        for path in paths:
            try:
                with path.open(encoding="utf-8") as handle:
                    yield from handle
            except FileNotFoundError:
                continue

    yield lines()


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
    return _object_map(obj, "data")


def _object_map(obj: Any, field: str) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None
    value = obj.get(field)
    return value if isinstance(value, dict) else None


def _binary_data_diff(
    raw: dict[str, Any], *, data_before: dict[str, Any] | None, data_after: dict[str, Any] | None
) -> Diff | None:
    """A ConfigMap's `binaryData` diff, when that map — and not `data` — is what changed.

    One audit entry is one ledger event, and a `Diff` is over one map. So an update that
    changes both maps records the `data` diff as it always has, and its `binaryData` change is
    not recorded: the recorded `data` diff is what the demo and every hint already rely on.
    """
    after = _object_map(raw.get("responseObject"), "binaryData")
    before = raw.get("_prior_binary_data")
    if before is None and after is None:
        return None

    binary = Diff(before=before, after=after, prior_value_captured=before is not None, field_path="binaryData")
    data_changed = (data_before is not None or data_after is not None) and bool(
        Diff(before=data_before, after=data_after).fields_changed
    )
    if data_changed or not binary.fields_changed:
        return None
    if before is None and (data_before is not None or data_after is not None):
        # First sight of a ConfigMap that carries both maps: nothing was compared, so the
        # `data` path reports it exactly as before rather than claiming a binary change.
        return None
    return binary
