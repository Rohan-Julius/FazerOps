"""An in-memory stand-in for W43's Kubernetes sandbox, for tests that run without a cluster.

It implements the same four calls as `growth.sandbox.K8sSandbox` and reports what it saw in the
same shape — requests by the sandbox principal, denied ones included, and the collector-shaped
events for the ones that landed. `tests/e2e/test_containment.py` asserts the same verdicts
against a real API server, which is what keeps this fake honest.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from fazerops.actions.growth.sandbox import DECOY_KEY, Observation, ObservedRequest, _decoy
from fazerops.models import Actor, ChangeEvent, Diff, NormalizedAction, ResourceRef

SANDBOX_NAMESPACE = "fake-sandbox"
_ATTRIBUTES = {"data": "data", "binaryData": "binary_data"}


class FakeSandbox:
    def __init__(self, *, complete: bool = True) -> None:
        self.complete = complete
        self.objects: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
        self.requests: list[ObservedRequest] = []
        self.events: list[ChangeEvent] = []
        self.torn_down = False

    def provision(self, declared: ResourceRef, field: str, current: dict[str, Any]) -> ResourceRef:
        seeded = {key: value for key, value in current.items() if value is not None}
        seeded[DECOY_KEY] = _decoy(field)
        self.objects[(SANDBOX_NAMESPACE, declared.name)] = {field: seeded}
        self.objects[(SANDBOX_NAMESPACE, "neighbour")] = {"data": {"k": "v"}}
        return ResourceRef(kind=declared.kind, name=declared.name, namespace=SANDBOX_NAMESPACE)

    def client(self) -> Any:
        return _FakeCoreV1(self)

    def observe(self) -> Observation:
        return Observation(complete=self.complete, requests=list(self.requests), events=list(self.events))

    def teardown(self) -> None:
        self.torn_down = True


class _FakeCoreV1:
    """RBAC as the real sandbox's Role has it: get and patch, in the sandbox namespace only."""

    def __init__(self, box: FakeSandbox) -> None:
        self._box = box

    def _returned(self, stored: dict[str, dict[str, Any]]) -> SimpleNamespace:
        maps = {_ATTRIBUTES[field]: dict(values) for field, values in stored.items()}
        return SimpleNamespace(data=maps.get("data"), binary_data=maps.get("binary_data"), metadata=SimpleNamespace(resource_version="2"))

    def read_namespaced_config_map(self, name: str, namespace: str) -> SimpleNamespace:
        stored = self._box.objects.get((namespace, name))
        if stored is None or namespace != SANDBOX_NAMESPACE:
            raise RuntimeError("404")
        return self._returned(stored)

    def patch_namespaced_config_map(self, name: str, namespace: str, body: dict[str, Any]) -> SimpleNamespace:
        resource = ResourceRef(kind="ConfigMap", name=name, namespace=namespace)
        stored = self._box.objects.get((namespace, name))
        allowed = namespace == SANDBOX_NAMESPACE and stored is not None
        self._box.requests.append(ObservedRequest(verb="patch", resource_key=resource.blast_radius_key(), succeeded=allowed))
        if not allowed:
            raise RuntimeError("403" if namespace != SANDBOX_NAMESPACE else "404")

        for field, values in body.items():
            before = dict(stored.get(field) or {})
            after = dict(before)
            for key, value in values.items():
                if value is None:
                    after.pop(key, None)
                else:
                    after[key] = value
            stored[field] = after
            self._box.events.append(
                ChangeEvent(
                    id=f"fake-{len(self._box.events)}",
                    source="k8s_audit",
                    occurred_at=datetime.now(timezone.utc),
                    actor=Actor(raw="system:serviceaccount:fake-sandbox:writer", kind="service_account"),
                    action=NormalizedAction.UPDATE,
                    resource=resource,
                    diff=Diff(before=before, after=after, field_path=None if field == "data" else field),
                    in_band=False,
                    raw_ref="fake",
                )
            )
        return self._returned(stored)


def factory(**kwargs: Any):
    """A sandbox factory that remembers every sandbox it built."""
    built: list[FakeSandbox] = []

    def make() -> FakeSandbox:
        box = FakeSandbox(**kwargs)
        built.append(box)
        return box

    make.built = built  # type: ignore[attr-defined]
    return make


def never():
    def make() -> FakeSandbox:
        raise AssertionError("the pre-check must refuse before any sandbox is built")

    return make
