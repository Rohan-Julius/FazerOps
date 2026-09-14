"""Human-written support for Kubernetes writers — the half of a generated writer nobody generates.

W42's rung 3 lets a model author exactly two functions, `read` and `write`. Everything that turns
parameters into a resource reference, builds a client, or names the API methods lives here and
is written by a person, so the generated half cannot choose what it talks to: it is handed a
client and may call one method on it.

`CONTRACTS` is the whole contract. A `(kind, field)` pair is authorable only if the audit
collector records that map's prior value and its values can be restored — a ConfigMap's `data`
and its `binaryData`. A Secret's recorded values are redactions (`k8s_audit`), so a writer for it
would have nothing to write and none is authored.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from ...models import ResourceRef
from .registry import WriterSpec

__all__ = [
    "CONTRACTS",
    "MapContract",
    "api_for",
    "contract_for",
    "has_contract",
    "methods_for",
    "namespaced_params",
    "namespaced_resource",
    "stand_in_writer",
    "writer_contract",
]


@dataclass(frozen=True)
class MapContract:
    api_class: str  # the kubernetes client API class
    snake: str  # the resource's snake-case name in that API's method names
    attribute: str  # the map's attribute on the object the client returns
    body_field: str  # the map's key in a patch body — the API's own spelling


CONTRACTS: dict[tuple[str, str], MapContract] = {
    ("ConfigMap", "data"): MapContract("CoreV1Api", "config_map", "data", "data"),
    # The client returns snake case and the API takes camel case, so the two differ here and a
    # writer that reads `data` for this contract fails the probe rather than restoring nothing.
    ("ConfigMap", "binaryData"): MapContract("CoreV1Api", "config_map", "binary_data", "binaryData"),
}


def contract_for(kind: str, field: str = "data") -> MapContract:
    return CONTRACTS[(kind, field)]


def has_contract(kind: str, field: str = "data") -> bool:
    return (kind, field) in CONTRACTS


def methods_for(kind: str, field: str = "data") -> tuple[str, str]:
    """`(read method, write method)` — the only two calls a generated writer may make."""
    snake = contract_for(kind, field).snake
    return f"read_namespaced_{snake}", f"patch_namespaced_{snake}"


def writer_contract(kind: str, field: str = "data") -> dict[str, Any]:
    """Everything the authoring model is told. Built from this table and nothing else — no
    ledger text, no alert text, no diff value ever reaches the model that writes code."""
    contract = contract_for(kind, field)
    read_method, write_method = methods_for(kind, field)
    return {
        "resource_kind": kind,
        "field": field,
        "read_attribute": contract.attribute,
        "body_field": contract.body_field,
        "read_signature": "def read(params, *, client)",
        "write_signature": "def write(params, values, *, credential, client)",
        "read_method": read_method,
        "write_method": write_method,
        "params_keys": ["namespace", "name"],
    }


def namespaced_resource(kind: str) -> Callable[[Mapping[str, Any]], ResourceRef]:
    def resource(params: Mapping[str, Any]) -> ResourceRef:
        return ResourceRef(kind=kind, name=str(params["name"]), namespace=str(params["namespace"]))

    return resource


def namespaced_params(kind: str) -> Callable[[ResourceRef], dict[str, str] | None]:
    def params_for(resource: ResourceRef) -> dict[str, str] | None:
        if resource.kind != kind or not resource.namespace:
            return None
        return {"namespace": resource.namespace, "name": resource.name}

    return params_for


def api_for(kind: str, credential: Any = None) -> Any:
    """The typed API for `kind`, impersonating `credential`'s approver when given one (D3)."""
    from ...config import require_offline_capable

    require_offline_capable(f"k8s/{kind}")

    from kubernetes import client as k8s_client

    from ..k8s_client import api_client

    [api_class] = {contract.api_class for (k, _), contract in CONTRACTS.items() if k == kind}
    return getattr(k8s_client, api_class)(api_client(credential))


def stand_in_writer(kind: str, field: str = "data") -> WriterSpec:
    """A spec with the real, human-written resource mapping and a `read`/`write` that refuse.

    Replay uses it for a rung-3 candidate. A dry run and an inverse never call a writer, so
    evaluating a candidate never needs — and never gets — the generated code loaded.
    """

    def refuse(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("a stand-in writer is for evaluation; nothing may execute through it")

    return WriterSpec(
        resource_type=f"k8s/{kind}",
        field_path=field,
        source="k8s_audit",
        kind=kind,
        ref_params=("namespace", "name"),
        scope_field="namespace",
        resource=namespaced_resource(kind),
        params_for=namespaced_params(kind),
        read=refuse,
        write=refuse,
        authored_by="agent",
    )
