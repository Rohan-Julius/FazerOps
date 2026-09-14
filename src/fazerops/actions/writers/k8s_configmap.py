"""`k8s/ConfigMap:data` — the first writer, and a human-authored one (W41).

It expresses the multi-key ConfigMap gap as a declarative entry: a patch that changes several
keys at once, restored in one write. The recorded demo window holds that *shape* — the two-key
`auth-service-config` patch — but not an instance of the gap: that entry is the first in the log
for its ConfigMap, so no prior value was captured and nothing could restore it. W42 reaches this
writer only when rung 1 does not apply; `revert_configmap_key`'s declared widening covers the
same class more cheaply.

**No credential check here, on purpose.** `executors/writer.py` checks the actor credential
before this module's code is reached, and the credential is single-use: a second check here
would refuse a mutation a human approved. `test_writer_registry.py` asserts writers never call
the gate themselves.

**A strategic merge of exactly the recorded keys**, never a replace, for `configmap.py`'s
reason: a read-modify-write races any concurrent writer during the incident. A `None` value
deletes the key, because `None` in the recorded prior means the key did not exist before the
change being reverted.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ... import keys
from ...models import ResourceRef
from .registry import WriterSpec

__all__ = ["WRITER", "read", "write"]


def _resource(params: Mapping[str, Any]) -> ResourceRef:
    return keys.k8s_configmap(str(params["namespace"]), str(params["name"]))


def _params_for(resource: ResourceRef) -> dict[str, str] | None:
    if resource.kind != "ConfigMap" or not resource.namespace:
        return None
    return {"namespace": resource.namespace, "name": resource.name}


def read(params: Mapping[str, Any], *, client: Any = None) -> dict[str, Any]:
    client = client if client is not None else _core_v1()
    configmap = client.read_namespaced_config_map(
        name=params["name"], namespace=params["namespace"]
    )
    return dict(configmap.data or {})


def write(
    params: Mapping[str, Any],
    values: Mapping[str, Any],
    *,
    credential: Any = None,
    client: Any = None,
) -> dict[str, Any]:
    """Patch the recorded keys. Returns key *names* only — never values, for the reason
    `slack/handlers.approval_sink` gives about the redacted value printed back out."""
    client = client if client is not None else _core_v1(credential)
    patched = client.patch_namespaced_config_map(
        name=params["name"], namespace=params["namespace"], body={"data": dict(values)}
    )
    return {
        "namespace": params["namespace"],
        "name": params["name"],
        "keys": sorted(values),
        "resource_version": patched.metadata.resource_version,
    }


def _core_v1(credential: Any = None) -> Any:
    from ...config import require_offline_capable

    require_offline_capable("k8s/ConfigMap:data")

    from kubernetes import client as k8s_client

    from ..k8s_client import api_client

    # Impersonates the approver when writing, so the audit log names them (drift log, 14 Sep, D3).
    return k8s_client.CoreV1Api(api_client(credential))


WRITER = WriterSpec(
    resource_type="k8s/ConfigMap",
    field_path="data",
    source="k8s_audit",
    kind="ConfigMap",
    ref_params=("namespace", "name"),
    scope_field="namespace",
    resource=_resource,
    params_for=_params_for,
    read=read,
    write=write,
    authored_by="human",
)
