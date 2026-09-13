"""`revert_configmap_key` — Handoff §7, Tier 1. W24's executor.

The demo's action: restore one key of one ConfigMap to the value it held before an
out-of-band edit. Its inverse is itself, aimed at the value that is current now, which is
why ground rule #4 is cheap here (`actions/inverse.py`).

**This is the only code in the repo that has ever mutated a cluster.** Four things are
true before the patch goes out, and none of them is checked here — they are checked
upstream, by code that cannot be skipped:

1. the parameters matched the catalog schema (`catalog.validate_params`, at proposal time);
2. the inverse was computed and is not `None` (`ActionRequest.execute`, ground rule #4);
3. the declared preconditions were satisfied by collected evidence (`preconditions.check`);
4. a human approved it, and the approval minted the credential this function demands.

What *is* checked here is (4)'s terms — that the credential is an actor principal, for this
action, for this namespace, unexpired and unspent (`require_actor_credential`). That check
runs **before any client is constructed**, so a call with the wrong credential never opens
a connection to a cluster.

**A strategic-merge patch of one key, never a replace.** `patch_namespaced_config_map` with
a `{"data": {key: value}}` body leaves every other key untouched. A read-modify-write would
race any other writer and could silently discard a concurrent change — during an incident,
which is when concurrent changes happen.
"""

from __future__ import annotations

from typing import Any

from ...security.credentials import require_actor_credential

__all__ = ["revert_key"]


def revert_key(
    params: dict[str, Any],
    *,
    credential: Any = None,
    undo: Any = None,
    client: Any = None,
    recorded: Any = None,
) -> dict[str, Any]:
    """Patch one ConfigMap key to `target_value` — or, in the widened form, every recorded key.

    `recorded` is the request's hint. The widened `keys` form (W42 rung 1) takes its target
    values from it rather than from parameters, so a model never supplies a value, and it is
    checked with the same `recorded_keys` the inverse and the dry run use **before** the
    credential is spent: a refusal here must not burn an approval.

    `undo` arrives already computed — `ActionRequest.execute()` refuses to call this at all
    when the inverse is `None`, so an executor never has to decide whether it is safe to
    run. It is carried into the result rather than used, because the thing that needs the
    inverse is the incident record and the operator reading it, not this function.

    `client` is injectable for the e2e test's cleanup path and for a caller that already
    holds a configured `CoreV1Api`. When it is `None` one is built from the ambient
    kubeconfig, after the credential check.
    """
    namespace = params["namespace"]
    name = params["name"]

    if params.get("keys") is not None:
        from ..inverse import recorded_keys

        found = recorded_keys(params, recorded)
        if found is None:
            raise ValueError(
                "revert_configmap_key: the recorded values do not fit these keys and this "
                "ConfigMap; refusing (ground rule #4)"
            )
        keys, prior, _ = found
        require_actor_credential(credential, action_id="revert_configmap_key", namespace=namespace)
        client = client if client is not None else _core_v1()
        patched = client.patch_namespaced_config_map(
            name=name, namespace=namespace, body={"data": {k: prior[k] for k in keys}}
        )
        # Key names only, never values — the widened form restores values the card masked.
        return {
            "action_id": "revert_configmap_key",
            "namespace": namespace,
            "name": name,
            "keys": keys,
            "resource_version": patched.metadata.resource_version,
            "inverse": None if undo is None else {"action_id": undo.action_id, "params": undo.params},
        }

    key = params["key"]
    target_value = params["target_value"]

    # Before the client, always. A credential failure must not be reachable only after a
    # connection to a cluster has already been opened with whatever identity was ambient.
    require_actor_credential(
        credential, action_id="revert_configmap_key", namespace=namespace
    )

    client = client if client is not None else _core_v1()

    # Strategic merge of exactly one key — see the module docstring on why not a replace.
    patched = client.patch_namespaced_config_map(
        name=name, namespace=namespace, body={"data": {key: target_value}}
    )

    return {
        "action_id": "revert_configmap_key",
        "namespace": namespace,
        "name": name,
        "key": key,
        "value": (patched.data or {}).get(key),
        "resource_version": patched.metadata.resource_version,
        "inverse": None if undo is None else {"action_id": undo.action_id, "params": undo.params},
    }


def _core_v1() -> Any:
    """A Kubernetes client from the ambient kubeconfig.

    Built here rather than at module scope for the reason `config.require_offline_capable`
    exists: a client constructed at import reaches for a config file and then for a cluster,
    and on a judge's machine with no kubeconfig that is an import-time failure in a module
    the fixture demo never calls.
    """
    from ...config import require_offline_capable

    require_offline_capable("revert_configmap_key")

    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config

    k8s_config.load_kube_config()
    return k8s_client.CoreV1Api()
