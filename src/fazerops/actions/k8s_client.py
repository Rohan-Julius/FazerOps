"""A Kubernetes API client that acts as the approver, not as the kubeconfig.

Every executor and writer used to build its client straight from the ambient kubeconfig, so the
API server's audit log recorded each approved revert as `system:admin` — and `k8s_audit` then
collected FazerOps's own mutation as an unattributed out-of-band change in the next incident
(drift log, 14 Sep, D3). Impersonation puts the approver on the audit event as
`impersonatedUser`; the kubeconfig's principal only has to be allowed to impersonate.

`setup_k3d.sh` binds `KUBERNETES_ACTOR_GROUP` to the permissions the actions need. The namespace
scope is still enforced by `require_actor_credential`, not by RBAC — the same honest split
`credentials.session_policy` states for the k3d half of the build.

**Automation layer** (plan §3.5).
"""

from __future__ import annotations

from typing import Any

__all__ = ["api_client"]


def api_client(credential: Any = None) -> Any:
    """An `ApiClient` from the kubeconfig, impersonating `credential`'s approver when given one.

    A `None` credential gives the ambient identity. That is only ever reached by a read
    (`writers.k8s_configmap.read`) — every mutating path has already passed
    `require_actor_credential`, which refuses `None`.
    """
    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config

    k8s_config.load_kube_config()
    api = k8s_client.ApiClient()
    if credential is not None:
        from ..security.credentials import kubernetes_identity

        user, groups = kubernetes_identity(credential)
        api.set_default_header("Impersonate-User", user)
        # `set_default_header` keeps one value per header name, and Kubernetes reads repeated
        # `Impersonate-Group` headers for several groups — so this is correct for exactly one.
        [group] = groups
        api.set_default_header("Impersonate-Group", group)
    return api
