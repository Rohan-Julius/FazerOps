"""`helm_rollback` — Handoff §7, Tier 1. W20b's executor.

Roll a release back to an earlier revision. Handoff §5 notes revision N−1 gives the inverse
for free: rolling back to the revision deployed right now restores exactly what this action
replaces, which is why ground rule #4 costs nothing here.

The same four things are true before `helm` is invoked, and none of them is checked in this
module — they are checked upstream by code that cannot be skipped:

1. the parameters matched the catalog schema (`catalog.validate_params`, at proposal time);
2. the inverse was computed and is not `None` (`ActionRequest.execute`, ground rule #4);
3. `target_revision_exists` was satisfied **from collected evidence**, not by asking Helm
   (`preconditions.py`) — a precondition that calls the cluster cannot be evaluated during
   the outage it exists for;
4. a human approved it, and the approval minted the credential this function demands.

**`helm rollback` is invoked with an explicit revision, never with a bare release name.**
`helm rollback <release>` with no revision rolls back one step from wherever the release
happens to be *now* — which is not necessarily where it was when the dry run was rendered.
The revision is computed upstream and passed through, so the action that executes is the
action a human read.

`--wait` is deliberately **not** passed. It blocks until every resource reports ready, and
a rollback during an incident is frequently rolling back *to* a state whose pods are still
coming up; the operator is watching, and a command that hangs for five minutes on camera
reads as a failure. The post-rollback `helm status` below reports the revision Helm
actually landed on, which is the fact worth having.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

from ...security.credentials import require_actor_credential

__all__ = ["rollback"]

HELM_BIN = "helm"
# Longer than the collector's 20s: `helm history` reads a secret, a rollback re-applies a
# manifest and runs hooks. Still bounded — an unbounded call is one that hangs the demo.
HELM_TIMEOUT_SECONDS = 120


def rollback(
    params: dict[str, Any],
    *,
    credential: Any = None,
    undo: Any = None,
    runner: Any = None,
) -> dict[str, Any]:
    """Roll `release` back to `target_revision`.

    `undo` arrives already computed — `ActionRequest.execute()` refuses to call this at all
    when the inverse is `None`. It is carried into the result rather than used, because the
    thing that needs the inverse is the incident record and the operator reading it.

    `runner` is injectable so the unit tests exercise this function's real argument
    construction without a cluster, and so the e2e test can capture the exact command. When
    it is `None`, `subprocess.run` is used — after the credential check.
    """
    release = params["release"]
    namespace = params["namespace"]
    target_revision = params["target_revision"]

    # Before the binary, always. A credential failure must not be reachable only after
    # `helm` has already been handed a cluster and an ambient kubeconfig identity.
    require_actor_credential(credential, action_id="helm_rollback", namespace=namespace)

    runner = runner if runner is not None else _run

    runner(
        [
            HELM_BIN,
            "rollback",
            release,
            # `str` because a revision is an int everywhere else in this build and argv is
            # not. An int reaching subprocess is a TypeError mid-mutation, which is the
            # worst possible moment for one.
            str(target_revision),
            "--namespace",
            namespace,
        ]
    )

    landed = _revision_after(runner, release=release, namespace=namespace)

    return {
        "action_id": "helm_rollback",
        "release": release,
        "namespace": namespace,
        "requested_revision": target_revision,
        # Helm creates a *new* revision that restores the target's manifest, so the release
        # does not report `target_revision` after a rollback — it reports N+1. Naming the
        # two separately keeps the record honest; conflating them would make the incident
        # record claim the release is sitting on a revision it is not.
        "revision": landed,
        "inverse": None if undo is None else {"action_id": undo.action_id, "params": undo.params},
    }


def _revision_after(runner: Any, *, release: str, namespace: str) -> int | None:
    """The revision Helm landed on, or `None` if it cannot be read.

    `None` rather than a raise: the mutation has already happened by this point, and
    failing here would report a successful rollback as an error and invite a retry of
    something that already ran.
    """
    try:
        status = runner(
            [HELM_BIN, "status", release, "--namespace", namespace, "-o", "json"]
        )
        return json.loads(status or "{}").get("version")
    except Exception:
        return None


def _run(argv: list[str]) -> str:
    from ...config import require_offline_capable

    require_offline_capable("helm_rollback")

    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=HELM_TIMEOUT_SECONDS, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:3])} failed: {result.stderr.strip()}")
    return result.stdout
