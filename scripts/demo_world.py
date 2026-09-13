#!/usr/bin/env python3
"""The demo's world: real people changing a real cluster, the alerts that follow, and the hands that fix things.

    ./scripts/setup_k3d.sh
    .venv/bin/python -m fazerops.actions.server          # FAZEROPS_MODE=live, FAZEROPS_SANDBOX_CONTEXT=k3d-fazerops
    .venv/bin/python scripts/demo_world.py story         # two incidents, two people, two hand fixes

FazerOps is told nothing here. Each change is made against the k3d API server by its own
authenticated identity — `priya@` and `arun@` with client certificates the cluster's CSR API signs,
`dinesh@` fixing things by hand — so the audit log attributes every change the way a production
cluster would. The only thing that reaches FazerOps is an Alertmanager payload.

**The story is the smallest one catalog growth acts on** (`docs/catalog_self_extension.md` §7.1):
two incidents, caused by two different people, each an out-of-band edit to two keys of
`auth-service-config` at once — a shape the shipped catalog's single-key revert cannot restore, so
the proposer declines — and each put back by hand. After the second fix, the growth job has a gap
seen across two incidents and two actors, with two human remediations to replay against, and
opens a pull request widening `revert_configmap_key` (W42 rung 1).

`auth-service-config`, not `billing-api-config`, because the cluster tests edit the latter, and a
recent single-key edit in the window would give the proposer something to propose instead.

    setup                 identities, RBAC, and a baseline audit entry for the ConfigMap
    change --actor NAME   priya or arun edits two keys (the prior values are remembered)
    alert                 an Alertmanager payload to the automation server
    fix                   dinesh puts the remembered values back by hand
    story                 all of the above, twice
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from capture_audit_fixture import Principal, cluster_endpoint, kubectl, mint_client_certificate  # noqa: E402

NAMESPACE = "auth"
CONFIGMAP = "auth-service-config"
SERVICE = "auth-service"
STATE = REPO_ROOT / ".fazerops" / "demo-world"

PEOPLE = {"priya": "priya@faber-demo.io", "arun": "arun@faber-demo.io", "dinesh": "dinesh@faber-demo.io"}

# Each out-of-band edit changes two keys at once: a new token issuer and a shorter session.
EDITS = {
    "priya": {"issuer": "auth-v2.faber-demo.internal", "session.ttl": "900"},
    "arun": {"issuer": "auth-v3.faber-demo.internal", "session.ttl": "600"},
}


def principal(name: str, state: Path = STATE) -> Principal:
    """A person's kubectl, with a certificate reused while it has hours left on it."""
    state.mkdir(parents=True, exist_ok=True)
    server, ca_file, empty = cluster_endpoint(state)
    certificate, key = state / f"{name}.crt", state / f"{name}.key"
    if certificate.exists() and time.time() - certificate.stat().st_mtime < 20 * 3600:
        return Principal(PEOPLE[name], [f"--client-certificate={certificate}", f"--client-key={key}"], server, ca_file, empty)
    return mint_client_certificate(PEOPLE[name], state, server, ca_file, empty)


def current_data() -> dict[str, str]:
    return json.loads(kubectl("-n", NAMESPACE, "get", "configmap", CONFIGMAP, "-o", "jsonpath={.data}") or "{}")


def setup(state: Path = STATE) -> None:
    exists = kubectl("-n", NAMESPACE, "get", "configmap", CONFIGMAP, "--ignore-not-found", "-o", "name").strip()
    if not exists:
        kubectl("apply", "-f", str(REPO_ROOT / "config" / "k8s" / "auth-service.yaml"))

    role = "fazerops-demo-configmap-editor"
    kubectl("apply", "-f", "-", stdin=json.dumps({
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": role, "namespace": NAMESPACE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "patch"]}],
            },
            *(
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                    "metadata": {"name": f"fazerops-demo-{name}", "namespace": NAMESPACE},
                    "roleRef": {"kind": "Role", "name": role, "apiGroup": "rbac.authorization.k8s.io"},
                    "subjects": [{"kind": "User", "name": username, "apiGroup": "rbac.authorization.k8s.io"}],
                }
                for name, username in PEOPLE.items()
            ),
        ],
    }))

    # A write that changes no data, so the audit log holds the ConfigMap's body before anyone's
    # edit: the collector can only show what an edit replaced if it saw the object earlier.
    kubectl("-n", NAMESPACE, "annotate", "--overwrite", "configmap", CONFIGMAP, f"fazerops.io/demo-baseline={int(time.time())}")
    for name in PEOPLE:
        principal(name, state)


def change(actor: str, state: Path = STATE) -> dict[str, str]:
    edit = EDITS[actor]
    before = current_data()
    if all(before.get(key) == value for key, value in edit.items()):
        raise SystemExit(f"{CONFIGMAP} already holds {actor}'s edit; run `fix` first")
    (state / "prior.json").write_text(json.dumps({key: before.get(key) for key in edit}), encoding="utf-8")
    principal(actor, state).kubectl("-n", NAMESPACE, "patch", "configmap", CONFIGMAP, "--type", "merge", "-p", json.dumps({"data": edit}))
    return edit


def fix(state: Path = STATE) -> dict[str, str]:
    prior = json.loads((state / "prior.json").read_text(encoding="utf-8"))
    principal("dinesh", state).kubectl("-n", NAMESPACE, "patch", "configmap", CONFIGMAP, "--type", "merge", "-p", json.dumps({"data": prior}))
    return prior


def alert_payload(fired_at: datetime | None = None) -> dict:
    fired_at = fired_at or datetime.now(timezone.utc)
    return {
        "receiver": "fazerops",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "AuthServiceLoginErrors", "service": SERVICE, "severity": "critical", "namespace": NAMESPACE},
                "annotations": {"summary": "auth-service login error rate above threshold; sessions expiring early"},
                "startsAt": fired_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "fingerprint": secrets.token_hex(8),
            }
        ],
    }


def alert(server: str) -> dict:
    request = urllib.request.Request(
        f"{server.rstrip('/')}/alerts", data=json.dumps(alert_payload()).encode("utf-8"), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.loads(response.read().decode("utf-8"))


def story(server: str, *, pause: float) -> None:
    setup()
    for actor in ("priya", "arun"):
        print(f"{PEOPLE[actor]} edits {CONFIGMAP} out of band: {change(actor)}")
        time.sleep(3)  # the audit log is written as the request is served; the alert follows the change
        print(f"alert → {alert(server)}")
        time.sleep(pause)
        print(f"{PEOPLE['dinesh']} puts it back by hand: {fix()}")
        time.sleep(3)
    print("\nTwo incidents, two actors, two hand fixes. The growth job's next cycle has a gap to propose.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="demo_world")
    parser.add_argument("--server", default="http://127.0.0.1:8081")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("setup")
    change_parser = sub.add_parser("change")
    change_parser.add_argument("--actor", choices=sorted(EDITS), required=True)
    sub.add_parser("alert")
    sub.add_parser("fix")
    story_parser = sub.add_parser("story")
    story_parser.add_argument("--pause", type=float, default=20.0, help="seconds between an alert and the hand fix")
    args = parser.parse_args(argv)

    if args.command == "setup":
        setup()
    elif args.command == "change":
        print(change(args.actor))
    elif args.command == "alert":
        print(json.dumps(alert(args.server), indent=2))
    elif args.command == "fix":
        print(fix())
    else:
        story(args.server, pause=args.pause)
    return 0


if __name__ == "__main__":
    sys.exit(main())
