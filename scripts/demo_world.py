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

**The `binaryData` story is the one rung 3 acts on.** The same ConfigMap's second map holds the
token signing key. No human-written writer restores a `binaryData` map, so the one-shot the server
offers is written by the model, and the growth job's pull request adds a new catalog action over a
generated writer rather than widening an existing one:

    binary-setup                 a baseline signing key, so the audit log holds the map before any edit
    binary-change --actor NAME   priya or arun rotates the signing key by hand
    binary-fix                   dinesh puts the remembered key back by hand
    binary-story                 all of the above, twice

**The `billing` story is the video's case 1** (Idea §7): `dinesh@` lowers `billing-api-config`'s
`pool.max` from 100 to 20 by hand, and the shipped catalog's `revert_configmap_key` restores it.

    billing-setup                RBAC so dinesh can edit billing-api-config
    billing-change               dinesh sets pool.max to 20 (the prior value is remembered)
    billing-fix                  dinesh puts the remembered value back (a reset, not part of the story)

`alert --story auth|binary|billing` sends each story's own alert.
"""

from __future__ import annotations

import argparse
import base64
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


BINARY_KEY = "signing.jwk"
BINARY_BASELINE = b'{"kid":"auth-2026-09-01","alg":"ES256"}'
BINARY_EDITS = {
    "priya": b'{"kid":"auth-2026-09-14-priya","alg":"ES256"}',
    "arun": b'{"kid":"auth-2026-09-14-arun","alg":"ES256"}',
}


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def current_binary() -> dict[str, str]:
    return json.loads(kubectl("-n", NAMESPACE, "get", "configmap", CONFIGMAP, "-o", "jsonpath={.binaryData}") or "{}")


def binary_setup(state: Path = STATE) -> None:
    setup(state)
    # Written by the admin, before anyone's edit: the collector can only record what a key rotation
    # replaced if an earlier audit entry already carried the binary map.
    if current_binary().get(BINARY_KEY) != _b64(BINARY_BASELINE):
        kubectl("-n", NAMESPACE, "patch", "configmap", CONFIGMAP, "--type", "merge", "-p", json.dumps({"binaryData": {BINARY_KEY: _b64(BINARY_BASELINE)}}))


def binary_change(actor: str, state: Path = STATE) -> dict[str, str]:
    edit = {BINARY_KEY: _b64(BINARY_EDITS[actor])}
    before = current_binary()
    if before.get(BINARY_KEY) == edit[BINARY_KEY]:
        raise SystemExit(f"{CONFIGMAP} already holds {actor}'s signing key; run `binary-fix` first")
    if BINARY_KEY not in before:
        raise SystemExit(f"{CONFIGMAP} has no {BINARY_KEY} to rotate; run `binary-setup` first")
    (state / "prior_binary.json").write_text(json.dumps({BINARY_KEY: before[BINARY_KEY]}), encoding="utf-8")
    principal(actor, state).kubectl("-n", NAMESPACE, "patch", "configmap", CONFIGMAP, "--type", "merge", "-p", json.dumps({"binaryData": edit}))
    return edit


def binary_fix(state: Path = STATE) -> dict[str, str]:
    prior = json.loads((state / "prior_binary.json").read_text(encoding="utf-8"))
    principal("dinesh", state).kubectl("-n", NAMESPACE, "patch", "configmap", CONFIGMAP, "--type", "merge", "-p", json.dumps({"binaryData": prior}))
    return prior


def binary_story(server: str, *, pause: float) -> None:
    binary_setup()
    for actor in ("priya", "arun"):
        print(f"{PEOPLE[actor]} rotates the signing key in {CONFIGMAP} out of band: {binary_change(actor)}")
        time.sleep(3)
        print(f"alert → {alert(server, story='binary')}")
        time.sleep(pause)
        print(f"{PEOPLE['dinesh']} puts the signing key back by hand: {binary_fix()}")
        time.sleep(3)
    print("\nTwo incidents, two actors, two hand fixes of a binary map. The growth job's next cycle authors a writer.")


BILLING_NAMESPACE = "billing"
BILLING_CONFIGMAP = "billing-api-config"
POOL_KEY, POOL_EDIT = "pool.max", "20"


def billing_setup(state: Path = STATE) -> None:
    role = "fazerops-demo-configmap-editor"
    kubectl("apply", "-f", "-", stdin=json.dumps({
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": role, "namespace": BILLING_NAMESPACE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "patch"]}],
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": "fazerops-demo-dinesh", "namespace": BILLING_NAMESPACE},
                "roleRef": {"kind": "Role", "name": role, "apiGroup": "rbac.authorization.k8s.io"},
                "subjects": [{"kind": "User", "name": PEOPLE["dinesh"], "apiGroup": "rbac.authorization.k8s.io"}],
            },
        ],
    }))
    principal("dinesh", state)


def _pool_max() -> str:
    return kubectl("-n", BILLING_NAMESPACE, "get", "configmap", BILLING_CONFIGMAP, "-o", f"jsonpath={{.data.{POOL_KEY.replace('.', chr(92) + '.')}}}")


def _set_pool_max(value: str, state: Path) -> None:
    principal("dinesh", state).kubectl(
        "-n", BILLING_NAMESPACE, "patch", "configmap", BILLING_CONFIGMAP, "--type", "merge", "-p", json.dumps({"data": {POOL_KEY: value}})
    )


def billing_change(state: Path = STATE) -> dict[str, str]:
    before = _pool_max()
    if before == POOL_EDIT:
        raise SystemExit(f"{BILLING_CONFIGMAP} already holds {POOL_KEY}={POOL_EDIT}; run `billing-fix` first")
    (state / "prior_billing.json").write_text(json.dumps({POOL_KEY: before}), encoding="utf-8")
    _set_pool_max(POOL_EDIT, state)
    return {POOL_KEY: POOL_EDIT}


def billing_fix(state: Path = STATE) -> dict[str, str]:
    prior = json.loads((state / "prior_billing.json").read_text(encoding="utf-8"))
    _set_pool_max(prior[POOL_KEY], state)
    return prior


# One alert per story. The binary story's is about token signatures, not session length: the alert
# is on screen, and it should describe what a rotated signing key actually breaks.
ALERTS = {
    "auth": (SERVICE, NAMESPACE, "AuthServiceLoginErrors", "auth-service login error rate above threshold; sessions expiring early"),
    "binary": (SERVICE, NAMESPACE, "AuthServiceTokenSignatureFailures", "auth-service rejecting logins: token signature verification failing"),
    "billing": ("billing-api", BILLING_NAMESPACE, "BillingApiLatencyHigh", "billing-api p99 latency above threshold; error rate climbing"),
}


def alert_payload(fired_at: datetime | None = None, story: str = "auth") -> dict:
    fired_at = fired_at or datetime.now(timezone.utc)
    service, namespace, name, summary = ALERTS[story]
    return {
        "receiver": "fazerops",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": name, "service": service, "severity": "critical", "namespace": namespace},
                "annotations": {"summary": summary},
                "startsAt": fired_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "fingerprint": secrets.token_hex(8),
            }
        ],
    }


def alert(server: str, story: str = "auth") -> dict:
    request = urllib.request.Request(
        f"{server.rstrip('/')}/alerts", data=json.dumps(alert_payload(story=story)).encode("utf-8"), headers={"Content-Type": "application/json"}
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
    alert_parser = sub.add_parser("alert")
    alert_parser.add_argument("--story", choices=sorted(ALERTS), default="auth")
    sub.add_parser("fix")
    sub.add_parser("billing-setup")
    sub.add_parser("billing-change")
    sub.add_parser("billing-fix")
    story_parser = sub.add_parser("story")
    story_parser.add_argument("--pause", type=float, default=20.0, help="seconds between an alert and the hand fix")
    sub.add_parser("binary-setup")
    binary_change_parser = sub.add_parser("binary-change")
    binary_change_parser.add_argument("--actor", choices=sorted(BINARY_EDITS), required=True)
    sub.add_parser("binary-fix")
    binary_story_parser = sub.add_parser("binary-story")
    binary_story_parser.add_argument("--pause", type=float, default=20.0, help="seconds between an alert and the hand fix")
    args = parser.parse_args(argv)

    if args.command == "setup":
        setup()
    elif args.command == "change":
        print(change(args.actor))
    elif args.command == "alert":
        print(json.dumps(alert(args.server, story=args.story), indent=2))
    elif args.command == "billing-setup":
        billing_setup()
    elif args.command == "billing-change":
        print(billing_change())
    elif args.command == "billing-fix":
        print(billing_fix())
    elif args.command == "fix":
        print(fix())
    elif args.command == "binary-setup":
        binary_setup()
    elif args.command == "binary-change":
        print(binary_change(args.actor))
    elif args.command == "binary-fix":
        print(binary_fix())
    elif args.command == "binary-story":
        binary_story(args.server, pause=args.pause)
    else:
        story(args.server, pause=args.pause)
    return 0


if __name__ == "__main__":
    sys.exit(main())
