#!/usr/bin/env python3
"""W7b — regenerate `fixtures/k8s_audit/billing_window.json` from a real cluster.

Until this runs, the K8s collector is tested against a schema this repo *inferred* rather
than one Kubernetes produced: it could pass every test and still fail on the first real
audit entry. So the six demo events are performed against the W7 cluster by the principals
the story names, and the API server's own output becomes the fixture.

**Shapes are real; the clock is staged.** Captured events carry whatever wall-clock time
the capture happened at, so the audit-level timestamps are shifted onto the demo's window
(Idea §7: the ConfigMap edit lands 38 minutes before the alert). That shift is the *only*
edit made to a captured payload — see `_shift_onto_the_demo_window` for what is
deliberately left alone and why.

Getting `dinesh@faber-demo.io` rather than `system:admin` into the log needs a real
authenticating identity, so the script mints short-lived client certificates through the
cluster's own CSR API. They live in a temp directory for the duration of the run. Nothing
here touches anything but the local k3d cluster.

    ./scripts/setup_k3d.sh && .venv/bin/python scripts/capture_audit_fixture.py
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLUSTER = "fazerops"
CONTEXT = f"k3d-{CLUSTER}"
AUDIT_LOG = REPO_ROOT / ".k3d" / "audit" / "audit.log"
FIXTURE = REPO_ROOT / "fixtures" / "k8s_audit" / "billing_window.json"

DINESH = "dinesh@faber-demo.io"
PRIYA = "priya@faber-demo.io"

# Idea §7. The alert fires at 14:41; the correlation window is [10:41, 14:41). These are
# the narrative times the captured entries are shifted onto — the anchor deliberately
# outside the window, the causal edit 38 minutes before the page.
NARRATIVE_TIMES = {
    "anchor": datetime(2026, 9, 6, 9, 12, 4, tzinfo=timezone.utc),
    "secret": datetime(2026, 9, 6, 11, 30, 2, tzinfo=timezone.utc),
    "auth": datetime(2026, 9, 6, 12, 47, 33, tzinfo=timezone.utc),
    "deployment": datetime(2026, 9, 6, 13, 55, 10, tzinfo=timezone.utc),
    "causal": datetime(2026, 9, 6, 14, 3, 11, tzinfo=timezone.utc),
    "read": datetime(2026, 9, 6, 14, 20, 47, tzinfo=timezone.utc),
}

# The rotated Secret value. It is allowlisted in `.gitleaks.toml` precisely because it is
# supposed to look like a credential: the fixture's job is to prove the collector redacts
# secret material before it can reach a Slack message or a model prompt.
ROTATED_SECRET_B64 = base64.b64encode(b"supersecret-rotated").decode()


def run(cmd: list[str], stdin: str | None = None, check: bool = True) -> str:
    result = subprocess.run(cmd, input=stdin, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise SystemExit(f"failed: {' '.join(cmd[:4])}...\n{result.stderr.strip()}")
    return result.stdout


def kubectl(*args: str, stdin: str | None = None, check: bool = True) -> str:
    return run(["kubectl", "--context", CONTEXT, *args], stdin=stdin, check=check)


class Principal:
    """kubectl connection flags for one authenticated identity.

    Built as explicit --server/--certificate-authority flags rather than by editing the
    user's kubeconfig: this script must not leave anything behind in ~/.kube/config.

    The empty --kubeconfig is load-bearing. Without it kubectl still merges the default
    config and its admin `client-cert-data` silently overrides the flags — every captured
    entry would then read `system:admin` and the fixture would attribute the demo's causal
    edit to the cluster administrator.
    """

    def __init__(self, name: str, auth_flags: list[str], server: str, ca_file: Path,
                 kubeconfig: Path):
        self.name = name
        self._base = ["kubectl", f"--kubeconfig={kubeconfig}", f"--server={server}",
                      f"--certificate-authority={ca_file}", *auth_flags]

    def kubectl(self, *args: str, stdin: str | None = None) -> str:
        return run([*self._base, *args], stdin=stdin)


def cluster_endpoint(workdir: Path) -> tuple[str, Path, Path]:
    server = kubectl("config", "view", "--raw", "--minify", "-o",
                     "jsonpath={.clusters[0].cluster.server}").strip()
    ca_b64 = kubectl("config", "view", "--raw", "--minify", "-o",
                     "jsonpath={.clusters[0].cluster.certificate-authority-data}").strip()
    ca_file = workdir / "ca.crt"
    ca_file.write_bytes(base64.b64decode(ca_b64))

    empty = workdir / "empty.kubeconfig"
    empty.write_text("apiVersion: v1\nkind: Config\n", encoding="utf-8")
    return server, ca_file, empty


def mint_client_certificate(username: str, workdir: Path, server: str, ca_file: Path,
                            kubeconfig: Path) -> Principal:
    """Issue a 24h client certificate for `username` through the cluster's CSR API.

    A human principal in an audit log is an X.509 common name. Impersonation (`--as`) would
    have been easier, but it records the *impersonator* as `user.username` and the target
    only in `impersonatedUser` — so the fixture would carry `system:admin` and the collector
    would have to be taught about a field it does not need. Capture convenience is not a
    reason to change product code (plan §0).
    """
    slug = username.split("@")[0]
    key = workdir / f"{slug}.key"
    csr = workdir / f"{slug}.csr"
    crt = workdir / f"{slug}.crt"

    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={username}"])

    csr_name = f"fazerops-capture-{slug}"
    kubectl("delete", "csr", csr_name, "--ignore-not-found")
    kubectl("apply", "-f", "-", stdin=json.dumps({
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": {"name": csr_name},
        "spec": {
            "request": base64.b64encode(csr.read_bytes()).decode(),
            "signerName": "kubernetes.io/kube-apiserver-client",
            "expirationSeconds": 86400,
            "usages": ["client auth"],
        },
    }))
    kubectl("certificate", "approve", csr_name)

    for _ in range(20):
        issued = kubectl("get", "csr", csr_name, "-o",
                         "jsonpath={.status.certificate}").strip()
        if issued:
            crt.write_bytes(base64.b64decode(issued))
            kubectl("delete", "csr", csr_name, "--ignore-not-found")
            return Principal(username, [f"--client-certificate={crt}", f"--client-key={key}"],
                             server, ca_file, kubeconfig)
        time.sleep(0.5)
    raise SystemExit(f"the CSR for {username} was approved but never signed")


def service_account_principal(namespace: str, name: str, server: str, ca_file: Path,
                              kubeconfig: Path) -> Principal:
    token = kubectl("create", "token", name, "-n", namespace, "--duration=30m").strip()
    return Principal(f"system:serviceaccount:{namespace}:{name}", [f"--token={token}"],
                     server, ca_file, kubeconfig)


def grant_rbac() -> None:
    """The narrative's principals need exactly the rights the narrative uses, and no more.

    `generic-garbage-collector` is not granted anything: it is a real controller identity
    that already holds cluster-wide patch rights, which is the whole reason it is the demo's
    control-plane noise.
    """
    kubectl("apply", "-f", "-", stdin=json.dumps({
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "ci"}},
            {"apiVersion": "v1", "kind": "ServiceAccount",
             "metadata": {"name": "deployer", "namespace": "ci"}},
            _role("billing", "fazerops-capture-configmap-editor", "configmaps",
                  ["get", "list", "update", "patch"]),
            _binding("billing", "fazerops-capture-dinesh", "fazerops-capture-configmap-editor",
                     {"kind": "User", "name": DINESH, "apiGroup": "rbac.authorization.k8s.io"}),
            _role("billing", "fazerops-capture-secret-rotator", "secrets",
                  ["get", "update", "patch"]),
            _binding("billing", "fazerops-capture-deployer", "fazerops-capture-secret-rotator",
                     {"kind": "ServiceAccount", "name": "deployer", "namespace": "ci"}),
            _role("auth", "fazerops-capture-configmap-editor", "configmaps",
                  ["get", "patch"]),
            _binding("auth", "fazerops-capture-priya", "fazerops-capture-configmap-editor",
                     {"kind": "User", "name": PRIYA, "apiGroup": "rbac.authorization.k8s.io"}),
        ],
    }))


def _role(namespace: str, name: str, resource: str, verbs: list[str]) -> dict:
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": name, "namespace": namespace},
        "rules": [{"apiGroups": [""], "resources": [resource], "verbs": verbs}],
    }


def _binding(namespace: str, name: str, role: str, subject: dict) -> dict:
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": name, "namespace": namespace},
        "roleRef": {"kind": "Role", "name": role, "apiGroup": "rbac.authorization.k8s.io"},
        "subjects": [subject],
    }


def perform_the_scenario(dinesh: Principal, priya: Principal,
                         deployer: Principal, collector: Principal) -> None:
    """Idea §7's six events, in order, each by the principal who performs it in the story.

    `replace` rather than `apply` for the ConfigMap edits: it is a PUT, so the audit entry
    carries verb `update` and a clean object body with no client-side apply annotation.
    """
    def configmap(pool_max: str) -> str:
        return json.dumps({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "billing-api-config", "namespace": "billing"},
            "data": {"pool.max": pool_max, "pool.min": "5", "timeout": "30s"},
        })

    # 1. The prior-state anchor. Its only job is to give the causal edit a `before`.
    dinesh.kubectl("replace", "-f", "-", stdin=configmap("100"))
    time.sleep(0.4)

    # 2. An in-band change: it arrived through the pipeline. Reported, never scored.
    deployer.kubectl("replace", "-f", "-", stdin=json.dumps({
        "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
        "metadata": {"name": "billing-api-db", "namespace": "billing"},
        "data": {"password": ROTATED_SECRET_B64},
    }))
    time.sleep(0.4)

    # 3. The competing candidate, one hop out through `depends_on`.
    priya.kubectl("patch", "configmap", "auth-service-config", "-n", "auth",
                  "--type", "merge", "-p", json.dumps({"data": {"session.ttl": "7200"}}))
    time.sleep(0.4)

    # 4. Control-plane noise, excluded by principal rather than by heuristics.
    collector.kubectl("patch", "deployment", "billing-api", "-n", "billing",
                      "--type", "merge", "-p", json.dumps(
                          {"metadata": {"annotations": {"fazerops.dev/capture": "w7b"}}}))
    time.sleep(0.4)

    # 5. The causal event: pool.max 100 -> 20, by hand, no PR, no pipeline.
    dinesh.kubectl("replace", "-f", "-", stdin=configmap("20"))
    time.sleep(0.4)

    # 6. A read of the very object the demo is about — the most tempting one to leak into
    #    a change ledger.
    dinesh.kubectl("get", "configmap", "billing-api-config", "-n", "billing", "-o", "json")


def select_the_six(entries: list[dict]) -> dict[str, dict]:
    """Pick the scenario's six entries out of everything the cluster logged meanwhile.

    Matched on (verb, resource, name, principal) rather than on position, because the
    cluster is logging its own traffic throughout and the six are interleaved with it.
    """
    wanted = [
        ("anchor", "update", "configmaps", "billing-api-config", DINESH),
        ("secret", "update", "secrets", "billing-api-db", "system:serviceaccount:ci:deployer"),
        ("auth", "patch", "configmaps", "auth-service-config", PRIYA),
        ("deployment", "patch", "deployments", "billing-api",
         "system:serviceaccount:kube-system:generic-garbage-collector"),
        ("causal", "update", "configmaps", "billing-api-config", DINESH),
        ("read", "get", "configmaps", "billing-api-config", DINESH),
    ]

    remaining = [e for e in entries if e.get("stage") == "ResponseComplete"]
    picked: dict[str, dict] = {}
    for key, verb, resource, name, user in wanted:
        for index, entry in enumerate(remaining):
            ref = entry.get("objectRef") or {}
            if (entry.get("verb") == verb and ref.get("resource") == resource
                    and ref.get("name") == name
                    and (entry.get("user") or {}).get("username") == user):
                picked[key] = entry
                # Consume it and everything before it, so `causal` cannot match the entry
                # `anchor` already took — the two are identical apart from one value.
                remaining = remaining[index + 1:]
                break
        else:
            raise SystemExit(f"no captured entry for '{key}' ({user} {verb} {name})")
    return picked


def _shift_onto_the_demo_window(entry: dict, narrative: datetime) -> dict:
    """Move an entry's audit-level timestamps onto the demo's clock.

    Only `requestReceivedTimestamp`, `stageTimestamp` and `responseCompleteTimestamp` move,
    all by the same delta, so the entry's own internal durations survive.

    What is deliberately *not* touched: `creationTimestamp`, `managedFields[].time` and
    `resourceVersion` inside the object bodies. They carry the real capture clock, which
    means an object can appear to have been created after an event that mutates it. That
    artifact is the honest cost of staging the clock, and it is disclosed in the fixture's
    README — rewriting those fields would mean inventing values the API server never
    emitted, which is exactly what this unit exists to stop doing.
    """
    received = _parse(entry["requestReceivedTimestamp"])
    delta = narrative - received.replace(microsecond=0)

    shifted = dict(entry)
    for field in ("requestReceivedTimestamp", "stageTimestamp", "responseCompleteTimestamp"):
        if field in shifted:
            shifted[field] = _format(_parse(shifted[field]) + delta)
    return shifted


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _format(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def read_entries(since_byte: int) -> list[dict]:
    entries = []
    with AUDIT_LOG.open(encoding="utf-8") as handle:
        handle.seek(since_byte)
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # a partially flushed final line, not corruption
    return entries


def main() -> int:
    if not AUDIT_LOG.exists():
        raise SystemExit(f"no audit log at {AUDIT_LOG} — run scripts/setup_k3d.sh first")

    with tempfile.TemporaryDirectory(prefix="fazerops-capture-") as tmp:
        workdir = Path(tmp)
        server, ca_file, kubeconfig = cluster_endpoint(workdir)

        grant_rbac()
        dinesh = mint_client_certificate(DINESH, workdir, server, ca_file, kubeconfig)
        priya = mint_client_certificate(PRIYA, workdir, server, ca_file, kubeconfig)
        deployer = service_account_principal("ci", "deployer", server, ca_file, kubeconfig)
        collector = service_account_principal("kube-system", "generic-garbage-collector",
                                              server, ca_file, kubeconfig)

        # Everything already in the log is somebody else's traffic.
        offset = AUDIT_LOG.stat().st_size
        perform_the_scenario(dinesh, priya, deployer, collector)

        # The API server buffers audit writes; the last entry is not on disk the instant
        # kubectl returns.
        for _ in range(20):
            try:
                picked = select_the_six(read_entries(offset))
                break
            except SystemExit:
                time.sleep(0.5)
        else:
            picked = select_the_six(read_entries(offset))  # raise with the real message

    ordered = [_shift_onto_the_demo_window(picked[key], NARRATIVE_TIMES[key])
               for key in NARRATIVE_TIMES]
    FIXTURE.write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {FIXTURE.relative_to(REPO_ROOT)} — {len(ordered)} captured entries")
    for key, entry in zip(NARRATIVE_TIMES, ordered):
        ref = entry["objectRef"]
        bodies = "+".join(f for f in ("requestObject", "responseObject") if f in entry) or "metadata only"
        print(f"  {entry['requestReceivedTimestamp']}  {key:<11} "
              f"{entry['verb']:<7} {ref['resource']}/{ref['name']:<20} {bodies}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
