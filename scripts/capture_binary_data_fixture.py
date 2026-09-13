#!/usr/bin/env python3
"""Capture a real ConfigMap `binaryData` update from the k3d API server's audit log.

    ./scripts/setup_k3d.sh && .venv/bin/python scripts/capture_binary_data_fixture.py

W42's second writer contract is a ConfigMap's `binaryData`, and the collector's diff of it is
tested against what Kubernetes actually wrote rather than a shape this repo inferred — the
lesson `fixtures/cloudtrail/` taught when Lambda turned out to version its event names.

It creates a ConfigMap carrying a binary map in a fresh namespace, patches one binary key, copies
the two resulting audit entries — untouched — into `tests/fixtures/k8s_audit_binary_data.json`,
and deletes the namespace. Outside `fixtures/` on purpose: the demo's collectors read every file
there, and this change belongs to no incident. Nothing but the local k3d cluster is touched.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

CONTEXT = "k3d-fazerops"
AUDIT_LOG = REPO_ROOT / ".k3d" / "audit" / "audit.log"
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "k8s_audit_binary_data.json"

BEFORE = base64.b64encode(b"\x00\x00\x01\x00 favicon, before").decode()
AFTER = base64.b64encode(b"\x00\x00\x01\x00 favicon, after").decode()


def main() -> int:
    from kubernetes import client, config

    config.load_kube_config(context=CONTEXT)
    core = client.CoreV1Api()
    namespace = f"fazerops-capture-{secrets.token_hex(4)}"
    name = "billing-api-assets"

    with AUDIT_LOG.open("r", encoding="utf-8") as log:
        log.seek(0, os.SEEK_END)
        core.create_namespace({"metadata": {"name": namespace}})
        try:
            core.create_namespaced_config_map(
                namespace,
                {"metadata": {"name": name}, "data": {"cache.ttl": "300"}, "binaryData": {"favicon.ico": BEFORE}},
            )
            core.patch_namespaced_config_map(name, namespace, {"binaryData": {"favicon.ico": AFTER}})

            wanted: dict[str, dict] = {}
            pending = ""
            deadline = time.monotonic() + 30
            while len(wanted) < 2 and time.monotonic() < deadline:
                lines = (pending + log.read()).split("\n")
                pending = lines.pop()
                for line in lines:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    ref = entry.get("objectRef") or {}
                    if (
                        entry.get("stage") == "ResponseComplete"
                        and ref.get("namespace") == namespace
                        and ref.get("name") == name
                        and entry.get("verb") in ("create", "patch")
                    ):
                        wanted[entry["verb"]] = entry
                time.sleep(0.2)
        finally:
            core.delete_namespace(namespace, propagation_policy="Background")

    if set(wanted) != {"create", "patch"}:
        print(f"captured {sorted(wanted)}; expected create and patch", file=sys.stderr)
        return 1

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps([wanted["create"], wanted["patch"]], indent=2) + "\n", encoding="utf-8")
    print(f"wrote {FIXTURE.relative_to(REPO_ROOT)} ({namespace}, deleted)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
