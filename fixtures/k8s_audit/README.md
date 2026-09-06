# Kubernetes audit fixtures — provenance

## Status: CAPTURED FROM A RUNNING CLUSTER (W7b, 6 Sep 2026)

**Every payload in `billing_window.json` was emitted by a real Kubernetes API server.**
Nothing here was hand-authored. Regenerate with:

```bash
./scripts/setup_k3d.sh
.venv/bin/python scripts/capture_audit_fixture.py
```

| | |
|---|---|
| Captured | 6 September 2026 |
| Cluster | k3d v5.9.0, k3s v1.35.5+k3s1 |
| Audit policy | `config/k8s/audit-policy.yaml` — `RequestResponse` for ConfigMaps and Secrets, `Metadata` elsewhere |
| Capture script | `scripts/capture_audit_fixture.py` |

Handoff §5 requires every collector to run in both live and fixture mode. Because these are
recordings rather than inventions, fixture mode replays genuine Kubernetes output — the
collector is tested against a schema the API server produced, not one this repo inferred.

The six events were performed by the principals the story names, each authenticating for
real: `dinesh@` and `priya@` hold client certificates issued through the cluster's own CSR
API, `ci:deployer` and `kube-system:generic-garbage-collector` use ServiceAccount tokens.
Impersonation (`kubectl --as`) was rejected deliberately — it records the impersonator in
`user.username` and the target only in `impersonatedUser`, so the fixture would have
attributed the demo's causal edit to `system:admin`.

### The one edit made to a captured payload, and the artifact it leaves

**The shapes are real; the clock is staged.** A capture carries whatever wall-clock time it
happened at, so `requestReceivedTimestamp`, `stageTimestamp` and `responseCompleteTimestamp`
are shifted onto the demo's window — all three by the same delta, so each entry's own
internal durations survive. Idea §7's narrative is what they are shifted onto: the alert
fires at 14:41, the window is `[10:41, 14:41)`, and the ConfigMap edit lands 38 minutes
before the page. Without the shift the fixture would need re-recording on every run.

**Nothing else is touched.** In particular `creationTimestamp`, `managedFields[].time` and
`resourceVersion` inside the object bodies still carry the real capture clock, which means
an object can appear to have been created *after* an event that mutates it. That artifact
is the honest cost of staging the clock and it is disclosed here rather than smoothed over:
rewriting those fields would mean inventing values the API server never emitted, which is
the exact failure mode W7b exists to end. Nothing in the collector reads them.

## The six events, and why each is here

| auditID | Time (UTC) | Level | Event | Why it is in the fixture |
|---|---|---|---|---|
| `1aa5e1ee` | 09:12:04 | `RequestResponse` | `update` ConfigMap `billing-api-config`, `pool.max: 100` | **Prior-state anchor, deliberately outside the window.** An audit entry for an `update` carries only the *new* object, so `before` must be reconstructed from the object's previous entry. Proves the collector indexes prior state before it filters by window — filtering first would leave the diff empty. |
| `017e86e7` | 11:30:02 | `RequestResponse` | `update` Secret `billing-api-db` by `system:serviceaccount:ci:deployer` | Two jobs. Exercises **secret redaction** (the base64 value must never reach a brief, a prompt or the markdown record), and exercises **`in_band`** — this one arrived through the pipeline, which is reported to the user and never scored (Handoff §3). |
| `b46cad11` | 12:47:33 | `RequestResponse` | `patch` ConfigMap `auth-service-config` by `priya@` | A genuine competing candidate, one hop out through `depends_on`. It has no earlier entry in the log, so it also proves the collector **declines to claim reversibility** when no prior value exists. |
| `a5f14c7f` | 13:55:10 | `Metadata` | `patch` Deployment `billing-api` by `kube-system:generic-garbage-collector` | **Control-plane noise that must be excluded.** kube-system mutates constantly; left in, it dominates every brief. Excluded by principal, not by heuristics on the object. Also the fixture's only `Metadata`-level entry, so the policy's second half is represented. |
| `3e2bdd8d` | 14:03:11 | `RequestResponse` | `update` ConfigMap `billing-api-config`, `pool.max: 100 → 20`, by `dinesh@` | **The causal event.** No PR, no pipeline, no deploy event — invisible to GitHub, which Idea §7 calls "the entire pitch". 38 minutes before the alert. |
| `66954ccf` | 14:20:47 | `RequestResponse` | `get` ConfigMap `billing-api-config` by `dinesh@` | **A read, and the most tempting one to leak through** — it touches the very object the demo is about, and under this policy it arrives carrying a full `responseObject`, so it could pollute prior state as well as the candidate list. A ledger that records reads is a log, not a change ledger. |

Two of the six must be excluded and one must fall outside the window, so a correct
collector returns **three** events. A collector that returned four, five or six would still
look plausible in the brief, which is why the count is asserted.

### What the real payloads changed

The hand-authored fixture had `auth-service-config`'s response body carry only the patched
key. A real API server returns the **whole object** in `responseObject` regardless of how
narrow the patch was — so with no prior entry to diff against, the collector reports every
field as "new value; prior value not captured". That is correct and correctly labelled, and
it is the kind of divergence that would otherwise have surfaced for the first time in live
mode, on camera.

### Why the audit policy does not filter

`config/k8s/audit-policy.yaml` records read verbs and kube-system principals rather than
dropping them. Both are excluded by `collectors/k8s_audit.py`, and this fixture is a
capture of that log — a policy that pre-filtered them would leave those filters with
nothing real to be tested against.
