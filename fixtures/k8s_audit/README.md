# Kubernetes audit fixtures — provenance

## Status: HAND-AUTHORED, awaiting replacement by W7b

**These payloads were written by hand on 6 Sep 2026. They were not captured from a running
cluster.** They are shaped from the documented `audit.k8s.io/v1` Event schema, but nothing
has yet verified that shape against what a real API server emits.

That is the whole reason **W7b** exists (plan §4, Sep 7): bring up k3d with the
`RequestResponse` audit policy, perform the demo's `kubectl edit`, and **replace this file
with the captured payloads**. Until then, `tests/collectors/test_k8s_audit.py` is asserting
against a schema that was inferred rather than observed — the collector could pass every
test and still fail on the first real audit entry.

Handoff §5 requires every collector to run in both live and fixture mode and says to build
fixture mode first. This is that first half, and it is not the finished article.

### What W7b changes, and what it deliberately keeps

- **Replaced:** `auditID` values, `resourceVersion`, `sourceIPs`, `userAgent`, and the
  exact field shapes — all of it comes from the real API server.
- **Kept:** the *narrative* timestamps. Captured events carry whatever wall-clock time the
  capture happened at; they are shifted onto the demo's window so the story holds
  (the ConfigMap edit lands 38 minutes before the alert, per Idea §7). **This shift is a
  deliberate, disclosed edit** — the shapes are real, the clock is staged. Anything else
  would mean re-recording the fixture every time the demo runs.
- **Never added back:** the `_fixture_note` keys this file used to carry. A real audit
  payload has no such field, and a fixture that carries keys the real source cannot produce
  is not a fixture — it is a mock wearing one. The notes now live below instead.

When W7b lands, replace this section with the capture date, the k3d version, and the
audit-policy path used.

## The six events, and why each is here

The scenario is Idea.md §7: an engineer edits a ConfigMap by hand at 14:03; the alert fires
at 14:41; the correlation window is `[10:41, 14:41)`.

| # | Time (UTC) | Event | Why it is in the fixture |
|---|---|---|---|
| `3f2a1c88` | 09:12:04 | `update` ConfigMap `billing-api-config`, `pool.max: 100` | **Prior-state anchor, and it is deliberately outside the window.** An audit entry for an `update` carries only the *new* object, so `before` has to be reconstructed from the object's previous entry. Proves the collector indexes prior state before it filters by window — if it filtered first, the diff would be empty. |
| `9c14e7b2` | 11:30:02 | `update` Secret `billing-api-db` by `system:serviceaccount:ci:deployer` | Two jobs. Exercises **secret redaction** (the base64 value must never reach a brief, a prompt or the markdown record), and exercises **`in_band`** — this one arrived through the pipeline, which is reported to the user and never scored (Handoff §3). |
| `b7d0e441` | 12:47:33 | `patch` ConfigMap `auth-service-config` by `priya@` | A genuine competing candidate, one hop out through `depends_on`. It has no earlier entry in the log, so it also proves the collector **declines to claim reversibility** when no prior value exists. |
| `e50c33a7` | 13:55:10 | `update` Deployment `billing-api` by `kube-system:generic-garbage-collector` | **Control-plane noise that must be excluded.** kube-system mutates constantly; left in, it dominates every brief. Excluded by principal, not by heuristics on the object. |
| `1a9f4d20` | 14:03:11 | `update` ConfigMap `billing-api-config`, `pool.max: 100 → 20`, by `dinesh@` | **The causal event.** No PR, no pipeline, no deploy event — invisible to GitHub, which Idea §7 calls "the entire pitch". 38 minutes before the alert. |
| `cc0b8f19` | 14:20:47 | `get` ConfigMap `billing-api-config` by `dinesh@` | **A read, and the most tempting one to leak through** — it touches the very object the demo is about. A ledger that records reads is a log, not a change ledger. |

Two of the six must be excluded and one must fall outside the window, so a correct
collector returns **three** events. A collector that returned four, five or six would still
look plausible in the brief, which is why the count is asserted.
