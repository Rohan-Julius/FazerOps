# Helm fixtures — provenance

## Status: CAPTURED FROM A REAL RELEASE (W11, 7 Sep 2026)

`billing_api.json` is `helm history billing-api -n billing -o json`, run against the k3d
cluster after the chart in `charts/billing-api` was installed and upgraded twice. Nothing
here was hand-authored. Regenerate with:

```bash
./scripts/setup_k3d.sh
.venv/bin/python scripts/capture_helm_fixture.py
```

| | |
|---|---|
| Captured | 7 September 2026 |
| Chart | `charts/billing-api` 0.1.0 |
| Cluster | k3d v5.9.0, k3s v1.35.5+k3s1 |
| Capture script | `scripts/capture_helm_fixture.py` |

**One field is edited: `updated`.** Captured revisions carry the wall-clock time of the
capture run, so the timestamps are shifted onto the demo's narrative, exactly as
`fixtures/k8s_audit/` does. Every other field is Helm's verbatim — including the local
`+05:30` offset, which is kept deliberately: Helm reports the machine's offset rather than
UTC, and a fixture that only ever said `Z` would not test the format Helm actually emits.

**All three revisions sit before the correlation window opens at 10:41**, and that is the
story rather than an accident. billing-api ships through Helm; the last release was the
morning before the page; the change that broke it was a hand edit inside the window that
Helm never saw.

## The wrapper

`helm history` output does not name the release it describes — the release is context the
caller had. So each file is `{release, namespace, history: [...]}`, where `history` is
Helm's output unmodified. The collector flattens the wrapper in `_prepare`; the alternative
was rewriting Helm's payloads into a shape Helm never produces, which is the thing these
fixtures exist not to do.
