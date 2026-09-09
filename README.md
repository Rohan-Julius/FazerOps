# FazerOps

**The change ledger for everything that didn't go through CI — and an agent that reads it when the page fires.**

Submission for the **AWS Agents for Humans** hackathon (Professional Agents track).

---

## The problem

When a production alert fires at 3am, the on-call engineer's first question is not *"what's broken"* — the alert says that. It's **"what changed?"**

Answering it means hand-querying CloudTrail, the Kubernetes audit log, Helm release history and recent merges, then reconstructing a timeline across five tools with different clocks and different notions of identity.

Incident-management tools coordinate the incident. Where they track change at all, they source it from GitHub and CI/CD — which makes them structurally blind to `kubectl edit`, console IAM edits, Helm rollouts outside the pipeline, parameter-group changes and Terraform applied from a laptop. Those are precisely the changes nobody canaries and nobody rolls back automatically.

FazerOps normalizes in-band and out-of-band mutations into a single **change ledger**, then runs an agent over it at alert time to answer *"what changed in this blast radius, and which change most plausibly caused this?"* — with evidence, diffs, and a reversible action attached.

## Status

**Under active development.** Built for the AWS Agents for Humans hackathon.

## Quickstart

```bash
uv sync
./scripts/run_demo.sh
```

Requires no AWS credentials and no network — the default path runs entirely on fixtures.

### Running against a real cluster

```bash
./scripts/setup_k3d.sh          # k3d + audit policy + the demo workload
pytest -m cluster               # the cluster-backed tests
```

`setup_k3d.sh` creates the cluster with `RequestResponse` auditing for ConfigMaps and
Secrets, which is what makes the demo's before/after diff a real object body rather than
an assertion. The fixtures under `fixtures/k8s_audit/` are recordings from this cluster,
not hand-authored payloads — `scripts/capture_audit_fixture.py` regenerates them.

## Stated limitations

Named here rather than half-built. Each is a deliberate boundary, and none of them is
hidden behind a partially working feature.

- **Blast radius comes from a checked-in manifest**, `config/service_manifest.yaml` — not
  from dependency auto-discovery. Discovery is a multi-month problem, and a half-working
  discovery layer reads as a broken feature. Resolution is the named service plus one hop
  through `depends_on`; two hops explodes the candidate set.
- **The priors table is hand-authored.** `config/priors.yaml` is operational judgement
  written down where it can be argued with, not something learned from incident data —
  there is no incident corpus behind this product. The file says so, and the levels are
  stated as `high`/`medium`/`low` so nobody mistakes a decimal for a measurement.
- **CloudTrail is read through `lookup_events`, not an S3 trail.** That API does not return
  the prior value of what changed, so a CloudTrail-sourced change shows the requested value
  labelled *"new value; prior value not captured"* rather than a reconstructed before/after.
  Kubernetes-sourced changes do carry a real diff, because the audit log records both
  bodies.
- **The default demo runs on fixtures.** Every fixture under `fixtures/` is a recording
  from the real source — a live Kubernetes API server, a real Helm release — with only the
  timestamps shifted onto the demo's narrative window; each directory's README states
  exactly what was edited. Live mode runs the same normalizers against the same code path.
- **The Kubernetes audit log is not exposed through the Kubernetes API.** The API server
  writes it to disk on the control-plane node, or ships it to a webhook. Live mode reads
  that file, which `setup_k3d.sh` bind-mounts onto the host. A production cluster ships the
  same JSON to a log sink and the collector would read it from there — a swap of one
  method, not a redesign.
- **There is no post-execution verification.** Nothing re-reads state to confirm that an
  approved remediation took effect; the human observes the recovery. This is a gap in the
  specification rather than an oversight, and it is disclosed rather than papered over.
- **The premise was not validated with pilot teams during the submission period.** The
  claim that out-of-band change is a dominant source of incidents rests on prior research
  and on the authors' experience, not on interviews conducted for this build. There was no
  pilot access, so no amount of schedule would have closed it.

## Safety

Four properties enforced structurally rather than by convention:

1. **The model never emits a command string.** It selects an `action_id` from a typed catalog and supplies validated parameters.
2. **Alert and log text is data, never instruction.** It enters model context inside an untrusted-data envelope.
3. **Read and write are different principals.** The actor credential is minted only after approval, scoped to one namespace, with a short TTL.
4. **Every mutating action computes its inverse before executing** and refuses to run if it cannot.

**Nothing in this system is unattended.** Tier 0 is autonomous but strictly read-only. Every mutation waits for a human approval — "auto-remediation" here means *proposed, dry-run, inverse-computed, executed on approval*.

## Prior-work disclosure

Per the hackathon's new-projects rule, stated plainly:

- **All code in this repository was written during the submission period** (opened 10 August 2026). The first commit in this repo is the start of the work.
- **A product brief and an earlier exploratory prototype predate the submission period.** Neither is included here. The product rationale and the technical specification this repository is built to derive from that prior thinking; they are design documents, not code, and they are not part of the submission.
- No other pre-existing code, template or scaffold was used beyond publicly available open-source dependencies declared in `pyproject.toml`.

## License

MIT — see [`LICENSE`](LICENSE).
