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

The containment sandbox (catalog growth) runs only on the cluster `FAZEROPS_SANDBOX_CONTEXT`
names — locally, `k3d-fazerops` — and never falls back to the current context. It creates a
throwaway namespace per check and deletes it afterwards.

### Running the automation layer

```bash
python -m fazerops.actions.server         # alerts in, brief and approval cards to Slack, clicks back,
                                          # and the catalog-growth job hourly beside them
python -m fazerops.actions.growth mine --commit-to . --base main   # one cycle, committed to local branches
```

The quickstart's `main.py` stays read-only; the automation server is a separate process
because an approval card and the click that decides it must reach the same one. The growth job
commits signed bundles to local `catalog-growth/*` branches, made in a throwaway worktree so the
checkout is untouched, and checks each as CI will. It never pushes: opening the PR is yours.

`setup_k3d.sh` creates the cluster with `RequestResponse` auditing for ConfigMaps and
Secrets, which is what makes the demo's before/after diff a real object body rather than
an assertion. The fixtures under `fixtures/k8s_audit/` are recordings from this cluster,
not hand-authored payloads — `scripts/capture_audit_fixture.py` regenerates them.

### Running the agents against a live model

The quickstart, the test suite and cassette replay need **no model key**. A key matters only
for `FAZEROPS_LLM=gemini`, which calls a real model. Copy `.env.example` to `.env`, then:

| Variable | What to set |
|---|---|
| `GEMINI_API_KEY` | A Vertex AI express key or an AI Studio key |
| `FAZEROPS_GEMINI_BACKEND` | `vertex` (default) or `aistudio` — it must match the key |
| `FAZEROPS_GEMINI_MODEL_ORCHESTRATOR` / `_CORRELATOR` / `_PROPOSER` | Optional. Models your key can reach; empty uses the defaults (`gemini-3.8-flash`, `gemini-3.1-pro-preview`) |
| `FAZEROPS_GEMINI_THINKING` | Optional. `off`, `minimal`, `low` (default), `medium` or `high`; use `off` for models older than Gemini 3 |

```bash
uv sync --extra gemini
set -a && . ./.env && set +a         # nothing under src/ reads .env; export it first
FAZEROPS_LLM=gemini ./scripts/run_demo.sh
```

That demo run calls **only the orchestrator** live, to choose scope and window. The brief it
prints is ranked in Python either way (ground rule #3); the correlator and proposer are not
part of `run_demo.sh`.

A live run costs money on a paid key. The model and thinking overrides apply to live runs
only: cassette replay always uses the committed defaults, and the recording scripts refuse
to run with different ones.

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
- **The action catalog grows from production evidence, and a model can write code.**
  When the agent finds a cause the catalog cannot act on — a declined proposal, a rejected one,
  a change with no computable inverse — that fact is recorded as a typed signal with no free
  text in it. A gap seen across at least two incidents and two distinct actors becomes a local
  PR bundle, by the cheapest of three routes: widening an existing action's parameters (only
  widenings the hand-written code already supports), a declarative entry over a human-written
  writer, or — only when neither can express the gap — a writer whose `read` and `write`
  functions a model authored. Every route must agree, in dry run, with every fix a human
  actually made for that gap, and the gap is recounted from signals the ledger still vouches
  for, or nothing is written. Generated code passes a strict allowlist and a test against a
  fake client, and is then run in a throwaway Kubernetes namespace under an identity that can
  touch one resource type there, with the audit log watched: a writer that reaches for anything
  but its declared resource is rejected. It never computes its own inverse, dry run or
  credential check. Nothing generated sets its own approval tier or permissions; CI rejects
  agent-authored commits that try, or whose evidence the ledger's deployment did not sign, and
  a merged generated action needs a manager's approval every time until it has a clean record.
  The sandbox proves containment, not safety under production load, and only Kubernetes has one.
- **During an incident, a missing action can be built for that incident only.** When the
  proposer declines and the top-ranked change is a Kubernetes change no catalog action can
  revert, Python — never the model — builds a one-shot action from the recorded prior value,
  using a human-written writer if one exists and a model-authored one otherwise. It is run in
  the sandbox first and then shown to a manager as an approval card; it is never added to the
  catalog and executes at most once per incident, resource and field. Its generated code runs
  in a separate interpreter that can reach only the resource named on the card. **The manager
  approves a diff, not the code** — nobody reviews a one-shot's code before it runs. CloudTrail
  changes never get a one-shot: no prior value is recorded, and delivery is minutes late.
- **The premise was not validated with pilot teams during the submission period.** The
  claim that out-of-band change is a dominant source of incidents rests on prior research
  and on the authors' experience, not on interviews conducted for this build. There was no
  pilot access, so no amount of schedule would have closed it.

## Safety

Four properties enforced structurally rather than by convention:

1. **The model never emits a command string.** It selects an `action_id` from a typed catalog and supplies validated parameters. *One disclosed exception:* catalog growth can ask a model to write a writer's two functions — for a PR, or for a one-shot action during an incident. That code is allowlisted, template-bound and contained in a sandbox before anyone is asked; it runs in a separate interpreter pinned to one resource, only behind a human-written dry run, inverse and credential check, and only on a manager's approval. The model still never names an action.
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
