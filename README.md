# FaberOps

**The change ledger for everything that didn't go through CI — and an agent that reads it when the page fires.**

Submission for the **AWS Agents for Humans** hackathon (Professional Agents track).

---

## The problem

When a production alert fires at 3am, the on-call engineer's first question is not *"what's broken"* — the alert says that. It's **"what changed?"**

Answering it means hand-querying CloudTrail, the Kubernetes audit log, Helm release history and recent merges, then reconstructing a timeline across five tools with different clocks and different notions of identity.

Incident-management tools coordinate the incident. Where they track change at all, they source it from GitHub and CI/CD — which makes them structurally blind to `kubectl edit`, console IAM edits, Helm rollouts outside the pipeline, parameter-group changes and Terraform applied from a laptop. Those are precisely the changes nobody canaries and nobody rolls back automatically.

FaberOps normalizes in-band and out-of-band mutations into a single **change ledger**, then runs an agent over it at alert time to answer *"what changed in this blast radius, and which change most plausibly caused this?"* — with evidence, diffs, and a reversible action attached.

## Status

**Under active development.** See [`PLAN_FABEROPS.md`](PLAN_FABEROPS.md) for scope, schedule and cut priorities.

## Quickstart

```bash
uv sync
./scripts/run_demo.sh
```

Requires no AWS credentials and no network — the default path runs entirely on fixtures.

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
- **A product brief and an earlier exploratory prototype predate the submission period.** Neither is included here. The product rationale in [`docs/Idea.md`](docs/Idea.md) and the technical spec in [`docs/Handoff.md`](docs/Handoff.md) derive from that prior thinking; they are design documents, not code.
- No other pre-existing code, template or scaffold was used beyond publicly available open-source dependencies declared in `pyproject.toml`.

## License

MIT — see [`LICENSE`](LICENSE).
