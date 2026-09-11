# Recorded model responses

One JSON file per agent, mapping a request key → the response a real model returned.
`FAZEROPS_LLM=cassette` replays these so agent behaviour can be asserted in CI with **no
credentials and no network**.

## Provenance

**`correlator.json` was recorded on 11 Sep 2026 from `gemini-3.5-flash-lite`**, via
`scripts/record_cassettes.py` against the demo fixture alert. Re-record with:

```bash
.venv/bin/python scripts/record_cassettes.py      # needs GEMINI_API_KEY in .env
```

Inference runs on Gemini rather than Bedrock because Bedrock is blocked account-wide —
plan §9.2 carries the deviation and the named reversal. **When Bedrock access lands, set
`ACTIVE_PATH = LlmMode.DEMO` in `agents/llm.py` and re-record**, or the demo replays Gemini
tape while the repo claims a Bedrock path.

### Why recording mattered, immediately

The first real recording earned this file's existence. Gemini cited
`7c1f9a2e4b6d8033` — the **alert id** — as evidence for its causal claim, and W18's
validator dropped the claim. The validator was right; the *prompt* was wrong.
`render_alert_for_llm` had been wrapping the alert block with `event_id="..."`, which told
the model the alert was a citable event. Removing that attribute fixed it, and
`tests/security/test_envelope.py::test_the_alert_envelope_carries_no_event_id` is the
regression guard.

**No amount of hand-authored cassettes would have found that.** It is the same lesson
`fixtures/cloudtrail/` taught when recording real events revealed that Lambda versions its
CloudTrail event names (`UpdateFunctionConfiguration20150331v2`) — a hand-written fixture
would have passed every test and dropped every Lambda change in production.

Hand-constructed responses remain the right tool for the **adversarial** cases in
`tests/agents/test_correlator_contract.py`: no real model emits a fabricated event id on
demand, so that fabrication has to be authored. They are the wrong tool for judging whether
the validator's rules match what a model actually produces. Both kinds are needed.

## Keys

The filename is the agent. The key inside is a SHA-256 prefix over `{agent, model,
messages, params}` — see `src/fazerops/agents/cassette.py`. **A prompt change invalidates
every key for that agent**, by design: a cassette layer that tolerated drift would let the
citation validator be tested against a response the current prompt can no longer produce.
When a replay misses, re-record; do not hand-edit a key.

**Prune orphans on re-record.** A changed prompt strands its old key permanently, and they
accumulate silently until the file is unreviewable.
`test_recorded_cassette.py::test_the_cassette_holds_no_orphaned_keys` enforces one live
recording per agent.

## Not a cache

These are committed test fixtures. `.fazerops/` is the gitignored runtime directory (the
token ledger lives there); this directory is tracked and reviewed.
