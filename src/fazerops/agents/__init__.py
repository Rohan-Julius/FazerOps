"""The three model-calling nodes (Handoff §2, plan §3.2a).

`orchestrator` (W19b) chooses scope and window over a manifest-bounded tool schema;
`correlator` (W18) writes the narrative and cites evidence; `proposer` (W22) selects an
`action_id` from the catalog and parameterizes it.

The four collectors are *not* here. They are deterministic `FunctionNode`s under
`collectors/` — real Strands graph nodes that make zero model calls (plan §3.2a).
"""
