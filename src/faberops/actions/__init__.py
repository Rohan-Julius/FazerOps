"""The automation layer's action catalog (Handoff §7).

**The investigation layer imports nothing from this package** (plan §3.5). A `Brief` must
render to Slack, stdout or markdown with this entire package deleted, and
`tests/integration/test_layer_seam.py` asserts exactly that by blocking the import.

Ships all three Handoff §7 actions, each with a working executor — the catalog carries no
declared-but-unimplemented entries, because an entry without an executor is a live path to
an `ImportError` mid-demo.
"""
