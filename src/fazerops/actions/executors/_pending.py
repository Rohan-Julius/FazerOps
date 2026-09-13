"""The boundary between a catalog entry that is *declared* and one that *executes*.

Plan §4 forbids declared-but-unimplemented catalog entries because an entry with no
executor is a live path to an `ImportError` mid-demo. That rule is about the **import**:
every `executor:` in `config/actions.yaml` resolves to a real callable, checked at catalog
load time by `catalog.resolve_executor`.

**Nothing raises this any more.** All three Handoff §7 executors are written —
`configmap` (W24), `helm` (W20b) and `rds` (W20c), the last two on 12 Sep — so the catalog
carries no declared-but-unimplemented entry on any axis: every `executor:` resolves *and*
every one of them executes.

It is kept rather than deleted because it is the thing that made the staging honest. While
a body was unwritten it raised this, by name, with its work unit in the message —
deliberately loud and deliberately *not* an ImportError: the failure was visible in a test,
attributable to a known unit, and reached only after the inverse had been computed and the
dry run rendered, so everything ground rule #4 promises was exercised regardless. A fourth
action arriving later should use it the same way rather than inventing a quieter marker.

`tests/unit/test_catalog_schema.py` asserts the resolvability. `tests/security/test_credential_gate.py`
reads the AST of every executor in this package and requires each written body to call
`require_actor_credential`; it skips any still raising `pending`, and **that skip list is
now empty**, so all three executors are covered by it rather than two.
"""

from __future__ import annotations


class ExecutorNotYetImplemented(NotImplementedError):
    """Raised by an executor whose mutating body is scheduled but not yet written."""


def pending(action_id: str, unit: str) -> ExecutorNotYetImplemented:
    return ExecutorNotYetImplemented(
        f"{action_id}: the executor is declared and resolvable, but its mutating body is "
        f"scheduled as {unit} and has not been written. The inverse and dry-run paths are "
        f"complete and tested."
    )
