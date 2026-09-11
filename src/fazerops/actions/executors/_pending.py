"""The boundary between a catalog entry that is *declared* and one that *executes*.

Plan §4 forbids declared-but-unimplemented catalog entries because an entry with no
executor is a live path to an `ImportError` mid-demo. That rule is about the **import**:
every `executor:` in `config/actions.yaml` resolves to a real callable, checked at catalog
load time by `catalog.resolve_executor`.

The mutating bodies land on their own scheduled days — W24 (`configmap`, Sep 11), W20b
(`helm`, Sep 12), W20c (`rds`, Sep 12). Until then each executor raises this, by name, with
its work unit in the message. That is deliberately loud and deliberately *not* an
ImportError: the failure is visible in a test, attributable to a known unit, and reached
only after the inverse has already been computed and the dry run already rendered — so
everything ground rule #4 promises is exercised regardless.

`tests/unit/test_catalog_schema.py` asserts the resolvability; it will assert executability
as each unit lands.
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
