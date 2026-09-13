"""The one executor for every writer-backed action. W41, `docs/catalog_self_extension.md` §3.

**The gate runs here, before any writer code is reached** — which is how a writer inherits the
credential guarantee without anyone remembering to write it in. This file sits in
`executors/`, so `test_every_executor_calls_the_gate` reads its AST like every other
executor's, and `test_writer_registry.py` additionally asserts the gate call precedes the call
into the writer.

The same four things are true before this runs as for `configmap.py`: parameters validated,
inverse computed, preconditions met, and a human's approval minted the credential.
"""

from __future__ import annotations

from typing import Any

from ...security.credentials import require_actor_credential

__all__ = ["execute"]


def execute(
    request: Any,
    *,
    credential: Any = None,
    undo: Any = None,
    catalog: Any = None,
    client: Any = None,
) -> dict[str, Any]:
    """Write the recorded prior values back through the action's writer.

    Takes the request rather than its parameters because the target lives on the hint: it is
    the value a collector observed, never one a model supplied.
    """
    from ..writers.registry import recorded_values

    values = recorded_values(request, request.spec(catalog))
    if values is None:
        raise ValueError(
            f"{request.action_id}: no recorded values fit this action, so there is nothing "
            "known to restore; refusing (ground rule #4)"
        )
    writer = values.writer

    # Before the writer, always. The writer is the component that may one day be generated.
    require_actor_credential(
        credential,
        action_id=request.action_id,
        namespace=str(request.params[writer.scope_field]),
    )

    result = writer.write(dict(request.params), values.prior, credential=credential, client=client)
    return {
        "action_id": request.action_id,
        "writer": writer.id,
        "authored_by": writer.authored_by,
        "result": result,
        "inverse": None if undo is None else {"action_id": undo.action_id, "params": undo.params},
    }
