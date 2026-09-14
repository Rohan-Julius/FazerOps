"""W42 rung 3 — a writer authored by a model, and every gate between it and the catalog.

`docs/catalog_self_extension.md` §2a, §3, §7.7. Plan §9.2's ground-rule-#1 deviation lives here.

The model writes the bodies of exactly two functions. Before anything else happens they pass
three checks, each closing a different way generated code could do more than it declares:

1. **An AST allowlist** (`validate_sources`). Not a denylist: every node type, every name, every
   call and every attribute must be one this module names. No imports, no dunder or private
   attributes, no loops that can hang, and exactly one call on the client in each function — to
   the one method `writers/k8s_support.py` names for that kind. `client` may appear only as the
   receiver of that call, so it cannot be aliased, stored or passed on.
2. **A fixed template** (`render_module` / `validate_module`). Everything outside `read` and
   `write` — the imports, the resource mapping, the client construction, the `WriterSpec` with
   `authored_by="agent"` — is our text. CI re-renders it from the two functions on every
   agent-authored commit and rejects any difference, so a later commit cannot widen the module.
3. **A probe in a separate interpreter** (`probe`), `-I -S`, an empty environment, a ten-second
   timeout and only the allowlisted builtins, calling the functions against a fake client:
   `read` must return the data map, and `write` must issue exactly one patch to the named
   resource carrying exactly the values given, and return none of them.

**What this does not prove.** The probe is behaviour against a fake, and it sees only the probe's
own parameters: a writer honest in the probe's namespace and lying everywhere else passes it
(`tests/security/test_injection_miner.py` holds one). The allowlist is a property of the source,
not a sandbox for arbitrary code. What catches the rest is W43's containment run against a real
API server (`sandbox.py`), and at execution the relay below, which pins every client call to the
declared resource. Beyond those, what stands between generated code and production is what stands
in front of every action: a human-written dry run and inverse, a namespace-scoped credential
checked before the writer runs, and an approval every time.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict

from .generate import (
    CatalogCandidate,
    GenerationResult,
    RungOutcome,
    RungReason,
    WIDENINGS,
    Widening,
    candidate_id_for,
    cited,
    generate,
    writer_action_id,
    writer_entry,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..catalog import Catalog
    from ..writers.registry import WriterRegistry
    from .miner import Gap, MinerThresholds
    from .signals import GapSignalStore

__all__ = [
    "GENERATED_PACKAGE",
    "ProbeResult",
    "SAFE_BUILTINS",
    "SAFE_METHODS",
    "author_candidate",
    "module_path_for",
    "probe",
    "render_module",
    "validate_module",
    "validate_sources",
]

GENERATED_PACKAGE = "src/fazerops/actions/writers/generated"
MAX_FUNCTION_CHARS = 4000

SAFE_BUILTINS = frozenset({"dict", "list", "sorted", "str", "len", "isinstance", "set", "tuple", "bool", "int"})
SAFE_METHODS = frozenset({"get", "items", "keys", "values"})

_SIGNATURES = {
    "read": (("params",), ("client",)),
    "write": (("params", "values"), ("credential", "client")),
}

_ALLOWED_NODES: tuple[type[ast.AST], ...] = (
    ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Return, ast.Assign, ast.Expr,
    ast.If, ast.For, ast.Name, ast.Load, ast.Store, ast.Attribute, ast.Call, ast.keyword,
    ast.Constant, ast.Dict, ast.List, ast.Tuple, ast.Set, ast.DictComp, ast.ListComp,
    ast.SetComp, ast.comprehension, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not,
    ast.Compare, ast.Eq, ast.NotEq, ast.Is, ast.IsNot, ast.In, ast.NotIn, ast.IfExp,
    ast.Subscript, ast.JoinedStr, ast.FormattedValue,
)


# --------------------------------------------------------------------------------------
# 1 — the allowlist
# --------------------------------------------------------------------------------------


def validate_sources(kind: str, read_source: str, write_source: str, *, field: str = "data") -> list[str]:
    """Every reason the two functions are not acceptable. Empty means accepted."""
    from ..writers.k8s_support import has_contract, methods_for

    if not has_contract(kind, field):
        return [f"no writer contract exists for {kind!r}" + ("" if field == "data" else f" field {field!r}")]
    read_method, write_method = methods_for(kind, field)
    return [
        *_validate_function("read", read_source, allowed_method=read_method),
        *_validate_function("write", write_source, allowed_method=write_method),
    ]


def _validate_function(name: str, source: str, *, allowed_method: str) -> list[str]:
    if not isinstance(source, str) or len(source) > MAX_FUNCTION_CHARS:
        return [f"{name}: source is missing or longer than {MAX_FUNCTION_CHARS} characters"]
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"{name}: does not parse ({exc.msg})"]

    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        return [f"{name}: must be exactly one plain function definition"]
    function = tree.body[0]
    problems: list[str] = []

    if function.name != name:
        problems.append(f"{name}: defines {function.name!r}")
    if function.decorator_list or function.returns is not None:
        problems.append(f"{name}: decorators and annotations are not allowed")

    positional, keyword_only = _SIGNATURES[name]
    args = function.args
    if (
        args.posonlyargs
        or args.vararg
        or args.kwarg
        or args.defaults
        or any(default is not None for default in args.kw_defaults)
        or tuple(a.arg for a in args.args) != positional
        or tuple(a.arg for a in args.kwonlyargs) != keyword_only
        or any(a.annotation is not None for a in (*args.args, *args.kwonlyargs))
    ):
        signature = f"({', '.join(positional)}, *, {', '.join(keyword_only)})"
        problems.append(f"{name}: signature must be exactly {name}{signature}")

    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    bound = {*positional, *keyword_only} | {
        node.id for node in ast.walk(function) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }
    client_calls = 0

    for node in ast.walk(function):
        if not isinstance(node, _ALLOWED_NODES):
            problems.append(f"{name}: {type(node).__name__} is not allowed")
            continue

        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            problems.append(f"{name}: attribute {node.attr!r} is not allowed")

        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id == "credential":
                problems.append(f"{name}: `credential` must not be used; it is checked before a writer runs")
            elif node.id == "client":
                attribute, call = parents.get(node), parents.get(parents.get(node))
                if not (
                    isinstance(attribute, ast.Attribute)
                    and isinstance(call, ast.Call)
                    and call.func is attribute
                ):
                    problems.append(f"{name}: `client` may only be the receiver of one method call")
            elif node.id not in bound and node.id not in SAFE_BUILTINS:
                problems.append(f"{name}: name {node.id!r} is not allowed")

        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id in {"client", "credential", *SAFE_BUILTINS}:
            problems.append(f"{name}: may not rebind {node.id!r}")

        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id not in SAFE_BUILTINS:
                    problems.append(f"{name}: may not call {func.id!r}")
            elif isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name) and func.value.id == "client":
                    client_calls += 1
                    if func.attr != allowed_method:
                        problems.append(f"{name}: may call only client.{allowed_method}, not client.{func.attr}")
                elif func.attr not in SAFE_METHODS:
                    problems.append(f"{name}: may not call method {func.attr!r}")
            else:
                problems.append(f"{name}: only direct calls are allowed")
            if any(isinstance(arg, ast.Starred) for arg in node.args) or any(k.arg is None for k in node.keywords):
                problems.append(f"{name}: argument unpacking is not allowed")

    if client_calls != 1:
        problems.append(f"{name}: must call client.{allowed_method} exactly once, found {client_calls}")
    return sorted(set(problems))


# --------------------------------------------------------------------------------------
# 2 — the template
# --------------------------------------------------------------------------------------

_TEMPLATE = '''\
"""A generated writer (W42 rung 3). Only `read` and `write` were authored by a model; the rest is
fixed template text that CI re-renders and compares on every agent-authored commit."""
# Generated by FazerOps catalog growth from {candidate_id}; authored by {model}.
# Inert until a reviewer adds this module to writers.registry.WRITER_MODULES.

from __future__ import annotations

from ..k8s_support import api_for, namespaced_params, namespaced_resource
from ..registry import WriterSpec

KIND = {kind!r}
FIELD = {field!r}


{read_source}

{write_source}

def _read(params, *, client=None):
    return read(params, client=client if client is not None else api_for(KIND))


def _write(params, values, *, credential=None, client=None):
    return write(
        params, values, credential=credential, client=client if client is not None else api_for(KIND, credential)
    )


WRITER = WriterSpec(
    resource_type="k8s/" + KIND,
    field_path=FIELD,
    source="k8s_audit",
    kind=KIND,
    ref_params=("namespace", "name"),
    scope_field="namespace",
    resource=namespaced_resource(KIND),
    params_for=namespaced_params(KIND),
    read=_read,
    write=_write,
    authored_by="agent",
)
'''


def module_path_for(kind: str, field: str = "data") -> str:
    return f"{GENERATED_PACKAGE}/k8s_{kind.lower()}_{field.lower()}.py"


def render_module(
    kind: str, read_source: str, write_source: str, *, candidate_id: str, model: str, field: str = "data"
) -> str:
    return _TEMPLATE.format(
        candidate_id=candidate_id,
        model=model,
        kind=kind,
        field=field,
        read_source=read_source.strip("\n") + "\n",
        write_source=write_source.strip("\n") + "\n",
    )


def validate_module(source: str) -> list[str]:
    """A generated module is acceptable only if it is the template around two allowlisted
    functions. Compared on the AST, so comments (the provenance lines) may differ and nothing
    else may."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"module does not parse ({exc.msg})"]

    def constants(name: str) -> list[str]:
        return [
            node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ]

    kinds, fields = constants("KIND"), constants("FIELD")
    functions = {
        node.name: ast.get_source_segment(source, node)
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in {"read", "write"}
    }
    if len(kinds) != 1 or len(fields) != 1 or set(functions) != {"read", "write"}:
        return ["module must define exactly one KIND, one FIELD, one read and one write"]

    kind, field = kinds[0], fields[0]
    problems = validate_sources(kind, functions["read"] or "", functions["write"] or "", field=field)
    if problems:
        return problems

    expected = render_module(kind, functions["read"], functions["write"], candidate_id="-", model="-", field=field)
    if ast.dump(tree) != ast.dump(ast.parse(expected)):
        return ["module differs from the generated-writer template outside read and write"]
    return []


# --------------------------------------------------------------------------------------
# 3 — the probe
# --------------------------------------------------------------------------------------


class ProbeResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    problems: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return not self.problems


_HARNESS = r"""
import builtins, json, sys

spec = json.loads(sys.stdin.read())
calls = []

class Obj:
    def __init__(self, **fields):
        self.__dict__.update(fields)

def pick(args, kwargs, names):
    bound = dict(zip(names, args))
    bound.update(kwargs)
    return [bound.get(n) for n in names]

def read_method(*args, **kwargs):
    name, namespace = pick(args, kwargs, ("name", "namespace"))
    calls.append(["read", name, namespace])
    return Obj(**{spec["read_attribute"]: dict(spec["existing"])}, metadata=Obj(resource_version="41"))

def write_method(*args, **kwargs):
    name, namespace, body = pick(args, kwargs, ("name", "namespace", "body"))
    calls.append(["patch", name, namespace, body])
    return Obj(data={}, metadata=Obj(resource_version="42"))

client = Obj()
setattr(client, spec["read_method"], read_method)
setattr(client, spec["write_method"], write_method)


namespace = {"__builtins__": {name: getattr(builtins, name) for name in spec["builtins"]}}
exec(spec["read_source"], namespace)
exec(spec["write_source"], namespace)

read_result = namespace["read"](spec["params"], client=client)
write_result = namespace["write"](spec["params"], dict(spec["values"]), credential=None, client=client)
print(json.dumps({"read": read_result, "write": write_result, "calls": calls}, default=str))
"""

_PROBE_PARAMS = {"namespace": "probe-ns", "name": "probe-resource"}
_PROBE_EXISTING = {"probe.alpha": "OLD-VALUE-SENTINEL", "probe.untouched": "KEEP-SENTINEL"}
_PROBE_VALUES = {"probe.alpha": "RESTORED-VALUE-SENTINEL", "probe.removed": None}


def probe(
    kind: str, read_source: str, write_source: str, *, field: str = "data", timeout: float = 10.0
) -> ProbeResult:
    """Run the two functions once each, in a separate interpreter, against a fake client."""
    from ..writers.k8s_support import contract_for, methods_for

    contract = contract_for(kind, field)
    read_method, write_method = methods_for(kind, field)
    payload = json.dumps(
        {
            "read_source": read_source,
            "write_source": write_source,
            "read_method": read_method,
            "write_method": write_method,
            "read_attribute": contract.attribute,
            "builtins": sorted(SAFE_BUILTINS),
            "params": _PROBE_PARAMS,
            "existing": _PROBE_EXISTING,
            "values": _PROBE_VALUES,
        }
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-c", _HARNESS],
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except subprocess.TimeoutExpired:
        return ProbeResult(problems=(f"probe timed out after {timeout:.0f}s",))

    if completed.returncode != 0:
        last = (completed.stderr.strip().splitlines() or ["no output"])[-1]
        return ProbeResult(problems=(f"probe raised: {last[:200]}",))

    try:
        observed = json.loads(completed.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return ProbeResult(problems=("probe produced no readable result",))

    problems: list[str] = []
    name, namespace = _PROBE_PARAMS["name"], _PROBE_PARAMS["namespace"]

    if observed["read"] != _PROBE_EXISTING:
        problems.append(f"read did not return the resource's {field} map unchanged")
    expected_calls = [["read", name, namespace], ["patch", name, namespace, {contract.body_field: _PROBE_VALUES}]]
    if observed["calls"] != expected_calls:
        problems.append(
            "the client was not called exactly once to read and once to patch the named resource "
            "with exactly the given values"
        )
    if not isinstance(observed["write"], dict):
        problems.append("write did not return a dict")
    leaked = [s for s in ("SENTINEL",) if s in json.dumps(observed["write"])]
    if leaked:
        problems.append("write returned a value; results must carry key names only")
    return ProbeResult(problems=tuple(problems))


# --------------------------------------------------------------------------------------
# Running a generated writer against a real client — W43's sandbox, W44's one-shot
# --------------------------------------------------------------------------------------


class GeneratedWriterFailed(RuntimeError):
    """A generated writer did not complete: refused, raised, hung, or asked for a call it may not make."""


_PROXY_HARNESS = r"""
import builtins, json, sys

spec = json.loads(sys.stdin.readline())

class Obj:
    def __init__(self, **fields):
        self.__dict__.update(fields)

def wrap(value):
    if isinstance(value, dict) and value.get("__obj__"):
        return Obj(**{key: wrap(item) for key, item in value["fields"].items()})
    return value

def relay(method, names):
    def invoke(*args, **kwargs):
        bound = dict(zip(names, args))
        bound.update(kwargs)
        sys.stdout.write(json.dumps({"call": method, "kwargs": bound}) + "\n")
        sys.stdout.flush()
        reply = json.loads(sys.stdin.readline())
        if "error" in reply:
            raise RuntimeError(reply["error"])
        return wrap(reply["result"])
    return invoke

client = Obj()
setattr(client, spec["read_method"], relay(spec["read_method"], ("name", "namespace")))
setattr(client, spec["write_method"], relay(spec["write_method"], ("name", "namespace", "body")))

namespace = {"__builtins__": {name: getattr(builtins, name) for name in spec["builtins"]}}
exec(spec["read_source"], namespace)
exec(spec["write_source"], namespace)
result = namespace["write"](spec["params"], dict(spec["values"]), credential=None, client=client)
sys.stdout.write(json.dumps({"done": result}, default=str) + "\n")
sys.stdout.flush()
"""


def run_generated_writer(
    kind: str,
    field: str,
    read_source: str,
    write_source: str,
    params: dict[str, Any],
    values: dict[str, Any],
    *,
    client: Any,
    pin: tuple[str, str] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Run a generated `write` in a separate interpreter, relaying its client calls through here.

    **The generated code never shares a process with a client or a credential.** It is handed a
    proxy whose two methods send each call to this function, which makes it with the real client
    and returns only the contract's map and a resource version. A call to any other method, or
    with any argument but the contract's, is refused without reaching the client.

    `pin` — `(namespace, name)` — additionally refuses a call aimed anywhere else. That is the
    execution-time guard a one-shot runs under (W44). W43's sandbox passes none, because there the
    point is to observe what the writer does, not to stop it.

    **Pinned, the write itself is fixed too, not only its target.** A writer can tell the probe's
    namespace and a sandbox's from production using nothing the allowlist refuses — a comparison
    on `params["namespace"]` — so being honest in both says nothing about what it does here. So a
    pinned run lets through exactly the call the probe demanded: one patch whose body is
    `{body_field: values}`, the values the human-written dry run showed the approver. A different
    body, a second patch, or no patch at all fails the run. What is left to a generated writer
    at execution is whether to raise, and a raise is a failed action, never a quiet one.
    """
    import select
    import time

    from ..writers.k8s_support import contract_for, methods_for

    problems = validate_sources(kind, read_source, write_source, field=field)
    if problems:
        raise GeneratedWriterFailed("refused by the allowlist: " + "; ".join(problems))

    contract = contract_for(kind, field)
    read_method, write_method = methods_for(kind, field)
    arguments = {read_method: {"name", "namespace"}, write_method: {"name", "namespace", "body"}}
    # Through the same JSON the harness receives `values` in, so a value compares as the writer
    # was handed it rather than as this process holds it.
    pinned_body = json.loads(json.dumps({contract.body_field: dict(values)}, default=str))
    patches = 0
    spec = {
        "read_source": read_source,
        "write_source": write_source,
        "read_method": read_method,
        "write_method": write_method,
        "builtins": sorted(SAFE_BUILTINS),
        "params": dict(params),
        "values": dict(values),
    }

    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", _PROXY_HARNESS],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    deadline = time.monotonic() + timeout

    def send(message: dict[str, Any]) -> None:
        assert process.stdin is not None
        process.stdin.write(json.dumps(message, default=str) + "\n")
        process.stdin.flush()

    try:
        send(spec)
        while True:
            remaining = deadline - time.monotonic()
            ready, _, _ = select.select([process.stdout], [], [], max(remaining, 0))
            if not ready:
                raise GeneratedWriterFailed(f"the writer did not finish within {timeout:.0f}s")
            line = process.stdout.readline()  # type: ignore[union-attr]
            if not line:
                process.wait(timeout=5)
                last = ((process.stderr.read() if process.stderr else "").strip().splitlines() or ["no output"])[-1]
                raise GeneratedWriterFailed(f"the writer raised: {last[:200]}")

            message = json.loads(line)
            if "done" in message:
                if pin is not None and patches != 1:
                    raise GeneratedWriterFailed(f"the writer patched the declared resource {patches} times, not once")
                return message["done"] if isinstance(message["done"], dict) else {"result": message["done"]}

            method, kwargs = message.get("call"), message.get("kwargs") or {}
            if method not in arguments or set(kwargs) != arguments[method]:
                send({"error": f"refused: {method!r} with {sorted(kwargs)} is not a contract call"})
                continue
            if pin is not None and (kwargs.get("namespace"), kwargs.get("name")) != pin:
                send({"error": "refused: the call is aimed outside the declared resource"})
                continue
            if pin is not None and method == write_method:
                # Refused rather than corrected: a writer that builds any other body is not the
                # writer the probe and the sandbox saw, and running it at all would be trusting it.
                if kwargs.get("body") != pinned_body:
                    send({"error": "refused: the patch body is not exactly the values given"})
                    continue
                if patches:
                    send({"error": "refused: the declared resource was already patched"})
                    continue
                patches += 1
            try:
                returned = getattr(client, method)(**kwargs)
            except Exception as exc:  # the API's answer, relayed; the writer decides what to do with it
                send({"error": f"{type(exc).__name__}: {getattr(exc, 'status', '')}".strip()})
                continue
            send({"result": _relayed(returned, contract.attribute)})
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()


def _relayed(returned: Any, attribute: str) -> dict[str, Any]:
    """The contract's map and a resource version — nothing else of the API object crosses back."""
    metadata = getattr(returned, "metadata", None)
    return {
        "__obj__": True,
        "fields": {
            attribute: dict(getattr(returned, attribute, None) or {}),
            "metadata": {"__obj__": True, "fields": {"resource_version": getattr(metadata, "resource_version", None)}},
        },
    }


def generated_writer_spec(kind: str, field: str, read_source: str, write_source: str) -> Any:
    """A `WriterSpec` whose `write` runs generated code through `run_generated_writer`, pinned
    to the resource its parameters name. For a one-shot (W44) — never registered process-wide."""
    from ..writers.k8s_support import api_for, namespaced_params, namespaced_resource
    from ..writers.registry import WriterSpec

    def refuse_read(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise GeneratedWriterFailed("a one-shot never reads through generated code")

    def write(params: dict[str, Any], values: dict[str, Any], *, credential: Any = None, client: Any = None) -> dict[str, Any]:
        return run_generated_writer(
            kind,
            field,
            read_source,
            write_source,
            dict(params),
            dict(values),
            # The approver's identity, so the audit log names who approved this one-shot (D3).
            client=client if client is not None else api_for(kind, credential),
            pin=(str(params["namespace"]), str(params["name"])),
        )

    return WriterSpec(
        resource_type=f"k8s/{kind}",
        field_path=field,
        source="k8s_audit",
        kind=kind,
        ref_params=("namespace", "name"),
        scope_field="namespace",
        resource=namespaced_resource(kind),
        params_for=namespaced_params(kind),
        read=refuse_read,
        write=write,
        authored_by="agent",
    )


def functions_of(module_source: str) -> tuple[str, str]:
    """The authored `read` and `write` out of a rendered module, as source."""
    tree = ast.parse(module_source)
    found = {
        node.name: ast.get_source_segment(module_source, node) or ""
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in {"read", "write"}
    }
    return found["read"], found["write"]


def verify_candidate_containment(
    candidate: CatalogCandidate, store: Any, ledger: Any, *, sandbox: Any | None = None
) -> Any:
    """§8's containment step for a rung-3 candidate, before its PR (W43).

    **Once per recorded change the corpus anchors on**, each against the resource that change
    touched and the blast-radius keys it was stamped with when it was recorded — so a writer is
    contained against every resource the evidence is about, not a representative one. Each
    sandbox is seeded with the values its change left and asked to restore the ones it replaced.
    The first run that is not contained is the verdict; otherwise the last, carrying the count.
    """
    from ...models import BlastRadius
    from ..writers.registry import hint_for, registry_override
    from .generate import evaluation_catalog, evaluation_registry
    from .sandbox import generated_subject, verify_containment

    kind, field = candidate.gap.resource_kind.value, candidate.gap.field_path.value
    read_source, write_source = functions_of(candidate.module_source or "")
    demonstrations = store.demonstrations(candidate.key)
    if not demonstrations:
        raise ValueError(f"{candidate.candidate_id}: no demonstration to take a declared reference from")

    evaluation = evaluation_catalog(candidate)
    registry = evaluation_registry(candidate)
    subject = generated_subject(kind, field, read_source, write_source)
    report = None
    runs = 0
    seen: set[str] = set()

    for demonstration in demonstrations:
        if demonstration.anchor_event_id in seen:
            continue
        seen.add(demonstration.anchor_event_id)
        anchor = ledger.get(demonstration.anchor_event_id)
        if anchor is None:
            raise ValueError(f"{candidate.candidate_id}: an anchor of the corpus is not in the ledger")
        with registry_override(registry):
            hint = hint_for(anchor, evaluation.get(candidate.action_id))
        if hint is None:
            raise ValueError(f"{candidate.candidate_id}: {anchor.id} carries no values this writer could restore")

        report = verify_containment(
            subject,
            declared=registry.get(candidate.writer).resource(hint["ref"]),
            radius=BlastRadius(service=demonstration.incident_id, keys=set(anchor.blast_radius_keys)),
            prior=hint["prior"],
            current=hint["current"],
            sandbox=sandbox,
        )
        runs += 1
        if not report.contained:
            break

    return report.model_copy(update={"runs": runs})


def accept_authored(kind: str, field: str, read_source: str, write_source: str) -> list[str]:
    """The allowlist, then the probe — every reason an authored writer is refused. Shared by
    rung 3 and the one-shot path (W44), so the two cannot gate generated code differently."""
    problems = validate_sources(kind, read_source, write_source, field=field)
    if not problems:
        problems = list(probe(kind, read_source, write_source, field=field).problems)
    return problems


# --------------------------------------------------------------------------------------
# Rung 3
# --------------------------------------------------------------------------------------


async def author_candidate(
    gap: Gap,
    store: GapSignalStore,
    *,
    catalog: Catalog | None = None,
    registry: WriterRegistry | None = None,
    thresholds: MinerThresholds | None = None,
    widenings: tuple[Widening, ...] = WIDENINGS,
    meter: Any | None = None,
    cassette_directory: Any | None = None,
) -> GenerationResult:
    """Generation with rung 3. Runs the deterministic rungs first and calls a model only when
    they end in `writer_authoring_required` — a cheaper rung always wins."""
    from ...agents.writer_author import author_writer
    from ..catalog import default_catalog
    from ..writers.k8s_support import writer_contract

    result = generate(gap, store, catalog=catalog, registry=registry, thresholds=thresholds, widenings=widenings)
    if result.candidate is not None or result.rungs[-1].reason is not RungReason.WRITER_AUTHORING_REQUIRED:
        return result

    catalog = catalog if catalog is not None else default_catalog()
    key = gap.key
    kind, field = key.resource_kind.value, key.field_path.value
    prior_rungs = result.rungs[:-1]

    if writer_action_id(key) in catalog:
        return GenerationResult(key=key, rungs=(*prior_rungs, RungOutcome(rung=3, reason=RungReason.ID_TAKEN)))

    authored = await author_writer(writer_contract(kind, field), meter=meter, cassette_directory=cassette_directory)

    problems = accept_authored(kind, field, authored.read_source, authored.write_source)
    if problems:
        return GenerationResult(
            key=key,
            rungs=(*prior_rungs, RungOutcome(rung=3, reason=RungReason.WRITER_REJECTED)),
            problems=tuple(problems),
        )

    candidate_id = candidate_id_for(key)
    writer_id = f"k8s/{kind}:{field}"
    rungs = (*prior_rungs, RungOutcome(rung=3, reason=RungReason.GENERATED))
    return GenerationResult(
        key=key,
        rungs=rungs,
        candidate=CatalogCandidate(
            candidate_id=candidate_id,
            gap=gap.aggregate,
            rung=3,
            writer=writer_id,
            entry=writer_entry(key, writer_id, ("namespace", "name")),
            cited_event_ids=cited(store, key),
            rungs=rungs,
            module_path=module_path_for(kind, field),
            module_source=render_module(
                kind,
                authored.read_source,
                authored.write_source,
                candidate_id=candidate_id,
                model=authored.model,
                field=field,
            ),
            authored_by_model=authored.model,
        ),
    )
