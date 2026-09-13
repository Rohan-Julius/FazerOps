"""W41 — the writer registry and the generic revert substrate. `docs/catalog_self_extension.md` §3.

The artifact Phase G eventually generates is a **writer**, never an executor: `read` and
`write` for one field of one resource type. Everything an approver's decision rests on lives
somewhere else and is human-written:

* **the inverse** — `inverse.py`, built from the prior value a collector recorded;
* **the dry-run diff** — `dry_run.py`, rendered from the same recorded values;
* **the credential gate** — `executors/writer.py`, checked before any writer code is reached.

So `WriterSpec` has no field for either rendering, and it is a slotted frozen dataclass rather
than a Pydantic model: there is no attribute a writer can set — at construction, afterwards, or
through `model_validate` — to supply its own. A wrong inverse is an unrecoverable mutation and a
dry run that lies is an approval card that means nothing (plan §4 W41); neither may come from
the code most likely to be wrong.

**The generic hint.** A collector's hint carries one hand-written action's parameters. A
writer-backed action is keyed on the resource and the recorded values instead:

    {"action_id", "writer", "ref": {<ref params>}, "prior": {field: value}, "current": {...}}

The target of a revert is `prior`, observed in production — never a value a model supplied,
which is why a writer-backed action's parameters name its resource and nothing else.

**This is also rung 2's interpreter** (plan §4, W42): a declarative `actions.yaml` entry is a
`writer:` line over a writer registered here. Every writer registered today is
`authored_by="human"`. Nothing in W41 generates anything.
"""

from __future__ import annotations

import functools
import importlib
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from ...models import ChangeEvent, ChangeSource, ResourceRef

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..catalog import ActionSpec, Catalog
    from ..inverse import ActionRequest

__all__ = [
    "RecordedValues",
    "SUPPORTED_FIELD_PATHS",
    "UnknownWriter",
    "WRITER_MODULES",
    "WriterRegistry",
    "WriterSpec",
    "default_registry",
    "hint_for",
    "invert",
    "recorded_values",
    "registry_override",
    "request_for_event",
]

# Every module that defines a writer. Explicit rather than discovered by walking the package,
# so a file dropped into `writers/` does not become executable by existing — adding a writer
# is an edit to this line, and that edit is what a reviewer sees.
WRITER_MODULES: tuple[str, ...] = ("fazerops.actions.writers.k8s_configmap",)

# The field paths a collector records **both halves** of. A revert needs an observed prior
# value, and only the audit collector's ConfigMap maps have one (`growth.signals.FieldPath`).
SUPPORTED_FIELD_PATHS = frozenset({"data", "binaryData"})

_RESOURCE_TYPE = re.compile(r"^(k8s|aws|helm)/[A-Z][A-Za-z0-9]*$")


class UnknownWriter(KeyError):
    """A catalog entry or a hint named a writer nobody registered. There is no fallback."""


@dataclass(frozen=True, slots=True, kw_only=True)
class WriterSpec:
    """One field of one resource type, and the two functions that touch it.

    `resource` and `params_for` translate between a `ResourceRef` and the action's reference
    parameters. They are part of the writer because they are type-specific, and they are
    pure: neither may construct a client.
    """

    resource_type: str
    field_path: str
    source: ChangeSource
    kind: str
    ref_params: tuple[str, ...]
    scope_field: str
    resource: Callable[[Mapping[str, Any]], ResourceRef]
    params_for: Callable[[ResourceRef], dict[str, str] | None]
    read: Callable[..., dict[str, Any]]
    write: Callable[..., dict[str, Any]]
    authored_by: Literal["human", "agent"] = "human"

    def __post_init__(self) -> None:
        if not _RESOURCE_TYPE.match(self.resource_type):
            raise ValueError(f"resource_type {self.resource_type!r} must look like k8s/ConfigMap")
        if self.field_path not in SUPPORTED_FIELD_PATHS:
            raise ValueError(
                f"{self.resource_type}: field path {self.field_path!r} has no recorded prior "
                f"value to revert to; supported: {sorted(SUPPORTED_FIELD_PATHS)}"
            )
        if self.scope_field not in self.ref_params:
            # A credential scoped to something the action does not name is a scope nothing
            # can check against the resource the writer then touches.
            raise ValueError(
                f"{self.resource_type}: scope_field {self.scope_field!r} must be one of "
                f"ref_params {self.ref_params}"
            )
        for name in ("resource", "params_for", "read", "write"):
            if not callable(getattr(self, name)):
                raise TypeError(f"{self.resource_type}: {name} must be callable")

    @property
    def id(self) -> str:
        return f"{self.resource_type}:{self.field_path}"

    def matches(self, event: ChangeEvent) -> bool:
        from ..growth.signals import field_path_of

        return (
            event.source == self.source
            and event.resource.kind == self.kind
            and field_path_of(event).value == self.field_path
        )


class WriterRegistry:
    def __init__(self, writers: Iterable[WriterSpec]) -> None:
        self._writers: dict[str, WriterSpec] = {}
        for writer in writers:
            if not isinstance(writer, WriterSpec):
                raise TypeError(f"expected a WriterSpec, got {type(writer).__name__}")
            if writer.id in self._writers:
                raise ValueError(f"two writers registered for {writer.id}")
            self._writers[writer.id] = writer

    @classmethod
    def load(cls, modules: Iterable[str] = WRITER_MODULES) -> WriterRegistry:
        writers = []
        for module_path in modules:
            writer = getattr(importlib.import_module(module_path), "WRITER", None)
            if not isinstance(writer, WriterSpec):
                raise TypeError(f"{module_path} must define WRITER as a WriterSpec")
            writers.append(writer)
        return cls(writers)

    def get(self, writer_id: str) -> WriterSpec:
        try:
            return self._writers[writer_id]
        except KeyError:
            raise UnknownWriter(
                f"no writer registered for {writer_id!r}; known: {', '.join(sorted(self._writers))}"
            ) from None

    def __contains__(self, writer_id: object) -> bool:
        return writer_id in self._writers

    def __iter__(self) -> Iterator[WriterSpec]:
        return iter(self._writers.values())

    def __len__(self) -> int:
        return len(self._writers)


@functools.lru_cache(maxsize=1)
def _loaded_registry() -> WriterRegistry:
    return WriterRegistry.load()


_OVERRIDE: ContextVar[WriterRegistry | None] = ContextVar("fazerops_writer_registry", default=None)


def default_registry() -> WriterRegistry:
    override = _OVERRIDE.get()
    return override if override is not None else _loaded_registry()


@contextmanager
def registry_override(registry: WriterRegistry) -> Iterator[WriterRegistry]:
    """Evaluate against `registry` for the duration of a block — W42's replay of a rung-3
    candidate, whose writer is a stand-in and must never be the process-wide registry.
    A context variable rather than a global swap, so a concurrent investigation is unaffected."""
    token = _OVERRIDE.set(registry)
    try:
        yield registry
    finally:
        _OVERRIDE.reset(token)


# --------------------------------------------------------------------------------------
# The generic substrate
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RecordedValues:
    writer: WriterSpec
    prior: dict[str, Any]
    current: dict[str, Any]


def hint_for(
    event: ChangeEvent, action: ActionSpec, *, registry: WriterRegistry | None = None
) -> dict[str, Any] | None:
    """The generic hint for reverting `event` with a writer-backed `action`, or `None`."""
    if action.writer is None:
        return None
    writer = (registry or default_registry()).get(action.writer)
    if not writer.matches(event):
        return None

    from ..growth.signals import prior_value_recorded

    if not prior_value_recorded(event) or event.diff is None:
        return None
    ref = writer.params_for(event.resource)
    fields = event.diff.fields_changed
    if ref is None or not fields:
        return None

    return {
        "action_id": action.id,
        "writer": writer.id,
        "ref": ref,
        "prior": {name: (event.diff.before or {}).get(name) for name in fields},
        "current": {name: (event.diff.after or {}).get(name) for name in fields},
    }


def recorded_values(
    request: ActionRequest, action: ActionSpec, *, registry: WriterRegistry | None = None
) -> RecordedValues | None:
    """The request's hint, checked against the action it is being used for.

    `None` whenever the hint does not fit — another action's, another writer's, or recorded
    against a **different resource** than the parameters name. The last one is the check
    that matters: without it, values observed on one ConfigMap could be written to another,
    with a dry run that faithfully renders the wrong target.
    """
    hint = request.inverse_hint or {}
    if action.writer is None or hint.get("writer") != action.writer:
        return None
    if hint.get("action_id") != request.action_id:
        return None

    prior, current, ref = hint.get("prior"), hint.get("current"), hint.get("ref")
    if not isinstance(prior, dict) or not isinstance(current, dict) or not isinstance(ref, dict):
        return None
    if not prior or set(prior) != set(current):
        return None

    registry = registry or default_registry()
    if action.writer not in registry:
        return None
    writer = registry.get(action.writer)
    if any(str(ref.get(name)) != str(request.params.get(name)) for name in writer.ref_params):
        return None

    return RecordedValues(writer=writer, prior=dict(prior), current=dict(current))


def invert(
    request: ActionRequest, action: ActionSpec
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """The same action with the recorded values swapped: `(params, hint)`, or `None`."""
    values = recorded_values(request, action)
    if values is None:
        return None
    hint = {**(request.inverse_hint or {}), "prior": values.current, "current": values.prior}
    return dict(request.params), hint


def request_for_event(event: ChangeEvent, catalog: Catalog | None = None) -> ActionRequest | None:
    """The catalog action that reverts `event`, inverse included — or `None`.

    A collector's own hint first, because it names a hand-written action; then any
    writer-backed action whose writer matches. This is what `growth.signals` asks when it
    decides whether a change is a gap, so a gap stops being mined the day the action that
    closes it is merged.
    """
    from ..catalog import UnknownAction, ValidationRejected, default_catalog
    from ..inverse import ActionRequest, request_from_hint

    catalog = catalog if catalog is not None else default_catalog()

    try:
        request = request_from_hint(event.inverse_hint, catalog=catalog)
    except (UnknownAction, ValidationRejected):
        request = None
    if request is not None and request.inverse(catalog=catalog) is not None:
        return request

    for action in catalog:
        if action.retired:
            continue  # a tombstone never closes a gap (W45)
        hint = hint_for(event, action)
        if hint is None:
            continue
        try:
            candidate = ActionRequest.for_action(
                action.id, hint["ref"], inverse_hint=hint, catalog=catalog
            )
        except (UnknownAction, ValidationRejected):
            continue
        if candidate.inverse(catalog=catalog) is not None:
            return candidate

    return None
