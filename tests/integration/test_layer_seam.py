"""Plan §3.5 — the frozen seam between the investigation and automation layers.

**This test is never allowed to go red.**

The automation layer's design may be redrawn after this build. That is only survivable if
a re-plan cannot force investigation rework, which requires the dependency to run one way:
investigation emits a `Brief`; automation consumes one and emits a `Proposal`. Nothing
flows back.

Written now, before `fazerops.actions` and `fazerops.slack.handlers` exist, and it stays
green as they are added. Writing it afterwards would mean writing it against whatever
coupling had already crept in.
"""

from __future__ import annotations

import builtins
import importlib
import json
import sys
from pathlib import Path

import pytest

FIXTURE_ALERTS = Path(__file__).resolve().parents[2] / "fixtures" / "alerts"

# The automation layer. The investigation layer must not import any of these, at any depth.
AUTOMATION_MODULES = ("fazerops.actions", "fazerops.slack", "fazerops.security.credentials")


@pytest.fixture
def automation_layer_deleted(monkeypatch):
    """Make the automation layer unimportable, as if it had been deleted from the repo.

    Blocks `__import__` rather than only clearing `sys.modules`, so a lazy import inside a
    function body fails too — that is precisely where accidental coupling hides.
    """
    for name in list(sys.modules):
        if name.startswith(AUTOMATION_MODULES):
            monkeypatch.delitem(sys.modules, name, raising=False)

    real_import = builtins.__import__

    def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith(AUTOMATION_MODULES):
            raise ImportError(
                f"{name} is in the automation layer; the investigation layer must not "
                "import it (plan §3.5)"
            )
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _guarded_import)

    # **`builtins.__import__` alone is not the guard it looks like.** An `import x` statement
    # goes through it; `importlib.import_module` does not — it calls `_bootstrap._find_and_load`
    # directly. Before `fazerops.actions.catalog` existed, the guard test below passed because
    # the module was simply absent (`ModuleNotFoundError` is an `ImportError`), so the hole was
    # invisible until W20 created the module (11 Sep). A `meta_path` finder closes both routes,
    # because every import that is not already in `sys.modules` consults it.
    class _Blocker:
        @staticmethod
        def find_spec(name, path=None, target=None):
            if name.startswith(AUTOMATION_MODULES):
                raise ImportError(
                    f"{name} is in the automation layer; the investigation layer must not "
                    "import it (plan §3.5)"
                )
            return None

    monkeypatch.setattr(sys, "meta_path", [_Blocker(), *sys.meta_path])


async def test_a_complete_brief_renders_with_the_automation_layer_deleted(
    automation_layer_deleted, monkeypatch
):
    """The seam, asserted end to end: ingest, collect, rank, render — all of it standing
    on its own."""
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")

    from fazerops.ingest.alerts import normalize_alert
    from fazerops.pipeline import investigate
    from fazerops.render.text import render_brief

    alert = normalize_alert(
        json.loads((FIXTURE_ALERTS / "alertmanager.json").read_text(encoding="utf-8"))
    )
    brief = await investigate(alert)

    assert brief.candidates, "the brief must carry candidates without the automation layer"
    assert brief.top.event.resource.name == "billing-api-config"

    rendered = render_brief(brief)
    assert "billing-api-config" in rendered
    assert "pool.max: 100 → 20" in rendered
    assert "Nothing shipped through CI in this window." in rendered


@pytest.mark.parametrize(
    "module_name",
    ["fazerops.actions.catalog", "fazerops.actions", "fazerops.security.credentials"],
)
def test_the_guard_actually_blocks_the_automation_layer(automation_layer_deleted, module_name):
    """A guard that does not guard passes every test for the wrong reason — and this one
    did, for five days.

    `fazerops.actions.catalog` did not exist until W20, so `import_module` raised
    `ModuleNotFoundError` and the test was green for a reason that had nothing to do with
    the guard. `fazerops.actions.catalog` is now a real module, which is why the parameters
    below name modules that exist: a guard proved against a missing module proves nothing.
    """
    with pytest.raises(ImportError, match="automation layer"):
        importlib.import_module(module_name)


@pytest.mark.parametrize(
    "module_name",
    [
        "fazerops.models",
        "fazerops.pipeline",
        "fazerops.radius",
        "fazerops.render.text",
        "fazerops.ingest.alerts",
        "fazerops.main",
        "fazerops.correlation.scoring",
        "fazerops.collectors.k8s_audit",
        "fazerops.collectors.github",
        # Added with W22 (12 Sep). `graph.py`'s docstring has claimed to be automation-free
        # since W19; until the proposer existed there was nothing tempting it to import
        # `actions/`, so the claim had never been tested. W22 is exactly that temptation —
        # the diagram's `correlator → proposer` edge — and it is why the proposer arrives
        # as an injected node factory rather than as an import.
        "fazerops.agents.graph",
        "fazerops.agents.orchestrator",
        "fazerops.agents.correlator",
    ],
)
def test_every_investigation_module_imports_cleanly_without_automation(
    automation_layer_deleted, monkeypatch, module_name
):
    """Parameterized so a new investigation-layer module is covered by adding one line —
    and so the failure names the module that broke the seam, not just 'the pipeline'.

    Purged through `monkeypatch.delitem` rather than a bare `del`, so pytest restores the
    original module objects afterwards. A bare delete leaves freshly-imported duplicates
    in `sys.modules`: later tests then monkeypatch a module global on the new object while
    their already-imported classes still read the old one, and the patch silently does
    nothing. That failure appears in an unrelated test file, which is a long afternoon.
    """
    for name in list(sys.modules):
        if name.startswith("fazerops"):
            monkeypatch.delitem(sys.modules, name)
    importlib.import_module(module_name)


def test_the_inverse_hint_stays_opaque_to_the_investigation_layer(automation_layer_deleted):
    """`Candidate.inverse_hint` is data the investigation layer carries and never reads.
    Only `actions/inverse.py` interprets it — which is what lets the automation layer's
    shape change without touching anything upstream."""
    import inspect

    from fazerops import models

    source = inspect.getsource(models.Candidate)
    assert "inverse_hint" in source

    # Carried through untouched, whatever shape it happens to have.
    event_source = inspect.getsource(models.ChangeEvent)
    assert "dict[str, Any] | None" in event_source


async def test_the_brief_is_json_serializable_without_the_automation_layer(
    automation_layer_deleted, monkeypatch
):
    """AgentCore requires a JSON-serializable response (plan §1.1), and the markdown
    record consumes the same object. Neither may need the automation layer present."""
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")

    from fazerops.ingest.alerts import normalize_alert
    from fazerops.pipeline import investigate

    alert = normalize_alert(
        json.loads((FIXTURE_ALERTS / "alertmanager.json").read_text(encoding="utf-8"))
    )
    brief = await investigate(alert)

    payload = json.loads(brief.model_dump_json())
    assert payload["incident_id"] == "INC-7c1f9a2e4b6d8033-20260906T144100Z"
    assert payload["candidates"][0]["rank"] == 1
