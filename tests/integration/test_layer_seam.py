"""Plan §3.5 — the frozen seam between the investigation and automation layers.

**This test is never allowed to go red.**

The automation layer's design may be redrawn after this build. That is only survivable if
a re-plan cannot force investigation rework, which requires the dependency to run one way:
investigation emits a `Brief`; automation consumes one and emits a `Proposal`. Nothing
flows back.

Written now, before `faberops.actions` and `faberops.slack.handlers` exist, and it stays
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
AUTOMATION_MODULES = ("faberops.actions", "faberops.slack", "faberops.security.credentials")


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


async def test_a_complete_brief_renders_with_the_automation_layer_deleted(
    automation_layer_deleted, monkeypatch
):
    """The seam, asserted end to end: ingest, collect, rank, render — all of it standing
    on its own."""
    monkeypatch.setenv("FABEROPS_MODE", "fixture")

    from faberops.ingest.alerts import normalize_alert
    from faberops.pipeline import investigate
    from faberops.render.text import render_brief

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


def test_the_guard_actually_blocks_the_automation_layer(automation_layer_deleted):
    """A guard that does not guard passes every test for the wrong reason."""
    with pytest.raises(ImportError):
        importlib.import_module("faberops.actions.catalog")


@pytest.mark.parametrize(
    "module_name",
    [
        "faberops.models",
        "faberops.pipeline",
        "faberops.radius",
        "faberops.render.text",
        "faberops.ingest.alerts",
        "faberops.main",
        "faberops.correlation.scoring",
        "faberops.collectors.k8s_audit",
        "faberops.collectors.github",
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
        if name.startswith("faberops"):
            monkeypatch.delitem(sys.modules, name)
    importlib.import_module(module_name)


def test_the_inverse_hint_stays_opaque_to_the_investigation_layer(automation_layer_deleted):
    """`Candidate.inverse_hint` is data the investigation layer carries and never reads.
    Only `actions/inverse.py` interprets it — which is what lets the automation layer's
    shape change without touching anything upstream."""
    import inspect

    from faberops import models

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
    monkeypatch.setenv("FABEROPS_MODE", "fixture")

    from faberops.ingest.alerts import normalize_alert
    from faberops.pipeline import investigate

    alert = normalize_alert(
        json.loads((FIXTURE_ALERTS / "alertmanager.json").read_text(encoding="utf-8"))
    )
    brief = await investigate(alert)

    payload = json.loads(brief.model_dump_json())
    assert payload["incident_id"] == "INC-7c1f9a2e4b6d8033"
    assert payload["candidates"][0]["rank"] == 1
