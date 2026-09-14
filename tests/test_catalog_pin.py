"""The one test a catalog change is allowed to fail (`tests/conftest.py` says why the suite is pinned)."""

from __future__ import annotations

from pathlib import Path

from conftest import PINNED_ACTIONS

SHIPPED_ACTIONS = Path(__file__).resolve().parents[1] / "config" / "actions.yaml"


def test_the_pinned_catalog_is_the_shipped_catalog():
    assert PINNED_ACTIONS.read_bytes() == SHIPPED_ACTIONS.read_bytes(), (
        "config/actions.yaml has changed, and the suite still tests the old catalog. Before merging: "
        "copy it to tests/fixtures/catalog/actions.yaml, re-record the cassettes whose prompts embed "
        "the catalog (scripts/record_cassettes.py, scripts/record_injection_cassettes.py), and review "
        "the catalog-growth tests, which build their gaps against what the catalog cannot yet revert."
    )


def test_the_suite_loads_the_pinned_catalog():
    from fazerops.actions import catalog

    assert catalog.DEFAULT_ACTIONS == PINNED_ACTIONS
