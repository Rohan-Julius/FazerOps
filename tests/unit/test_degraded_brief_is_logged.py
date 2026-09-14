"""A degraded brief names its failed source in the server log.

The brief carries only the flag, and the investigation state dies with the request, so without
this line "a change source was unavailable" cannot be traced afterwards (W31, 14 Sep: a live
brief went degraded once and nothing recorded which collector failed).
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _sandbox_fakes as fakes  # noqa: E402

from fazerops.actions.runtime import Automation  # noqa: E402
from fazerops.collectors.base import CollectorResult  # noqa: E402
from fazerops.ingest.alerts import normalize_alert  # noqa: E402
from fazerops.pipeline import build_collectors  # noqa: E402

ALERT = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "alerts" / "alertmanager.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("FAZEROPS_MODE", "fixture")
    monkeypatch.setenv("FAZEROPS_LLM", "stub")


class _Unreachable:
    def __init__(self, source):
        self.source = source

    async def fetch(self, radius, window):
        return CollectorResult(self.source, [], error="HTTP Error 502: Bad Gateway")


def _automation(tmp_path):
    return Automation.assemble(
        state_dir=tmp_path, runner=lambda *a: {"action_id": "revert_configmap_key"}, sandbox=fakes.factory()
    )


async def test_a_failed_collector_is_named_in_the_log(tmp_path, caplog):
    collectors = build_collectors()
    failing = next(c for c in collectors if c.source == "github")
    collectors = [c for c in collectors if c is not failing] + [_Unreachable(failing.source)]

    with caplog.at_level(logging.WARNING, logger="fazerops.actions.runtime"):
        response = await _automation(tmp_path).respond(normalize_alert(ALERT), collectors=collectors)

    assert response.brief.degraded
    [line] = [r.getMessage() for r in caplog.records if "degraded brief" in r.getMessage()]
    assert "github" in line and "502" in line


async def test_a_healthy_brief_logs_nothing(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="fazerops.actions.runtime"):
        response = await _automation(tmp_path).respond(normalize_alert(ALERT))

    assert not response.brief.degraded
    assert not [r for r in caplog.records if "degraded brief" in r.getMessage()]


async def test_a_failed_proposer_is_logged_though_the_brief_is_not_degraded(tmp_path, caplog, monkeypatch):
    """A correlator or proposer failure costs the brief its narrative or its action, not a source,
    so it no longer marks the brief degraded (`graph.ANNOTATION_NODES`). The log still says why."""
    import fazerops.agents.proposer as proposer_module

    async def fails(*args, **kwargs):
        raise ValueError("the proposal cited evidence the brief does not hold")

    monkeypatch.setattr(proposer_module, "propose", fails)
    with caplog.at_level(logging.WARNING, logger="fazerops.actions.runtime"):
        response = await _automation(tmp_path).respond(normalize_alert(ALERT))

    assert not response.brief.degraded
    [line] = [r.getMessage() for r in caplog.records if "node errors" in r.getMessage()]
    assert "degraded" not in line and "proposer" in line and "does not hold" in line
