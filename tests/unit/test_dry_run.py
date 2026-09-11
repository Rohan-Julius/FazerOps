"""W21 — dry-run rendering. Handoff §7, plan §4.

Two assertions, and the second is the one with teeth:

* it renders a before/after diff;
* it performs **zero** mutating calls.

"Zero mutating calls" is asserted two ways on purpose. Behaviourally: every network and
subprocess entry point is replaced with a landmine for the duration of the call. And
structurally: the AST of `dry_run.py` is read to prove it imports nothing that could reach a
cluster. The behavioural test proves this call was clean; the structural one proves every
call is, including ones nobody wrote a test for.
"""

from __future__ import annotations

import ast
import socket
import subprocess
from pathlib import Path

import pytest

from fazerops.actions.dry_run import DryRun, render
from fazerops.actions.inverse import ActionRequest, request_from_hint

SRC = Path(__file__).resolve().parents[2] / "src" / "fazerops"

CONFIGMAP_HINT = {
    "action_id": "revert_configmap_key",
    "namespace": "billing",
    "name": "billing-api-config",
    "key": "pool.max",
    "prior_value": "100",
    "current_value": "20",
}

HELM_HINT = {
    "action_id": "helm_rollback",
    "release": "billing-api",
    "namespace": "billing",
    "target_revision": 2,
    "current_revision": 3,
}

RDS_HINT = {
    "action_id": "restore_db_parameter",
    "parameter_group": "billing-primary-params",
    "parameter": "max_connections",
    "prior_value": "200",
    "current_value": "50",
}


@pytest.fixture
def no_side_effects(monkeypatch):
    """Replace every way out of this process with a landmine.

    A dry run that opened a socket or spawned `kubectl` would trip one of these. Blocking
    `socket.socket` itself rather than a boto3 client catches a path that builds its own
    client — which is exactly the path a test that mocks one specific client would miss.
    """

    def forbidden(*args, **kwargs):
        raise AssertionError("a dry run performed I/O")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "check_output", forbidden)


# --------------------------------------------------------------------------------------
# The diff
# --------------------------------------------------------------------------------------


def test_configmap_dry_run_renders_before_and_after(no_side_effects):
    dry = render(request_from_hint(CONFIGMAP_HINT))

    assert isinstance(dry, DryRun)
    assert dry.target == "billing/configmap/billing-api-config"
    assert len(dry.lines) == 1

    line = dry.lines[0]
    assert line.field == "pool.max"
    assert line.before == "20", "before is the value that is live now"
    assert line.after == "100", "after is the value this action restores"

    text = dry.render()
    assert "pool.max: 20 → 100" in text


def test_the_dry_run_states_reversibility_from_the_computed_inverse(no_side_effects):
    """Not a declared flag. The card says "reversible" only when an inverse was actually
    constructed — ground rule #4 in the one place an operator reads it."""
    dry = render(request_from_hint(CONFIGMAP_HINT))

    assert dry.reversible is True
    assert dry.inverse_summary is not None
    assert "target_value=20" in dry.inverse_summary
    assert "reversible: revert_configmap_key" in dry.render()


def test_an_irreversible_action_says_it_will_refuse_to_execute(no_side_effects):
    """The honest version of the same card. An operator must not be shown a diff that reads
    as approvable when `execute()` is going to refuse."""
    request = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
    )
    dry = render(request)

    assert dry.reversible is False
    assert dry.inverse_summary is None
    assert "refuse to execute" in dry.render()
    assert "ground rule #4" in dry.render()


def test_an_uncaptured_prior_value_renders_as_such_not_as_empty(no_side_effects):
    """Plan §3.6 and Handoff §5 both insist the distinction survives to the screen: "we set
    it to X" and "we changed it from nothing to X" are different claims."""
    request = ActionRequest.for_action(
        "revert_configmap_key",
        {
            "namespace": "billing",
            "name": "billing-api-config",
            "key": "pool.max",
            "target_value": "100",
        },
        inverse_hint=dict(CONFIGMAP_HINT, current_value=None),
    )
    dry = render(request)

    assert dry.lines[0].prior_value_captured is False
    assert dry.lines[0].before is None
    assert "prior value not captured" in dry.render()
    assert "→" not in dry.render(), "an arrow implies a before that was never observed"


def test_helm_dry_run_renders_the_revision_change(no_side_effects):
    dry = render(request_from_hint(HELM_HINT))

    assert dry.target == "billing/helm/billing-api"
    assert "revision: 3 → 2" in dry.render()
    # A rollback is not a single-value edit, and the card has to say so.
    assert any("whole release manifest" in note for note in dry.notes)


def test_rds_dry_run_names_the_tier_and_the_approver(no_side_effects):
    """Tier 2 is only meaningful if the escalation reason is on the card (W26b)."""
    dry = render(request_from_hint(RDS_HINT))

    assert dry.target == "rds/parameter-group/billing-primary-params"
    assert "max_connections: 50 → 200" in dry.render()
    assert any("manager" in note for note in dry.notes)
    assert any("Tier 2" in note for note in dry.notes)


def test_a_sensitive_field_is_redacted_in_the_diff(no_side_effects):
    """The dry run is the last surface before a value is shown to a human and echoed into
    an approval record. It redacts again rather than relying on the collector having done
    it — a future collector might not."""
    hint = dict(CONFIGMAP_HINT, key="db.password", prior_value="hunter2", current_value="swordfish")
    dry = render(request_from_hint(hint))

    text = dry.render()
    assert "hunter2" not in text and "swordfish" not in text
    assert "<redacted>" in text
    # The inverse summary is a second surface and it leaked (11 Sep): it masked on the
    # *parameter* name, and `target_value` carries no hint that its contents are a secret.
    assert "<redacted>" in dry.inverse_summary


def test_two_different_secrets_do_not_render_as_unchanged(no_side_effects):
    """A redacted diff must still say the value is changing.

    Both values mask to the same `<redacted>` string, so a renderer comparing the rendered
    text calls this "unchanged" — a card telling an operator nothing will happen immediately
    before something does. `DiffLine.changed` is computed from the raw values for this
    reason alone.
    """
    hint = dict(CONFIGMAP_HINT, key="db.password", prior_value="hunter2", current_value="swordfish")
    dry = render(request_from_hint(hint))

    assert dry.lines[0].before == dry.lines[0].after == "<redacted>"
    assert dry.lines[0].changed is True
    assert "(unchanged)" not in dry.render()
    assert "→" in dry.render()


def test_an_action_that_changes_nothing_says_so(no_side_effects):
    """The other side of the same flag: a genuine no-op must not render as a change."""
    hint = dict(CONFIGMAP_HINT, prior_value="20", current_value="20")
    dry = render(request_from_hint(hint))

    assert dry.lines[0].changed is False
    assert "(unchanged)" in dry.render()


# --------------------------------------------------------------------------------------
# Zero mutating calls
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("hint", [CONFIGMAP_HINT, HELM_HINT, RDS_HINT])
def test_dry_run_performs_no_io_at_all(no_side_effects, hint):
    """Every action, with the process's exits mined."""
    dry = render(request_from_hint(hint))
    assert dry.render()


def test_dry_run_module_imports_nothing_that_could_reach_a_cluster():
    """The structural half. A behavioural test proves *this* call was clean; reading the
    module proves every call is, including the ones nobody thought to write."""
    tree = ast.parse((SRC / "actions" / "dry_run.py").read_text(encoding="utf-8"))

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])

    forbidden = {"boto3", "botocore", "kubernetes", "subprocess", "socket", "requests", "httpx", "os"}
    assert not (imported & forbidden), f"dry_run.py imports {sorted(imported & forbidden)}"


def test_no_executor_is_resolved_by_a_dry_run(monkeypatch):
    """The executor is the only thing in the repo that mutates. A dry run must not so much
    as import it."""

    def spy(*args, **kwargs):
        raise AssertionError("a dry run resolved an executor")

    monkeypatch.setattr("fazerops.actions.catalog.resolve_executor", spy)
    assert render(request_from_hint(CONFIGMAP_HINT)).reversible is True
