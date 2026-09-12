"""W23 — the credential gate. Handoff §8, plan §4.

> *Enforce it structurally, not by convention.*

The plan's four assertions: the executor raises without an approval-minted credential; the
mint function is unreachable from any module except the approval handler; TTL ≤ 900s; and
the session policy names **exactly one** namespace.

**A happy-path test proves nothing here**, which the plan says outright, so almost every
test below is a refusal. Three of them are structural rather than behavioural:

* the AST of `credentials.py` is read to prove `SESSION_TTL_SECONDS` is a module constant
  and not a parameter anything can raise;
* the AST of every executor is read to prove each one calls the gate, so the guarantee
  covers executors nobody wrote a test for;
* `ActorCredential`'s constructor is exercised directly to prove there is no route in that
  skips the mint.

What this test does *not* claim is that a determined caller inside the process cannot forge
a credential. Python has no private constructor; `credentials.py` says so in its docstring
rather than implying otherwise here.
"""

from __future__ import annotations

import ast
import time
import types
from pathlib import Path

import pytest

from fazerops.security.credentials import (
    MINTING_MODULES,
    SESSION_TTL_SECONDS,
    ActorCredential,
    CredentialRefused,
    ReaderCredential,
    mint_actor_credential,
    reader_credential,
    require_actor_credential,
    session_policy,
)

SRC = Path(__file__).resolve().parents[2] / "src" / "fazerops"
CREDENTIALS = SRC / "security" / "credentials.py"


def _mint_as(module_name: str, **kwargs):
    """Call `mint_actor_credential` as if from `module_name`.

    The gate reads the calling frame's `__name__`, so a function built with a globals dict
    naming that module *is* a call from it as far as the check is concerned. That is the
    honest way to test a frame-based gate: anything else would test a mock of the gate.
    """
    source = compile(
        "def caller(mint, kwargs):\n    return mint(**kwargs)\n", "<synthetic>", "exec"
    )
    namespace: dict = {"__name__": module_name}
    exec(source, namespace)  # noqa: S102 - the point of the test
    return namespace["caller"](mint_actor_credential, kwargs)


GRANT = {
    "incident_id": "INC-1",
    "action_id": "revert_configmap_key",
    "namespace": "billing",
}


# --------------------------------------------------------------------------------------
# Assertion 2 — the mint function is unreachable from any module except the handler
# --------------------------------------------------------------------------------------


def test_minting_from_this_test_module_is_refused():
    """Imported successfully and still unusable. That is the shape of a structural gate:
    the import is not the permission."""
    with pytest.raises(CredentialRefused, match="may not mint"):
        mint_actor_credential(**GRANT)


@pytest.mark.parametrize(
    "module_name",
    [
        "fazerops.pipeline",
        "fazerops.agents.proposer",
        "fazerops.agents.correlator",
        "fazerops.collectors.k8s_audit",
        "fazerops.actions.inverse",
        "fazerops.actions.executors.configmap",
        "__main__",
        "evil",
    ],
)
def test_no_other_module_can_mint(module_name):
    """Including the proposer and the executor — the two modules closest to the mutation,
    and the two a reader would most expect to be trusted."""
    with pytest.raises(CredentialRefused, match="may not mint"):
        _mint_as(module_name, **GRANT)


@pytest.mark.parametrize("module_name", sorted(MINTING_MODULES))
def test_the_approval_handlers_can_mint(module_name):
    """The other direction, so the gate is not merely refusing everything."""
    credential = _mint_as(module_name, **GRANT)

    assert isinstance(credential, ActorCredential)
    assert credential.incident_id == "INC-1"
    assert credential.namespace == "billing"


def test_the_allowlist_names_only_approval_handlers():
    """A third entry here would be the quiet way this guarantee is lost — so the set is
    pinned, and widening it has to be a deliberate edit to a test."""
    assert MINTING_MODULES == {"fazerops.slack.handlers", "fazerops.actions.approval"}


def test_an_actor_credential_cannot_be_constructed_directly():
    """No public constructor. A caller cannot forge one by assembling the right fields."""
    with pytest.raises(CredentialRefused, match="cannot be constructed directly"):
        ActorCredential(
            incident_id="INC-1",
            action_id="revert_configmap_key",
            namespace="billing",
            expires_at=time.time() + 900,
        )


def test_a_forged_token_does_not_open_the_constructor():
    """The sentinel is identity-checked, not truthiness-checked — `_token=True` is the
    first thing anyone would try."""
    for forged in (True, 1, "token", object()):
        with pytest.raises(CredentialRefused):
            ActorCredential(
                incident_id="INC-1",
                action_id="revert_configmap_key",
                namespace="billing",
                expires_at=time.time() + 900,
                _token=forged,
            )


# --------------------------------------------------------------------------------------
# Assertion 1 — the executor raises without an approval-minted credential
# --------------------------------------------------------------------------------------


PARAMS = {
    "namespace": "billing",
    "name": "billing-api-config",
    "key": "pool.max",
    "target_value": "100",
}


class ExplodingClient:
    """Any use of this is a test failure: the credential check must happen first."""

    def patch_namespaced_config_map(self, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("a client was used before the credential was checked")


def test_the_executor_refuses_without_a_credential():
    from fazerops.actions.executors.configmap import revert_key

    with pytest.raises(CredentialRefused, match="requires an actor credential"):
        revert_key(PARAMS, client=ExplodingClient())


def test_the_executor_refuses_the_read_only_reader_principal():
    """Read and write are different principals, checked by type on every call rather than
    remembered by whoever wrote the executor."""
    from fazerops.actions.executors.configmap import revert_key

    with pytest.raises(CredentialRefused, match="read-only reader principal"):
        revert_key(PARAMS, credential=reader_credential(), client=ExplodingClient())


@pytest.mark.parametrize("forged", [{"AccessKeyId": "AKIA"}, "a string", 42, object()])
def test_the_executor_refuses_anything_that_is_not_an_actor_credential(forged):
    from fazerops.actions.executors.configmap import revert_key

    with pytest.raises(CredentialRefused, match="not an ActorCredential"):
        revert_key(PARAMS, credential=forged, client=ExplodingClient())


def test_the_executor_accepts_a_properly_minted_credential():
    """The happy path, present only so the refusals above are not vacuous."""
    from fazerops.actions.executors.configmap import revert_key

    class Patched:
        data = {"pool.max": "100"}
        metadata = types.SimpleNamespace(resource_version="42")

    class Client:
        def __init__(self):
            self.calls = []

        def patch_namespaced_config_map(self, **kwargs):
            self.calls.append(kwargs)
            return Patched()

    client = Client()
    result = revert_key(
        PARAMS, credential=_mint_as("fazerops.slack.handlers", **GRANT), client=client
    )

    assert result["value"] == "100"
    assert client.calls[0]["body"] == {"data": {"pool.max": "100"}}, "one key, merged"


def test_every_executor_calls_the_gate():
    """Structural, and the reason it is: a behavioural test covers the executors somebody
    wrote a test for. Reading the AST covers W20b's and W20c's too, the day their bodies
    land — which is Sep 12, under time pressure, which is when a forgotten check happens.
    """
    executors = sorted((SRC / "actions" / "executors").glob("*.py"))
    checked = []

    for path in executors:
        if path.name.startswith("_") or path.name == "__init__.py":
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        if "pending" in calls:
            continue  # body not written yet; `_pending.py` states why that is the boundary
        assert "require_actor_credential" in calls, f"{path.name} does not call the gate"
        checked.append(path.name)

    assert "configmap.py" in checked, "W24's executor must be covered by this assertion"


# --------------------------------------------------------------------------------------
# Assertion 3 — TTL ≤ 900s
# --------------------------------------------------------------------------------------


def test_the_ttl_is_900_seconds():
    assert SESSION_TTL_SECONDS <= 900


def test_a_minted_credential_expires_within_the_ttl():
    credential = _mint_as("fazerops.slack.handlers", **GRANT)

    assert 0 < credential.ttl_seconds <= SESSION_TTL_SECONDS


def test_an_expired_credential_is_refused(monkeypatch):
    credential = _mint_as("fazerops.slack.handlers", **GRANT)
    monkeypatch.setattr(time, "time", lambda: credential.expires_at + 1)

    with pytest.raises(CredentialRefused, match="expired"):
        require_actor_credential(
            credential, action_id="revert_configmap_key", namespace="billing"
        )


def test_the_ttl_is_a_constant_and_not_a_parameter():
    """Structural. An argument would mean a call site could ask for eight hours, and the
    one that did would be the one nobody reviewed — so the assertion is that no function
    in this module accepts a duration at all."""
    tree = ast.parse(CREDENTIALS.read_text(encoding="utf-8"))

    duration_names = {"ttl", "ttl_seconds", "duration", "duration_seconds", "expires_in"}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = node.args
        names = {a.arg for a in [*args.args, *args.posonlyargs, *args.kwonlyargs]}
        assert not (names & duration_names), f"{node.name} accepts a caller-supplied TTL"


# --------------------------------------------------------------------------------------
# Assertion 4 — the session policy names exactly one namespace
# --------------------------------------------------------------------------------------


def test_the_session_policy_names_exactly_one_namespace():
    policy = session_policy("billing", "restore_db_parameter")
    rendered = repr(policy)

    assert rendered.count("billing") == 1
    assert len(policy["Statement"]) == 1

    condition = policy["Statement"][0]["Condition"]["StringEquals"]
    assert list(condition.values()) == ["billing"]


def test_the_session_policy_grants_only_that_actions_api_calls():
    """Written per action rather than as one union, so a new action cannot inherit
    another's permissions by omission."""
    rds = session_policy("billing", "restore_db_parameter")["Statement"][0]["Action"]

    assert set(rds) == {"rds:ModifyDBParameterGroup", "rds:DescribeDBParameters"}
    assert not any(action.startswith("iam:") or action == "*" for action in rds)


def test_an_unknown_action_grants_nothing():
    """Fails closed. An action not in the table is one nobody scoped, and the safe reading
    of that is zero permissions, not a wildcard."""
    assert session_policy("billing", "not_a_real_action")["Statement"][0]["Action"] == []


# --------------------------------------------------------------------------------------
# The terms of the grant — one incident, one action, one namespace, one use
# --------------------------------------------------------------------------------------


def test_a_credential_for_another_namespace_is_refused():
    credential = _mint_as("fazerops.slack.handlers", **GRANT)

    with pytest.raises(CredentialRefused, match="scoped to namespace"):
        require_actor_credential(
            credential, action_id="revert_configmap_key", namespace="kube-system"
        )


def test_a_credential_for_another_action_is_refused():
    credential = _mint_as("fazerops.slack.handlers", **GRANT)

    with pytest.raises(CredentialRefused, match="minted for 'revert_configmap_key'"):
        require_actor_credential(credential, action_id="helm_rollback", namespace="billing")


def test_a_credential_for_another_incident_is_refused():
    credential = _mint_as("fazerops.slack.handlers", **GRANT)

    with pytest.raises(CredentialRefused, match="minted for incident"):
        require_actor_credential(
            credential,
            incident_id="INC-2",
            action_id="revert_configmap_key",
            namespace="billing",
        )


def test_a_credential_is_spent_once():
    """Handoff §8: one action per session. The second use raises rather than returning
    quietly — it is either a replayed approval or a retry around a mutation that may
    already have landed, and both need to stop here."""
    credential = _mint_as("fazerops.slack.handlers", **GRANT)

    require_actor_credential(credential, action_id="revert_configmap_key", namespace="billing")
    assert credential.spent is True

    with pytest.raises(CredentialRefused, match="already been used"):
        require_actor_credential(
            credential, action_id="revert_configmap_key", namespace="billing"
        )


def test_spending_is_visible_to_every_holder_of_the_credential():
    """The credential is frozen, so `_spent` lives in a list. Two callers sharing one
    object must not each get a use out of it — that is a double mutation."""
    credential = _mint_as("fazerops.slack.handlers", **GRANT)
    also_held = credential

    require_actor_credential(credential, action_id="revert_configmap_key", namespace="billing")

    assert also_held.spent is True


def test_the_secrets_stay_out_of_the_repr():
    """A credential lands in log lines and in the incident record. Its secret must not."""
    credential = _mint_as("fazerops.slack.handlers", **GRANT)
    object.__setattr__(credential, "secret_access_key", "SUPERSECRET")
    object.__setattr__(credential, "session_token", "SESSIONTOKEN")

    rendered = repr(credential)
    assert "SUPERSECRET" not in rendered
    assert "SESSIONTOKEN" not in rendered


def test_the_reader_principal_cannot_mutate():
    """A type-level fact, stated explicitly so a call site reads the answer rather than
    inferring it from the absence of a field."""
    assert reader_credential().can_mutate is False
    assert not hasattr(ReaderCredential, "spend")
