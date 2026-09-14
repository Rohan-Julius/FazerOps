"""The actor role's policy templates agree with what `security/credentials.py` actually sends.

Found live on 14 Sep: the first trust policy put `sts:TagSession` under the same `sts:SourceIdentity`
condition as `sts:AssumeRole`. AWS authorizes tagging as its own step and that condition fails there,
so every tagged assume — every approval FazerOps would ever make — was refused. These assertions pin
the shape that was then verified against a real role, so an edit cannot quietly reintroduce it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fazerops.security import credentials

POLICIES = Path(__file__).resolve().parents[2] / "config" / "aws"


def _load(name: str) -> dict:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def _statements_for(policy: dict, action: str) -> list[dict]:
    found = []
    for statement in policy["Statement"]:
        actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
        if action in actions:
            found.append(statement)
    return found


@pytest.fixture
def sent_tags(monkeypatch) -> list[dict]:
    """The tags `_assume` really sends, captured from a recording STS client."""
    monkeypatch.setenv("FAZEROPS_MODE", "live")
    calls: list[dict] = []

    class STS:
        def assume_role(self, **kwargs):
            calls.append(kwargs)
            return {"Credentials": {"AccessKeyId": "synthetic", "SecretAccessKey": "synthetic", "SessionToken": "synthetic"}}

    credentials._assume(
        STS(),
        role_arn="arn:aws:iam::111122223333:role/fazerops-actor",
        namespace="billing-primary-params",
        action_id="restore_db_parameter",
        incident_id="INC-1",
        approver="U0MGR",
    )
    return calls[0]["Tags"]


def test_assuming_requires_a_slack_source_identity():
    trust = _load("fazerops-actor-trust-policy.json")
    for action in ("sts:AssumeRole", "sts:SetSourceIdentity"):
        [statement] = _statements_for(trust, action)
        assert statement["Condition"]["StringLike"]["sts:SourceIdentity"] == "slack-*"


def test_tag_session_is_not_gated_on_the_source_identity():
    """The live failure. A `sts:SourceIdentity` condition on `sts:TagSession` refuses every tagged assume."""
    trust = _load("fazerops-actor-trust-policy.json")
    [statement] = _statements_for(trust, "sts:TagSession")

    assert "sts:SourceIdentity" not in json.dumps(statement.get("Condition", {}))
    assert "sts:AssumeRole" not in json.dumps(statement["Action"]), "tagging alone must not grant assuming"


def test_tag_session_allows_exactly_the_tag_keys_fazerops_sends(sent_tags):
    trust = _load("fazerops-actor-trust-policy.json")
    [statement] = _statements_for(trust, "sts:TagSession")

    allowed = set(statement["Condition"]["ForAllValues:StringEquals"]["aws:TagKeys"])
    assert allowed == {tag["Key"] for tag in sent_tags}


def test_the_permissions_policy_grants_what_the_session_policy_names_and_no_more():
    permissions = _load("fazerops-actor-permissions-policy.json")
    granted = {action for statement in permissions["Statement"] for action in statement["Action"]}

    assert granted == set(credentials._ACTIONS_FOR["restore_db_parameter"])


def test_no_real_account_id_is_committed():
    """Any 12-digit number is an account id. Checked by shape so this file does not have to name one."""
    import re

    for path in POLICIES.glob("*"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"(?<!\d)\d{12}(?!\d)", text), f"{path.name} contains an AWS account id"
        if path.suffix == ".json":
            assert "ACCOUNT_ID" in text, f"{path.name} lost its placeholder"
