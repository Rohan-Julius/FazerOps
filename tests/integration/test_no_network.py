"""Plan §3.4 — the zero-network guarantee is a test, and it is written on day one.

Retrofitting this after boto3 clients have leaked into module scope is half a day of
untangling. The failure it prevents is not an exception: a boto3 client constructed in
fixture mode reaches for IMDS and hangs for the credential-chain timeout, which on a
judge's clean machine looks exactly like the demo being broken.

Three things are removed, because any one of them alone is insufficient:

1. `socket.socket` raises        — nothing can open a connection
2. every `AWS_*` var is cleared  — nothing can read credentials from the environment
3. `HOME` points at a tmpdir     — `~/.aws/credentials` and `~/.kube/config` cannot be found
"""

from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta, timezone

import pytest

from faberops.collectors.base import BaseCollector
from faberops.config import ConfigError, is_offline, llm_mode, mode
from faberops.ledger.normalize import blast_radius_keys, normalize_action, normalize_actor
from faberops.models import BlastRadius, ChangeEvent, ResourceRef, TimeWindow
from faberops.radius import ServiceManifest

ALERT_TIME = datetime(2026, 9, 6, 14, 41, tzinfo=timezone.utc)


class NetworkAccessAttempted(AssertionError):
    """Raised in place of opening a socket, so the offending call site is in the traceback
    rather than showing up as a timeout somewhere unrelated."""


@pytest.fixture
def no_network(tmp_path, monkeypatch):
    """The full isolation. Anything that reaches the network under this fails loudly."""

    real_socket = socket.socket

    def _guarded_socket(family=socket.AF_INET, *args, **kwargs):
        # AF_UNIX is allowed: asyncio's event loop builds a self-pipe socketpair, and a
        # unix socket cannot reach a network by construction. Blocking it would fail every
        # async test for a reason that has nothing to do with the guarantee under test.
        if family in (socket.AF_INET, socket.AF_INET6):
            raise NetworkAccessAttempted(
                "the fixture path opened a network socket — see plan §3.4"
            )
        return real_socket(family, *args, **kwargs)

    def _forbidden(*args, **kwargs):
        raise NetworkAccessAttempted("the fixture path reached the network — see plan §3.4")

    monkeypatch.setattr(socket, "socket", _guarded_socket)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", _forbidden)  # DNS is network access too

    for name in [key for key in list(__import__("os").environ) if key.startswith("AWS_")]:
        monkeypatch.delenv(name, raising=False)

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("FABEROPS_MODE", "fixture")
    monkeypatch.setenv("FABEROPS_LLM", "stub")
    return tmp_path


class _K8sAuditFixtureCollector(BaseCollector):
    source = "k8s_audit"
    fixture_dir = "k8s_audit"

    def _normalize(self, raw):
        ref = ResourceRef(
            kind="ConfigMap",
            name=raw["objectRef"]["name"],
            namespace=raw["objectRef"]["namespace"],
        )
        return ChangeEvent(
            id=raw["auditID"],
            source="k8s_audit",
            occurred_at=raw["requestReceivedTimestamp"],
            actor=normalize_actor(raw["user"]["username"], "k8s_audit"),
            action=normalize_action(raw["verb"], "k8s_audit"),
            resource=ref,
            in_band=False,
            raw_ref=f"audit#{raw['auditID']}",
            blast_radius_keys=blast_radius_keys(ref),
        )


async def test_the_fixture_pipeline_runs_with_no_socket_no_credentials_no_home(
    no_network, monkeypatch
):
    """The judge's first five minutes, asserted: clean machine, nothing configured."""
    fixture_dir = no_network / "k8s_audit"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "configmap_edit.json").write_text(
        json.dumps(
            [
                {
                    "auditID": "audit-1",
                    "verb": "update",
                    "user": {"username": "dinesh@faber-demo.io"},
                    "requestReceivedTimestamp": "2026-09-06T14:03:11.123456Z",
                    "objectRef": {
                        "resource": "configmaps",
                        "name": "billing-api-config",
                        "namespace": "billing",
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("faberops.collectors.base.FIXTURE_ROOT", no_network)

    radius = ServiceManifest.load().resolve("billing-api")
    window = TimeWindow(start=ALERT_TIME - timedelta(hours=4), end=ALERT_TIME)

    result = await _K8sAuditFixtureCollector().fetch(radius, window)

    assert result.ok is True
    assert [event.resource.name for event in result.events] == ["billing-api-config"]
    assert result.events[0].actor.canonical == "dinesh"


def test_the_isolation_fixture_actually_blocks_sockets(no_network):
    """A guard that does not guard passes every test for the wrong reason."""
    with pytest.raises(NetworkAccessAttempted):
        socket.socket()  # defaults to AF_INET

    with pytest.raises(NetworkAccessAttempted):
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    with pytest.raises(NetworkAccessAttempted):
        socket.getaddrinfo("bedrock-runtime.us-east-1.amazonaws.com", 443)


def test_the_isolation_fixture_still_permits_unix_sockets(no_network):
    """Deliberately narrow: asyncio needs a socketpair, and a unix socket cannot reach a
    network. Widening the guard here would fail every async test for the wrong reason."""
    left, right = socket.socketpair()
    left.close()
    right.close()


def test_no_aws_credentials_are_visible(no_network):
    import os

    assert not [key for key in os.environ if key.startswith("AWS_")]
    assert not (no_network / ".aws").exists()


def test_the_manifest_and_identity_map_load_without_network_or_home(no_network):
    """Both are read from the repo, not from a config service. Stated as a test because a
    future 'just fetch it from S3' would break the clean-machine quickstart silently."""
    manifest = ServiceManifest.load()
    assert "billing-api" in manifest.service_names
    assert normalize_actor("dinesh@faber-demo.io", "k8s_audit").canonical == "dinesh"


def test_offline_is_the_default_when_nothing_is_configured(monkeypatch):
    """A judge who exports nothing gets the zero-credential path."""
    monkeypatch.delenv("FABEROPS_MODE", raising=False)
    monkeypatch.delenv("FABEROPS_LLM", raising=False)

    assert mode().value == "fixture"
    assert llm_mode().value == "stub"
    assert is_offline() is True


@pytest.mark.parametrize(
    ("mode_value", "llm_value", "expected"),
    [
        ("fixture", "stub", True),
        ("fixture", "cassette", True),
        ("fixture", "nova", False),  # the model call still needs the network
        ("live", "stub", False),
        ("live", "demo", False),
    ],
)
def test_offline_requires_both_switches(monkeypatch, mode_value, llm_value, expected):
    monkeypatch.setenv("FABEROPS_MODE", mode_value)
    monkeypatch.setenv("FABEROPS_LLM", llm_value)
    assert is_offline() is expected


def test_an_invalid_switch_fails_loudly_rather_than_defaulting(monkeypatch):
    """Silently falling back to a default means running the wrong path on demo day."""
    monkeypatch.setenv("FABEROPS_LLM", "claude-opus")
    with pytest.raises(ConfigError, match="claude-opus"):
        llm_mode()


def test_require_offline_capable_blocks_client_construction(no_network):
    from faberops.config import require_offline_capable

    with pytest.raises(RuntimeError, match="must not touch the network"):
        require_offline_capable("CloudTrailCollector")
