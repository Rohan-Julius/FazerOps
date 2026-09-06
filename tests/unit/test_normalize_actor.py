"""W3 — actor normalization. Handoff §3 calls this the hard part and the differentiator.

An actor bug makes one human look like three, or — worse — three humans look like one, and
the brief then names the wrong person as the author of the change.
"""

import pytest

from faberops.ledger.normalize import (
    IdentityMap,
    blast_radius_keys,
    default_identity_map,
    normalize_action,
    normalize_actor,
)
from faberops.models import NormalizedAction, ResourceRef

IAM_ARN = "arn:aws:iam::111122223333:user/dinesh"
ASSUMED_ROLE = "arn:aws:sts::111122223333:assumed-role/platform-engineer/dinesh"
K8S_USERNAME = "dinesh@faber-demo.io"
GITHUB_HANDLE = "dinesh-r"


@pytest.mark.parametrize(
    ("raw", "source"),
    [
        (IAM_ARN, "cloudtrail"),
        (ASSUMED_ROLE, "cloudtrail"),
        (K8S_USERNAME, "k8s_audit"),
        (GITHUB_HANDLE, "github"),
    ],
)
def test_one_human_across_three_sources_resolves_to_one_canonical_identity(raw, source):
    actor = normalize_actor(raw, source)
    assert actor.canonical == "dinesh"
    assert actor.resolved is True
    assert actor.kind == "human"
    assert actor.raw == raw  # the native identifier survives for the evidence trail


def test_unmapped_actor_passes_through_unresolved():
    """Handoff §3: partial mapping is fine. Guessing is not."""
    actor = normalize_actor("arn:aws:iam::111122223333:user/contractor", "cloudtrail")
    assert actor.resolved is False
    assert actor.canonical is None
    assert actor.display == "arn:aws:iam::111122223333:user/contractor"


def test_identifiers_do_not_leak_between_sources():
    """A GitHub handle appearing in a K8s audit log is not the same principal. Matching
    across sources without the map is how three humans become one."""
    assert normalize_actor(GITHUB_HANDLE, "k8s_audit").resolved is False
    assert normalize_actor(K8S_USERNAME, "github").resolved is False


def test_unmapped_principal_shape_is_inferred_but_attribution_is_not():
    service_account = normalize_actor("system:serviceaccount:kube-system:replicaset", "k8s_audit")
    assert service_account.kind == "service_account"
    assert service_account.resolved is False  # shape is a display hint, not an identity

    root = normalize_actor("arn:aws:iam::111122223333:root", "cloudtrail")
    assert root.kind == "root"


def test_pipeline_principal_is_reported_in_band():
    ci = normalize_actor("system:serviceaccount:ci:deployer", "k8s_audit")
    assert default_identity_map().is_in_band(ci) is True

    human = normalize_actor(K8S_USERNAME, "k8s_audit")
    assert default_identity_map().is_in_band(human) is False


def test_unresolved_actor_is_never_in_band():
    """Defaulting an unknown principal to in-band would hide exactly the hand-run
    `kubectl edit` the product exists to surface."""
    unknown = normalize_actor("someone-we-have-never-seen", "k8s_audit")
    assert default_identity_map().is_in_band(unknown) is False


def test_empty_identity_map_degrades_to_unresolved_rather_than_failing(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("identities: {}\n", encoding="utf-8")
    actor = IdentityMap.load(path).resolve(IAM_ARN, "cloudtrail")
    assert actor.resolved is False


# --- verbs ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("verb", "source", "expected"),
    [
        ("update", "k8s_audit", NormalizedAction.UPDATE),
        ("patch", "k8s_audit", NormalizedAction.UPDATE),
        ("create", "k8s_audit", NormalizedAction.CREATE),
        ("delete", "k8s_audit", NormalizedAction.DELETE),
        ("ModifyDBInstance", "cloudtrail", NormalizedAction.UPDATE),
        ("PutRolePolicy", "cloudtrail", NormalizedAction.UPDATE),
        ("AuthorizeSecurityGroupIngress", "cloudtrail", NormalizedAction.UPDATE),
        ("RevokeSecurityGroupIngress", "cloudtrail", NormalizedAction.REVOKE),
        ("RotateSecret", "cloudtrail", NormalizedAction.ROTATE),
        ("UpdateAutoScalingGroup", "cloudtrail", NormalizedAction.SCALE),
        ("SetDesiredCapacity", "cloudtrail", NormalizedAction.SCALE),
        ("upgrade", "helm", NormalizedAction.ROLLOUT),
        ("rollback", "helm", NormalizedAction.ROLLOUT),
    ],
)
def test_source_verbs_collapse_into_the_shared_vocabulary(verb, source, expected):
    assert normalize_action(verb, source) == expected


def test_unknown_verb_is_unknown_not_a_guess():
    """A wrong verb feeds a wrong type_prior, and the ranking then fails for a reason that
    looks like a scoring bug three modules away (W14)."""
    assert normalize_action("FrobnicateWidget", "cloudtrail") == NormalizedAction.UNKNOWN
    assert normalize_action("connect", "k8s_audit") == NormalizedAction.UNKNOWN


# --- blast radius stamping ------------------------------------------------------------


def test_event_is_stamped_with_its_own_key_and_owning_service():
    ref = ResourceRef(kind="ConfigMap", name="billing-api-config", namespace="billing")
    stamped = blast_radius_keys(ref)
    assert stamped == {"k8s:billing/configmap/billing-api-config", "service:billing-api"}


def test_a_resource_outside_the_manifest_still_gets_its_own_key():
    """An unmanifested resource is not evidence of nothing — it is just unattributed."""
    ref = ResourceRef(kind="ConfigMap", name="stray", namespace="default")
    assert blast_radius_keys(ref) == {"k8s:default/configmap/stray"}


def test_service_named_events_do_not_inherit_the_services_other_resource_keys():
    """A GitHub merge must not become retrievable by the RDS ARN. Over-stamping is how a
    ledger stops being evidence and starts being a guess."""
    ref = ResourceRef(kind="Repo", name="faber-demo/billing-api")
    stamped = blast_radius_keys(ref, services=["billing-api"])
    assert stamped == {"repo:faber-demo/billing-api", "service:billing-api"}
    assert not any(key.startswith("aws:") for key in stamped)
