"""W3 — normalization at the collector boundary. The highest-blast-radius module here.

Handoff §3 is explicit that this happens at the boundary and never downstream. Three
sources report the same instant three ways:

    CloudTrail   2026-09-06T14:03:11Z              UTC ISO8601
    K8s audit    2026-09-06T14:03:11.123456Z       RFC3339, variable sub-second precision
    Helm         Fri Sep  6 07:03:11 2026 -0700    local-formatted, offset appended

A timezone bug here does not raise. It reorders the causal chain, `temporal_proximity`
scores garbage, and the brief names the wrong change with total confidence — and you debug
the scorer for three hours looking for it. So every parse below is explicit, and a naive
timestamp raises rather than being assumed to be UTC.
"""

from __future__ import annotations

import functools
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ..models import Actor, ChangeSource, NormalizedAction, ResourceRef
from ..radius import ServiceManifest, default_manifest

DEFAULT_IDENTITY_MAP = Path(__file__).resolve().parents[3] / "config" / "identity_map.yaml"

# Python's fromisoformat accepts at most 6 fractional digits; RFC3339 permits more, and
# some audit backends emit nanoseconds. Truncate rather than reject — sub-microsecond
# precision is irrelevant to a 4-hour correlation window.
_FRACTION = re.compile(r"(\.\d{1,9})")

# Helm's `helm history` output, once whitespace is collapsed.
_HELM_FORMATS = (
    "%a %b %d %H:%M:%S %Y %z",  # with the offset Helm appends
    "%a %b %d %H:%M:%S %Y",  # without — rejected below, see parse_timestamp
)


class NaiveTimestampError(ValueError):
    """A timestamp arrived with no timezone. Assuming UTC is how the causal chain silently
    reorders; the collector must supply the offset its source actually reported."""


# --------------------------------------------------------------------------------------
# Time
# --------------------------------------------------------------------------------------


def parse_timestamp(value: str | datetime) -> datetime:
    """Parse any of the three source formats into a timezone-aware UTC datetime.

    Raises `NaiveTimestampError` if the input carries no offset. That is deliberate: every
    source in this build *does* report one, so a missing offset means the collector lost
    it, and defaulting to UTC would bury a real bug under a plausible-looking timestamp.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise NaiveTimestampError(f"naive datetime {value!r} — source offset was lost")
        return value.astimezone(timezone.utc)

    text = " ".join(value.strip().split())  # Helm pads single-digit days with two spaces

    iso_candidate = _FRACTION.sub(lambda m: m.group(1)[:7], text)
    try:
        parsed = datetime.fromisoformat(iso_candidate.replace("Z", "+00:00"))
    except ValueError:
        parsed = _parse_helm(text)
    else:
        if parsed.tzinfo is None:
            raise NaiveTimestampError(f"timestamp {value!r} carries no timezone offset")

    return parsed.astimezone(timezone.utc)


def _parse_helm(text: str) -> datetime:
    for fmt in _HELM_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            raise NaiveTimestampError(
                f"Helm timestamp {text!r} has no offset — run `helm history -o json`, "
                "which emits RFC3339, rather than parsing the table output"
            )
        return parsed
    raise ValueError(f"unrecognised timestamp format: {text!r}")


# --------------------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------------------


# The principal prefix a FazerOps-executed change carries: the Kubernetes username it impersonates
# (`security.credentials.kubernetes_identity`) and the STS session name it assumes. Defined here,
# on the investigation side, because the collectors must recognise it and must not import
# `security/credentials.py` (plan §3.5).
FAZEROPS_ACTOR_PREFIX = "fazerops:approved-by:"
FAZEROPS_SESSION_PREFIX = "fazerops-"
FAZEROPS_CANONICAL = "fazerops"


class IdentityMap:
    """`config/identity_map.yaml`, indexed for lookup by (source, raw principal)."""

    def __init__(self, identities: dict[str, dict], in_band_principals: list[str]) -> None:
        self._identities = identities
        self._in_band = set(in_band_principals)
        self._index: dict[tuple[str, str], str] = {}
        for canonical, spec in identities.items():
            for source in ("cloudtrail", "k8s_audit", "github", "helm"):
                for raw in spec.get(source) or []:
                    self._index[(source, raw)] = canonical

    @classmethod
    def load(cls, path: Path | str | None = None) -> IdentityMap:
        raw = yaml.safe_load(Path(path or DEFAULT_IDENTITY_MAP).read_text(encoding="utf-8")) or {}
        return cls(raw.get("identities") or {}, raw.get("in_band_principals") or [])

    def resolve(self, raw_principal: str, source: ChangeSource) -> Actor:
        canonical = self._index.get((source, raw_principal))

        if canonical is None and _is_fazerops(raw_principal, source):
            # Recognised by shape rather than listed: the approver is part of the principal, so
            # no finite list of entries could match. `raw` keeps who approved it.
            return Actor(raw=raw_principal, canonical=FAZEROPS_CANONICAL, resolved=True, kind="service_account")

        if canonical is None:
            return Actor(raw=raw_principal, resolved=False, kind=_infer_kind(raw_principal))

        spec = self._identities.get(canonical, {})
        return Actor(
            raw=raw_principal,
            canonical=canonical,
            resolved=True,
            kind=spec.get("kind", "unknown"),
        )

    def is_in_band(self, actor: Actor) -> bool:
        """Whether the change arrived through the pipeline. Reported to the user, never
        fed to the scorer — Handoff §3 calls boosting out-of-band changes circular."""
        return actor.resolved and actor.canonical in self._in_band


def _is_fazerops(raw_principal: str, source: ChangeSource) -> bool:
    if raw_principal.startswith(FAZEROPS_ACTOR_PREFIX):
        return True
    # CloudTrail's principal for an assumed role is the session name, which the actor credential
    # sets to `fazerops-{incident}-{action}`. Only there: a Kubernetes name may start `fazerops-`.
    return source == "cloudtrail" and raw_principal.startswith(f"{FAZEROPS_SESSION_PREFIX}INC-")


def _infer_kind(raw_principal: str) -> str:
    """Best-effort shape detection for principals with no identity-map entry. Only ever
    narrows the display, never the attribution — an unmapped actor stays unresolved."""
    if raw_principal.startswith("system:serviceaccount:"):
        return "service_account"
    if ":assumed-role/" in raw_principal:
        return "role"
    if raw_principal.endswith(":root") or raw_principal == "root":
        return "root"
    if raw_principal.startswith("arn:aws:iam::") and ":user/" in raw_principal:
        return "human"
    return "unknown"


@functools.lru_cache(maxsize=1)
def default_identity_map() -> IdentityMap:
    return IdentityMap.load()


def normalize_actor(raw_principal: str, source: ChangeSource) -> Actor:
    return default_identity_map().resolve(raw_principal, source)


# --------------------------------------------------------------------------------------
# Verbs
# --------------------------------------------------------------------------------------

_K8S_VERBS = {
    "create": NormalizedAction.CREATE,
    "update": NormalizedAction.UPDATE,
    "patch": NormalizedAction.UPDATE,
    "delete": NormalizedAction.DELETE,
    "deletecollection": NormalizedAction.DELETE,
}

# Ordered longest-prefix-first: `RevokeSecurityGroupIngress` must not match `Re...` before
# the more specific rules, and `RotateSecret` must not fall through to `Update`.
_CLOUDTRAIL_PREFIXES: tuple[tuple[str, NormalizedAction], ...] = (
    ("Revoke", NormalizedAction.REVOKE),
    ("Rotate", NormalizedAction.ROTATE),
    ("Create", NormalizedAction.CREATE),
    ("Delete", NormalizedAction.DELETE),
    ("Remove", NormalizedAction.DELETE),
    ("Terminate", NormalizedAction.DELETE),
    ("Modify", NormalizedAction.UPDATE),
    ("Update", NormalizedAction.UPDATE),
    ("Put", NormalizedAction.UPDATE),
    ("Attach", NormalizedAction.UPDATE),
    ("Detach", NormalizedAction.UPDATE),
    ("Authorize", NormalizedAction.UPDATE),
    ("SetDesiredCapacity", NormalizedAction.SCALE),
    ("UpdateAutoScalingGroup", NormalizedAction.SCALE),
)

_HELM_VERBS = {
    "install": NormalizedAction.CREATE,
    "upgrade": NormalizedAction.ROLLOUT,
    "rollback": NormalizedAction.ROLLOUT,
    "uninstall": NormalizedAction.DELETE,
}


def normalize_action(source_verb: str, source: ChangeSource) -> NormalizedAction:
    """Collapse a source's verb into the shared vocabulary.

    An unrecognised verb becomes `UNKNOWN` and is reported as such. It is never guessed
    into a neighbouring value, because a wrong verb feeds a wrong `type_prior` and the
    ranking then fails for a reason that looks like a scoring bug (W14).
    """
    if source == "k8s_audit":
        return _K8S_VERBS.get(source_verb.lower(), NormalizedAction.UNKNOWN)

    if source == "helm":
        return _HELM_VERBS.get(source_verb.lower(), NormalizedAction.UNKNOWN)

    if source == "github":
        return NormalizedAction.UPDATE  # a merge is a change to the repo's default branch

    if source == "cloudtrail":
        # Scale-specific event names are exact, not prefixes; check them first.
        for name, action in _CLOUDTRAIL_PREFIXES:
            if source_verb == name:
                return action
        for prefix, action in _CLOUDTRAIL_PREFIXES:
            if source_verb.startswith(prefix):
                return action
        return NormalizedAction.UNKNOWN

    return NormalizedAction.UNKNOWN


# --------------------------------------------------------------------------------------
# Blast radius stamping
# --------------------------------------------------------------------------------------


def blast_radius_keys(
    resource: ResourceRef,
    *,
    services: list[str] | None = None,
    manifest: ServiceManifest | None = None,
) -> set[str]:
    """Every key this event should be retrievable by.

    Handoff §3: populate at normalization time from the service manifest, never at query
    time. A query-time join cannot see the manifest as it stood when the event was
    recorded, so a manifest edit would silently rewrite history.
    """
    manifest = manifest or default_manifest()

    own_key = resource.blast_radius_key()
    result = {own_key}

    for service in manifest.owning_services(own_key):
        result.add(f"service:{service}")

    # Events that name a service rather than a resource — a Helm release, a GitHub merge.
    # Only the service key is added: stamping the service's *other* resource keys onto
    # this event would make a ConfigMap edit retrievable by the RDS ARN, which is how a
    # ledger stops being evidence and starts being a guess.
    for service in services or []:
        result.add(f"service:{service}")

    return result
