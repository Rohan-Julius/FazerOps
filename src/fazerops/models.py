"""The normalized data model. Handoff §3: the `ChangeEvent` is the product; everything
else is plumbing around it.

Two invariants are enforced here rather than downstream, because both fail silently:

* `occurred_at` must be timezone-aware. CloudTrail is UTC ISO8601, the K8s audit log is
  RFC3339 with variable sub-second precision, and Helm returns a local-formatted string.
  A naive datetime that slips through reorders the causal chain, and the symptom surfaces
  in the correlation scorer — three layers from the cause.
* `reversible=True` with no `inverse_hint` is a contradiction. Ground rule #4 says every
  mutating action computes its inverse before executing; an event that claims to be
  reversible without carrying the means to reverse it breaks that promise at the
  executor, on camera.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

# --------------------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------------------

ChangeSource = Literal["cloudtrail", "k8s_audit", "helm", "github", "flags"]


class NormalizedAction(str, Enum):
    """The verb vocabulary every source collapses into (Handoff §3).

    Deliberately small. An unrecognised source verb maps to `UNKNOWN` and is reported as
    such — it is never guessed into one of the others, because a wrong verb feeds a wrong
    `type_prior` and the ranking then fails for a reason that looks like a scoring bug.
    """

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    SCALE = "scale"
    ROLLOUT = "rollout"
    REVOKE = "revoke"
    ROTATE = "rotate"
    UNKNOWN = "unknown"


class AlertClass(str, Enum):
    """W13's classification target. `UNCLASSIFIED` is a real outcome, never a fallback
    guess — see `tests/unit/test_alert_classify.py`."""

    LATENCY_SPIKE = "latency_spike"
    ERROR_RATE_SPIKE = "error_rate_spike"
    CONNECTION_REFUSED = "connection_refused"
    AUTH_FAILURE = "auth_failure"
    OOM = "oom"
    DISK_PRESSURE = "disk_pressure"
    UNCLASSIFIED = "unclassified"


class Tier(int, Enum):
    """Declared in the action catalog, never inferred at runtime. `thresholds.yaml` may
    only promote T1 -> T2; nothing ever demotes (Handoff §7)."""

    READ_ONLY = 0
    ENGINEER_APPROVAL = 1
    MANAGER_APPROVAL = 2


# --------------------------------------------------------------------------------------
# Identity and resources
# --------------------------------------------------------------------------------------


class Actor(BaseModel):
    """Handoff §3: actor normalization is the hard part and the differentiator. The same
    human is an IAM ARN in CloudTrail, a username in the K8s audit log, and a handle in
    GitHub. Unmapped actors pass through with `resolved=False` rather than being dropped
    or guessed — an unresolved actor is honest; a wrongly-merged one makes three humans
    look like one.
    """

    model_config = ConfigDict(frozen=True)

    raw: str = Field(description="The principal exactly as the source reported it")
    canonical: str | None = Field(default=None, description="Identity-map resolution")
    resolved: bool = False
    kind: Literal["human", "service_account", "role", "root", "unknown"] = "unknown"
    source_ip: str | None = None

    @model_validator(mode="after")
    def _resolved_implies_canonical(self) -> Actor:
        if self.resolved and not self.canonical:
            raise ValueError("resolved=True requires a canonical identity")
        return self

    @property
    def display(self) -> str:
        return self.canonical or self.raw


class ResourceRef(BaseModel):
    """What a change touched, in whichever coordinate system its source uses."""

    model_config = ConfigDict(frozen=True)

    kind: str = Field(description="ConfigMap, Deployment, DBInstance, SecurityGroup, ...")
    name: str
    namespace: str | None = None
    region: str | None = None
    account: str | None = None
    arn: str | None = None
    cluster: str | None = None

    def blast_radius_key(self) -> str:
        """The canonical identifier this resource is indexed under.

        The *same* function must produce the key on both sides of the index — the
        collectors that write events (W3) and the resolver that queries them (W4). If the
        two ever disagree the ledger returns an empty candidate set and reports, with
        total confidence, that nothing changed.
        """
        if self.arn:
            return f"aws:{self.arn}"
        if self.namespace:
            return f"k8s:{self.namespace}/{self.kind.lower()}/{self.name}"
        return f"{self.kind.lower()}:{self.name}"


class Diff(BaseModel):
    """Before/after where obtainable. CloudTrail generally cannot supply `before` — per
    plan §3.6 we show the requested value labelled honestly rather than reconstructing it.
    """

    model_config = ConfigDict(frozen=True)

    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    prior_value_captured: bool = Field(
        default=True,
        description="False renders as 'new value; prior value not captured' (plan §3.6)",
    )
    field_path: str | None = Field(
        default=None,
        description="Which map of the object the diff is over, when a source records more "
        "than one. The audit collector sets `binaryData` for a ConfigMap's binary map and "
        "leaves `data` implicit. Structural, never projected into model context.",
    )

    @property
    def fields_changed(self) -> list[str]:
        keys = set(self.before or {}) | set(self.after or {})
        return sorted(k for k in keys if (self.before or {}).get(k) != (self.after or {}).get(k))


# --------------------------------------------------------------------------------------
# The ledger record
# --------------------------------------------------------------------------------------


class ChangeEvent(BaseModel):
    """One normalized infrastructure mutation. Handoff §3."""

    model_config = ConfigDict(frozen=True)

    id: str
    source: ChangeSource
    occurred_at: AwareDatetime
    actor: Actor
    action: NormalizedAction
    resource: ResourceRef
    diff: Diff | None = None

    blast_radius_keys: set[str] = Field(
        default_factory=set,
        description="Populated at normalization time from the service manifest, never at "
        "query time (Handoff §3) — a query-time join cannot see the manifest as it stood "
        "when the event was recorded.",
    )

    in_band: bool = Field(
        description="Did this arrive via CI/CD? Reported to the user; deliberately NOT a "
        "correlation feature. Boosting a change because it is out-of-band is circular "
        "reasoning, and W15's test asserts it is not an input to the score."
    )

    reversible: bool = False
    inverse_hint: dict[str, Any] | None = Field(
        default=None,
        description="Opaque to the investigation layer. Only actions/inverse.py "
        "interprets it (plan §3.5).",
    )
    raw_ref: str = Field(description="Pointer to the original payload, never its contents")

    @field_validator("occurred_at")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        """`AwareDatetime` has already rejected naive input; collapse the rest to UTC so
        ordering is total across sources with different offsets."""
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _reversible_requires_inverse(self) -> ChangeEvent:
        if self.reversible and self.inverse_hint is None:
            raise ValueError(
                "reversible=True requires an inverse_hint — ground rule #4: an action "
                "that cannot compute its inverse must not claim to be reversible"
            )
        return self


# --------------------------------------------------------------------------------------
# Investigation inputs
# --------------------------------------------------------------------------------------


class TimeWindow(BaseModel):
    """Half-open `[start, end)`. Stated explicitly because an inclusive end double-counts
    an event that lands exactly on the alert timestamp."""

    model_config = ConfigDict(frozen=True)

    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode="after")
    def _ordered(self) -> TimeWindow:
        if self.start >= self.end:
            raise ValueError(f"window start {self.start} is not before end {self.end}")
        return self

    def contains(self, moment: datetime) -> bool:
        return self.start <= moment < self.end

    @property
    def hours(self) -> float:
        return (self.end - self.start).total_seconds() / 3600.0


class BlastRadius(BaseModel):
    """Resolved from `config/service_manifest.yaml`, one hop through `depends_on`
    (Handoff §4). Two hops explodes the candidate set."""

    model_config = ConfigDict(frozen=True)

    service: str
    keys: set[str] = Field(default_factory=set)
    direct_keys: set[str] = Field(
        default_factory=set,
        description="Keys belonging to the named service itself. The one-hop dependency "
        "keys score lower in W14's radius_overlap, so the two are kept distinct.",
    )

    def overlaps(self, event_keys: set[str]) -> bool:
        return bool(self.keys & event_keys)


class Alert(BaseModel):
    """Normalized from any of three payload shapes — Alertmanager, CloudWatch, PagerDuty
    (Idea.md §6 promises generic ingest).

    `summary` is attacker-influenceable: it can contain user input echoed through an error
    string. It only ever reaches a model inside W16's `<untrusted_data>` envelope.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    service: str
    summary: str
    fired_at: AwareDatetime
    alert_class: AlertClass = AlertClass.UNCLASSIFIED
    severity: str | None = None
    payload_shape: Literal["alertmanager", "cloudwatch", "pagerduty"] | None = None
    raw_ref: str | None = None

    @field_validator("fired_at")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(timezone.utc)


# --------------------------------------------------------------------------------------
# The seam — plan §3.5. Frozen contract between investigation and automation.
# --------------------------------------------------------------------------------------


class Candidate(BaseModel):
    """A scored `ChangeEvent`. `features` is carried alongside the score so the brief can
    explain *why* something ranked where it did without the model re-deriving it —
    ground rule #3, deterministic maths in Python."""

    model_config = ConfigDict(frozen=True)

    event: ChangeEvent
    score: float = Field(ge=0.0, le=1.0)
    features: dict[str, float] = Field(default_factory=dict)
    rank: int = Field(ge=1)

    @property
    def inverse_hint(self) -> dict[str, Any] | None:
        """Opaque passthrough. The investigation layer never interprets this."""
        return self.event.inverse_hint


class CIStatus(BaseModel):
    """W11a — the pitch's punchline, as data rather than as a hardcoded string.

    Idea.md §7 chose the demo scenario so the cause is *invisible to GitHub*. The renderer
    branches on `merge_count`, so the line is only ever true because the data says so.
    """

    model_config = ConfigDict(frozen=True)

    merge_count: int = Field(ge=0)
    repos_checked: list[str] = Field(default_factory=list)


class CoverageGap(BaseModel):
    """The part of the window a source answered for but could not yet see.

    A source whose events arrive late — CloudTrail's do — returns *ok, zero events* for the
    minutes before the alert, which are exactly the minutes `temporal_proximity` scores
    highest. That is not a failed source, so it is not `degraded` (every live brief built at
    alert time would be); it is a stated hole in the evidence, rendered as such.
    """

    model_config = ConfigDict(frozen=True)

    source: ChangeSource
    unobserved: TimeWindow
    delivery_lag_minutes: float = Field(gt=0)
    status: Literal["open", "caught_up", "unreachable"] = Field(
        default="open",
        description="`open` while late changes may still arrive; closed by `coverage.watch_coverage` "
        "once the source has had its full lag to deliver, or could not be reached to check.",
    )
    checked_at: AwareDatetime | None = None
    late_changes: int = Field(default=0, ge=0)

    @property
    def settles_at(self) -> datetime:
        """When a re-query of the same window would see everything the source will deliver."""
        return self.unobserved.end + timedelta(minutes=self.delivery_lag_minutes)


class RankStability(BaseModel):
    """Whether rank 1 depends on the weights (`correlation/sensitivity.py`).

    A statement about the scorer, not about the world: rendered for the human, never
    projected into model context, never an input to a score.
    """

    model_config = ConfigDict(frozen=True)

    dominant: bool = Field(
        description="Rank 1 is >= every other candidate on every feature, so no non-negative "
        "weighting can rank another candidate above it."
    )
    margin: float
    challenger_rank: int | None = None
    feature: str | None = None
    weight_from: float | None = None
    weight_to: float | None = Field(
        default=None,
        description="The single-weight value at which the challenger draws level with rank 1 "
        "— the smallest such change across every feature and challenger.",
    )


class Brief(BaseModel):
    """What the investigation layer emits. Plan §3.5: a `Brief` must render — to Slack,
    stdout or markdown — with the entire automation layer deleted."""

    model_config = ConfigDict(frozen=True)

    incident_id: str
    alert: Alert
    radius: BlastRadius
    window: TimeWindow
    candidates: list[Candidate] = Field(default_factory=list)
    ci_status: CIStatus
    narrative: str | None = Field(
        default=None,
        description="Authored by the correlator agent. Every claim carries an evidence "
        "id or W18's validator drops it.",
    )
    evidence_ids: list[str] = Field(default_factory=list)
    degraded: bool = Field(
        default=False,
        description="True when a collector failed or the orchestrator hit its turn cap. "
        "The brief still renders; it says so rather than silently reporting less.",
    )
    stability: RankStability | None = Field(
        default=None, description="None with fewer than two candidates."
    )
    coverage_gaps: list[CoverageGap] = Field(default_factory=list)
    reranked_at: AwareDatetime | None = Field(
        default=None, description="When late changes last changed this brief's ranking."
    )
    ranked_first_from: str | None = Field(
        default=None,
        description="The event that was rank 1 when the brief was first posted, set only while a "
        "late change has displaced it. The proposal and any approval card were drafted from that "
        "ranking, and say so.",
    )

    @model_validator(mode="after")
    def _ranks_are_dense_and_ordered(self) -> Brief:
        expected = list(range(1, len(self.candidates) + 1))
        actual = [c.rank for c in self.candidates]
        if actual != expected:
            raise ValueError(f"candidate ranks must be 1..n in order, got {actual}")
        return self

    @property
    def top(self) -> Candidate | None:
        return self.candidates[0] if self.candidates else None


class Proposal(BaseModel):
    """What the automation layer emits, and the entire attack surface of the model's
    output. `action_id` is validated against the catalog; there is no free-form command
    string anywhere in this object (ground rule #1)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)
    tier: Tier = Tier.ENGINEER_APPROVAL
