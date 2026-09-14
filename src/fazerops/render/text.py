"""Plain-text brief renderer — the stdout surface, and the one the layer-seam test uses.

Slack Block Kit (W25) is the demo's visible surface, but this renderer is what proves the
seam: a `Brief` renders here with `fazerops.actions` and `fazerops.slack` deleted from the
process (plan §3.5). It also carries the clean-machine quickstart, where a judge with no
Slack workspace still sees the full finding.
"""

from __future__ import annotations

import textwrap

from ..collectors.github import render_ci_status
from ..models import Brief, Candidate, CoverageGap, RankStability

RULE = "─" * 68

SOURCE_NAMES = {
    "cloudtrail": "CloudTrail",
    "k8s_audit": "The Kubernetes audit log",
    "helm": "Helm",
    "github": "GitHub",
    "flags": "Feature flags",
}


def describe_stability(stability: RankStability, brief: Brief) -> str:
    """One sentence on whether rank 1 depends on the weights. Shared with the Slack card so the
    two surfaces cannot word the claim differently."""
    if stability.dominant:
        return (
            "#1 is at least as high as every other change on every feature, so no choice of "
            f"weights ranks another change above it (lead {stability.margin:.2f})."
        )
    challenger = brief.candidates[(stability.challenger_rank or 2) - 1].event.resource
    return (
        f"Fragile: #{stability.challenger_rank} {challenger.kind} {challenger.name} draws level "
        f"if the {stability.feature} weight moves {stability.weight_from:.2f} → "
        f"{stability.weight_to:.2f} (lead {stability.margin:.2f})."
    )


def describe_coverage_gap(gap: CoverageGap) -> str:
    name = SOURCE_NAMES.get(gap.source, gap.source)
    if gap.status == "caught_up":
        arrived = (
            "no change arrived late"
            if gap.late_changes == 0
            else f"{gap.late_changes} change{'' if gap.late_changes == 1 else 's'} arrived late and "
            f"{'is' if gap.late_changes == 1 else 'are'} in the ranking above"
        )
        return f"{name} caught up at {gap.checked_at:%H:%M} UTC: {arrived}."
    if gap.status == "unreachable":
        return (
            f"{name} could not be re-checked at {gap.checked_at:%H:%M} UTC; changes after "
            f"{gap.unobserved.start:%H:%M} UTC may be missing from this brief."
        )
    return (
        f"{name} may not yet show changes after {gap.unobserved.start:%H:%M} UTC: its events can "
        f"arrive up to {gap.delivery_lag_minutes:.0f} min late, so late changes may still appear "
        f"until {gap.settles_at:%H:%M} UTC."
    )


def describe_reranked(brief: Brief) -> str | None:
    if brief.reranked_at is None:
        return None
    if brief.ranked_first_from is None:
        return f"Re-ranked at {brief.reranked_at:%H:%M} UTC after late changes arrived; #1 is unchanged."
    first = next((c.event.resource for c in brief.candidates if c.event.id == brief.ranked_first_from), None)
    was = f"{first.kind} {first.name}" if first is not None else brief.ranked_first_from
    return (
        f"Re-ranked at {brief.reranked_at:%H:%M} UTC after late changes arrived: when this brief "
        f"was first posted, #1 was {was}."
    )


def approval_card_note(brief: Brief) -> str | None:
    """What an approval card drafted from `brief`'s first ranking must say now, or `None`.

    A displaced rank 1 outranks an open gap: the card's proposal is already known to rest on a
    ranking that changed, which matters more than one that still might.
    """
    if brief.ranked_first_from is not None and brief.top is not None:
        top = brief.top.event.resource
        first = next((c.event.resource for c in brief.candidates if c.event.id == brief.ranked_first_from), None)
        was = f"{first.kind} {first.name}" if first is not None else brief.ranked_first_from
        return (
            f"Re-ranked at {brief.reranked_at:%H:%M} UTC after late changes arrived: #1 is now "
            f"{top.kind} {top.name}. This card was drafted when #1 was {was} — check it before approving."
        )
    still_open = [gap for gap in brief.coverage_gaps if gap.status == "open"]
    if still_open:
        gap = min(still_open, key=lambda g: g.unobserved.start)
        return (
            f"Changes recorded by {SOURCE_NAMES.get(gap.source, gap.source)} after {gap.unobserved.start:%H:%M} UTC "
            f"may still arrive until {gap.settles_at:%H:%M} UTC. If one does, this card will say so."
        )
    return None


def render_brief(brief: Brief) -> str:
    lines: list[str] = [
        RULE,
        f"FazerOps change brief · {brief.incident_id}",
        RULE,
        f"Alert     {brief.alert.summary}",
        f"Service   {brief.alert.service}",
        f"Fired     {_stamp(brief.alert.fired_at)}",
        f"Window    {_stamp(brief.window.start)} → {_stamp(brief.window.end)}"
        f"  ({brief.window.hours:.0f}h)",
        "",
    ]

    if not brief.radius.keys:
        # Said out loud rather than rendered as an empty candidate list, which would read
        # as "nothing changed" when the truth is "we did not know where to look".
        lines += [
            f"Could not resolve '{brief.alert.service}' in config/service_manifest.yaml.",
            "No blast radius, so no changes were searched for.",
            RULE,
        ]
        return "\n".join(lines)

    count = len(brief.candidates)
    plural = "" if count == 1 else "s"
    lines.append(
        f"{count} change{plural} touching {brief.alert.service}'s blast radius "
        f"in the last {brief.window.hours:.0f}h"
    )
    reranked = describe_reranked(brief)
    if reranked:
        lines.append(f"! {reranked}")
    lines.append("")

    for candidate in brief.candidates:
        lines.extend(_render_candidate(candidate, brief))
        lines.append("")

    if brief.stability is not None:
        wrapped = textwrap.wrap(describe_stability(brief.stability, brief), width=len(RULE) - 10)
        lines += [f"Ranking   {wrapped[0]}", *(f"          {line}" for line in wrapped[1:]), ""]

    lines.append(render_ci_status(brief.ci_status))

    if brief.narrative:
        lines += ["", brief.narrative]

    if brief.degraded:
        lines += [
            "",
            "! Degraded: at least one change source was unavailable. "
            "This brief may be incomplete.",
        ]

    for gap in brief.coverage_gaps:
        lines += ["", f"! {describe_coverage_gap(gap)}"]

    lines.append(RULE)
    return "\n".join(lines)


def _render_candidate(candidate: Candidate, brief: Brief) -> list[str]:
    event = candidate.event
    minutes_before = (brief.alert.fired_at - event.occurred_at).total_seconds() / 60.0

    heading = (
        f"#{candidate.rank}  {event.resource.kind} {event.resource.name}"
        f"  ·  score {candidate.score:.2f}"
    )
    lines = [
        heading,
        f"    {event.action.value} by {event.actor.display}"
        f"{'' if event.actor.resolved else ' (unresolved identity)'}"
        f", {minutes_before:.0f} minutes before the alert",
    ]

    if event.diff and event.diff.fields_changed:
        for field in event.diff.fields_changed:
            before = (event.diff.before or {}).get(field)
            after = (event.diff.after or {}).get(field)
            if event.diff.prior_value_captured:
                lines.append(f"    {field}: {before} → {after}")
            else:
                # Plan §3.6 — CloudTrail rarely carries the prior value. Say so rather
                # than reconstructing it, which is a multi-hour build for a claim the
                # video never shows.
                lines.append(f"    {field}: {after}  (new value; prior value not captured)")

    lines.append(f"    in band: {'yes' if event.in_band else 'no'}  ·  evidence {event.id}")

    if event.reversible:
        lines.append("    reversible: inverse computed")

    return lines


def _stamp(moment) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")
