"""Plain-text brief renderer — the stdout surface, and the one the layer-seam test uses.

Slack Block Kit (W25) is the demo's visible surface, but this renderer is what proves the
seam: a `Brief` renders here with `faberops.actions` and `faberops.slack` deleted from the
process (plan §3.5). It also carries the clean-machine quickstart, where a judge with no
Slack workspace still sees the full finding.
"""

from __future__ import annotations

from ..collectors.github import render_ci_status
from ..models import Brief, Candidate

RULE = "─" * 68


def render_brief(brief: Brief) -> str:
    lines: list[str] = [
        RULE,
        f"FaberOps change brief · {brief.incident_id}",
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
    lines.append("")

    for candidate in brief.candidates:
        lines.extend(_render_candidate(candidate, brief))
        lines.append("")

    lines.append(render_ci_status(brief.ci_status))

    if brief.narrative:
        lines += ["", brief.narrative]

    if brief.degraded:
        lines += [
            "",
            "! Degraded: at least one change source was unavailable. "
            "This brief may be incomplete.",
        ]

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
