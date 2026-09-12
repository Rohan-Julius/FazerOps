"""W25 — Block Kit rendering. Handoff §9.

Two message types, and they are deliberately separate functions rather than one renderer
with a flag:

* **Change brief** (Tier 0, posted automatically) — header, window and sources, the top
  three candidates with a collapsed diff, an explicit CI-status line, then the proposal
  block with Approve / Reject / Show all changes.
* **Approval card** — the action in plain language, the dry-run diff in a code block, the
  computed inverse stated explicitly, and the tier with, for Tier 2, why it escalated.

**Nothing here performs I/O.** These functions take a `Brief` and a `DryRun` and return
JSON-serializable lists, which is what lets `tests/unit/test_blocks.py` run in the CI
default with no token, no socket and no workspace. `handlers.py` is the only module in
this package that talks to Slack.

Two constraints are enforced in code rather than trusted to fit:

* **Slack rejects a message with more than 50 blocks**, and rejects the whole message —
  so a brief with many candidates would fail to post at the moment it mattered most.
  `_bounded` trims and says how many were dropped, rather than letting Slack refuse.
* **Every string sourced from an alert or a diff is escaped** (`_escape`). Slack mrkdwn
  cannot execute anything, but a ConfigMap value containing `*Approved by SRE*` renders
  as bold text that reads like the system said it. Ground rule #2 treats that text as
  attacker-influenceable everywhere it is displayed, not only where it enters a model.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ..models import Brief, Candidate, Tier

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..actions.dry_run import DryRun

__all__ = [
    "BLOCK_LIMIT",
    "TOP_CANDIDATES",
    "approval_card",
    "change_brief",
]

# Slack's hard limit. A message over it is rejected whole, not truncated by Slack.
BLOCK_LIMIT = 50

# Handoff §9: "top three candidates". The rest reach a human through "Show all changes".
TOP_CANDIDATES = 3

# Slack rejects an interactive element whose `value` exceeds 2000 characters.
_VALUE_LIMIT = 2000

# A collapsed diff is a summary, not a record. Beyond this the card stops being scannable
# and the operator stops reading it, which is worse than an explicit "N more".
_DIFF_LINES = 4


def change_brief(
    brief: Brief, *, proposal_summary: str | None = None, action_id: str | None = None
) -> list[dict[str, Any]]:
    """The Tier 0 brief, posted automatically when an investigation completes.

    `proposal_summary` and `action_id` come from the automation layer (W22). They are
    optional because the brief is a Tier 0 artifact that must post whether or not any
    action was proposed — an investigation that found a cause nobody has an action for is
    still the product, and suppressing the brief until a proposal exists would hide it.
    """
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": _plain(f"{brief.alert.service} · {_alert_class_label(brief)}"),
        },
        {
            "type": "context",
            "elements": [
                _mrkdwn(
                    f"*{brief.incident_id}*  ·  fired {_stamp(brief.alert.fired_at)}  ·  "
                    f"searched {brief.window.hours:.0f}h across "
                    f"cloudtrail, k8s_audit, helm, github"
                )
            ],
        },
        {"type": "section", "text": _mrkdwn(f"> {_escape(brief.alert.summary)}")},
    ]

    if not brief.radius.keys:
        # The same distinction the text renderer draws: "we did not know where to look" is
        # not "nothing changed", and an empty candidate list on a card reads as the latter.
        blocks.append(
            {
                "type": "section",
                "text": _mrkdwn(
                    f":warning: Could not resolve *{_escape(brief.alert.service)}* in the "
                    "service manifest. No blast radius, so no changes were searched for."
                ),
            }
        )
        return _bounded(blocks)

    shown = brief.candidates[:TOP_CANDIDATES]
    remaining = len(brief.candidates) - len(shown)

    blocks.append({"type": "divider"})
    for candidate in shown:
        blocks.extend(_candidate_blocks(candidate, brief))

    blocks.append({"type": "context", "elements": [_mrkdwn(_ci_line(brief))]})

    if brief.narrative:
        blocks.append({"type": "section", "text": _mrkdwn(_escape(brief.narrative))})

    if brief.degraded:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    _mrkdwn(
                        ":warning: *Degraded* — at least one change source was "
                        "unavailable. This brief may be incomplete."
                    )
                ],
            }
        )

    blocks.extend(
        _proposal_blocks(
            brief,
            proposal_summary=proposal_summary,
            action_id=action_id,
            remaining=remaining,
        )
    )
    return _bounded(blocks)


def approval_card(
    dry_run: DryRun,
    *,
    incident_id: str,
    tier: Tier,
    escalation_reason: str | None = None,
) -> list[dict[str, Any]]:
    """The approval card. Handoff §9's four required elements, in its order.

    `tier` is passed in rather than read from the catalog here, because it is the
    *effective* tier after `thresholds.yaml` promotion (W26) — a card that displayed the
    declared tier would understate an escalation on precisely the action that escalated.
    """
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": _plain("Approval required")},
        {"type": "section", "text": _mrkdwn(f"*{_escape(dry_run.summary)}*")},
        {
            "type": "context",
            "elements": [_mrkdwn(f"`{_escape(dry_run.target)}`  ·  *{incident_id}*")],
        },
        {"type": "section", "text": _mrkdwn(_code(_diff_text(dry_run)))},
    ]

    # Ground rule #4 on the one surface an operator actually reads. An action whose inverse
    # could not be computed says so here in the same words `execute()` will refuse with,
    # rather than letting someone approve something that is about to refuse.
    if dry_run.reversible:
        blocks.append(
            {
                "type": "section",
                "text": _mrkdwn(f"*Inverse*  `{_escape(dry_run.inverse_summary or '')}`"),
            }
        )
    else:
        blocks.append(
            {
                "type": "section",
                "text": _mrkdwn(
                    ":no_entry: *No inverse could be computed.* This action will refuse "
                    "to execute (ground rule #4)."
                ),
            }
        )

    blocks.append({"type": "context", "elements": [_mrkdwn(_tier_line(tier, escalation_reason))]})

    for note in dry_run.notes:
        blocks.append({"type": "context", "elements": [_mrkdwn(f":information_source: {_escape(note)}")]})

    # The buttons are omitted entirely when the action cannot run. Rendering a disabled
    # Approve is not a thing Block Kit offers, and rendering a live one next to a refusal
    # invites the click that the refusal exists to prevent.
    if dry_run.reversible and not dry_run.unmet_preconditions:
        blocks.append(
            _actions(
                incident_id,
                dry_run.action_id,
                include_show_all=False,
                approve_style="danger" if tier is Tier.MANAGER_APPROVAL else "primary",
            )
        )

    return _bounded(blocks)


# --------------------------------------------------------------------------------------
# Pieces
# --------------------------------------------------------------------------------------


def _candidate_blocks(candidate: Candidate, brief: Brief) -> list[dict[str, Any]]:
    event = candidate.event
    minutes = (brief.alert.fired_at - event.occurred_at).total_seconds() / 60.0

    heading = (
        f"*#{candidate.rank}  {_escape(event.resource.kind)} "
        f"{_escape(event.resource.name)}*  ·  score `{candidate.score:.2f}`"
    )
    detail = (
        f"{event.action.value} by *{_escape(event.actor.display)}*"
        f"{'' if event.actor.resolved else ' _(unresolved identity)_'}, "
        f"{minutes:.0f} min before the alert"
    )

    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": _mrkdwn(f"{heading}\n{detail}")}
    ]

    diff = _collapsed_diff(event)
    if diff:
        blocks.append({"type": "section", "text": _mrkdwn(_code(diff))})

    in_band = "yes" if event.in_band else "*no*"
    blocks.append(
        {
            "type": "context",
            "elements": [_mrkdwn(f"in band: {in_band}  ·  evidence `{_escape(event.id)}`")],
        }
    )
    return blocks


def _collapsed_diff(event: Any) -> str:
    """The changed fields, bounded. `None` before renders as "not captured" — plan §3.6
    keeps that distinct from an empty prior value all the way to the screen."""
    diff = event.diff
    if diff is None or not diff.fields_changed:
        return ""

    fields = diff.fields_changed
    lines = []
    for field in fields[:_DIFF_LINES]:
        before = (diff.before or {}).get(field)
        after = (diff.after or {}).get(field)
        if diff.prior_value_captured:
            lines.append(f"{field}: {before} → {after}")
        else:
            lines.append(f"{field}: {after}  (new value; prior value not captured)")

    omitted = len(fields) - len(lines)
    if omitted:
        lines.append(f"… {omitted} more field{'' if omitted == 1 else 's'} changed")
    return "\n".join(lines)


def _proposal_blocks(
    brief: Brief,
    *,
    proposal_summary: str | None,
    action_id: str | None,
    remaining: int,
) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = [{"type": "divider"}]

    if proposal_summary and action_id:
        blocks.append(
            {"type": "section", "text": _mrkdwn(f"*Proposed*  {_escape(proposal_summary)}")}
        )
    else:
        blocks.append(
            {
                "type": "section",
                "text": _mrkdwn(
                    "_No action proposed. This brief is read-only — nothing will run._"
                ),
            }
        )

    blocks.append(
        _actions(
            brief.incident_id,
            action_id,
            include_show_all=remaining > 0,
            remaining=remaining,
        )
    )
    return blocks


def _actions(
    incident_id: str,
    action_id: str | None,
    *,
    include_show_all: bool,
    remaining: int = 0,
    approve_style: str = "primary",
) -> dict[str, Any]:
    """The interactive row.

    Approve and Reject appear only when there is an action to approve. A card offering
    Approve with nothing behind it is a button whose only possible outcome is an error, and
    ground rule #5's "nothing is unattended" is about a human deciding something real.
    """
    elements: list[dict[str, Any]] = []

    if action_id:
        payload = _payload(incident_id, action_id)
        elements += [
            {
                "type": "button",
                "action_id": "approve",
                "text": _plain("Approve"),
                "style": approve_style,
                "value": payload,
            },
            {
                "type": "button",
                "action_id": "reject",
                "text": _plain("Reject"),
                "value": payload,
            },
        ]

    if include_show_all:
        elements.append(
            {
                "type": "button",
                "action_id": "show_all",
                "text": _plain(f"Show all changes ({remaining} more)"),
                "value": _payload(incident_id, None),
            }
        )

    # Block Kit rejects an `actions` block with no elements, which would make a brief with
    # no proposal and no extra candidates unpostable. Fall back to a context line.
    if not elements:
        return {
            "type": "context",
            "elements": [_mrkdwn("_No actions available for this incident._")],
        }

    return {"type": "actions", "block_id": f"fazerops:{incident_id}", "elements": elements}


def _payload(incident_id: str, action_id: str | None) -> str:
    """What a button carries back.

    The **identifiers only** — never the parameters. `handlers.py` re-derives the action
    from the incident, so a payload edited in transit names an incident and an action id
    that are both checked against the catalog and the store; it cannot smuggle a namespace
    or a target value into an executor. That is the same argument as W19b's handles.
    """
    value = json.dumps({"incident_id": incident_id, "action_id": action_id})
    if len(value) > _VALUE_LIMIT:  # pragma: no cover - ids are short by construction
        raise ValueError(f"button payload is {len(value)} chars, over Slack's 2000 limit")
    return value


def _ci_line(brief: Brief) -> str:
    """Handoff §9 asks for an explicit CI line. Rendered from `merge_count`, never
    hardcoded — W11a's point is that the punchline is true because the data says so."""
    from ..collectors.github import render_ci_status

    return f":octagonal_sign: {_escape(render_ci_status(brief.ci_status))}"


def _tier_line(tier: Tier, escalation_reason: str | None) -> str:
    if tier is Tier.MANAGER_APPROVAL:
        reason = escalation_reason or "declared Tier 2 in the action catalog"
        return f"*Tier 2* — manager approval required. Escalated: {_escape(reason)}"
    return "*Tier 1* — engineer approval required."


def _diff_text(dry_run: DryRun) -> str:
    """The same lines `DryRun.render()` produces, minus its header — the two surfaces read
    one `DryRun`, so they cannot disagree about what is about to change."""
    lines = []
    for line in dry_run.lines:
        if not line.prior_value_captured:
            lines.append(f"{line.field}: {line.after}  (prior value not captured)")
        elif not line.changed:
            lines.append(f"{line.field}: {line.after}  (unchanged)")
        else:
            lines.append(f"{line.field}: {line.before} → {line.after}")

    for reason in dry_run.unmet_preconditions:
        lines.append(f"! precondition not met — {reason}")

    return "\n".join(lines) or "(no field-level diff available)"


def _alert_class_label(brief: Brief) -> str:
    return brief.alert.alert_class.value.replace("_", " ")


def _stamp(moment: Any) -> str:
    return moment.strftime("%Y-%m-%d %H:%M UTC")


# --------------------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------------------


def _escape(text: str) -> str:
    """Slack's three required escapes, applied to every string this module did not author.

    Slack mrkdwn has no code execution, so this is not an injection fix — it is a
    *spoofing* fix. An unescaped `<!channel>` in an alert summary pings everyone, and an
    unescaped `<https://evil/|approve here>` renders as a link an operator will click.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _code(text: str) -> str:
    """A fenced block. Backticks inside are neutralized rather than escaped — Slack has no
    escape for a backtick inside a fence, so a value containing ``` would otherwise close
    the block early and render the rest as message text."""
    return "```\n" + text.replace("```", "`​`​`") + "\n```"


def _plain(text: str) -> dict[str, Any]:
    return {"type": "plain_text", "text": text, "emoji": True}


def _mrkdwn(text: str) -> dict[str, Any]:
    return {"type": "mrkdwn", "text": text}


def _bounded(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the message postable.

    Slack rejects the *entire* message over 50 blocks, so an over-long brief does not
    arrive truncated — it does not arrive. Trimming here, and saying so, is the difference
    between a shortened brief and no brief during an incident.

    The last block is preserved: it is the actions row, and dropping the buttons while
    keeping the finding produces a card nobody can act on.
    """
    if len(blocks) <= BLOCK_LIMIT:
        return blocks

    tail = blocks[-1]
    kept = blocks[: BLOCK_LIMIT - 2]
    omitted = len(blocks) - len(kept) - 1
    return [
        *kept,
        {
            "type": "context",
            "elements": [
                _mrkdwn(
                    f":scissors: {omitted} further block{'' if omitted == 1 else 's'} "
                    "omitted to stay under Slack's 50-block limit. The full brief is in "
                    "the incident record."
                )
            ],
        },
        tail,
    ]
