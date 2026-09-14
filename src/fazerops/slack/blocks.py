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
    "close_decision",
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
    brief: Brief,
    *,
    proposal_summary: str | None = None,
    action_id: str | None = None,
    dry_run_digest: str | None = None,
    decided_line: str | None = None,
) -> list[dict[str, Any]]:
    """The Tier 0 brief, posted automatically when an investigation completes.

    Written for the on-call engineer who opens it mid-incident (user, 14 Sep): what changed, who,
    when, and whether it went through CI, in words rather than scores and ids. It names the
    proposed action and points to the approval card, where the decision is made (plan §9.2);
    `decided_line` replaces that pointer once the decision is recorded.

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
                    f"Alert fired {_stamp(brief.alert.fired_at)}. Searched the {brief.window.hours:.0f} hours "
                    "before it in AWS (CloudTrail), the Kubernetes audit log, Helm and GitHub.  ·  "
                    f"{brief.incident_id}"
                )
            ],
        },
        {"type": "section", "text": _mrkdwn(f"> {_escape(brief.alert.summary)}")},
    ]

    from ..render.text import describe_reranked

    reranked = describe_reranked(brief)
    if reranked:
        blocks.append({"type": "context", "elements": [_mrkdwn(f"*{_escape(reranked)}*")]})

    if not brief.radius.keys:
        # The same distinction the text renderer draws: "we did not know where to look" is
        # not "nothing changed", and an empty candidate list on a card reads as the latter.
        blocks.append(
            {
                "type": "section",
                "text": _mrkdwn(
                    f"Could not resolve *{_escape(brief.alert.service)}* in the "
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

    # Said only when it changes what the engineer should do. The dominant case read "no choice of
    # weights ranks another change above it (lead 0.01)" — true, and a sentence nobody paged at 3am
    # can use; the text renderer and the incident record still carry it.
    stability = brief.stability
    if stability is not None and not stability.dominant and 1 < (stability.challenger_rank or 0) <= len(brief.candidates):
        challenger = brief.candidates[stability.challenger_rank - 1].event.resource
        blocks.append(
            {
                "type": "context",
                "elements": [
                    _mrkdwn(
                        f"*Close call:* #{stability.challenger_rank} {_escape(challenger.kind)} "
                        f"{_escape(challenger.name)} is nearly as likely as #1. Check both before acting."
                    )
                ],
            }
        )

    blocks.append({"type": "context", "elements": [_mrkdwn(_ci_line(brief))]})

    if brief.narrative:
        blocks.append({"type": "section", "text": _mrkdwn(f"*What likely happened*\n{_escape(brief.narrative)}")})

    if brief.degraded:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    _mrkdwn("*Some change sources could not be searched*, so this list may be missing changes.")
                ],
            }
        )

    for gap in brief.coverage_gaps:
        blocks.append({"type": "context", "elements": [_mrkdwn(_escape(_gap_line(gap)))]})

    blocks.extend(
        _proposal_blocks(
            brief,
            proposal_summary=proposal_summary,
            action_id=action_id,
            remaining=remaining,
            dry_run_digest=dry_run_digest,
            decided_line=decided_line,
        )
    )
    return _bounded(blocks)


def approval_card(
    dry_run: DryRun,
    *,
    incident_id: str,
    tier: Tier,
    escalation_reason: str | None = None,
    provisional: bool = False,
    graduation: tuple[int, int] | None = None,
    one_shot: str | None = None,
    coverage_note: str | None = None,
    expires_at: float | None = None,
    cause: str | None = None,
) -> list[dict[str, Any]]:
    """The approval card. Handoff §9's four required elements, in its order.

    Written for the on-call engineer deciding mid-incident (user, 14 Sep): what it will do and whose
    change it undoes (`cause`), what will change, how to undo it, anything to do before or after, and
    who may approve — each labelled in words. The action id, the inverse's call signature and a
    "Tier" with no explanation were what the first live card showed.

    `one_shot` is W44's: `"human-written"` or `"generated"` for an action built for this incident
    and never added to the catalog, which the card says in so many words.

    `provisional` and `graduation` are W45's: a generated action says so on the card, with how
    far it is from graduating, beside — never instead of — its tier.

    `tier` is passed in rather than read from the catalog here, because it is the
    *effective* tier after `thresholds.yaml` promotion (W26) — a card that displayed the
    declared tier would understate an escalation on precisely the action that escalated.
    """
    what = f"*{_escape(dry_run.summary)}*" + (f"\n{_escape(cause)}" if cause else "")
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": _plain("Approval required")},
        {"type": "section", "text": _mrkdwn(what)},
        {"type": "context", "elements": [_mrkdwn(f"On `{_escape(dry_run.target)}`")]},
        {"type": "section", "text": _mrkdwn(f"*This will change*\n{_code(_diff_text(dry_run))}")},
    ]

    # Above the diff, where it is read before the decision: the ranking this card was drafted from
    # may still change, or already has (`render.text.approval_card_note`).
    if coverage_note:
        blocks.insert(3, {"type": "context", "elements": [_mrkdwn(f"*{_escape(coverage_note)}*")]})

    # Ground rule #4 on the one surface an operator actually reads: an action whose inverse could not
    # be computed says so, rather than letting someone approve something that is about to refuse.
    if dry_run.reversible:
        blocks.append({"type": "section", "text": _mrkdwn(f"To undo it: {_escape(_undo_text(dry_run))}")})
    else:
        blocks.append(
            {
                "type": "section",
                "text": _mrkdwn(
                    "*This cannot run.* FazerOps could not work out how to undo it, and it never makes a "
                    "change it cannot undo."
                ),
            }
        )

    if provisional:
        progress = f"generated, {graduation[0]}/{graduation[1]}" if graduation else "generated"
        blocks.append(
            {
                "type": "context",
                "elements": [
                    _mrkdwn(
                        f"*Provisional action* ({progress}) — added from what engineers fixed by hand in "
                        "past incidents, so a manager approves it every time until it has proven itself."
                    )
                ],
            }
        )

    if one_shot:
        # "Human-written writer" meant nothing to the engineer who first read it (user, 14 Sep): say who
        # wrote the code that will run, and whether anyone reviewed it.
        author = (
            "Its code was written by the AI for this incident, and nobody has reviewed it (generated writer)."
            if one_shot == "generated"
            else "It uses FazerOps' own code for this kind of resource, written and reviewed by developers."
        )
        blocks.append(
            {
                "type": "context",
                "elements": [
                    _mrkdwn(
                        "*One-shot action* — a one-time fix for this incident only, not one of the standard "
                        f"actions. {author} It was tried in a sandbox first, where it changed nothing but the "
                        "resource above. A manager must approve it."
                    )
                ],
            }
        )

    # Above the buttons, not in small print below them: a note here can be the difference between
    # an approval that fixes the incident and one that changes nothing until someone restarts pods.
    if dry_run.notes:
        bullets = "\n".join(f"• {_escape(note)}" for note in dry_run.notes)
        blocks.append({"type": "section", "text": _mrkdwn(f"*Important*\n{bullets}")})

    blocks.append({"type": "section", "text": _mrkdwn(_tier_line(tier, escalation_reason))})
    footer = incident_id
    if expires_at is not None:
        # Stated where the decision is made: after this the click refuses (`ApprovalExpired`).
        from datetime import datetime, timezone

        footer = f"Expires {datetime.fromtimestamp(expires_at, timezone.utc):%H:%M} UTC  ·  {incident_id}"
    blocks.append({"type": "context", "elements": [_mrkdwn(footer)]})

    # The buttons are omitted entirely when the action cannot run. Rendering a disabled
    # Approve is not a thing Block Kit offers, and rendering a live one next to a refusal
    # invites the click that the refusal exists to prevent.
    if dry_run.reversible and not dry_run.unmet_preconditions:
        blocks.append(
            _actions(
                incident_id,
                dry_run.action_id,
                dry_run_digest=dry_run.digest,
                include_show_all=False,
                approve_style="danger" if tier is Tier.MANAGER_APPROVAL or provisional or one_shot else "primary",
            )
        )

    return _bounded(blocks)


# --------------------------------------------------------------------------------------
# Pieces
# --------------------------------------------------------------------------------------


def _candidate_blocks(candidate: Candidate, brief: Brief) -> list[dict[str, Any]]:
    event = candidate.event
    minutes = (brief.alert.fired_at - event.occurred_at).total_seconds() / 60.0

    # Written for the on-call engineer reading it mid-incident (user, 14 Sep): no score, no evidence
    # id, no "in band". The score and the evidence ids are in the incident record, where a review
    # reads them; here they were numbers and ids nobody could act on.
    heading = f"*#{candidate.rank}  {_escape(event.resource.kind)} {_escape(event.resource.name)}*"
    who = f"*{_escape(event.actor.display)}*" + ("" if event.actor.resolved else " _(not linked to a known person)_")
    detail = (
        f"{_ACTION_WORDS.get(event.action.value, event.action.value)} by {who} at "
        f"{event.occurred_at:%H:%M} UTC, {_minutes_before(minutes)}"
    )

    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": _mrkdwn(f"{heading}\n{detail}")}
    ]

    diff = _collapsed_diff(event)
    if diff:
        blocks.append({"type": "section", "text": _mrkdwn(_code(diff))})

    route = "Shipped through CI" if event.in_band else "*Changed outside CI* — no pull request or deploy record"
    blocks.append({"type": "context", "elements": [_mrkdwn(route)]})
    return blocks


_ACTION_WORDS = {"create": "Created", "update": "Changed", "delete": "Deleted"}


def _minutes_before(minutes: float) -> str:
    if minutes < 1:
        return "less than a minute before the alert"
    return f"{minutes:.0f} min before the alert"


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
            lines.append(f"{field}: {after}  (new value; earlier value not recorded)")

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
    dry_run_digest: str | None = None,
    decided_line: str | None = None,
) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = [{"type": "divider"}]

    if proposal_summary and action_id:
        # Composed by this process, like `close_decision`'s line, and left unescaped so its approver
        # mention still renders as a mention.
        follow = decided_line or "Approve or reject it on the approval card below."
        blocks.append(
            {"type": "section", "text": _mrkdwn(f"*Proposed fix:* {_escape(proposal_summary)}\n{follow}")}
        )
        if brief.ranked_first_from is not None and decided_line is None:
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        _mrkdwn(
                            "This proposal was drafted from the ranking before late changes "
                            "arrived. Check it against the new #1 before approving."
                        )
                    ],
                }
            )
    else:
        blocks.append(
            {
                "type": "section",
                "text": _mrkdwn(
                    "_No action proposed. This message only reports what changed — nothing will run._"
                ),
            }
        )

    # The decision is made on the approval card alone (plan §9.2, 14 Sep). The brief keeps only
    # Show all changes, and says nothing at all when there is nothing more to show.
    if remaining > 0:
        blocks.append(_actions(brief.incident_id, None, include_show_all=True, remaining=remaining))
    return blocks


def _actions(
    incident_id: str,
    action_id: str | None,
    *,
    include_show_all: bool,
    remaining: int = 0,
    approve_style: str = "primary",
    dry_run_digest: str | None = None,
) -> dict[str, Any]:
    """The interactive row.

    Approve and Reject appear only when there is an action to approve. A card offering
    Approve with nothing behind it is a button whose only possible outcome is an error, and
    ground rule #5's "nothing is unattended" is about a human deciding something real.
    """
    elements: list[dict[str, Any]] = []

    # Approve and Reject need the digest of the dry run they sit under; without one
    # `parse_decision` refuses the click, so a button that could only ever fail is not rendered.
    if action_id and dry_run_digest:
        payload = _payload(incident_id, action_id, dry_run_digest)
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


def _payload(incident_id: str, action_id: str | None, dry_run_digest: str | None = None) -> str:
    """What a button carries back.

    The **identifiers only** — never the parameters. `handlers.py` re-derives the action
    from the incident, so a payload edited in transit names an incident and an action id
    that are both checked against the catalog and the store; it cannot smuggle a namespace
    or a target value into an executor. That is the same argument as W19b's handles.

    `dry_run` identifies what the clicker *read*, not what runs: the gateway compares it with the
    dry run it holds and refuses a mismatch (drift log, 14 Sep, D1). Editing it can only make a
    click refuse.
    """
    content: dict[str, Any] = {"incident_id": incident_id, "action_id": action_id}
    if dry_run_digest is not None:
        content["dry_run"] = dry_run_digest
    value = json.dumps(content)
    if len(value) > _VALUE_LIMIT:  # pragma: no cover - ids are short by construction
        raise ValueError(f"button payload is {len(value)} chars, over Slack's 2000 limit")
    return value


def close_decision(
    blocks: list[dict[str, Any]], *, action_id: str | None, line: str
) -> list[dict[str, Any]] | None:
    """The clicked message with `action_id`'s Approve and Reject replaced by `line`.

    Everything else is kept — on the brief, "Show all changes" stays clickable. Returns `None`
    when the message holds no buttons for this action, so the caller edits nothing rather than
    appending a line to a message that was never a decision.
    """
    closed: list[dict[str, Any]] = []
    touched = False
    for block in blocks:
        elements = block.get("elements") or []
        if block.get("type") != "actions":
            closed.append(block)
            continue
        kept = [
            element
            for element in elements
            if not (element.get("action_id") in ("approve", "reject") and _payload_action(element.get("value")) == action_id)
        ]
        if len(kept) == len(elements):
            closed.append(block)
            continue
        touched = True
        if kept:
            closed.append({**block, "elements": kept})
        closed.append({"type": "context", "elements": [_mrkdwn(line)]})
    return closed if touched else None


def _payload_action(value: Any) -> str | None:
    try:
        content = json.loads(value or "")
    except (TypeError, json.JSONDecodeError):
        return None
    return content.get("action_id") if isinstance(content, dict) else None


def _ci_line(brief: Brief) -> str:
    """Handoff §9 asks for an explicit CI line. Rendered from `merge_count`, never
    hardcoded — W11a's point is that the punchline is true because the data says so."""
    # Names the span. "In this window" left an engineer asking which window; the terminal renderer
    # keeps `collectors.github.render_ci_status`'s shorter form.
    count = brief.ci_status.merge_count
    span = f"in the {brief.window.hours:.0f} hours before the alert"
    if count == 0:
        return f"Nothing shipped through CI {span}."
    return f"{count} merge{'' if count == 1 else 's'} shipped through CI {span}."


def _tier_line(tier: Tier, escalation_reason: str | None) -> str:
    """Who may approve, in words, with the tier kept alongside for the audit trail (Handoff §9)."""
    if tier is Tier.MANAGER_APPROVAL:
        reason = escalation_reason or "this action always needs a manager"
        return f"*Needs approval from:* a manager (Tier 2) — {_escape(reason)}"
    return "*Needs approval from:* an on-call engineer (Tier 1). A manager can also approve."


def _diff_text(dry_run: DryRun) -> str:
    """The lines `DryRun.render()` is built from, labelled for a person rather than a log. Both
    surfaces read one `DryRun`, so they cannot disagree about what is about to change."""
    lines = []
    for line in dry_run.lines:
        if not line.prior_value_captured:
            lines.append(f"{line.field}: {line.after}  (earlier value not recorded)")
        elif not line.changed:
            lines.append(f"{line.field}: {line.after}  (unchanged)")
        else:
            lines.append(f"{line.field}: {line.before} → {line.after}")

    for reason in dry_run.unmet_preconditions:
        # Preconditions arrive as `name: explanation`; the name is for the logs.
        lines.append(f"Cannot run: {reason.split(': ', 1)[-1]}")

    return "\n".join(lines) or "(no field-by-field change to show)"


def _undo_text(dry_run: DryRun) -> str:
    """The inverse in words, read off the diff shown above it: each changed field set back to the value
    it holds now. The computed inverse is what runs; this is how a person reads it."""
    steps = [
        f"roll back to revision {line.before}" if line.field == "revision" else f"set {line.field} back to {line.before}"
        for line in dry_run.lines
        if line.changed and line.prior_value_captured
    ]
    if not steps:
        return f"run {dry_run.inverse_summary}" if dry_run.inverse_summary else "run the computed inverse"
    return steps[0] if len(steps) == 1 else ", ".join(steps[:-1]) + " and " + steps[-1]


def _gap_line(gap: Any) -> str:
    """The brief's line for a source that reports late, in words. `render.text.describe_coverage_gap`
    keeps the long form for the terminal and the incident record."""
    from ..render.text import SOURCE_NAMES

    name = SOURCE_NAMES.get(gap.source, gap.source)
    if gap.status == "caught_up":
        late = (
            "no changes arrived late"
            if gap.late_changes == 0
            else f"{gap.late_changes} late change{'' if gap.late_changes == 1 else 's'} added above"
        )
        return f"{name} has caught up ({gap.checked_at:%H:%M} UTC): {late}."
    if gap.status == "unreachable":
        return f"{name} could not be re-checked, so changes made after {gap.unobserved.start:%H:%M} UTC may be missing."
    return (
        f"{name} changes from the last {gap.delivery_lag_minutes:.0f} minutes may not be visible yet. "
        f"This message will update if any arrive (checking until {gap.settles_at:%H:%M} UTC)."
    )


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
                    f"{omitted} further block{'' if omitted == 1 else 's'} "
                    "omitted to stay under Slack's 50-block limit. The full brief is in "
                    "the incident record."
                )
            ],
        },
        tail,
    ]
