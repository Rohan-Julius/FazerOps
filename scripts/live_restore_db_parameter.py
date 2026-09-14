#!/usr/bin/env python3
"""Drive `restore_db_parameter` once against a real RDS parameter group, approved in Slack.

Investigation never proposes this action: CloudTrail records what a `ModifyDBParameterGroup` asked
for, never the value it replaced, so no hint carries a prior value (ground rule #4). This script is
the operator standing in for that missing half — it reads the group's *current* value from RDS and
takes the prior value from `--prior`, registers the action through the real gateway, posts the real
approval card, and listens on Socket Mode for the click. Everything after the card is production
code: the manager roster, the dry-run digest, the STS mint with the approver as `SourceIdentity`,
the executor, the decision log, closing the card and uploading the incident record.

    aws rds create-db-parameter-group ...   # tagged fazerops:namespace=<group>; see config/aws/README.md
    set -a; . ./.env; set +a
    .venv/bin/python scripts/live_restore_db_parameter.py --group billing-primary-params \\
        --parameter log_min_duration_statement --prior 5000

Creates nothing. Deleting the parameter group afterwards is the operator's.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from datetime import UTC, datetime

import boto3

from fazerops import keys
from fazerops.actions.inverse import ActionRequest
from fazerops.actions.preconditions import Evidence
from fazerops.actions.roster import default_roster
from fazerops.actions.server import assemble_from_env, decision_closer, record_poster
from fazerops.slack.handlers import (
    approval_card_for,
    approval_sink,
    post_brief,
    run_socket_mode,
    update_message,
    upload_record,
)


def current_value(client, group: str, parameter: str) -> str | None:
    for page in client.get_paginator("describe_db_parameters").paginate(DBParameterGroupName=group):
        for row in page["Parameters"]:
            if row["ParameterName"] == parameter:
                return row.get("ParameterValue")
    raise SystemExit(f"{parameter} is not a parameter of {group}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="live_restore_db_parameter")
    parser.add_argument("--group", required=True)
    parser.add_argument("--parameter", required=True)
    parser.add_argument("--prior", required=True, help="the value to restore; RDS keeps no history of it")
    parser.add_argument("--apply-method", default="immediate", choices=["immediate", "pending-reboot"])
    parser.add_argument("--wait", type=float, default=1800, help="seconds to wait for the click")
    args = parser.parse_args(argv)

    rds = boto3.client("rds")
    # Existence is read from RDS, not asserted: `parameter_group_exists` fails closed on an
    # inventory nobody looked at.
    rds.describe_db_parameter_groups(DBParameterGroupName=args.group)
    current = current_value(rds, args.group, args.parameter)
    if current == args.prior:
        raise SystemExit(f"{args.parameter} is already {args.prior}; there is nothing to restore")

    automation = assemble_from_env()
    automation.decided_hooks.append(decision_closer(automation, update_message, background=False))
    automation.decided_hooks.append(record_poster(automation, upload_record, background=False))

    incident_id = f"INC-live-rds-{datetime.now(UTC):%Y%m%dT%H%M%SZ}"
    request = ActionRequest.for_action(
        "restore_db_parameter",
        {
            "parameter_group": args.group,
            "parameter": args.parameter,
            "target_value": args.prior,
            "apply_method": args.apply_method,
        },
        inverse_hint={
            "action_id": "restore_db_parameter",
            "parameter_group": args.group,
            "parameter": args.parameter,
            "prior_value": args.prior,
            "current_value": current,
        },
    )
    evidence = Evidence(resource_keys=frozenset({keys.db_parameter_group(args.group).blast_radius_key()}), complete=True)
    pending = automation.gateway.register(incident_id, request, evidence=evidence)

    posted = post_brief(approval_card_for(pending), text=f"Approval needed: restore {args.parameter} on {args.group}")
    handle = (posted["channel"], posted["ts"])
    automation.cards[pending.key] = handle
    automation.threads[incident_id] = handle
    print(f"{incident_id}: card posted — {args.parameter} {current} -> {args.prior} on {args.group}, tier {pending.tier.name}")

    sink = approval_sink(automation.gateway, resolve_approver=default_roster().resolve, decisions=automation.decisions)
    threading.Thread(target=run_socket_mode, kwargs={"sink": sink}, daemon=True, name="slack-socket-mode").start()

    deadline = time.monotonic() + args.wait
    while time.monotonic() < deadline:
        outcome = automation.gateway.outcome(incident_id, "restore_db_parameter")
        if outcome is not None:
            time.sleep(3)  # the closer and the record upload run on the decision; let them land
            print(f"decided: {outcome}")
            print(f"{args.parameter} is now {current_value(rds, args.group, args.parameter)!r} on {args.group}")
            return 0
        time.sleep(2)
    print("no decision before --wait ran out", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
