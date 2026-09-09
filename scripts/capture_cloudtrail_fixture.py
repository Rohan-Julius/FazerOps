#!/usr/bin/env python3
"""W10a — generate real CloudTrail events and record them into `fixtures/cloudtrail/`.

Same rule as W7b and W11's capture scripts, and it matters most here: **a hand-authored
fixture is a mock of the AWS-native source, in an AWS hackathon, and a judge who opens
`fixtures/` can tell.** Recording reality also settles the `userIdentity` shapes rather
than assuming them — Handoff §5 warns that shape "varies significantly across event
sources", and an inferred schema is exactly the thing that passes every test and fails on
the first real payload.

So this script performs genuine mutations, waits for CloudTrail to surface them, and writes
back whatever `lookup_events` returned.

## What it creates, and what it costs

Nothing that bills, with one exception:

| Resource | Events emitted | Cost |
|---|---|---|
| Security group `billing-api-sg` | `AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress` | free |
| IAM role `billing-api-task-role` | `PutRolePolicy`, `AttachRolePolicy` | free |
| RDS **parameter group** `billing-primary-params` | `ModifyDBParameterGroup` | free — only instances bill |
| SSM parameter `/billing-api/pool/max` | `PutParameter` | free (Standard tier) |
| Secrets Manager secret `billing-api/db` | `UpdateSecret` | ~$0.40/month while it exists |
| Lambda function `billing-api-worker` | `UpdateFunctionConfiguration` | free tier |

`ModifyDBInstance` is deliberately **not** generated: the parameter-group variant covers the
same event class, and an RDS instance costs real money and ten minutes to create for a
payload shape we already have a sibling of.

Everything is torn down in a `finally` block. Re-running is safe — creation is idempotent
and cleanup runs even on Ctrl-C.

## Two fields are edited; everything else is verbatim

* **Timestamps** are shifted onto the demo's narrative, exactly as the other two capture
  scripts do. All of them land *outside* the correlation window `[10:41, 14:41)`, because
  Idea §7 specifies the brief shows **three** changes and they are the Kubernetes ones.
  CloudTrail's job in the demo is to have been read, not to add a candidate.
* **The account id** is rewritten to AWS's documentation placeholder `111122223333`
  (decision on record, 7 Sep). `fixtures/` ships in a public repository; an account id is
  not a credential, but it is an identifier tied to a person, permanently.

    aws sso login --profile <name>     # or however this machine is authenticated
    .venv/bin/python scripts/capture_cloudtrail_fixture.py
"""

from __future__ import annotations

import io
import json
import re
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "fixtures" / "cloudtrail"
REGION = "us-east-1"

PLACEHOLDER_ACCOUNT = "111122223333"

# AWS's own documentation placeholders. Used so a reader recognises these as synthetic at a
# glance rather than wondering whether a real key was committed.
PLACEHOLDER_ACCESS_KEY = "ASIAIOSFODNN7EXAMPLE"
PLACEHOLDER_PRINCIPAL = "AROAEXAMPLEPRINCIPALID"

# AWS assigns the security group id, so it cannot be chosen to match the demo manifest the
# way every other resource name here can. Rewriting it is what lets
# `config/service_manifest.yaml` keep one stable value across re-captures — otherwise every
# run would produce a fixture whose security-group events fall outside the blast radius
# until someone remembered to edit the manifest.
PLACEHOLDER_SECURITY_GROUP = "sg-0a1b2c3d"
_SECURITY_GROUP_ID = re.compile(r"\bsg-[0-9a-f]{8,17}\b")

# Identifiers that are unique to the capturing account and carry no information the
# collector needs. `userIdentity`'s *shape* is what W10 is tested against — which fields
# exist, and how they nest — and every one of those survives this substitution untouched.
#
# The access key id is not optional to redact: it is a temporary STS id with no secret
# attached and it expired the same day, but gitleaks matches `ASIA…`/`AKIA…` and a red
# secret-hygiene gate is not something this repo negotiates with. `.gitleaks.toml` says it
# outright — nothing is allowlisted to make a real finding go away, so the finding is
# removed instead of silenced.
_ACCESS_KEY = re.compile(r"\b(?:ASIA|AKIA)[A-Z0-9]{16}\b")
_PRINCIPAL_ID = re.compile(r"\b(?:AROA|AIDA)[A-Z0-9]{17,}\b")

# Names match `config/service_manifest.yaml` wherever the name is ours to choose, so a
# recorded event resolves into billing-api's blast radius rather than needing the manifest
# bent around whatever AWS happened to call things.
SECURITY_GROUP = "billing-api-sg"
ROLE = "billing-api-task-role"
PARAMETER_GROUP = "billing-primary-params"
SSM_PARAMETER = "/billing-api/pool/max"
SECRET = "billing-api/db"
FUNCTION = "billing-api-worker"

# A second, long-lived principal, created solely so the fixture carries a real `IAMUser`
# identity alongside the `AssumedRole` ones. Handoff §5 requires the collector to handle
# `IAMUser`, `AssumedRole` and `Root` explicitly, and an SSO session only ever produces the
# middle one — every event in this fixture would otherwise be the same shape, and W10's
# normalizer would be tested against a third of what it claims to handle.
DEPLOYER_USER = "billing-api-deployer"

# Under `service-role/`, not at the policy root — the root path 404s as NoSuchEntity.
MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

INLINE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["ssm:GetParameter"],
            "Resource": f"arn:aws:ssm:{REGION}:*:parameter{SSM_PARAMETER}",
        }
    ],
}

# The eight event names this script generates, in the order the story would have produced
# them. Handoff §5 names nine; `ModifyDBInstance` is the deliberate omission.
TARGET_EVENTS = [
    "AuthorizeSecurityGroupIngress",
    "PutRolePolicy",
    "AttachRolePolicy",
    "ModifyDBParameterGroup",
    "PutParameter",
    "UpdateSecret",
    "UpdateFunctionConfiguration",
    "RevokeSecurityGroupIngress",
    # Performed by DEPLOYER_USER rather than the SSO session, so this one event carries an
    # `IAMUser` identity. It has to be an event name no other step emits — the lookup is by
    # name, so two events sharing one name would be indistinguishable.
    "DeleteParameter",
]

# **Lambda versions its CloudTrail event names**, and nothing in the API documentation says
# so — `UpdateFunctionConfiguration` is recorded as `UpdateFunctionConfiguration20150331v2`,
# and reads appear as `GetFunction20150331v2`. Discovered by recording, on the first run
# that waited twenty minutes for an event that was already there under a different name.
#
# This is the single best argument for W10a existing at all: a hand-authored fixture would
# have carried the documented name, W10's tests would have passed against it, and the
# collector would have silently dropped every Lambda change in production. The collector
# (W10) has to match these by prefix for the same reason.
LOOKUP_ALIASES = {
    "UpdateFunctionConfiguration": "UpdateFunctionConfiguration20150331v2",
}

# Idea §7: the alert fires at 14:41 and the window is [10:41, 14:41). Every one of these is
# outside it — see the module docstring.
NARRATIVE_START = datetime(2026, 9, 4, 8, 12, 0, tzinfo=timezone.utc)
NARRATIVE_STEP = timedelta(minutes=37)

# `lookup_events` is eventually consistent and management events typically surface within
# a few minutes. Twenty is generous rather than optimistic; the script says what it is
# waiting for while it waits.
LOOKUP_TIMEOUT_SECONDS = 20 * 60
LOOKUP_INTERVAL_SECONDS = 30


def log(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------------------


def default_vpc(ec2) -> str:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
    if not vpcs:
        raise SystemExit(
            "no default VPC in this region — create one with "
            f"`aws ec2 create-default-vpc --region {REGION}`, or point this script at a VPC id"
        )
    return vpcs[0]["VpcId"]


def generate(session: boto3.Session) -> None:
    """Perform the mutations. Each call is the *reason* an event name appears in the log."""
    ec2 = session.client("ec2")
    iam = session.client("iam")
    rds = session.client("rds")
    ssm = session.client("ssm")
    secrets = session.client("secretsmanager")
    lambda_client = session.client("lambda")

    log("creating the security group")
    group_id = _ensure_security_group(ec2)

    log("  AuthorizeSecurityGroupIngress")
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [{"CidrIp": "10.0.0.0/16", "Description": "billing-api to primary"}],
            }
        ],
    )

    log("creating the IAM role")
    _ensure_role(iam)

    log("  PutRolePolicy")
    iam.put_role_policy(
        RoleName=ROLE,
        PolicyName="billing-api-read-pool-config",
        PolicyDocument=json.dumps(INLINE_POLICY),
    )

    log("  AttachRolePolicy")
    iam.attach_role_policy(RoleName=ROLE, PolicyArn=MANAGED_POLICY)

    log("creating the RDS parameter group")
    _ensure_parameter_group(rds)

    log("  ModifyDBParameterGroup")
    rds.modify_db_parameter_group(
        DBParameterGroupName=PARAMETER_GROUP,
        Parameters=[
            {
                "ParameterName": "max_connections",
                "ParameterValue": "40",
                "ApplyMethod": "pending-reboot",
            }
        ],
    )

    log("  PutParameter")
    ssm.put_parameter(Name=SSM_PARAMETER, Value="20", Type="String", Overwrite=True)

    log("creating the secret")
    _ensure_secret(secrets)

    log("  UpdateSecret")
    secrets.update_secret(SecretId=SECRET, Description="billing-api primary credentials")

    log("creating the Lambda function")
    _ensure_function(session, lambda_client)

    log("  UpdateFunctionConfiguration")
    lambda_client.update_function_configuration(FunctionName=FUNCTION, Timeout=15)

    log("creating the long-lived IAM user")
    deployer = _ensure_deployer(iam)

    log("  DeleteParameter (as an IAMUser, not the SSO session)")
    deployer.client("ssm").delete_parameter(Name=SSM_PARAMETER)

    log("  RevokeSecurityGroupIngress")
    ec2.revoke_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
            }
        ],
    )


def _ensure_security_group(ec2) -> str:
    try:
        return ec2.create_security_group(
            GroupName=SECURITY_GROUP,
            Description="FazerOps W10a fixture capture",
            VpcId=default_vpc(ec2),
        )["GroupId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidGroup.Duplicate":
            raise
        groups = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [SECURITY_GROUP]}]
        )["SecurityGroups"]
        return groups[0]["GroupId"]


def _ensure_role(iam) -> None:
    try:
        iam.create_role(RoleName=ROLE, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))
        time.sleep(10)  # IAM is eventually consistent; Lambda's role check fails without it
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise


def _ensure_parameter_group(rds) -> None:
    try:
        rds.create_db_parameter_group(
            DBParameterGroupName=PARAMETER_GROUP,
            DBParameterGroupFamily="postgres16",
            Description="FazerOps W10a fixture capture",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBParameterGroupAlreadyExists":
            raise


def _ensure_secret(secrets) -> None:
    try:
        secrets.create_secret(Name=SECRET, SecretString=json.dumps({"password": "placeholder"}))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceExistsException":
            raise


def _ensure_deployer(iam) -> boto3.Session:
    """Create an IAM user with an access key and return a session authenticated as it.

    The key lives for the length of this run and is deleted in `cleanup`. It never reaches
    disk: it is held in the returned session and nowhere else, and the fixture's redaction
    pass rewrites the `AKIA…` id that CloudTrail records anyway.
    """
    try:
        iam.create_user(UserName=DEPLOYER_USER)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise

    iam.attach_user_policy(
        UserName=DEPLOYER_USER, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMFullAccess"
    )
    key = iam.create_access_key(UserName=DEPLOYER_USER)["AccessKey"]

    # IAM access keys are eventually consistent and a fresh one is rejected for a few
    # seconds. This wait is expected rather than defensive, like the Lambda role wait above.
    time.sleep(15)

    return boto3.Session(
        aws_access_key_id=key["AccessKeyId"],
        aws_secret_access_key=key["SecretAccessKey"],
        region_name=REGION,
    )


def _delete_deployer(session: boto3.Session) -> None:
    iam = session.client("iam")
    for key in iam.list_access_keys(UserName=DEPLOYER_USER)["AccessKeyMetadata"]:
        iam.delete_access_key(UserName=DEPLOYER_USER, AccessKeyId=key["AccessKeyId"])
    for policy in iam.list_attached_user_policies(UserName=DEPLOYER_USER)["AttachedPolicies"]:
        iam.detach_user_policy(UserName=DEPLOYER_USER, PolicyArn=policy["PolicyArn"])
    iam.delete_user(UserName=DEPLOYER_USER)


def _ensure_function(session: boto3.Session, lambda_client) -> None:
    account = session.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account}:role/{ROLE}"

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("index.py", "def handler(event, context):\n    return {}\n")

    for attempt in range(6):
        try:
            lambda_client.create_function(
                FunctionName=FUNCTION,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": buffer.getvalue()},
                Timeout=10,
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceConflictException":
                break
            # The role exists but IAM has not propagated to Lambda yet. This is the one
            # retry in this script that is genuinely expected rather than defensive.
            if code == "InvalidParameterValueException" and attempt < 5:
                time.sleep(10)
                continue
            raise

    # `create_function` returns while the function is still `Pending`, and a configuration
    # update against a pending function is refused. The waiter is what makes the next call
    # deterministic rather than a race the script wins on a fast day.
    lambda_client.get_waiter("function_active_v2").wait(FunctionName=FUNCTION)


# --------------------------------------------------------------------------------------
# Recording
# --------------------------------------------------------------------------------------


def lookup(session: boto3.Session, since: datetime) -> dict[str, dict[str, Any]]:
    """One `lookup_events` payload per target event name, newest first.

    Looked up by `EventName` one at a time rather than by scanning the whole window: the
    API is rate-limited, and a name-scoped lookup is what the collector's live path will do
    anyway.
    """
    trail = session.client("cloudtrail")
    found: dict[str, dict[str, Any]] = {}

    for name in TARGET_EVENTS:
        response = trail.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": LOOKUP_ALIASES.get(name, name)}
            ],
            StartTime=since,
            MaxResults=1,
        )
        events = response.get("Events") or []
        if events:
            found[name] = events[0]

    return found


def wait_for_events(session: boto3.Session, since: datetime) -> dict[str, dict[str, Any]]:
    deadline = time.monotonic() + LOOKUP_TIMEOUT_SECONDS
    found: dict[str, dict[str, Any]] = {}

    while time.monotonic() < deadline:
        found = lookup(session, since)
        missing = [name for name in TARGET_EVENTS if name not in found]
        if not missing:
            return found
        log(f"  waiting on {len(missing)} of {len(TARGET_EVENTS)}: {', '.join(missing)}")
        time.sleep(LOOKUP_INTERVAL_SECONDS)

    missing = [name for name in TARGET_EVENTS if name not in found]
    raise SystemExit(
        f"CloudTrail did not surface {missing} within "
        f"{LOOKUP_TIMEOUT_SECONDS // 60} minutes. The resources were still cleaned up; "
        "re-run the script rather than hand-authoring the missing payloads."
    )


def record(found: dict[str, dict[str, Any]], account: str) -> list[dict[str, Any]]:
    """Shift the clock, redact the account, and change nothing else.

    `lookup_events` returns `CloudTrailEvent` as a JSON *string*, which is what the
    collector has to parse in live mode — so it is kept as a string here rather than
    unpacked into an object the API never returns.
    """
    payloads: list[dict[str, Any]] = []

    for index, name in enumerate(TARGET_EVENTS):
        event = found[name]
        when = NARRATIVE_START + index * NARRATIVE_STEP

        detail = json.loads(event["CloudTrailEvent"])
        detail["eventTime"] = when.strftime("%Y-%m-%dT%H:%M:%SZ")

        payload = {
            **event,
            "EventTime": when,
            "CloudTrailEvent": json.dumps(detail),
        }
        payloads.append(json.loads(json.dumps(payload, default=_serialize)))

    return _redact_identifiers(payloads, account)


def _serialize(value: Any) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    raise TypeError(f"{type(value).__name__} is not JSON-serializable")


def _redact_identifiers(payloads: list[dict[str, Any]], account: str) -> list[dict[str, Any]]:
    """Replace account-linked identifiers everywhere they appear, including inside ARNs.

    A blunt substitution on the serialized payload, deliberately: the account id turns up in
    `userIdentity.accountId`, in `recipientAccountId`, inside every ARN in
    `requestParameters` and inside `resources[].ARN`, and enumerating those is how one gets
    missed. `arn:aws:iam::aws:policy/...` is untouched because it carries no account id.

    The assertion at the end is the point of the function. A redaction that silently fails
    is worse than none, because the fixture then *looks* redacted — so this refuses to
    write the file rather than trusting that the substitutions ran.
    """
    text = json.dumps(payloads)

    text = text.replace(account, PLACEHOLDER_ACCOUNT)
    text = _ACCESS_KEY.sub(PLACEHOLDER_ACCESS_KEY, text)
    text = _PRINCIPAL_ID.sub(PLACEHOLDER_PRINCIPAL, text)
    text = _SECURITY_GROUP_ID.sub(PLACEHOLDER_SECURITY_GROUP, text)

    survivors = {
        "account id": re.search(rf"\b{re.escape(account)}\b", text),
        "access key id": _ACCESS_KEY.search(text.replace(PLACEHOLDER_ACCESS_KEY, "")),
        "principal id": _PRINCIPAL_ID.search(text.replace(PLACEHOLDER_PRINCIPAL, "")),
    }
    leaked = [name for name, hit in survivors.items() if hit]
    if leaked:
        raise SystemExit(f"{', '.join(leaked)} survived redaction — refusing to write the fixture")

    return json.loads(text)


# --------------------------------------------------------------------------------------
# Cleanup
# --------------------------------------------------------------------------------------


def cleanup(session: boto3.Session) -> None:
    """Best effort, and loud about what it could not remove.

    Every deletion is independent: one failure must not strand the other five resources,
    and a resource this script leaves behind is a resource that quietly bills.
    """
    steps = [
        ("lambda function", lambda: session.client("lambda").delete_function(FunctionName=FUNCTION)),
        (
            "secret",
            lambda: session.client("secretsmanager").delete_secret(
                SecretId=SECRET, ForceDeleteWithoutRecovery=True
            ),
        ),
        ("ssm parameter", lambda: session.client("ssm").delete_parameter(Name=SSM_PARAMETER)),
        (
            "rds parameter group",
            lambda: session.client("rds").delete_db_parameter_group(
                DBParameterGroupName=PARAMETER_GROUP
            ),
        ),
        (
            "role policy",
            lambda: session.client("iam").delete_role_policy(
                RoleName=ROLE, PolicyName="billing-api-read-pool-config"
            ),
        ),
        (
            "attached policy",
            lambda: session.client("iam").detach_role_policy(
                RoleName=ROLE, PolicyArn=MANAGED_POLICY
            ),
        ),
        ("role", lambda: session.client("iam").delete_role(RoleName=ROLE)),
        ("deployer user and its access key", lambda: _delete_deployer(session)),
        ("security group", lambda: _delete_security_group(session)),
    ]

    log("\ncleaning up")
    for label, action in steps:
        try:
            action()
            log(f"  removed {label}")
        except ClientError as exc:
            log(f"  could not remove {label}: {exc.response['Error']['Code']} — remove it by hand")


def _delete_security_group(session: boto3.Session) -> None:
    ec2 = session.client("ec2")
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [SECURITY_GROUP]}]
    )["SecurityGroups"]
    for group in groups:
        ec2.delete_security_group(GroupId=group["GroupId"])


# --------------------------------------------------------------------------------------


def main() -> int:
    # `--record-only` skips generation and reads events already in CloudTrail's history,
    # which retains 90 days. It exists because the events outlive the resources: a run that
    # emitted everything and then failed to *find* one of them has no reason to create six
    # resources again.
    record_only = "--record-only" in sys.argv

    session = boto3.Session(region_name=REGION)

    try:
        identity = session.client("sts").get_caller_identity()
    except Exception as exc:  # noqa: BLE001 - the message matters more than the type
        raise SystemExit(f"no usable AWS credentials: {exc}") from None

    account = identity["Account"]
    log(f"account {account[:4]}… in {REGION}, as {identity['Arn'].rsplit('/', 1)[-1]}\n")

    if record_only:
        log("--record-only: reading events already in CloudTrail history, creating nothing\n")
        since = datetime.now(timezone.utc) - timedelta(hours=6)
        found = wait_for_events(session, since)
    else:
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        try:
            generate(session)
            log("\nwaiting for CloudTrail to surface the events (usually a few minutes)")
            found = wait_for_events(session, since)
        finally:
            cleanup(session)

    payloads = record(found, account)

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    target = FIXTURE_DIR / "billing_window.json"
    target.write_text(json.dumps(payloads, indent=2) + "\n", encoding="utf-8")

    log(f"\nwrote {len(payloads)} events to {target.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
