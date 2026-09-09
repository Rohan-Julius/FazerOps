# CloudTrail fixtures — provenance

## Status: RECORDED FROM A REAL AWS ACCOUNT (W10a, 8 Sep 2026)

**Every payload in `billing_window.json` came back from `cloudtrail:LookupEvents`.** Nothing
here was hand-authored. The nine events were caused by nine genuine mutations performed
against a real account, and the resources that emitted them were destroyed in the same run.

```bash
.venv/bin/python scripts/capture_cloudtrail_fixture.py               # generate + record
.venv/bin/python scripts/capture_cloudtrail_fixture.py --record-only # record only
```

| | |
|---|---|
| Captured | 8 September 2026 |
| Region | `us-east-1` |
| API | `lookup_events` — management events, the path Handoff §5 chooses |
| Capture script | `scripts/capture_cloudtrail_fixture.py` |

## Why this is recorded rather than written

Handoff §5 warns that `userIdentity` "varies significantly across event sources", and plan
§4 puts it bluntly: a hand-authored fixture is a mock of the AWS-native source, in an AWS
hackathon, and a judge who opens `fixtures/` can tell.

It justified itself on the first run. **Lambda versions its CloudTrail event names.** The
API documentation calls the operation `UpdateFunctionConfiguration`; CloudTrail records it
as `UpdateFunctionConfiguration20150331v2`, and reads appear as `GetFunction20150331v2`. A
fixture written from the documentation would have carried the wrong name, W10's tests would
have passed against it, and the collector would have silently dropped every Lambda change
in production. `collectors/cloudtrail.py` matches by prefix because of what this recording
showed, not because prefix matching seemed tidy.

## The nine events

Eight of Handoff §5's nine named event types, plus `DeleteParameter`. `ModifyDBInstance` is
the deliberate omission — `ModifyDBParameterGroup` covers the same class, and an RDS
instance costs real money for a payload shape we already have a sibling of.

| Event | Identity type | Why it is here |
|---|---|---|
| `AuthorizeSecurityGroupIngress` | `AssumedRole` | Handoff §5 |
| `RevokeSecurityGroupIngress` | `AssumedRole` | Handoff §5; W14's `(revoke, security_group_ingress) × connection_refused` prior |
| `PutRolePolicy` | `AssumedRole` | Handoff §5; W14's `(put, iam_role_policy) × auth_failure` prior |
| `AttachRolePolicy` | `AssumedRole` | Handoff §5 |
| `ModifyDBParameterGroup` | `AssumedRole` | Handoff §5; the resource W20c's Tier 2 action targets |
| `PutParameter` | `AssumedRole` | Handoff §5 |
| `UpdateSecret` | `AssumedRole` | Handoff §5 |
| `UpdateFunctionConfiguration20150331v2` | `AssumedRole` | Handoff §5 — and the versioned-name discovery above |
| `DeleteParameter` | **`IAMUser`** | Performed by a separate long-lived IAM user, solely so the fixture carries a second identity shape |

**`Root` is not represented, and that is a disclosed gap.** Handoff §5 asks for `IAMUser`,
`AssumedRole` and `Root` to be handled explicitly. The first two are recorded here. Emitting
a genuine `Root` event requires authenticating as the account root, which is exactly what
AWS tells you never to do — so `_actor_from` handles the shape and
`tests/collectors/test_cloudtrail_normalize.py` exercises it against a constructed payload,
labelled as constructed. The alternative was recording a real root action, and no fixture is
worth that.

## What was edited

Timestamps and four classes of identifier. **Every other field is exactly what AWS
returned**, including `CloudTrailEvent` being a JSON *string* rather than an object — that
is what the API hands back, and a pre-parsed fixture would test a shape AWS never emits.

| Field | Edit | Why |
|---|---|---|
| `eventTime` / `EventTime` | Shifted onto 4 September 2026 | Idea §7 specifies the brief shows **three** changes, and they are the Kubernetes ones. Every event here sits outside the correlation window `[10:41, 14:41)` — CloudTrail's job in the demo is to have been *read*, not to add a candidate. |
| Account id | → `111122223333` | AWS's documentation placeholder. `fixtures/` ships in a public repository, and an account id is an identifier tied to a person, permanently. |
| Access key ids | → `ASIAIOSFODNN7EXAMPLE` | Temporary STS ids with no secret attached, expired the same day — but `gitleaks` matches `ASIA…`/`AKIA…`, and `.gitleaks.toml` says outright that nothing is allowlisted to make a real finding go away. So the finding is removed rather than silenced. |
| Principal ids | → `AROAEXAMPLEPRINCIPALID` | Same reasoning; unique to the capturing account and carrying nothing the collector reads. |
| Security group id | → `sg-0a1b2c3d` | The one id AWS assigns rather than accepts. Rewriting it lets `config/service_manifest.yaml` hold a stable value across re-captures instead of needing an edit after every run. |

The redaction pass **refuses to write the file** if any of those survive — a redaction that
fails silently is worse than none, because the fixture then merely *looks* redacted.

## What CloudTrail redacted itself

`PutParameter`'s value reads `HIDDEN_DUE_TO_SECURITY_REASONS`. That is AWS's own redaction,
passed through untouched: rewriting it would hide the fact that AWS considered the field
sensitive, which is information the brief should carry.
