# The FazerOps actor role

An approved AWS action (`restore_db_parameter`) runs as this role, never as the automation host's own
identity. `security/credentials.py` assumes it per approval for 900 seconds, with an inline session
policy naming one parameter group, the approver as `SourceIdentity` (`slack-<user id>`), and the
incident, action and approver as session tags. CloudTrail then records who approved each mutation.

Without `FAZEROPS_ACTOR_ROLE_ARN` those actions are refused before a card opens.

**Creating the role is a change to your AWS account, so FazerOps does not do it for you.** IAM roles
and policies cost nothing. Replace `ACCOUNT_ID` in both JSON files first.

```bash
aws iam create-role \
  --role-name fazerops-actor \
  --assume-role-policy-document file://config/aws/fazerops-actor-trust-policy.json \
  --max-session-duration 3600

aws iam put-role-policy \
  --role-name fazerops-actor \
  --policy-name restore-db-parameter \
  --policy-document file://config/aws/fazerops-actor-permissions-policy.json
```

Then set `FAZEROPS_ACTOR_ROLE_ARN=arn:aws:iam::<ACCOUNT_ID>:role/fazerops-actor` in `.env`.

- **The trust policy's `Principal` is the whole account.** Narrow it to the IAM user or role the
  automation server runs as once that is fixed.
- **The role cannot be assumed without an approver.** `sts:AssumeRole` requires a `slack-*`
  `SourceIdentity`, so a session with none is refused by AWS, not only by FazerOps.
- **`sts:TagSession` is a separate statement, on purpose.** AWS authorizes tagging as its own step,
  and a `sts:SourceIdentity` condition on it fails — the first version of this file put all three
  actions under one condition, and every tagged assume was refused (found live, 14 Sep). Tagging is
  instead limited to the three keys FazerOps sends; it cannot assume the role on its own.
- **Parameter groups must carry a `fazerops:namespace` tag.** The session policy FazerOps attaches at
  assume time narrows this to the one group the approval named.

To remove it:

```bash
aws iam delete-role-policy --role-name fazerops-actor --policy-name restore-db-parameter
aws iam delete-role --role-name fazerops-actor
```
