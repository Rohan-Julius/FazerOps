"""Blast-radius key construction — the one place a resource becomes an index key.

Both sides of the ledger index depend on producing byte-identical keys: the collectors
that *write* events (W3) and the resolver that *queries* them (W4). If they ever disagree
the query returns an empty candidate set and the brief reports, with total confidence,
that nothing changed. That is a silent failure with no exception and no log line.

The defence is that neither side builds a key string. Both build a `ResourceRef` through
the helpers below and let `ResourceRef.blast_radius_key()` be the single implementation.
"""

from __future__ import annotations

from .models import ResourceRef


# Singular lowercase form -> the Kind as Kubernetes spells it. `.title()` would give
# "Statefulset", which is wrong in the brief even though the blast-radius key lowercases it.
WORKLOAD_KINDS = {
    "deployment": "Deployment",
    "statefulset": "StatefulSet",
    "daemonset": "DaemonSet",
    "cronjob": "CronJob",
    "job": "Job",
}


def k8s_workload(namespace: str, workload: str) -> ResourceRef:
    """Parse the manifest's `kind/name` workload form (Handoff §4: `deployment/billing-api`).

    The kind prefix is load-bearing: without it the manifest can only ever describe
    Deployments, so a StatefulSet in a service's blast radius would be silently recorded
    as the wrong resource type and never match the audit collector's key for it.

    A bare name is accepted and read as a Deployment, because that is overwhelmingly the
    common case and rejecting it would turn a manifest typo into a stack trace at import
    time — but Handoff §4's canonical form carries the prefix.
    """
    kind_part, slash, name = workload.partition("/")
    if not slash:
        return ResourceRef(kind="Deployment", name=workload, namespace=namespace)

    kind = WORKLOAD_KINDS.get(kind_part.lower(), kind_part.title())
    return ResourceRef(kind=kind, name=name, namespace=namespace)


def k8s_configmap(namespace: str, name: str) -> ResourceRef:
    return ResourceRef(kind="ConfigMap", name=name, namespace=namespace)


def k8s_secret(namespace: str, name: str) -> ResourceRef:
    return ResourceRef(kind="Secret", name=name, namespace=namespace)


def aws_resource(arn: str) -> ResourceRef:
    """ARN-addressed AWS resources. The ARN's own last segment is the resource name, and
    the service segment is the kind — both are derivable, so callers pass only the ARN."""
    parts = arn.split(":")
    service = parts[2] if len(parts) > 2 else "aws"
    region = parts[3] or None if len(parts) > 3 else None
    account = parts[4] or None if len(parts) > 4 else None
    name = arn.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
    return ResourceRef(
        kind=service, name=name, arn=arn, region=region, account=account
    )


def security_group(group_id: str) -> ResourceRef:
    return ResourceRef(kind="SecurityGroup", name=group_id)


def iam_role(role_name: str) -> ResourceRef:
    return ResourceRef(kind="IAMRole", name=role_name)


def github_repo(full_name: str) -> ResourceRef:
    return ResourceRef(kind="Repo", name=full_name)


def service_key(service: str) -> str:
    """Services are not resources, so they have no `ResourceRef`. Events that name a
    service directly — a Helm release, a GitHub merge — carry this alongside their own
    resource key, which is how a merge to `faber-demo/billing-api` lands in the radius."""
    return f"service:{service}"
