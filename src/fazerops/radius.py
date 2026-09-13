"""W4 — blast-radius resolution from the checked-in service manifest (Handoff §4).

The failure mode this guards against is silent: if the ConfigMap is not in the radius, the
causal event never enters the candidate set and the brief says nothing changed. There is
no exception, no empty-result warning, and nothing in the Slack message to suggest the
answer was filtered out rather than absent.

So: an unknown service returns an *empty* radius, never everything. A resolver that falls
back to the whole manifest turns a typo into a 40-candidate brief, which is worse than
returning nothing because it looks like it worked.
"""

from __future__ import annotations

import functools
from pathlib import Path

import yaml

from . import keys
from .models import BlastRadius, ResourceRef

DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / "config" / "service_manifest.yaml"

# Handoff §4: one hop is defensible and demoable; two hops explodes the candidate set.
MAX_HOPS = 1

# `service=owner/repo[,service=owner/repo]` — the repositories a deployment actually watches,
# replacing the manifest's placeholders per service without editing the checked-in file.
SERVICE_REPOS_ENV = "FAZEROPS_SERVICE_REPOS"


def _repo_overrides() -> dict[str, list[str]]:
    import os

    overrides: dict[str, list[str]] = {}
    for part in (os.environ.get(SERVICE_REPOS_ENV) or "").split(","):
        if not part.strip():
            continue
        service, separator, repo = part.partition("=")
        if not separator or "/" not in repo:
            raise ValueError(f"{SERVICE_REPOS_ENV} entries are service=owner/repo; got {part.strip()!r}")
        overrides.setdefault(service.strip(), []).append(repo.strip())
    return overrides


class ServiceManifest:
    """Parsed `config/service_manifest.yaml`, with resolution over it."""

    def __init__(self, services: dict[str, dict]) -> None:
        self._services = services

    @classmethod
    def load(cls, path: Path | str | None = None) -> ServiceManifest:
        raw = yaml.safe_load(Path(path or DEFAULT_MANIFEST).read_text(encoding="utf-8"))
        services = (raw or {}).get("services") or {}
        for service, repos in _repo_overrides().items():
            if service not in services:
                # A typo here would silently watch nothing, and "nothing shipped" is the claim
                # this product must never make by accident.
                raise ValueError(f"{SERVICE_REPOS_ENV} names {service!r}, which the manifest does not know")
            services[service] = {**services[service], "github": {**(services[service].get("github") or {}), "repos": repos}}
        return cls(services)

    @property
    def service_names(self) -> tuple[str, ...]:
        """The orchestrator's `resolve_blast_radius` tool draws its parameter enum from
        this at import time (plan §3.1), so the model cannot name a service that does not
        exist — the rejection is in the tool schema, not in the prompt."""
        return tuple(sorted(self._services))

    def knows(self, service: str) -> bool:
        return service in self._services

    def refs_for(self, service: str) -> list[ResourceRef]:
        """Every resource the manifest attributes to one service, as `ResourceRef`s.

        Keys are never built here — see `keys.py` for why both sides of the index must
        derive them from the same `ResourceRef.blast_radius_key()`.
        """
        spec = self._services.get(service)
        if spec is None:
            return []

        refs: list[ResourceRef] = []

        k8s = spec.get("kubernetes") or {}
        namespace = k8s.get("namespace")
        if namespace:
            for name in k8s.get("workloads") or []:
                refs.append(keys.k8s_workload(namespace, name))
            for name in k8s.get("configmaps") or []:
                refs.append(keys.k8s_configmap(namespace, name))
            for name in k8s.get("secrets") or []:
                refs.append(keys.k8s_secret(namespace, name))

        aws = spec.get("aws") or {}
        for arn in aws.get("resources") or []:
            refs.append(keys.aws_resource(arn))
        for group_id in aws.get("security_groups") or []:
            refs.append(keys.security_group(group_id))
        for role in aws.get("iam_roles") or []:
            refs.append(keys.iam_role(role))
        for group in aws.get("db_parameter_groups") or []:
            refs.append(keys.db_parameter_group(group))
        for parameter in aws.get("ssm_parameters") or []:
            refs.append(keys.ssm_parameter(parameter))
        for name in aws.get("secrets") or []:
            refs.append(keys.secret(name))
        for name in aws.get("functions") or []:
            refs.append(keys.lambda_function(name))

        helm = spec.get("helm") or {}
        helm_namespace = helm.get("namespace") or namespace
        if helm_namespace:
            for release in helm.get("releases") or []:
                refs.append(keys.helm_release(helm_namespace, release))

        github = spec.get("github") or {}
        for repo in github.get("repos") or []:
            refs.append(keys.github_repo(repo))

        return refs

    def keys_for(self, service: str) -> set[str]:
        if not self.knows(service):
            return set()
        return {ref.blast_radius_key() for ref in self.refs_for(service)} | {
            keys.service_key(service)
        }

    def resolve(self, service: str, hops: int = MAX_HOPS) -> BlastRadius:
        """The named service's resources, plus `hops` levels of `depends_on`."""
        if not self.knows(service):
            # Deliberately empty. See the module docstring.
            return BlastRadius(service=service, keys=set(), direct_keys=set())

        direct = self.keys_for(service)

        reached = {service}
        frontier = {service}
        for _ in range(max(hops, 0)):
            next_frontier: set[str] = set()
            for name in frontier:
                for dependency in (self._services.get(name) or {}).get("depends_on") or []:
                    if dependency not in reached:
                        next_frontier.add(dependency)
            reached |= next_frontier
            frontier = next_frontier
            if not frontier:
                break

        all_keys: set[str] = set()
        for name in reached:
            all_keys |= self.keys_for(name)

        return BlastRadius(service=service, keys=all_keys, direct_keys=direct)

    def owning_services(self, key: str) -> set[str]:
        """Reverse lookup, used at normalization time (Handoff §3) to stamp an event with
        every service whose radius it falls inside."""
        return {name for name in self._services if key in self.keys_for(name)}


@functools.lru_cache(maxsize=1)
def default_manifest() -> ServiceManifest:
    """Cached because the orchestrator's tool enum reads it at import time and the
    collectors read it once per event during normalization."""
    return ServiceManifest.load()


def resolve(service: str, hops: int = MAX_HOPS) -> BlastRadius:
    return default_manifest().resolve(service, hops=hops)
