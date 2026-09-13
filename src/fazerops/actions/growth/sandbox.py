"""W43 — sandbox recipes and containment verification. `docs/catalog_self_extension.md` §6, §6.1, §7.4.

For a hand-written action a human wrote and tested the dry run. A generated writer's dry run is
still human-written (§3), but the writer itself can touch more than it declares. So it is **run
against an ephemeral target and watched with our own collector**, and it passes only if

    observed_mutations ⊆ { declared_resource_ref }

The instrument is the machinery that detects unauthorised infrastructure changes: the Kubernetes
audit log, normalized by `K8sAuditCollector`. The dry run stops being an assertion and becomes a
measurement.

**Recipes are declared, and most resource types have none** (§6.1). `observed` means a collector
sees the mutation, with prior values, as it happens — the audit log at `RequestResponse`, which
is Kubernetes. CloudTrail is `delayed`. Everything else is `none`. Only `observed` may run here,
and only `observed` may back a one-shot (W44).

**Checked before anything is provisioned** (§7.4): the declared reference must be exactly one
concrete, namespaced resource, and inside the incident's blast radius. Without that, the
containment comparison passes vacuously — a candidate declares broadly and acts broadly.

**What the sandbox is.** One fresh namespace holding a clone of the declared resource seeded with
the *recorded current* values (the state the revert applies to), an untouched decoy key, and a
neighbouring resource; one ServiceAccount whose Role allows `get` and `patch` on that resource
type in that namespace only; and a cursor into the audit log taken before any of it was created.
The writer runs as that ServiceAccount, so every request it makes is attributable to it — and
**denied requests are counted too**, because a writer that tried to reach another namespace and
was stopped by RBAC is a writer that lied about its reference, whatever RBAC did about it.

**What this proves, and does not** (§6). Containment: the writer mutated nothing outside its
declared reference and left the resource holding exactly the values it was given. Not safety
under production conditions — an empty namespace has no traffic, no neighbours that matter and no
contention. And a recipe can be wrong (§10a): containment is verified against what the recipe
provisioned, which is why recipes are human-written, reviewed at an executor's trust level, and
live in a file an agent-authored commit may not touch.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from ...models import BlastRadius, ChangeEvent, ResourceRef

__all__ = [
    "ContainmentReport",
    "K8sSandbox",
    "Observation",
    "ObservedRequest",
    "RECIPES",
    "RecipeClass",
    "SandboxRecipe",
    "Subject",
    "Verdict",
    "generated_subject",
    "human_subject",
    "precheck",
    "recipe_for",
    "resource_type_of",
    "verify_containment",
]

DECOY_KEY = "fazerops-sandbox-untouched"
SANDBOX_CONTEXT_ENV = "FAZEROPS_SANDBOX_CONTEXT"
# The audit log of the sandbox cluster's API server, as a file this process can read. Defaults to
# the collector's; a dedicated sandbox cluster writes its own.
SANDBOX_AUDIT_LOG_ENV = "FAZEROPS_SANDBOX_AUDIT_LOG"


class SandboxNotConfigured(RuntimeError):
    """No cluster was named for containment runs."""


# --------------------------------------------------------------------------------------
# Recipes
# --------------------------------------------------------------------------------------


class RecipeClass(str, Enum):
    OBSERVED = "observed"
    DELAYED = "delayed"
    NONE = "none"


@dataclass(frozen=True)
class SandboxRecipe:
    resource_type: str
    recipe_class: RecipeClass
    why: str


_CLOUDTRAIL = "CloudTrail delivers 5–15 minutes late and lookup_events returns no prior value"

RECIPES: dict[str, SandboxRecipe] = {
    recipe.resource_type: recipe
    for recipe in (
        SandboxRecipe(
            "k8s/ConfigMap",
            RecipeClass.OBSERVED,
            "the audit log records ConfigMap bodies at RequestResponse, as each request is served",
        ),
        SandboxRecipe(
            "k8s/Secret",
            RecipeClass.NONE,
            "the collector redacts Secret values, so a restored value cannot be observed",
        ),
        *(
            SandboxRecipe(f"aws/{kind}", RecipeClass.DELAYED, _CLOUDTRAIL)
            for kind in ("DBParameterGroup", "SecurityGroup", "IAMRole", "IAMPolicy", "Parameter", "Function")
        ),
    )
}


def recipe_for(resource_type: str) -> SandboxRecipe:
    return RECIPES.get(
        resource_type,
        SandboxRecipe(resource_type, RecipeClass.NONE, "no sandbox recipe has been authored for this resource type"),
    )


def resource_type_of(event: ChangeEvent) -> str:
    prefix = {"k8s_audit": "k8s", "cloudtrail": "aws", "helm": "helm", "github": "github"}.get(event.source, event.source)
    return f"{prefix}/{event.resource.kind}"


# --------------------------------------------------------------------------------------
# What runs, and what comes back
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Subject:
    """A writer under test: its identity and how to call its `write` with a given client."""

    writer_id: str
    kind: str
    field: str
    authored_by: str
    run: Callable[[dict[str, Any], dict[str, Any], Any], Any]


def human_subject(writer: Any) -> Subject:
    return Subject(
        writer_id=writer.id,
        kind=writer.kind,
        field=writer.field_path,
        authored_by=writer.authored_by,
        run=lambda params, values, client: writer.write(params, values, credential=None, client=client),
    )


def generated_subject(kind: str, field: str, read_source: str, write_source: str) -> Subject:
    """Generated code runs in its own interpreter even here, unpinned: the sandbox measures what
    it does rather than stopping it (`authoring.run_generated_writer`)."""
    from .authoring import run_generated_writer

    return Subject(
        writer_id=f"k8s/{kind}:{field}",
        kind=kind,
        field=field,
        authored_by="agent",
        run=lambda params, values, client: run_generated_writer(
            kind, field, read_source, write_source, params, values, client=client
        ),
    )


class ObservedRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    verb: str
    resource_key: str
    succeeded: bool


@dataclass
class Observation:
    complete: bool
    requests: list[ObservedRequest] = field(default_factory=list)
    events: list[ChangeEvent] = field(default_factory=list)


class Sandbox(Protocol):
    def provision(self, declared: ResourceRef, field: str, current: Mapping[str, Any]) -> ResourceRef: ...
    def client(self) -> Any: ...
    def observe(self) -> Observation: ...
    def teardown(self) -> None: ...


class Verdict(str, Enum):
    CONTAINED = "contained"
    NO_RECIPE = "no_recipe"
    NOT_OBSERVABLE = "not_observable"
    DECLARED_REF_NOT_CONCRETE = "declared_ref_not_concrete"
    DECLARED_REF_OUTSIDE_RADIUS = "declared_ref_outside_radius"
    MUTATED_OUTSIDE_DECLARED_REF = "mutated_outside_declared_ref"
    OBSERVATION_INCOMPLETE = "observation_incomplete"
    WRITER_FAILED = "writer_failed"
    NOTHING_OBSERVED = "nothing_observed"
    OBSERVED_VALUES_DIFFER = "observed_values_differ"


class ContainmentReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    writer_id: str
    authored_by: str
    recipe_class: RecipeClass
    verdict: Verdict
    sandbox_ran: bool
    declared: str
    observed_outside: tuple[str, ...] = ()
    detail: str | None = None
    runs: int = 1

    @property
    def contained(self) -> bool:
        return self.verdict is Verdict.CONTAINED


# --------------------------------------------------------------------------------------
# The check
# --------------------------------------------------------------------------------------

_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_DNS_SUBDOMAIN = re.compile(r"^(?=.{1,253}$)[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")


def precheck(declared: ResourceRef, kind: str, radius: BlastRadius) -> tuple[Verdict, str] | None:
    """§7.4, before anything exists. A concrete reference is one resource by exact name — no
    pattern, no ARN, no missing namespace — and it must be one the incident's radius holds."""
    if (
        declared.kind != kind
        or declared.arn
        or not declared.namespace
        or not _DNS_LABEL.match(declared.namespace)
        or not _DNS_SUBDOMAIN.match(declared.name)
    ):
        return Verdict.DECLARED_REF_NOT_CONCRETE, f"{declared.blast_radius_key()} is not exactly one {kind}"
    if declared.blast_radius_key() not in radius.keys:
        return Verdict.DECLARED_REF_OUTSIDE_RADIUS, f"{declared.blast_radius_key()} is outside {radius.service}'s blast radius"
    return None


def verify_containment(
    subject: Subject,
    *,
    declared: ResourceRef,
    radius: BlastRadius,
    prior: Mapping[str, Any],
    current: Mapping[str, Any],
    sandbox: Callable[[], Sandbox] | None = None,
) -> ContainmentReport:
    """Run `subject` against a sandbox clone of `declared` and judge what the collector saw.

    `prior` is what the writer is asked to restore and `current` what the clone is seeded with
    — both recorded by a collector, never supplied by a model. `sandbox` builds the sandbox and is
    called only once the recipe and the pre-check have both passed.
    """
    recipe = recipe_for(f"k8s/{subject.kind}")

    def report(verdict: Verdict, *, ran: bool, detail: str | None = None, outside: tuple[str, ...] = ()) -> ContainmentReport:
        return ContainmentReport(
            writer_id=subject.writer_id,
            authored_by=subject.authored_by,
            recipe_class=recipe.recipe_class,
            verdict=verdict,
            sandbox_ran=ran,
            declared=declared.blast_radius_key(),
            observed_outside=outside,
            detail=detail,
        )

    if recipe.recipe_class is RecipeClass.NONE:
        return report(Verdict.NO_RECIPE, ran=False, detail=recipe.why)
    if recipe.recipe_class is RecipeClass.DELAYED:
        return report(Verdict.NOT_OBSERVABLE, ran=False, detail=recipe.why)
    refused = precheck(declared, subject.kind, radius)
    if refused is not None:
        return report(refused[0], ran=False, detail=refused[1])
    if not prior:
        return report(Verdict.NOTHING_OBSERVED, ran=False, detail="there are no recorded values to restore")

    box = (sandbox or K8sSandbox)()
    failure: str | None = None
    try:
        target = box.provision(declared, subject.field, current)
        try:
            subject.run({"namespace": target.namespace, "name": target.name}, dict(prior), box.client())
        except Exception as exc:
            failure = f"{type(exc).__name__}: {exc}"[:300]
        observation = box.observe()
    finally:
        box.teardown()

    verdict, detail, outside = judge(observation, target=target, field=subject.field, prior=prior, failure=failure)
    return report(verdict, ran=True, detail=detail, outside=outside)


def judge(
    observation: Observation,
    *,
    target: ResourceRef,
    field: str,
    prior: Mapping[str, Any],
    failure: str | None,
) -> tuple[Verdict, str | None, tuple[str, ...]]:
    """Order is the rule: a mutation outside the reference condemns the writer however the run
    ended, so it is judged before an incomplete observation or a writer that raised."""
    from ...collectors.k8s_audit import MUTATING_VERBS

    target_key = target.blast_radius_key()
    mutated = {request.resource_key for request in observation.requests if request.verb in MUTATING_VERBS}
    outside = tuple(sorted(mutated - {target_key}))
    if outside:
        return Verdict.MUTATED_OUTSIDE_DECLARED_REF, "requested a mutation outside its declared reference", outside
    if not observation.complete:
        return Verdict.OBSERVATION_INCOMPLETE, "the audit log never showed the end of the run", ()
    if failure is not None:
        return Verdict.WRITER_FAILED, failure, ()

    landed = [event for event in observation.events if event.resource.blast_radius_key() == target_key]
    if not landed:
        return Verdict.NOTHING_OBSERVED, "the collector observed no change to the declared resource", ()

    diff = landed[-1].diff
    expected_path = None if field == "data" else field
    if diff is None or diff.field_path != expected_path:
        return Verdict.OBSERVED_VALUES_DIFFER, f"the change the collector observed was not to {field}", ()
    after = diff.after or {}
    for key, value in prior.items():
        if (value is None and key in after) or (value is not None and str(after.get(key)) != str(value)):
            return Verdict.OBSERVED_VALUES_DIFFER, "the resource does not hold the values the writer was given", ()
    if after.get(DECOY_KEY) != _decoy(field):
        return Verdict.OBSERVED_VALUES_DIFFER, "a key the writer was not given changed", ()
    return Verdict.CONTAINED, None, ()


def _decoy(field: str) -> str:
    return base64.b64encode(b"untouched").decode() if field == "binaryData" else "untouched"


# --------------------------------------------------------------------------------------
# The Kubernetes recipe
# --------------------------------------------------------------------------------------


class K8sSandbox:
    """One ephemeral namespace, one principal, one audit-log cursor — `observed`'s recipe.

    Needs a cluster whose API server writes the audit log this process can read: the k3d cluster
    `scripts/setup_k3d.sh` creates, or `FAZEROPS_SANDBOX_CONTEXT` naming another. It creates only
    namespaced objects inside the namespace it creates, and deletes that namespace on teardown.
    """

    PRINCIPAL = "writer"

    def __init__(
        self,
        *,
        context: str | None = None,
        audit_log: Path | str | None = None,
        timeout: float = 30.0,
    ) -> None:
        from ...collectors.k8s_audit import audit_log_path
        from ...config import require_offline_capable

        require_offline_capable("the containment sandbox")

        # Named, never defaulted. The current context of a process that remediates production is
        # the production cluster, and a sandbox there is generated code in production with extra
        # steps. So the cluster is one somebody chose for this, and a missing choice refuses.
        chosen = context or os.environ.get(SANDBOX_CONTEXT_ENV)
        if not chosen:
            raise SandboxNotConfigured(
                f"no sandbox cluster: set {SANDBOX_CONTEXT_ENV} to a kubeconfig context reserved for "
                "containment runs. The sandbox never falls back to the current context."
            )

        from kubernetes import client as k8s_client
        from kubernetes import config as k8s_config

        self._client_module = k8s_client
        # A client of its own, rather than `load_kube_config`, which rewrites the process-wide
        # default that every executor's client is built from.
        self._admin = k8s_config.new_client_from_config(context=chosen)
        self._core = k8s_client.CoreV1Api(self._admin)
        self._rbac = k8s_client.RbacAuthorizationV1Api(self._admin)
        configured_log = audit_log or os.environ.get(SANDBOX_AUDIT_LOG_ENV)
        self._audit_log = Path(configured_log) if configured_log else audit_log_path()
        self._timeout = timeout
        self.namespace = f"fazerops-sandbox-{secrets.token_hex(4)}"
        self._handle: Any = None
        self._pending = ""
        self._scoped: Any = None
        self._scoped_api: Any = None
        self._created = False

    @property
    def principal(self) -> str:
        return f"system:serviceaccount:{self.namespace}:{self.PRINCIPAL}"

    def provision(self, declared: ResourceRef, field: str, current: Mapping[str, Any]) -> ResourceRef:
        from ...collectors.k8s_audit import RESOURCE_KINDS
        from ..writers.k8s_support import contract_for

        contract = contract_for(declared.kind, field)
        [plural] = [name for name, kind in RESOURCE_KINDS.items() if kind == declared.kind]
        namespace = self.namespace

        # The cursor comes first, so everything this sandbox causes is after it.
        if not self._audit_log.is_file():
            raise FileNotFoundError(f"no audit log at {self._audit_log}; containment has no instrument")
        self._handle = self._audit_log.open("r", encoding="utf-8")
        self._handle.seek(0, os.SEEK_END)

        self._core.create_namespace({"metadata": {"name": namespace, "labels": {"fazerops.io/sandbox": "containment"}}})
        self._created = True
        create = getattr(self._core, f"create_namespaced_{contract.snake}")
        seeded = {key: value for key, value in current.items() if value is not None}
        seeded[DECOY_KEY] = _decoy(field)
        create(namespace, {"metadata": {"name": declared.name}, contract.body_field: seeded})
        neighbour = "neighbour" if declared.name != "neighbour" else "neighbour-2"
        create(namespace, {"metadata": {"name": neighbour}, "data": {"k": "v"}})

        self._core.create_namespaced_service_account(namespace, {"metadata": {"name": self.PRINCIPAL}})
        self._rbac.create_namespaced_role(
            namespace,
            {
                "metadata": {"name": self.PRINCIPAL},
                "rules": [{"apiGroups": [""], "resources": [plural], "verbs": ["get", "patch"]}],
            },
        )
        self._rbac.create_namespaced_role_binding(
            namespace,
            {
                "metadata": {"name": self.PRINCIPAL},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": self.PRINCIPAL},
                "subjects": [{"kind": "ServiceAccount", "name": self.PRINCIPAL, "namespace": namespace}],
            },
        )
        token = self._core.create_namespaced_service_account_token(
            self.PRINCIPAL, namespace, {"spec": {"expirationSeconds": 600}}
        ).status.token

        admin = self._admin.configuration
        scoped = self._client_module.Configuration(host=admin.host)
        scoped.ssl_ca_cert = admin.ssl_ca_cert
        scoped.verify_ssl = admin.verify_ssl
        # The whole header value, not a prefix: client 36 looks prefixes up under `BearerToken`
        # and older clients under `authorization`, and a prefix under the wrong one sends a bare
        # token the API server answers with 401.
        scoped.api_key = {"authorization": f"Bearer {token}"}
        self._scoped_api = self._client_module.ApiClient(scoped)
        self._scoped = self._client_module.CoreV1Api(self._scoped_api)

        # RBAC reaches the authorizer through an informer, so the first request can precede it.
        read = getattr(self._scoped, f"read_namespaced_{contract.snake}")
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                read(declared.name, namespace)
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)

        return ResourceRef(kind=declared.kind, name=declared.name, namespace=namespace)

    def client(self) -> Any:
        return self._scoped

    def observe(self) -> Observation:
        """Everything the principal asked for, up to a barrier request it makes last.

        The API server writes the audit log in request order, so once the barrier — a read of a
        name nothing else uses — is in the log, every earlier request of this principal is too.
        """
        from ...collectors.k8s_audit import MUTATING_VERBS, RESOURCE_KINDS, TERMINAL_STAGE, K8sAuditCollector

        barrier = f"barrier-{secrets.token_hex(4)}"
        try:
            self._scoped.read_namespaced_config_map(barrier, self.namespace)
        except Exception:
            pass  # a 404 is the expected answer; the request is what matters

        relevant: list[dict[str, Any]] = []
        requests: list[ObservedRequest] = []
        complete = False
        deadline = time.monotonic() + self._timeout

        while not complete and time.monotonic() < deadline:
            for entry in self._new_entries():
                if entry.get("stage") != TERMINAL_STAGE:
                    continue
                ref = entry.get("objectRef") or {}
                user = (entry.get("user") or {}).get("username")
                if user == self.principal and ref.get("name") == barrier:
                    complete = True
                if user != self.principal and ref.get("namespace") != self.namespace:
                    continue
                relevant.append(entry)
                if user == self.principal and str(entry.get("verb", "")).lower() in MUTATING_VERBS:
                    plural = ref.get("resource", "")
                    resource = ResourceRef(
                        kind=RESOURCE_KINDS.get(plural, plural.rstrip("s").title() or "Unknown"),
                        name=ref.get("name") or "*",
                        namespace=ref.get("namespace"),
                    )
                    code = int((entry.get("responseStatus") or {}).get("code", 0))
                    requests.append(
                        ObservedRequest(
                            verb=str(entry.get("verb")).lower(),
                            resource_key=resource.blast_radius_key(),
                            succeeded=200 <= code < 300,
                        )
                    )
            if not complete:
                time.sleep(0.2)

        events = [
            event
            for item, event in K8sAuditCollector().normalize_entries(relevant)
            if (item.get("user") or {}).get("username") == self.principal
        ]
        return Observation(complete=complete, requests=requests, events=events)

    def _new_entries(self) -> Iterator[dict[str, Any]]:
        if self._handle is None:
            return
        chunk = self._handle.read()
        if not chunk and self._rotated():
            self._handle.close()
            self._handle = self._audit_log.open("r", encoding="utf-8")
            chunk = self._handle.read()
        text = self._pending + chunk
        lines = text.split("\n")
        self._pending = lines.pop()  # a line the API server is still writing
        for line in lines:
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def _rotated(self) -> bool:
        try:
            return os.stat(self._audit_log).st_ino != os.fstat(self._handle.fileno()).st_ino
        except OSError:
            return False

    def teardown(self) -> None:
        try:
            if self._created:
                self._core.delete_namespace(self.namespace, propagation_policy="Background")
        except Exception:
            pass  # already gone; nothing else was created outside it
        finally:
            if self._handle is not None:
                self._handle.close()
            if self._scoped_api is not None:
                self._scoped_api.close()
            self._admin.close()
