#!/usr/bin/env bash
# W7 — bring up the local cluster the demo's evidence chain runs on (Handoff §5).
#
# The only non-obvious part is the audit configuration. k3s does not enable auditing by
# default and there is no way to turn it on after the fact: the policy file has to be
# inside the server container and the kube-apiserver flags have to be set at creation, so
# a cluster created without these is not fixable, only replaceable.
#
# The audit log directory is bind-mounted back onto the host so the log can be read
# without `docker exec` — `tests/e2e/test_k3d_audit.py` and W7b's fixture capture both
# read it as an ordinary file.
#
#   ./scripts/setup_k3d.sh              create if absent, then apply the manifests
#   ./scripts/setup_k3d.sh --recreate   delete first (the only way to change the policy)
#   ./scripts/setup_k3d.sh --delete     tear down and stop
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER="${FABEROPS_CLUSTER:-faberops}"
POLICY_FILE="$REPO_ROOT/config/k8s/audit-policy.yaml"
AUDIT_DIR="${FABEROPS_AUDIT_DIR:-$REPO_ROOT/.k3d/audit}"

# Where the policy and the log live *inside* the server container.
POLICY_IN_CONTAINER="/var/lib/rancher/k3s/server/audit-policy.yaml"
AUDIT_DIR_IN_CONTAINER="/var/log/kubernetes/audit"

recreate=false
delete_only=false
for arg in "$@"; do
  case "$arg" in
    --recreate) recreate=true ;;
    --delete)   delete_only=true ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

for tool in k3d kubectl docker; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is not on PATH" >&2; exit 1; }
done
docker info >/dev/null 2>&1 || { echo "the Docker daemon is not running" >&2; exit 1; }

cluster_exists() { k3d cluster list -o json | grep -q "\"name\":\"$CLUSTER\""; }

if $delete_only; then
  cluster_exists && k3d cluster delete "$CLUSTER"
  exit 0
fi

if $recreate && cluster_exists; then
  k3d cluster delete "$CLUSTER"
fi

if cluster_exists; then
  echo "cluster '$CLUSTER' already exists — reusing it (--recreate to rebuild with a fresh audit policy)"
else
  mkdir -p "$AUDIT_DIR"
  echo "creating cluster '$CLUSTER' with RequestResponse auditing for ConfigMaps and Secrets"

  # A file mount for the policy, a directory mount for the log. `@server:*` targets every
  # server node; agents run no API server and need neither.
  k3d cluster create "$CLUSTER" \
    --agents 0 \
    --timeout 180s \
    --volume "$POLICY_FILE:$POLICY_IN_CONTAINER@server:*" \
    --volume "$AUDIT_DIR:$AUDIT_DIR_IN_CONTAINER@server:*" \
    --k3s-arg "--kube-apiserver-arg=audit-policy-file=$POLICY_IN_CONTAINER@server:*" \
    --k3s-arg "--kube-apiserver-arg=audit-log-path=$AUDIT_DIR_IN_CONTAINER/audit.log@server:*" \
    --k3s-arg "--kube-apiserver-arg=audit-log-maxage=1@server:*" \
    --k3s-arg "--kube-apiserver-arg=audit-log-maxbackup=1@server:*" \
    --k3s-arg "--kube-apiserver-arg=audit-log-maxsize=64@server:*"
fi

kubectl --context "k3d-$CLUSTER" wait --for=condition=Ready node --all --timeout=120s

# A cluster whose API server silently ignored the audit flags looks identical to a working
# one until the demo, so fail here instead of there.
if [ ! -s "$AUDIT_DIR/audit.log" ]; then
  echo "audit log is empty or missing at $AUDIT_DIR/audit.log — the policy did not take effect" >&2
  echo "inspect with: docker logs k3d-$CLUSTER-server-0" >&2
  exit 1
fi

kubectl --context "k3d-$CLUSTER" apply -f "$REPO_ROOT/config/k8s/billing-api.yaml"
kubectl --context "k3d-$CLUSTER" apply -f "$REPO_ROOT/config/k8s/auth-service.yaml"
kubectl --context "k3d-$CLUSTER" -n billing rollout status deployment/billing-api --timeout=120s

cat <<EOF

cluster '$CLUSTER' is up.
  context:    k3d-$CLUSTER
  audit log:  $AUDIT_DIR/audit.log
  verify:     pytest -m cluster
EOF
