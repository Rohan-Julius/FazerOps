#!/usr/bin/env bash
# W29 — the one deploy path for the AgentCore Runtime (plan §9.2, "Added 14 Sep (night)").
#
#   ./scripts/deploy_agentcore.sh            # build locally, push to ECR, update the Runtime
#
# Creates resources and a new Runtime version on every run. It is the user's to run, not CI's.
#
# The toolkit builds from its OWN copy of the Dockerfile, `.bedrock_agentcore/<agent>/Dockerfile`,
# taken at `configure` — not from the root file. An edit to the root Dockerfile that is not copied
# across never reaches the image: on 14 Sep the image shipped without `google-genai` that way, and
# the first live invocation died on an ImportError. A symlink does not fix it, because BuildKit sends
# the link rather than its target. So this script copies, checks the copy, and only then deploys.
set -euo pipefail
cd "$(dirname "$0")/.."

AGENT="${FAZEROPS_AGENTCORE_AGENT:-fazerops}"
AGENTCORE="${AGENTCORE_BIN:-.venv/bin/agentcore}"
BUILD_DIR=".bedrock_agentcore/$AGENT"

if [[ ! -f .bedrock_agentcore.yaml ]]; then
  echo "no .bedrock_agentcore.yaml — configure first:" >&2
  echo "  agentcore configure --entrypoint agentcore_app.py --name $AGENT --deployment-type container \\" >&2
  echo "    --container-runtime docker --disable-otel --disable-memory --region sa-east-1 --non-interactive" >&2
  exit 1
fi

mkdir -p "$BUILD_DIR"
rm -f "$BUILD_DIR/Dockerfile"
cp Dockerfile "$BUILD_DIR/Dockerfile"
if ! cmp -s Dockerfile "$BUILD_DIR/Dockerfile"; then
  echo "could not sync $BUILD_DIR/Dockerfile with the root Dockerfile" >&2
  exit 1
fi

# Configuration only — never a key. The Gemini key is held by AgentCore Identity (`fazerops-gemini`).
# The orchestrator runs on Pro because Flash was throttled past the graph's 120 s backstop (14 Sep).
exec env AGENTCORE_SUPPRESS_RECOMMENDATION=1 "$AGENTCORE" deploy --local-build --auto-update-on-conflict \
  --env FAZEROPS_MODE=fixture \
  --env FAZEROPS_LLM=gemini \
  --env FAZEROPS_GEMINI_BACKEND=vertex \
  --env FAZEROPS_GEMINI_MODEL_ORCHESTRATOR=gemini-3.1-pro-preview \
  --env FAZEROPS_GEMINI_KEY_PROVIDER=fazerops-gemini \
  --env FAZEROPS_SESSION_STORE=dynamodb \
  --env FAZEROPS_SESSION_TABLE=fazerops-incident-sessions \
  --env FAZEROPS_SESSION_REGION=sa-east-1 \
  "$@"
