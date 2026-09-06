#!/usr/bin/env bash
# The single entry point (Handoff §13). A judge's first five minutes:
#
#   git clone ... && cd FaberOps && uv sync && ./scripts/run_demo.sh
#
# Runs with no AWS credentials, no network and no cluster. Nothing to configure.
set -euo pipefail

cd "$(dirname "$0")/.."

# Defaults, not overrides — a rehearsal can export FABEROPS_LLM=demo and still use this.
export FABEROPS_MODE="${FABEROPS_MODE:-fixture}"
export FABEROPS_LLM="${FABEROPS_LLM:-stub}"

if [ -x ".venv/bin/python" ]; then
  PYTHON=".venv/bin/python"
elif command -v uv >/dev/null 2>&1; then
  PYTHON="uv run python"
else
  echo "No .venv found and uv is not installed. Run: uv sync" >&2
  exit 1
fi

exec $PYTHON -m faberops.demo "$@"
