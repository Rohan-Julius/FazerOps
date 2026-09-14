#!/usr/bin/env bash
# W30 — clean-machine quickstart verification (Handoff §13: "have someone who didn't
# write it run it"; this script is the automatable half of that requirement — the
# mechanical proxy for a judge's first five minutes, not a substitute for an actual
# independent run, which still needs a person other than the author).
#
# Proves the README's quickstart bootstraps with none of this machine's ambient state:
# a bare `env -i` shell (no AWS_*, no FAZEROPS_*, no Slack/Gemini/GitHub credentials,
# nothing this session has exported), a fresh local clone (isolates from uncommitted
# working-tree edits — cloning the real public URL was verified separately, by hand,
# tonight, and depends on GitHub's own uptime rather than this repo), and a fresh
# `uv` cache directory so `uv sync` actually resolves and installs rather than reusing
# a warm cache. Fails on the first thing that doesn't work (`set -euo pipefail`).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d)"
UV_BIN="$(command -v uv || true)"
trap 'rm -rf "$WORKDIR"' EXIT

if [ -z "$UV_BIN" ]; then
  echo "FAIL: uv not found on PATH" >&2
  exit 1
fi

echo "== cloning a fresh, local checkout of $REPO_ROOT =="
git clone --quiet "$REPO_ROOT" "$WORKDIR/FazerOps"

echo "== running uv sync + run_demo.sh in a bare environment (no AWS_*, no FAZEROPS_*, no cached uv env) =="
OUTPUT="$(env -i \
  HOME="$WORKDIR/home" \
  PATH="$(dirname "$UV_BIN"):/usr/bin:/bin:/usr/sbin:/sbin" \
  UV_CACHE_DIR="$WORKDIR/uv-cache" \
  TERM=dumb \
  bash -c "
    set -euo pipefail
    mkdir -p \"$WORKDIR/home\"
    cd \"$WORKDIR/FazerOps\"
    uv sync >&2
    ./scripts/run_demo.sh
  ")"

echo "$OUTPUT"

echo "== asserting the brief rendered =="
grep -q "FazerOps change brief" <<<"$OUTPUT"
grep -q "ConfigMap billing-api-config" <<<"$OUTPUT"
grep -Eq "ConfigMap billing-api-config +· +score 0\.[7-9][0-9]" <<<"$OUTPUT"
grep -q "Nothing shipped through CI in this window." <<<"$OUTPUT"

echo "PASS: quickstart runs clean on a fresh local checkout with no AWS/FazerOps/Slack/Gemini credentials and a cold uv cache"
