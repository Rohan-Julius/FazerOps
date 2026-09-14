# W29 — the AgentCore Runtime container. Handoff §10.
#
# AgentCore Runtime requires **linux/arm64**, an HTTP server on **0.0.0.0:8080**, and the
# `/invocations` and `/ping` routes — all three of which `BedrockAgentCoreApp` provides, so
# this file's only job is to produce a correct image. The platform is pinned in the `FROM`
# rather than left to `docker build --platform`: an amd64 image builds and runs perfectly on
# a developer's machine and is rejected by the Runtime, which is a failure that costs a
# deploy cycle to discover.
FROM --platform=linux/arm64 python:3.12-slim

# Defaults are the zero-credential path (plan §5). A deployed container with no AWS or
# Gemini configuration still answers with the recorded fixture brief rather than failing,
# and `invoke`'s response reports which mode it came up in so the difference is never
# guessed from the output. The deployment overrides these with `agentcore deploy --env`
# (FAZEROPS_LLM=gemini, the Identity provider name, the session store) — never a key.
ENV FAZEROPS_MODE=fixture \
    FAZEROPS_LLM=stub \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies before source, so an edit to `src/` does not invalidate the install layer.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
# `gemini` because the deployed agent is Gemini-backed (plan §9.2); without the extra the image
# builds, deploys and answers `/ping`, and the first live invocation fails on an ImportError.
RUN pip install --no-cache-dir ".[gemini]" bedrock-agentcore

# Everything the fixture path reads. `fixtures/` is the point of the zero-credential mode
# and `config/` holds the service manifest, the action catalog and the thresholds — without
# them the blast radius resolves to nothing and the brief reports, confidently, that
# nothing changed.
COPY config/ ./config/
COPY fixtures/ ./fixtures/
COPY agentcore_app.py ./

# `config/` is resolved relative to the installed package (`catalog.CONFIG_ROOT` walks up
# from `src/fazerops/actions/`), so the container needs it where an editable checkout would
# have it. Installing the package non-editable moves it, and this restores the layout the
# code already expects rather than making the code aware of a container.
RUN python - <<'PY'
import pathlib, fazerops
root = pathlib.Path(fazerops.__file__).resolve().parents[2]
for name in ("config", "fixtures"):
    target = root / name
    if not target.exists():
        target.symlink_to(pathlib.Path("/app") / name, target_is_directory=True)
PY

EXPOSE 8080

CMD ["python", "agentcore_app.py"]
