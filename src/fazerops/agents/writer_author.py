"""W42 rung 3 — the agent that authors a writer. `docs/catalog_self_extension.md` §2a, §3.

**The one place in this system a model writes code that may eventually execute** — plan §9.2's
ground-rule-#1 deviation. What keeps it admissible is everything around it rather than anything in
it:

* **Its only input is a contract built from a human-written table** (`writers/k8s_support.py`):
  a resource kind, two client method names, two signatures. No ledger text, alert text or diff
  value reaches it, so no writable ConfigMap can steer what gets written.
* **It never sees, names or chooses an action.** The proposer's vocabulary is untouched; this
  agent is invoked by deterministic Python after the miner and generation have decided a writer
  is needed (§4).
* **Its output is checked, never trusted**: an AST allowlist, a fixed module template CI
  re-renders, and a probe in a separate interpreter against a fake client
  (`actions/growth/authoring.py`). A human then reads it, merges it, adds it to
  `WRITER_MODULES`, declares its tier, and approves every execution — whose inverse, dry run and
  credential check are all human-written.

Same four modes and the same metering and cassette discipline as the other agents.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict

__all__ = ["AuthoredWriter", "WriterAuthoringFailed", "author_writer", "build_messages"]


class WriterAuthoringFailed(RuntimeError):
    """The model returned nothing usable — distinct from a writer the validator rejected."""


class AuthoredWriter(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    read_source: str
    write_source: str
    model: str


# One-line docstring on purpose: Pydantic ships it as the schema `description`.
class _WireOutput(BaseModel):
    """Authored writer functions."""

    read_source: str
    write_source: str


def build_messages(contract: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "role": "user",
            "content": [
                {
                    "text": "Write `read` and `write` for this contract.\n\n"
                    + json.dumps(contract, indent=2, sort_keys=True)
                }
            ],
        }
    ]


def _stub(contract: dict[str, Any]) -> dict[str, str]:
    """The canned answer for `FAZEROPS_LLM=stub`: a correct writer for the contract, so the CI
    default exercises the validator and the probe rather than bypassing them."""
    read_method, write_method = contract["read_method"], contract["write_method"]
    attribute, body_field = contract["read_attribute"], contract["body_field"]
    return {
        "read_source": (
            "def read(params, *, client):\n"
            f'    obj = client.{read_method}(name=params["name"], namespace=params["namespace"])\n'
            f"    return dict(obj.{attribute} or {{}})\n"
        ),
        "write_source": (
            "def write(params, values, *, credential, client):\n"
            f"    patched = client.{write_method}(\n"
            f'        name=params["name"], namespace=params["namespace"], body={{"{body_field}": dict(values)}}\n'
            "    )\n"
            "    return {\n"
            '        "namespace": params["namespace"],\n'
            '        "name": params["name"],\n'
            '        "keys": sorted(values),\n'
            '        "resource_version": patched.metadata.resource_version,\n'
            "    }\n"
        ),
    }


def _parse(raw: Any) -> dict[str, str]:
    try:
        return _WireOutput.model_validate(raw).model_dump()
    except Exception as exc:  # a malformed tape or response, never a partial writer
        raise WriterAuthoringFailed(f"the writer author's response did not match its schema: {exc}") from exc


async def author_writer(
    contract: dict[str, Any], *, meter: Any | None = None, cassette_directory: Any | None = None
) -> AuthoredWriter:
    from ..config import LlmMode, llm_mode
    from .cassette import Cassette, request_key
    from .correlator import generation_params_for
    from .llm import model_for, provider_for, recording_model_for
    from .prompts.writer_author import SYSTEM_PROMPT

    mode = llm_mode()
    if mode is LlmMode.STUB:
        return AuthoredWriter(**_stub(contract), model="stub")

    messages = build_messages(contract)
    model = (
        recording_model_for("writer_author")
        if mode is LlmMode.CASSETTE
        else model_for("writer_author", mode)
    )
    key = request_key(
        "writer_author", model, messages, system=SYSTEM_PROMPT, **generation_params_for(mode)
    )
    cassette = Cassette("writer_author", directory=cassette_directory)

    if mode is LlmMode.CASSETTE:
        return AuthoredWriter(**_parse(cassette.replay(key)), model=model)

    response, usage = await _invoke(provider_for(mode), model, messages)
    if meter is not None:
        meter.record("writer_author", model, usage["in"], usage["out"], estimated=usage.get("estimated", False))
    if mode is LlmMode.RECORD:
        cassette.record(key, response, model=model)
    return AuthoredWriter(**_parse(response), model=model)


async def _invoke(provider, model: str, messages: list[dict]) -> tuple[dict, dict]:
    from ..config import require_offline_capable
    from .correlator import _bedrock_model, _estimated_usage, _gemini_model, _usage_from
    from .llm import Provider
    from .prompts.writer_author import SYSTEM_PROMPT

    require_offline_capable("writer_author")
    client = _gemini_model(model) if provider is Provider.GEMINI else _bedrock_model(model)

    output: _WireOutput | None = None
    usage: dict[str, int] | None = None
    async for event in client.structured_output(_WireOutput, messages, SYSTEM_PROMPT):
        usage = _usage_from(event) or usage
        if "output" in event:
            output = event["output"]

    if output is None:
        raise WriterAuthoringFailed("the model returned no structured output")
    return output.model_dump(), usage or _estimated_usage(messages, output)
