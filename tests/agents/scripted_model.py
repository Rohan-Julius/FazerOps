"""A Strands `Model` that emits a scripted turn sequence. Test support for W19b.

The orchestrator's whole risk is in its *loop* — a runaway tool cycle, a model that never
dispatches, a model that follows an instruction it found in an alert summary. None of that
is reachable by calling a function; it needs a real agentic loop with a real turn counter.

So rather than mock `Agent`, this drives the genuine Strands loop with a fake provider.
Everything under test is the production path: the real `@tool` schemas, the real
`Limits(turns=...)` enforcement, the real tool executor, the real session handles. Only
the tokens are fake.

The event shapes below are Bedrock's `ConverseStream` shapes, which is what Strands'
`Model` contract is defined in terms of.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterable
from typing import Any

from strands.models import Model


class ScriptedModel(Model):
    """Replays a list of turns. Each turn is either `("tool", name, params)` or
    `("text", body)`.

    A script that runs out keeps repeating its final turn, so a "call this tool forever"
    script is one entry long and the turn cap is what stops it — which is the assertion.
    """

    def __init__(self, turns: list[tuple[Any, ...]], *, usage: dict[str, int] | None = None):
        self._turns = list(turns)
        self._index = 0
        self._usage = usage or {"inputTokens": 120, "outputTokens": 30, "totalTokens": 150}
        self.calls: list[list[dict]] = []

    # -- Model contract -----------------------------------------------------------------

    def get_config(self) -> dict[str, Any]:
        return {"model_id": "scripted"}

    def update_config(self, **kwargs: Any) -> None:
        pass

    async def structured_output(self, output_model, prompt, system_prompt=None, **kwargs):
        raise NotImplementedError("ScriptedModel drives the tool loop, not structured output")

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs) -> AsyncIterable[dict]:
        self.calls.append(list(messages))
        turn = self._turns[min(self._index, len(self._turns) - 1)]
        self._index += 1

        yield {"messageStart": {"role": "assistant"}}
        if turn[0] == "tool":
            _, name, params = turn
            yield {
                "contentBlockStart": {
                    "start": {"toolUse": {"toolUseId": f"t{self._index}", "name": name}},
                    "contentBlockIndex": 0,
                }
            }
            yield {
                "contentBlockDelta": {
                    "delta": {"toolUse": {"input": json.dumps(params)}},
                    "contentBlockIndex": 0,
                }
            }
            yield {"contentBlockStop": {"contentBlockIndex": 0}}
            yield {"messageStop": {"stopReason": "tool_use"}}
        else:
            yield {"contentBlockDelta": {"delta": {"text": turn[1]}, "contentBlockIndex": 0}}
            yield {"contentBlockStop": {"contentBlockIndex": 0}}
            yield {"messageStop": {"stopReason": "end_turn"}}

        yield {"metadata": {"usage": self._usage, "metrics": {"latencyMs": 1}}}

    # -- Inspection ---------------------------------------------------------------------

    @property
    def prompt_text(self) -> str:
        """Every user-role text block the model was ever shown, concatenated.

        This is what `test_orchestrator_envelope.py` asserts against: the envelope claim is
        about what actually reached the provider, not about what a renderer returned.
        """
        parts: list[str] = []
        for conversation in self.calls:
            for message in conversation:
                if message.get("role") != "user":
                    continue
                for block in message.get("content") or []:
                    if isinstance(block, dict) and "text" in block:
                        parts.append(block["text"])
        return "\n".join(parts)
