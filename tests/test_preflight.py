"""W1 — preflight. System Python is 3.9; Strands needs >=3.10. Catching that here costs
seconds, catching it on Sep 9 at the first Agent import costs an hour of confusing
ImportErrors that look like an SDK problem.
"""

import sys


def test_python_is_at_least_3_10():
    assert sys.version_info >= (3, 10), (
        f"Strands requires Python >=3.10; running {sys.version.split()[0]}. "
        "Activate the uv venv: source .venv/bin/activate"
    )


def test_pydantic_is_v2():
    import pydantic

    assert pydantic.VERSION.startswith("2."), (
        f"models.py is written against Pydantic v2; found {pydantic.VERSION}"
    )


def test_strands_core_imports_resolve():
    """PLAN §1.1 confirmed surfaces. If this goes red the pinned SDK moved under us."""
    from strands import Agent, tool  # noqa: F401
    from strands.models import BedrockModel  # noqa: F401
    from strands.multiagent import GraphBuilder  # noqa: F401


def test_strands_function_node_surface_exists():
    """PLAN §1.1: the FunctionNode pattern is what makes the four collectors real graph
    nodes. If these names moved, §3.2's topology needs rework before W19, not during it.
    """
    from strands.multiagent.base import (  # noqa: F401
        MultiAgentBase,
        MultiAgentResult,
        NodeResult,
        Status,
    )
