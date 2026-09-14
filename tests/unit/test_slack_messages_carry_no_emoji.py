"""FazerOps's Slack messages carry no emoji (user decision, 14 Sep).

Checked over every string literal in the modules that compose Slack text, rather than over a few
rendered messages, so a new refusal or a new card line added later is covered without anyone
remembering to add it here. Docstrings are skipped: they are not sent.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "fazerops"
SLACK_TEXT_MODULES = [
    PACKAGE / "slack" / "blocks.py",
    PACKAGE / "slack" / "handlers.py",
    PACKAGE / "slack" / "commands.py",
    PACKAGE / "actions" / "server.py",
]

# `:word:` — Slack renders these as emoji. A shortcode is never glued to a word on its left, which is
# what separates it from an identifier such as `fazerops:approved-by:U0IC`; times (`14:41`) never match.
SHORTCODE = re.compile(r"(?<![\w:-]):[a-z][a-z0-9_+]*:")
UNICODE_EMOJI = re.compile("[\U0001F300-\U0001FAFF☀-➿⬀-⯿️]")


def _sent_strings(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings
    ]


@pytest.mark.parametrize("path", SLACK_TEXT_MODULES, ids=lambda p: p.name)
def test_no_emoji_in_any_string_a_slack_message_is_built_from(path):
    offending = [
        f"{path.name}:{line}: {text[:60]!r}"
        for line, text in _sent_strings(path)
        if SHORTCODE.search(text) or UNICODE_EMOJI.search(text)
    ]
    assert not offending, "\n".join(offending)


def test_the_check_would_catch_one():
    assert SHORTCODE.search(":white_check_mark: approved")
    assert not SHORTCODE.search("fired 14:41:00 · fazerops:approved-by:U0IC")
