"""Single-line match keys for the rule engine.

Extracted from evaluate.py so the engine file stays inside the repo's ~200-line
contract (AGENTS.md rule 8). This module owns ONE concern: given a trace line
and a match condition, does the line satisfy it. Cross-line concerns
(track_field / on_change) stay in evaluate.py.

Every key here is documented in evaluate.py's module docstring, which is the
user-facing reference. Adding a key means adding it in both places, in the same
commit.
"""
from __future__ import annotations

import json
import re
from typing import Any

URL_RE = re.compile(r"https?://", re.IGNORECASE)

SINGLE_KEYS = {
    "message_type", "tool", "tool_name_contains", "arguments_contains",
    "arguments_keys", "arguments_value_not_in", "arguments_contains_url",
    "arguments_regex", "tool_name_regex",
}
TRACE_KEYS = {"track_field", "on_change"}
KNOWN_KEYS = SINGLE_KEYS | TRACE_KEYS | {"OR"}

# Keys whose value is an allowlist of argument names checked for membership.
_URL_ARG_KEYS = ("redirect_uri", "url", "destination", "endpoint", "webhook")


class RuleError(ValueError):
    """A rule file that cannot possibly behave as written."""


def validate_match(match: dict, rule_id: str, where: str = "match") -> None:
    """Reject unknown keys at load time.

    A typo'd key used to mean "never matches": a permanent false negative with
    no signal anywhere, invisible in a green test run.
    """
    if not isinstance(match, dict):
        raise RuleError(f"{rule_id}: {where} must be a mapping")
    for key, cond in match.items():
        if key not in KNOWN_KEYS:
            raise RuleError(
                f"{rule_id}: unknown match key {key!r} in {where}; "
                f"known keys: {sorted(KNOWN_KEYS - {'OR'})}")
        if key in {"arguments_regex", "tool_name_regex"} and not isinstance(cond, dict):
            raise RuleError(f"{rule_id}: {key} must be a {{field: pattern}} mapping")
        if key == "OR":
            if not isinstance(cond, list):
                raise RuleError(f"{rule_id}: OR must be a list of match blocks")
            for i, block in enumerate(cond):
                validate_match(block, rule_id, f"match.OR[{i}]")


def cond_matches(entry: dict, key: str, cond: Any) -> bool:
    """Does this trace line satisfy one match condition?"""
    tool = entry.get("tool") or ""
    args = entry.get("arguments")
    args_text = json.dumps(args, default=str) if args is not None else ""

    if key == "message_type":
        return entry.get("message_type") == cond
    if key == "tool":
        return tool == cond
    if key == "tool_name_contains":
        return any(s in tool for s in cond)
    if key == "tool_name_regex":
        return all(re.search(p, tool) for p in cond.values())
    if key == "arguments_contains":
        return any(s in args_text for s in cond)
    if key == "arguments_contains_url":
        return bool(URL_RE.search(args_text))
    if key == "arguments_keys":
        return isinstance(args, dict) and all(k in args for k in cond)
    if key == "arguments_regex":
        if not isinstance(args, dict):
            return False
        for arg_key, pattern in cond.items():
            if arg_key not in args:
                return False
            if not re.search(pattern, str(args[arg_key])):
                return False
        return True
    if key == "arguments_value_not_in":
        if not isinstance(args, dict):
            return False
        arg_key = next((k for k in _URL_ARG_KEYS if k in args), None)
        if arg_key is None:
            return False
        return args[arg_key] not in cond
    return False  # unreachable: validate_match rejects unknown keys at load


def block_matches(entry: dict, spec: dict) -> bool:
    for key, cond in spec.items():
        if key == "OR":
            continue
        if not cond_matches(entry, key, cond):
            return False
    return True


def line_matches(match: dict, entry: dict) -> bool:
    """Sibling keys always apply (AND); an OR list additionally needs one hit.

    The engine used to return early on OR and silently discard every sibling
    key, so a rule declaring `message_type: tools/call` fired on tools/list
    lines it explicitly excluded.
    """
    for key, cond in match.items():
        if key == "OR" or key in TRACE_KEYS:
            continue
        if not cond_matches(entry, key, cond):
            return False
    blocks = match.get("OR")
    if blocks is not None:
        return any(block_matches(entry, b) for b in blocks)
    return True
