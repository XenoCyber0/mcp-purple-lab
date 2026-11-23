"""Single-line match keys for the rule engine.

Extracted from evaluate.py so the engine file stays inside the repo's ~200-line
contract (AGENTS.md rule 8). This module owns ONE concern: given a trace line
and a match condition, does the line satisfy it. Cross-line concerns
(track_field / on_change / tool_name_shadow) live in tracking.py.

Every key here is documented in evaluate.py's module docstring, which is the
user-facing reference. Adding a key means adding it in both places, in the same
commit.

v2 compiles every pattern once, at rule load. re.search(pattern, ...) used to
recompile per line per rule, and an invalid pattern only exploded during
evaluation -- where re.error is not a ValueError, so run.py reported it as exit
1 ("attack missed") instead of exit 2 ("setup failure").
"""
from __future__ import annotations

import json
import re
from typing import Any

URL_RE = re.compile(r"https?://", re.IGNORECASE)

_URL_ARG_KEYS = ("redirect_uri", "url", "destination", "endpoint", "webhook")

_ARGS_KEYS = {
    "arguments_contains", "arguments_keys", "arguments_value_not_in",
    "arguments_value_regex_not_in", "arguments_contains_url", "arguments_regex",
}
_LIST_KEYS = {
    "tool_name_contains", "arguments_contains", "arguments_keys",
    "arguments_value_not_in", "arguments_value_regex_not_in",
}
_STR_KEYS = {"message_type", "tool", "track_field"}

SINGLE_KEYS = {
    "message_type", "tool", "tool_name_contains", "arguments_contains",
    "arguments_keys", "arguments_value_not_in", "arguments_value_regex_not_in",
    "arguments_contains_url", "arguments_regex", "tool_name_regex",
}
TRACE_KEYS = {"track_field", "on_change", "tool_name_shadow"}
KNOWN_KEYS = SINGLE_KEYS | TRACE_KEYS | {"OR"}

_RE_CACHE: dict[tuple[str, int], re.Pattern] = {}


class RuleError(ValueError):
    """A rule file that cannot possibly behave as written."""


def compile_pattern(pattern: str, rule_id: str = "rule",
                    flags: int = 0) -> re.Pattern:
    """Compile once, cache, and turn a bad pattern into a load-time RuleError."""
    key = (pattern, flags)
    hit = _RE_CACHE.get(key)
    if hit is not None:
        return hit
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        raise RuleError(
            f"{rule_id}: invalid regex {pattern!r}: {exc}") from None
    _RE_CACHE[key] = compiled
    return compiled


def arguments_text(entry: dict) -> str:
    """Canonical serialization of a line's arguments, computed once per line."""
    args = entry.get("arguments")
    return "" if args is None else json.dumps(args, default=str)


def validate_match(match: dict, rule_id: str, where: str = "match") -> None:
    """Reject unknown keys and impossible values at load time.

    A typo'd key used to mean "never matches": a permanent false negative with
    no signal anywhere. A bad regex used to surface as exit 1 and read as
    "attack missed". Both are setup failures, so both raise RuleError here.
    """
    if not isinstance(match, dict):
        raise RuleError(f"{rule_id}: {where} must be a mapping")
    for key, cond in match.items():
        if key not in KNOWN_KEYS:
            raise RuleError(
                f"{rule_id}: unknown match key {key!r} in {where}; known keys: "
                f"{sorted(KNOWN_KEYS - {'OR'})}")
        if key == "OR":
            if not isinstance(cond, list):
                raise RuleError(f"{rule_id}: OR must be a list of match blocks")
            for i, block in enumerate(cond):
                validate_match(block, rule_id, f"match.OR[{i}]")
            continue
        if key in _LIST_KEYS and not isinstance(cond, list):
            raise RuleError(f"{rule_id}: {key} must be a list")
        if key in _STR_KEYS and not isinstance(cond, str):
            raise RuleError(f"{rule_id}: {key} must be a string")
        if key in ("arguments_contains_url", "tool_name_shadow") \
                and not isinstance(cond, bool):
            raise RuleError(f"{rule_id}: {key} must be true or false")
        if key == "on_change" and not isinstance(cond, dict):
            raise RuleError(f"{rule_id}: on_change must be a mapping")
        if key in ("tool_name_regex", "arguments_regex"):
            if not isinstance(cond, dict):
                raise RuleError(
                    f"{rule_id}: {key} must be a {{field: pattern}} mapping")
            for pattern in cond.values():
                compile_pattern(pattern, rule_id)
        if key == "arguments_value_regex_not_in":
            for pattern in cond:
                compile_pattern(pattern, rule_id, re.IGNORECASE)


def cond_matches(entry: dict, key: str, cond: Any,
                 args_text: str | None = None) -> bool:
    """Does this trace line satisfy one match condition?

    args_text is serialized once per line by evaluate_all and shared by every
    rule; json.dumps used to run once per condition per rule per line.
    """
    tool = entry.get("tool") or ""
    if args_text is None and key in _ARGS_KEYS:
        args_text = arguments_text(entry)
    args = entry.get("arguments")

    if key == "message_type":
        return entry.get("message_type") == cond
    if key == "tool":
        return tool == cond
    if key == "tool_name_contains":
        return any(s in tool for s in cond)
    if key == "tool_name_regex":
        return all(compile_pattern(p).search(tool) for p in cond.values())
    if key == "arguments_contains":
        return any(s in (args_text or "") for s in cond)
    if key == "arguments_contains_url":
        return bool(URL_RE.search(args_text or ""))
    if key == "arguments_keys":
        return isinstance(args, dict) and all(k in args for k in cond)
    if key == "arguments_regex":
        if not isinstance(args, dict):
            return False
        for arg_key, pattern in cond.items():
            if arg_key not in args:
                return False
            if not compile_pattern(pattern).search(str(args[arg_key])):
                return False
        return True
    if key == "arguments_value_not_in":
        if not isinstance(args, dict):
            return False
        arg_key = next((k for k in _URL_ARG_KEYS if k in args), None)
        if arg_key is None:
            return False
        return args[arg_key] not in cond
    if key == "arguments_value_regex_not_in":
        # Structural allowlist: the first URL-ish argument must NOT match any of
        # these host-anchored patterns, so app.example matches a pattern like
        # ^https?://([a-z0-9-]+\.)*app\.example([:/?#]|$) but attacker.example
        # does not. A bare substring would allowlist lookalike hosts.
        if not isinstance(args, dict):
            return False
        arg_key = next((k for k in _URL_ARG_KEYS if k in args), None)
        if arg_key is None:
            return False
        value = str(args[arg_key])
        return not any(compile_pattern(p, flags=re.IGNORECASE).search(value)
                       for p in cond)
    return False  # unreachable: validate_match rejects unknown keys at load


def block_matches(entry: dict, spec: dict,
                  args_text: str | None = None) -> bool:
    for key, cond in spec.items():
        if key == "OR" or key in TRACE_KEYS:
            continue
        if not cond_matches(entry, key, cond, args_text):
            return False
    return True


def line_matches(match: dict, entry: dict,
                 args_text: str | None = None) -> bool:
    """Sibling keys always apply (AND); an OR list additionally needs one hit.

    The engine used to return early on OR and silently discard every sibling
    key, so a rule declaring `message_type: tools/call` fired on tools/list
    lines it explicitly excluded.
    """
    for key, cond in match.items():
        if key == "OR" or key in TRACE_KEYS:
            continue
        if not cond_matches(entry, key, cond, args_text):
            return False
    blocks = match.get("OR")
    if blocks is not None:
        if args_text is None:
            args_text = arguments_text(entry)
        return any(block_matches(entry, b, args_text) for b in blocks)
    return True
