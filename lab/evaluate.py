#!/usr/bin/env python3
"""Rule engine: evaluate detection rules against a trace.

Rules are Sigma-style YAML (see lab/rules/). The matcher is deliberately small
and fully deterministic:

match keys
----------
message_type       exact match on the trace line's message_type
tool               exact match on the trace line's tool
tool_name_contains any of these substrings appears in the tool name
arguments_contains any of these substrings appears in the serialized arguments
arguments_keys     all of these keys must be present in arguments
arguments_value_not_in
                   value for that key must NOT be any of the allowlist entries
arguments_contains_url
                   an http(s) URL appears in the serialized arguments
track_field        cross-line rule: remember the value of this field on every
                   matching line; fire if it ever changes (schema drift)
on_change.fired    fire when the tracked value changes

OR
--
A key `OR` in match holds a list of match-blocks; the line matches if any
block matches. Without OR, all present keys must match (AND).

Output
------
Each fired rule reports the 1-based trace line numbers it matched -- that is
the evidence. A rule with no trace lines never fires, and the report says so.
"""
from __future__ import annotations

import json
import re
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

URL_RE = re.compile(r"https?://", re.IGNORECASE)


class Rule:
    def __init__(self, path: str):
        if yaml is None:
            raise RuntimeError("pyyaml is required: pip install pyyaml")
        with open(path, encoding="utf-8") as fh:
            self.data = yaml.safe_load(fh)
        self.id = self.data["id"]
        self.title = self.data.get("title", self.id)
        self.severity = self.data.get("severity", "medium")
        self.atlas = self.data.get("atlas_technique", "")
        self.match = self.data.get("match", {})

    # ---------- single-line matching ----------

    def line_matches(self, entry: dict) -> bool:
        match = self.match
        if "OR" in match:
            return any(self._block_matches(entry, b) for b in match["OR"])
        return self._block_matches(entry, match)

    def _block_matches(self, entry: dict, spec: dict) -> bool:
        for key, cond in spec.items():
            if not self._cond_matches(entry, key, cond):
                return False
        return True

    def _cond_matches(self, entry: dict, key: str, cond: Any) -> bool:
        tool = entry.get("tool") or ""
        args = entry.get("arguments")
        args_text = json.dumps(args, default=str) if args is not None else ""

        if key == "message_type":
            return entry.get("message_type") == cond
        if key == "tool":
            return tool == cond
        if key == "tool_name_contains":
            return any(s in tool for s in cond)
        if key == "arguments_contains":
            return any(s in args_text for s in cond)
        if key == "arguments_contains_url":
            return bool(URL_RE.search(args_text))
        if key == "arguments_keys":
            return isinstance(args, dict) and all(k in args for k in cond)
        if key == "arguments_value_not_in":
            if not isinstance(args, dict):
                return False
            key_in_args = next((k for k in ("redirect_uri", "url") if k in args), None)
            if key_in_args is None:
                return False
            return args[key_in_args] not in cond
        return False

    # ---------- whole-trace matching ----------

    def evaluate(self, trace: list[dict], rules: list["Rule"] | None = None) -> list[int]:
        """Return the 1-based line numbers this rule fired on."""
        hits: list[int] = []
        if "track_field" in self.match:
            hits = self._evaluate_change_tracker(trace)
        else:
            for i, entry in enumerate(trace, 1):
                if self.line_matches(entry):
                    hits.append(i)
        return hits

    def _evaluate_change_tracker(self, trace: list[dict]) -> list[int]:
        field = self.match["track_field"]
        seen = None
        drift_lines: list[int] = []
        for i, entry in enumerate(trace, 1):
            if entry.get("message_type") != "tools/list.result":
                continue
            value = entry.get(field)
            if value is None:
                continue
            norm = json.dumps(value, sort_keys=True)
            if seen is not None and norm != seen:
                # this line is proof the schema changed
                drift_lines.append(i)
                # also flag the listing of a new dangerous tool name
            seen = norm
        if not drift_lines:
            return []
        # additionally flag any later call to a tool name matching the OR list
        extra: list[int] = []
        or_block = self.match.get("OR", [])
        for block in or_block:
            subs = block.get("tool_name_contains", [])
            if not subs:
                continue
            for i, entry in enumerate(trace, 1):
                tool = entry.get("tool") or ""
                if entry.get("message_type") != "tools/call.result":
                    continue
                if any(s in tool for s in subs):
                    extra.append(i)
        return sorted(set(drift_lines + extra))


def load_rules(rules_dir: str) -> list[Rule]:
    import os
    rules = []
    for name in sorted(os.listdir(rules_dir)):
        if name.endswith((".yaml", ".yml")):
            rules.append(Rule(os.path.join(rules_dir, name)))
    return rules


def evaluate_all(rules: list[Rule], trace: list[dict]) -> list[dict]:
    """Returns one result per rule: what fired and the evidence lines."""
    results = []
    for rule in rules:
        hits = rule.evaluate(trace)
        results.append({
            "rule": rule.id,
            "title": rule.title,
            "severity": rule.severity,
            "atlas_technique": rule.atlas,
            "fired": bool(hits),
            "trace_lines": hits,
            "match_count": len(hits),
        })
    return results
