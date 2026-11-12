#!/usr/bin/env python3
"""Rule engine: evaluate detection rules against a trace.

Rules are Sigma-style YAML (see lab/rules/). Single-line matching lives in
matching.py; this module owns rule loading, cross-line tracking, and scoring.
It is deliberately small and fully deterministic.

match keys
----------
message_type        exact match on the trace line's message_type
tool                exact match on the trace line's tool
tool_name_contains  any of these substrings appears in the tool name
tool_name_regex     {label: pattern}; every pattern must match the tool name
arguments_contains  any of these substrings appears in the serialized arguments
arguments_keys      all of these keys must be present in arguments
arguments_value_not_in
                    the first URL-ish argument (redirect_uri, url, destination,
                    endpoint, webhook) must NOT be an allowlist entry
arguments_contains_url
                    an http(s) URL appears in the serialized arguments
arguments_regex     {argument_name: pattern}; re.search must succeed for every
                    listed argument. Matches the STRUCTURE of a value, so a
                    rule can express "host is external" instead of enumerating
                    every legitimate callback.
track_field         cross-line: remember this field on every tools/list.result
                    line; fire if it ever changes (drift). Point it at a full
                    field or a digest, NEVER at an excerpt -- a 200-char
                    preview made append-only schema drift invisible.
on_change.fired     whether a change fires the rule (default true; false makes
                    the rule a pure call-flagger)
tool_name_shadow    cross-line: true on a tools/call line whose tool name
                    STRICTLY extends another tool advertised on a
                    tools/list.result line (fetch -> fetch_all). Prefix
                    ambiguity is a relation between two list entries, so no
                    single-line key can express it.

OR
--
A key `OR` in match holds a list of match-blocks. The OTHER keys in `match`
always apply (AND); at least one OR block must additionally match. OR groups
sub-conditions, it does not replace its siblings: a rule declaring
`message_type: tools/call` with an OR list never fires on a tools/list line.
(The engine used to return early on OR and silently discard every sibling key.)

Cross-line keys: `tool_name_shadow: true` restricts matching to tools/call
lines whose tool name strictly extends another tool advertised on a
tools/list.result line in the same trace (fetch_all shadows fetch). The
relation spans two lines, so Rule.evaluate applies it and line_matches skips
it; sibling keys still AND on the call line.

Unknown match keys raise RuleError at load time. A typo'd key used to mean
"never matches" -- a permanent false negative with no signal anywhere.

Output
------
Each fired rule reports the 1-based trace line numbers it matched -- that is
the evidence. A rule with no trace lines never fires, and the report says so.
"""
from __future__ import annotations

import json
import os

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from matching import (  # noqa: E402
    RuleError, TRACE_KEYS, line_matches, validate_match,
)

__all__ = ["Rule", "RuleError", "load_rules", "evaluate_all"]


class Rule:
    def __init__(self, path: str):
        if yaml is None:
            raise RuntimeError("pyyaml is required: pip install pyyaml")
        with open(path, encoding="utf-8") as fh:
            self.data = yaml.safe_load(fh)
        self.id = self.data["id"]
        self.title = self.data.get("title", self.id)
        self.severity = self.data.get("severity", "medium")
        self.confidence = self.data.get("confidence", "medium")
        self.atlas = self.data.get("atlas_technique", "")
        self.match = self.data.get("match", {})
        validate_match(self.match, self.id)

    def line_matches(self, entry: dict) -> bool:
        return line_matches(self.match, entry)

    # ---------- whole-trace matching ----------

    def evaluate(self, trace: list[dict]) -> list[int]:
        """Return the 1-based line numbers this rule fired on."""
        if "track_field" in self.match:
            return self._evaluate_change_tracker(trace)
        baseline = None
        if "tool_name_shadow" in self.match:
            baseline = self._baseline_tool_names(trace)
        hits: list[int] = []
        for i, entry in enumerate(trace, 1):
            if baseline is not None and not self._shadows(entry, baseline):
                continue
            if self.line_matches(entry):
                hits.append(i)
        return hits

    @staticmethod
    def _baseline_tool_names(trace: list[dict]) -> set[str]:
        """Every tool name advertised on any tools/list.result line."""
        names: set[str] = set()
        for entry in trace:
            if entry.get("message_type") != "tools/list.result":
                continue
            listed = entry.get("tool_names")
            if isinstance(listed, list):
                names.update(str(n) for n in listed)
                continue
            tools = entry.get("tools")
            if isinstance(tools, list):
                names.update(
                    str(t["name"]) for t in tools
                    if isinstance(t, dict) and t.get("name")
                )
        return names

    def _shadows(self, entry: dict, baseline: set[str]) -> bool:
        """True when the called tool STRICTLY extends another advertised name.

        fetch_all shadows fetch; fetch itself shadows nothing. A prefix pair
        alone is not an attack -- the rule's sibling keys must also match.
        """
        if not self.match.get("tool_name_shadow"):
            return False
        tool = entry.get("tool") or ""
        return any(other != tool and tool.startswith(other) for other in baseline)

    def _evaluate_change_tracker(self, trace: list[dict]) -> list[int]:
        field = self.match["track_field"]
        fire_on_change = bool((self.match.get("on_change") or {}).get("fired", True))
        seen = None
        changed: list[int] = []
        for i, entry in enumerate(trace, 1):
            if entry.get("message_type") != "tools/list.result":
                continue
            value = entry.get(field)
            if value is None:
                continue
            norm = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
            if seen is not None and norm != seen:
                changed.append(i)  # this line is proof the schema moved
            seen = norm
        # Flag suspicious tool CALLS only once the schema actually moved (or
        # when the rule opted out of change-tracking). Firing on the name list
        # alone degrades this rule into a blunt tool-name blacklist, which is
        # the over-breadth that gets detections ignored and then deleted.
        if not changed and fire_on_change:
            return []
        drift_lines = changed if fire_on_change else []
        extra: list[int] = []
        for block in self.match.get("OR") or []:
            subs = block.get("tool_name_contains", [])
            if not subs:
                continue
            for i, entry in enumerate(trace, 1):
                if entry.get("message_type") != "tools/call.result":
                    continue
                if any(s in (entry.get("tool") or "") for s in subs):
                    extra.append(i)
        return sorted(set(drift_lines + extra))


def load_rules(rules_dir: str) -> list[Rule]:
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
            "confidence": rule.confidence,
            "atlas_technique": rule.atlas,
            "fired": bool(hits),
            "trace_lines": hits,
            "match_count": len(hits),
        })
    return results
