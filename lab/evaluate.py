#!/usr/bin/env python3
"""Rule engine: load Sigma-style detection rules and evaluate them on a trace.

Rules are YAML (see lab/rules/). Single-line matching lives in matching.py;
the two cross-line relations live in tracking.py. This module owns loading,
validation, the rule model, and the evaluation loop.

match keys
----------
message_type        exact match on the trace line's message_type
tool                exact match on the trace line's tool
tool_name_contains  any of these substrings appears in the tool name
tool_name_regex     {label: pattern}; every pattern must match the tool name
arguments_contains  any of these substrings appears in the arguments text
arguments_keys      all of these keys must be present in arguments
arguments_value_not_in
                    the first URL-ish argument (redirect_uri, url, destination,
                    endpoint, webhook) must NOT be an allowlist entry
arguments_value_regex_not_in
                    the same argument must NOT match any of these regexes
                    (re.search, case-insensitive). Host-anchored patterns with a
                    ([:/?#]|$) boundary express "host is allowlisted" without
                    enumerating paths, and without allowing attacker.example.
arguments_contains_url
                    an http(s) URL appears in the serialized arguments
arguments_regex     {argument_name: pattern}; re.search must succeed for every
                    listed argument. Matches the STRUCTURE of a value.
track_field         cross-line: remember this field on every tools/list.result
                    line; fire when it changes (drift). Point it at a full field
                    or a digest, NEVER at an excerpt.
on_change.fired     whether a change fires the rule (default true; false makes
                    it a pure call-flagger)
tool_name_shadow    cross-line: true on a tools/call line whose tool name
                    STRICTLY extends another advertised name (fetch -> fetch_all)

OR
--
A key `OR` holds a list of match blocks. The OTHER keys always apply (AND); at
least one OR block must additionally match. The engine used to return early on
OR and discard every sibling key.

Unknown keys, wrong-typed values, and invalid regexes raise RuleError at load
time. run.py maps RuleError to exit 2 (setup failure), never to exit 1 (missed
attack), because those two outcomes mean opposite things to a pipeline.

Output
------
Each fired rule reports the 1-based trace line numbers it matched: that is the
evidence. A rule with no trace lines never fires.

Loading is cached per directory and invalidated by (name, mtime, size), so the
matrix, the CLI zinc the tests do not re-parse the same YAML four times.
"""
from __future__ import annotations

import os

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from matching import (  # noqa: E402
    RuleError, arguments_text, line_matches, validate_match,
)
from tracking import change_hits, shadow_hits  # noqa: E402

__all__ = ["Rule", "RuleError", "load_rules", "evaluate_all"]

_CACHE: dict[str, tuple[tuple, list["Rule"]]] = {}


class Rule:
    def __init__(self, path: str):
        if yaml is None:
            raise RuntimeError("pyyaml is required: pip install pyyaml")
        with open(path, encoding="utf-8") as fh:
            self.data = yaml.safe_load(fh)
        if not isinstance(self.data, dict):
            raise RuleError(f"{path}: rule is not a mapping")
        if not self.data.get("id"):
            raise RuleError(f"{path}: rule has no id")
        self.id = str(self.data["id"])
        self.title = self.data.get("title", self.id)
        self.severity = self.data.get("severity", "medium")
        self.confidence = self.data.get("confidence", "medium")
        self.atlas = self.data.get("atlas_technique", "")
        self.match = self.data.get("match") or {}
        validate_match(self.match, self.id)

    def line_matches(self, entry: dict,
                     args_text: str | None = None) -> bool:
        return line_matches(self.match, entry, args_text)

    def evaluate(self, trace: list[dict],
                 args_texts: list[str] | None = None) -> list[int]:
        """Return the 1-based line numbers this rule fired on.

        Cross-line keys delegate to tracking.py; everything else is a pure AND
        over one line, with OR as an additional any-of group crucially.
        """
        if "track_field" in self.match:
            return change_hits(self.match, trace)
        if args_texts is None:
            args_texts = [arguments_text(entry) for entry in trace]
        if "tool_name_shadow" in self.match:
            return shadow_hits(self.match, trace, args_texts)
        return [i for i, (entry, text) in enumerate(zip(trace, args_texts), 1)
                if line_matches(self.match, entry, text)]


def _signature(rules_dir: str) -> tuple:
    sig = []
    for name in sorted(os.listdir(rules_dir)):
        if not name.endswith((".yaml", ".yml")):
            continue
        st = os.stat(os.path.join(rules_dir, name))
        sig.append((name, st.st_mtime_ns, st.st_size))
    return tuple(sig)


def load_rules(rules_dir: str) -> list[Rule]:
    """Parse every rule once per process; re-parse when a file changes."""
    sig = _signature(rules_dir)
    cached = _CACHE.get(rules_dir)
    if cached and cached[0] == sig:
        return list(cached[1])
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for name in sorted(os.listdir(rules_dir)):
        if not name.endswith((".yaml", ".yml")):
            continue
        rule = Rule(os.path.join(rules_dir, name))
        if rule.id in seen:
            raise RuleError(
                f"duplicate rule id {rule.id!r}: {seen[rule.id]} and {name}")
        seen[rule.id] = name
        rules.append(rule)
    _CACHE[rules_dir] = (sig, rules)
    return list(rules)


def evaluate_all(rules: list[Rule], trace: list[dict]) -> list[dict]:
    """Returns one result per rule: what fired and the evidence lines."""
    args_texts = [arguments_text(entry) for entry in trace]
    results = []
    for rule in rules:
        hits = rule.evaluate(trace, args_texts)
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
