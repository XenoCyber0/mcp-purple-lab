"""JSONL telemetry for the lab, with a hash chain.

One JSON object per line, written in order, every line addressable by its
1-based line number. Detection rules cite those line numbers as evidence.

Hash chain
----------
Every line carries `seq`, `prev_hash` and `hash`. `hash` is SHA-256 over the
line's own canonical JSON with `hash` removed, chained through `prev_hash`
(line 1 uses the empty string). Editing, inserting or dropping a line breaks
the chain from that point on; `verify_trace()` re-derives it and names the
first bad line.

Honest scope: the chain is self-contained. It catches accidental edits,
truncation and line renumbering -- the failures that silently invalidate an
evidence citation -- but anyone willing to recompute the whole chain could
still forge it. Anchoring the final root hash OUTSIDE the artifact (a signed
report, a CI log, a git blob) is what would make it tamper-proof. Until then
call it hash-chained, not tamper-proof.

The chain fields are additive: they do not shift line numbers, so every
existing rule and every existing evidence citation keeps working.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def _canonical(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


def _line_hash(entry: dict) -> str:
    return hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()


class Trace:
    def __init__(self, path: str):
        self.path = path
        self._fh = open(path, "w", encoding="utf-8")
        self._count = 0
        self._prev_hash = ""

    def record(self, direction: str, message_type: str, **fields: Any) -> int:
        """Append one event. Returns its 1-based line number."""
        self._count += 1
        entry = {"dir": direction, "message_type": message_type,
                 "seq": self._count, "prev_hash": self._prev_hash}
        entry.update(fields)
        entry["hash"] = _line_hash(entry)
        self._prev_hash = entry["hash"]
        self._fh.write(json.dumps(entry, default=str) + "\n")
        self._fh.flush()
        return self._count

    @property
    def count(self) -> int:
        return self._count

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()

    def __enter__(self) -> "Trace":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def read_trace(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def verify_trace(path: str) -> tuple[bool, str]:
    """Re-derive the chain. Returns (ok, message naming the first bad line)."""
    prev = ""
    entries = read_trace(path)
    for i, entry in enumerate(entries, 1):
        if entry.get("seq") != i:
            return False, f"line {i}: seq={entry.get('seq')!r}, expected {i}"
        if entry.get("prev_hash") != prev:
            return False, f"line {i}: prev_hash does not chain to line {i - 1}"
        if _line_hash(entry) != entry.get("hash"):
            return False, f"line {i}: content hash mismatch (line was edited)"
        prev = entry["hash"]
    return True, f"{len(entries)} lines, chain intact"


def excerpt(value: Any, limit: int = 200) -> str:
    """Human-readable preview for a trace field.

    NEVER feed an excerpt to a detection rule. Truncating at 200 chars made
    append-only schema drift invisible: a tool appended at the end of a long
    tools/list lands past the window. Rules compare full fields or digests
    (see mcp_client.tools_digest); previews are for humans only.
    """
    text = json.dumps(value, default=str)
    return text if len(text) <= limit else text[: limit - 3] + "..."
