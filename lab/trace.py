"""JSONL telemetry for the lab.

One JSON object per line, written in order, every line addressable by its
1-based line number. Detection rules cite those line numbers as evidence.
"""
from __future__ import annotations

import json
from typing import Any


class Trace:
    def __init__(self, path: str):
        self.path = path
        self._fh = open(path, "w", encoding="utf-8")
        self._count = 0

    def record(self, direction: str, message_type: str, **fields: Any) -> int:
        """Append one event. Returns its 1-based line number."""
        self._count += 1
        entry = {"dir": direction, "message_type": message_type}
        entry.update(fields)
        self._fh.write(json.dumps(entry, default=str) + "\n")
        self._fh.flush()
        return self._count

    @property
    def count(self) -> int:
        return self._count

    def close(self) -> None:
        self._fh.close()


def read_trace(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def excerpt(value: Any, limit: int = 200) -> str:
    text = json.dumps(value, default=str)
    return text if len(text) <= limit else text[: limit - 3] + "..."
