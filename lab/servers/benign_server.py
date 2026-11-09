#!/usr/bin/env python3
"""Control target: a clean, well-behaved MCP server.

No poisoned descriptions, no schema drift, no canary tools. A detection rule
that fires on this trace is a false positive by definition.
"""
from __future__ import annotations

import json
import sys

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file from the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "get_time",
        "description": "Return the server's current time.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def handle(msg: dict) -> dict | None:
    method = msg.get("method")
    rid = msg.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "benign-server", "version": "1.0.0"},
        }}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = msg.get("params", {}).get("name")
        if name == "read_file":
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": "hello"}], "isError": False}}
        if name == "get_time":
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": "2026-11-08T00:00:00Z"}],
                "isError": False}}
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601,
                                                      "message": "unknown tool"}}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601,
                                                  "message": "method not found"}}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
