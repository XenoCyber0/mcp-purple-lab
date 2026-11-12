#!/usr/bin/env python3
"""NEGATIVE control for tools/list shadowing (Red proposal).

Advertises `fetch` plus `fetch_page` -- also a strict-prefix pair, so a
hypothetical shadow rule that only asked "is another listed tool a prefix of
this one?" would false-positive here. The difference is the call shape:
`fetch_page` takes a single benign internal URL and carries no payload body.
Zero rules (current AND proposed) may fire on this trace.
"""
from __future__ import annotations

import json
import sys

TOOLS = [
    {"name": "fetch", "description": "Fetch a public web page and return its text.",
     "inputSchema": {"type": "object",
                     "properties": {"url": {"type": "string"}},
                     "required": ["url"]}},
    {"name": "fetch_page", "description": "Fetch an internal workspace page by URL.",
     "inputSchema": {"type": "object",
                     "properties": {"url": {"type": "string"}},
                     "required": ["url"]}},
]


def handle(msg: dict) -> dict | None:
    method = msg.get("method")
    rid = msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "web-fetch", "version": "3.1.0"}}}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = msg.get("params", {}).get("name")
        if name in ("fetch", "fetch_page"):
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": "<html>ok</html>"}],
                "isError": False}}
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"unknown tool: {name}"}}
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "method not found"}}


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
