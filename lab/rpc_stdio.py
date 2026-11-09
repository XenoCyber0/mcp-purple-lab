"""stdio JSON-RPC 2.0 framing with id-routed reads.

Split out of mcp_client.py so the MCP semantics stay inside the 220-line CI
contract, and so notification handling lives where it belongs: in the
transport. `_read()` used to treat the next JSON object as the response to
whatever was pending -- a server pushing notifications/tools/list_changed (a
spec-compliant move) shifted every subsequent message by one and the client
silently mis-parsed the stream.

read_until(id) returns the response whose id matches and hands every
id-less notification to the transport's on_notification callback on the way.
A response with a non-matching id is a protocol violation: recorded and
raised, never dropped.
"""
from __future__ import annotations

import json
from typing import Callable


class RpcError(Exception):
    pass


class StdioRpc:
    def __init__(self, write, readline,
                 on_notification: Callable[[dict], None] | None = None):
        self._write = write
        self._readline = readline
        self.on_notification = on_notification

    def send(self, msg: dict) -> int | None:
        self._write(json.dumps(msg) + "\n")
        return msg.get("id")

    def read_until(self, expect_id: int | None) -> dict:
        while True:
            line = self._readline()
            if not line:
                raise RpcError("server closed stdout")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RpcError(f"non-JSON line: {line[:200]!r}") from exc
            if "id" not in msg:
                if self.on_notification:
                    self.on_notification(msg)
                continue
            if msg["id"] == expect_id:
                return msg
            raise RpcError(
                f"out-of-order response: got id={msg['id']}, expected "
                f"{expect_id}; responses are never dropped")
