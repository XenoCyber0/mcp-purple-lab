"""stdio JSON-RPC 2.0 framing with id-routed reads.

Split out of mcp_client.py so the MCP semantics stay inside the 220-line CI
contract, and so notification handling lives where it belongs: in the
transport. `_read()` used to treat the next JSON object as the response to
whatever was pending -- a server pushing notifications/tools/list_changed (a
spec-compliant move) shifted every subsequent message by one and the client
silently mis-parsed the stream.

read_until(id) returns the response whose id matches and hands every
id-less notification to the transport's on_notification callback on the way.
A response with a non-matching id is buffered, not dropped: JSON-RPC lets a
server answer a pipeline in any order. A server-initiated REQUEST (method + id,
e.g. roots/list) is answered -32601 instead of being mistaken for a reply.

v2 fixed three defects that made the lab reject conformant servers:
integer-only ids (JSON-RPC allows String|Number; `true` is not id 1),
out-of-order pipelined responses, and server-initiated requests.
"""
from __future__ import annotations

import json
from typing import Callable

_MAX_PENDING = 64


class RpcError(Exception):
    pass


def _is_id(value) -> bool:
    """JSON-RPC ids: string or number. bool is an int subclass -- exclude it."""
    return isinstance(value, (str, int, float)) and not isinstance(value, bool)


class StdioRpc:
    def __init__(self, write, readline,
                 on_notification: Callable[[dict], None] | None = None,
                 on_server_request: Callable[[dict], None] | None = None):
        self._write = write
        self._readline = readline
        self.on_notification = on_notification
        self.on_server_request = on_server_request
        self.invalid_requests: list[dict] = []
        # Responses that arrived before their request was read, keyed by id.
        self._pending: dict = {}

    def send(self, msg: dict):
        self._write(json.dumps(msg) + "\n")
        return msg.get("id")

    def _refuse_server_request(self, msg: dict) -> None:
        """Answer a request we cannot serve, as the spec requires.

        Silently ignoring a server->client request (sampling, roots) leaves the
        server waiting forever; treating it as a response corrupts the stream.
        """
        if self.on_server_request:
            self.on_server_request(msg)
        self.send({"jsonrpc": "2.0", "id": msg.get("id"),
                   "error": {"code": -32601, "message": "Method not found",
                             "data": {"method": msg.get("method")}}})

    def read_until(self, expect_id: int | None) -> dict:
        if expect_id in self._pending:
            return self._pending.pop(expect_id)
        while True:
            line = self._readline()
            if not line:
                raise RpcError("server closed stdout")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RpcError(f"non-JSON line: {line[:200]!r}") from exc
            if not isinstance(msg, dict):
                # A JSON scalar/array is a protocol violation, not a
                # notification: reply -32600 and keep looping.
                self.invalid_requests.append({"raw": line[:500]})
                self.send({"jsonrpc": "2.0", "id": None,
                           "error": {"code": -32600,
                                     "message": "Invalid Request: expected a JSON object"}})
                continue
            if "method" in msg:
                if "id" in msg:
                    self._refuse_server_request(msg)
                elif self.on_notification:
                    self.on_notification(msg)
                continue
            if "id" not in msg:
                raise RpcError(f"frame has neither id nor method: {msg!r}")
            mid = msg["id"]
            if not _is_id(mid):
                raise RpcError(
                    f"invalid response id {mid!r}; JSON-RPC ids are string or number")
            if mid == expect_id:
                return msg
            if mid in self._pending:
                raise RpcError(f"duplicate response id={mid!r}")
            if len(self._pending) >= _MAX_PENDING:
                raise RpcError("too many out-of-order responses; server is not "
                               "tracking request ids")
            self._pending[mid] = msg
