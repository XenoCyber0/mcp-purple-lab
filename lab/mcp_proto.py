"""Wire-level helpers shared by McpClient and its stdio transport.

Extracted in v2, when mcp_client.py reached 219 of the 220 lines the CI
file-size contract (AGENTS.md rule 8) allows: every compatibility fix started
life as a red build. Nothing here owns a subprocess or a rule -- it is pure
protocol, so client and transport can both import it without a cycle.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import shlex
import subprocess
import sys
import threading

VERSION = "2.0.0"
PROTOCOL_VERSION = "2024-11-05"
LIST_CHANGED = "notifications/tools/list_changed"
READ_TIMEOUT = 10.0

_EOF = object()
_PY_NAMES = ("python", "python3", "py")


class McpError(Exception):
    """A failure that belongs to the MCP session, not to the lab harness."""


def _unquote_nt(token: str) -> str:
    # shlex(posix=False) keeps quotes so "C:\Program Files\py.exe" stays one
    # token; the quotes themselves must not reach CreateProcess.
    if len(token) > 1 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def resolve_command(cmd) -> list[str]:
    """Turn a scenario `server` value into argv, safely.

    The old implementation was `cmd.split()`: a checkout under "Program Files"
    or "/home/me/my repo" died looking for a file named "my", and the failure
    surfaced as a setup error with no hint that the path was the problem.
    Accepts a shell-style string (quotes honoured on both platforms) or an
    explicit argv list, which is what a path containing spaces wants.

    A bare `python`/`python3`/`py` becomes sys.executable, so the lab is
    never half-run by a different interpreter than the one that started it.
    """
    if isinstance(cmd, (list, tuple)):
        parts = [str(p) for p in cmd]
    else:
        text = str(cmd).strip()
        parts = shlex.split(text, posix=os.name != "nt")
        if os.name == "nt":
            parts = [_unquote_nt(p) for p in parts]
    if not parts:
        raise McpError("empty server command")
    if parts[0] in _PY_NAMES:
        parts[0] = sys.executable
    return parts


def tools_digest(tools: list[dict]) -> str:
    """SHA-256 over the canonical tool list: sorted by name, keys sorted.

    Sorting by name means a server merely reordering an otherwise identical
    list is NOT drift; adding, removing, or changing any field of any tool IS.
    A digest over the FULL list cannot be evaded by appending a tool past a
    200-char preview window, which is how a real rug-pull actually lands.
    """
    canon = json.dumps(sorted(tools, key=lambda t: t.get("name", "")),
                       sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


class LineReader:
    """`readline()` with a deadline, pumped by a daemon thread.

    A server that never answers used to block the client until GitHub's
    6-hour job cap: the step produced nothing, and a hung scenario was
    indistinguishable from a slow one. The caller now gets a TimeoutError it
    can turn into exit 2 (setup failure confined to the network boundary).
    """

    def __init__(self, stream):
        self._q: queue.Queue = queue.Queue()
        self._thread = threading.Thread(target=self._pump, args=(stream,),
                                        daemon=True, name="mcp-stdout")
        self._thread.start()

    def _pump(self, stream) -> None:
        try:
            for line in stream:
                self._q.put(line)
        except (OSError, ValueError):
            pass  # pipe closed under us: normal at shutdown
        finally:
            self._q.put(_EOF)

    def readline(self, timeout: float | None = None) -> str:
        try:
            item = self._q.get(timeout=timeout) if timeout else self._q.get()
        except queue.Empty:
            raise TimeoutError(
                f"no response from MCP server within {timeout:g}s") from None
        return "" if item is _EOF else item


def initialize_session(client) -> None:
    """Perform the MCP handshake and record what the server agreed to.

    Kept beside the transport, not inside McpClient, because the 220-line CI
    contract leaves the client no room for prose and because a second client
    implementation (a harness adapter) should not re-derive the handshake.
    """
    result = client.request("initialize", {
        "protocolVersion": client.protocol_version,
        "capabilities": {},
        "clientInfo": {"name": "mcp-purple-lab", "version": VERSION},
    }) or {}
    negotiated = result.get("protocolVersion")
    if isinstance(negotiated, str) and negotiated:
        client.protocol_version = negotiated
    client.server_info = result.get("serverInfo") or {}
    client.trace.record("lab", "handshake",
                        protocol=client.protocol_version,
                        server=client.server_info.get("name"),
                        server_version=client.server_info.get("version"))
    client.notify("notifications/initialized")


def shutdown(proc, stderr_thread: threading.Thread,
             timeout: float = 2.0) -> None:
    """Close stdin, then escalate wait -> terminate -> kill.

    Closing stdin is the polite signal: a stdio server exits its read loop. The
    rest is the guarantee that a wedged child cannot hold a CI runner open.
    """
    try:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait(timeout=timeout)
    for pipe in (proc.stdout, proc.stderr):
        try:
            if pipe and not pipe.closed:
                pipe.close()
        except OSError:
            pass
    stderr_thread.join(timeout=1.0)
