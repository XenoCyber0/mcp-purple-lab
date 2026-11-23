# Harness compatibility

The lab speaks the same wire contract as every MCP harness: newline-delimited
JSON-RPC 2.0 over stdio, ids that may be string or number, notifications that
must not shift the reply stream, and exit codes 0/1/2 that a pipeline can gate
on.

What is verified here is the *server* side of that contract. All four lab
servers answer a pipelined `initialize` + `tools/list` handshake with string
ids, and the client accepts both id types, buffers out-of-order replies, and
answers server-initiated requests with -32601. `tests/test_v2.py` runs that
conformance against every server.

The GUI clients below are configured the same way but were not launched in CI.
Treat the config shape as documented, the framing as tested.

## Matrix

| Harness | Config file | Root key | Transport | Status |
|---|---|---|---|---|
| Claude Desktop | `claude_desktop_config.json` | `mcpServers` | stdio | framing CI-tested |
| Claude Code | `.mcp.json` (project) | `mcpServers` | stdio | framing CI-tested |
| Cursor | `.cursor/mcp.json` | `mcpServers` | stdio | framing CI-tested |
| VS Code (Copilot) | `.vscode/mcp.json` | `servers` + `type: stdio` | stdio | framing CI-tested |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` | stdio | framing CI-tested |
| Cline | `cline_mcp_settings.json` | `mcpServers` | stdio | framing CI-tested |
| Continue | `.continue/mcpServers/*.json` | `mcpServers` | stdio | framing CI-tested |
| Zed | `settings.json` | `context_servers` | stdio | framing CI-tested |
| Goose | `config.yaml` | `extensions` | stdio | framing CI-tested |
| Roo Code | `mcp_settings.json` | `mcpServers` | stdio | framing CI-tested |
| MCP Inspector | UI / CLI | n/a | stdio | framing CI-tested |
| GitHub Actions / GitLab / Jenkins | shell step | n/a | subprocess | exit-code contract |

## Claude Desktop / Claude Code / Cursor / Windsurf / Cline / Continue / Roo

All of these read the same `mcpServers` object. Use absolute paths in a real
config; the relative form below is what the repo sample uses.

```json
{
  "mcpServers": {
    "purple-benign": {
      "command": "python",
      "args": ["lab/servers/benign_server.py"]
    },
    "purple-poisoned": {
      "command": "python",
      "args": ["lab/servers/evil_server.py"]
    }
  }
}
```

A ready file is at `examples/harnesses/mcp.json`.

## VS Code

VS Code uses `servers`, and each entry needs `type: stdio`:

```json
{
  "servers": {
    "purple-benign": {
      "type": "stdio",
      "command": "python",
      "args": ["${workspaceFolder}/lab/servers/benign_server.py"]
    }
  }
}
```

See `examples/harnesses/vscode.json`.

## Zed

Zed calls the same concept `context_servers`:

```json
{
  "context_servers": {
    "purple-benign": {
      "command": "python",
      "args": ["lab/servers/benign_server.py"],
      "env": {}
    }
  }
}
```

See `examples/harnesses/zed.json`.

## Goose

Goose takes an `extensions` entry with `type: stdio` and a command list. The
flags are the same; put the server path last.

## CI harnesses

Exit codes are the API, unchanged since v0.1.0:

| code | meaning |
|---|---|
| 0 | expected attack detected, or control clean |
| 1 | attack missed, or control false-positived |
| 2 | setup failure: bad scenario, missing server, hung server, unreadable rule |

Machine-readable per-scenario output:

```bash
python lab/run.py lab/scenarios/tool_poisoning.yaml --format json | jq .
```

The report includes `scenario`, `expected_detection`, `exit_code`, `detected`,
`duration_ms`, `results`, and the `evidence` line numbers.

## Adding a harness

If it launches a command and speaks newline-delimited JSON-RPC on stdin/stdout,
it can launch `lab/servers/*.py`. If it needs a different root key, copy one of
the example files. A new harness profile is a docs change only; do not add a
dependency for it.
