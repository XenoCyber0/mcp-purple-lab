# benign-control-001 - Control - clean server, no attack

- expected rule : none (control)
- ATLAS         : -
- trace         : `HACK\blue\out_pos\benign-control-001.trace.jsonl` (chain intact)
- rules fired   : 0/3
- verdict       : **clean (control)** (exit 0)

## Rules

| rule | severity | confidence | atlas | fired | trace lines |
|---|---|---|---|---|---|
| `mcp_oauth_confused_deputy` | high | medium | T1550 | no | - |
| `mcp_schema_drift` | critical | high | T1548 | no | - |
| `mcp_tool_poisoning` | high | high | T1041 | no | - |
