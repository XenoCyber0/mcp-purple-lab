# schema-rugpull-001 - Server mutates tools/list after session start

- expected rule : `mcp_schema_drift`
- ATLAS         : T1548
- trace         : `HACK\blue\out_pos\schema-rugpull-001.trace.jsonl` (chain intact)
- rules fired   : 2/3
- verdict       : **DETECTED** (exit 0)

## Rules

| rule | severity | confidence | atlas | fired | trace lines |
|---|---|---|---|---|---|
| `mcp_oauth_confused_deputy` | high | medium | T1550 | no | - |
| `mcp_schema_drift` | critical | high | T1548 | YES | 14, 17 |
| `mcp_tool_poisoning` | high | high | T1041 | YES | 16 |
