# confused-deputy-001 - OAuth redirect_uri authorization-code theft

- expected rule : `mcp_oauth_confused_deputy`
- ATLAS         : T1550
- trace         : `HACK\blue\out_pos\confused-deputy-001.trace.jsonl` (chain intact)
- rules fired   : 1/3
- verdict       : **DETECTED** (exit 0)

## Rules

| rule | severity | confidence | atlas | fired | trace lines |
|---|---|---|---|---|---|
| `mcp_oauth_confused_deputy` | high | medium | T1550 | YES | 7 |
| `mcp_schema_drift` | critical | high | T1548 | no | - |
| `mcp_tool_poisoning` | high | high | T1041 | no | - |
