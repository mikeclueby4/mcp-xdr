# CLAUDE.md

GENERALIZABILITY NOTICE: Keep all documentation/comments generalized. No "in this tenant" explanations - rephrase as "some tenants" if safe or flag to the user for investigation and clarification on what is truthful factually-supported documentation to show to the public.

## Project Overview

MCP server for Microsoft Defender Advanced Hunting and Microsoft Sentinel. Enables AI assistants to execute KQL queries and investigate security events via natural language. Fork of [trickyfalcon/mcp-defender](https://github.com/trickyfalcon/mcp-defender), rewritten to use `InteractiveBrowserCredential` (auth code + PKCE) — authenticates as the signed-in user, requires only `ThreatHunting.Read.All` (Delegated), no certificate or secret.

## Key Files

```
src/mcp_xdr/_config.py         # Constants + _sentinel_workspace_id mutable state (no internal imports)
src/mcp_xdr/_auth.py           # Azure credential init + token fetch (all azure-identity imports here only)
src/mcp_xdr/_output.py         # TSV formatting, overflow logic, _append_query_log
src/mcp_xdr/_client.py         # Raw httpx callers: run_hunting_query_raw, run_sentinel_query_raw, _sentinel_result_to_tsv
src/mcp_xdr/_tools_hunting.py  # run_hunting_query tool + TOOL_DEFINITION
src/mcp_xdr/_tools_sentinel.py # run_sentinel_query tool + TOOL_DEFINITION
src/mcp_xdr/_tools_schema.py   # get_schema tool + TOOL_DEFINITION (schema listing + per-table)
src/mcp_xdr/server.py          # Wire-up only: MCP Server object, tool registry, list_tools, call_tool, main
tests/test_server.py           # Unit tests: tool schema, overflow, get_schema modes (mocked, no live API calls)
pyproject.toml                 # Entry point: mcp-xdr → mcp_xdr.server:main
HOWTO-ENTRA-APPREG-DELEGATED.md  # Entra ID app registration guide
~/.mcp-xdr/logs/queries/       # Daily query logs (YYYY-MM-DD.md)
```

## Architecture

**Module DAG** (strictly acyclic):
```
_config  ←  _auth, _output  ←  _client  ←  _tools_*  ←  server
                _cache ↗
```
`_cache` imports only `_config`; `_tools_schema` imports `_cache` + `_client`.
Adding a new Graph API tool: create `_tools_foo.py` (imports `_client`, `_output`, `_config`; exports `TOOL_DEFINITION` + handler), add one import + one entry to `_ALWAYS_TOOLS` in `server.py`. No other files change.

**Tool registry** — `_ALWAYS_TOOLS` / `_SENTINEL_TOOLS` in `server.py` are `(Tool, handler_lambda)` lists iterated by `list_tools` and `call_tool`. Sentinel tool included only when `_config._sentinel_workspace_id` is set.

**Tools exposed** (2 permanent + 1 conditional on `SENTINEL_WORKSPACE_ID`):
- `run_hunting_query` — Graph Security API (`POST /v1.0/security/runHuntingQuery`); TSV output, `[MCP-XDR:OVERFLOW]` line + tmpfile when result > 10 KB.
- `get_schema` — no args: TSV table list (`Table`, `Defender`, `Sentinel`, `SentinelLastSeen`, `SentinelSolution`); with `table_name`: merged schema (`ColumnName`, `DefenderType`, `SentinelType`) + 3 sample rows per source. Results disk-cached (`~/.mcp-xdr/<tenant>.cache/`). Cache key encodes active sources (`alltables-defsen.tsv`, `schema-<Table>-defsen.txt`).
- `run_sentinel_query` — Log Analytics API (`POST api.loganalytics.azure.com/v1/workspaces/{id}/query`); same TSV/overflow format.

**Auth priority** (all need `AZURE_TENANT_ID` + `AZURE_CLIENT_ID`): CertificateCredential → ClientSecretCredential → InteractiveBrowserCredential (browser on first use, DPAPI cache). Graph scope only at `authenticate()` time; Sentinel token acquired lazily to avoid `AADSTS70011`.

> **Sentinel token scope:** use SP app ID `ca7f3f0b-7d91-482c-8e09-c5d840d0eac5/.default` — the URL alias is not in `servicePrincipalNames`.

## Testing

```bash
python -m pytest tests/ -v   # all tests mocked, no live API calls
```

**To test code changes, the MCP server must be bounced**: ask the user to "/mcp", select mcp-xdr, and click Reconnect.

**Mock patch targets:** tool modules call `_client.run_hunting_query_raw(...)` via module reference (not `from`-imported). Patch at `"mcp_xdr._client.run_hunting_query_raw"` and `"mcp_xdr._client.run_sentinel_query_raw"` — these intercept all callers.

**`_sentinel_workspace_id` in tests:** `import mcp_xdr._config as cfg; cfg._sentinel_workspace_id = "fake-ws"` (restore in `finally`). Never `from _config import` — that snapshots the value at import time.

## Bundled Claude Code Skill

`.claude/skills/xdr/SKILL.md` — KQL authoring guidance loaded automatically. Self-improves by updating `references/tables/<TableName>.md` via the `xdr-refine` subagent.

`.claude/settings.json` — pre-registers `microsoft-learn` MCP for anyone opening this repo.

`.claude/skills/xdr-workspace/` — eval suite (`evals.json`). Run with `model=sonnet-4.6`, `effort=low`; view results with `start <path>.html`.

`.claude/agents/xdr-refine.md` — subagent for per-table reference doc updates.
