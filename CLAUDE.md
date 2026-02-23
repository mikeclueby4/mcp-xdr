# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP server for Microsoft Defender Advanced Hunting. Enables AI assistants to execute KQL queries and investigate security events via natural language through the Model Context Protocol.

**Use case**: Users ask questions in natural language → AI translates to KQL → MCP executes against Defender → AI interprets results.

**API**: Uses WindowsDefenderATP API (`api.securitycenter.microsoft.com`) for direct, fast access.

## Commands

```bash
# Install dependencies (first time setup)
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run the MCP server
mcp-defender

# Run tests
pytest

# Run single test
pytest tests/test_server.py::test_list_tools -v

# Lint
ruff check .
ruff check --fix .  # auto-fix

# Type check
mypy src
```

## Architecture

```
src/mcp_defender/
  server.py      # Main MCP server - hunting tools only
```

**Tools exposed:**
- `run_hunting_query` - Execute KQL queries against Defender Advanced Hunting
- `get_hunting_schema` - Dynamically fetch available tables and columns

**Key components in server.py:**
- `server` - MCP Server instance
- `get_credential()` - Lazy-initialized Azure credential
- `get_access_token()` - Gets bearer token for Defender API
- `run_defender_query()` - Executes KQL via httpx to Defender API
- `list_tools()` - Declares the two hunting tools
- `call_tool()` - Routes tool calls to handlers

**Authentication:**
1. Reads `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` from environment
2. Uses either:
   - `CertificateCredential` if `AZURE_CLIENT_CERTIFICATE_PATH` is set (recommended)
   - `ClientSecretCredential` if `AZURE_CLIENT_SECRET` is set (fallback)
3. Optional: `AZURE_CLIENT_CERTIFICATE_PASSWORD` for encrypted certificates
4. Gets token with scope: `https://api.securitycenter.microsoft.com/.default`

## WindowsDefenderATP API

- Endpoint: `https://api.securitycenter.microsoft.com`
- Advanced Hunting: `POST /api/advancedqueries/run`
- Request body: `{"Query": "<KQL>"}`
- Response: `{"Schema": [...], "Results": [...], "Stats": {...}}`

## Required API Permissions

App registration needs this WindowsDefenderATP permission (Application type):
- `AdvancedQuery.Read.All` - Run advanced queries
