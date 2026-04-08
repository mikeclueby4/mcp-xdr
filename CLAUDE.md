# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Fork of [trickyfalcon/mcp-defender](https://github.com/trickyfalcon/mcp-defender)** — replaces app-registration certificate/secret auth with `InteractiveBrowserCredential` (auth code + PKCE), so the server authenticates as the signed-in user rather than a service principal. Requires only a public client app registration with `AdvancedHunting.Read` (Delegated) — no certificate or secret.

MCP server for Microsoft Defender Advanced Hunting. Enables AI assistants to execute KQL queries and investigate security events via natural language through the Model Context Protocol.

**Use case**: Users ask questions in natural language → AI translates to KQL → MCP executes against Defender → AI interprets results.

**API**: Uses unified M365 Defender API (`api.security.microsoft.com`) covering all workloads (Device, Identity, Email, Cloud App, AI tables).

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

**Authentication (priority order in `get_credential()`):**

All three require `AZURE_TENANT_ID` + `AZURE_CLIENT_ID`. Then:

1. **CertificateCredential** — if `AZURE_CLIENT_CERTIFICATE_PATH` is set (optional: `AZURE_CLIENT_CERTIFICATE_PASSWORD`). Application auth, no user required.
2. **ClientSecretCredential** — if `AZURE_CLIENT_SECRET` is set. Application auth, no user required.
3. **InteractiveBrowserCredential** — fallback when only `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` are set. Opens a browser for interactive sign-in (auth code + PKCE). Token is cached; browser only appears on first use or after expiry.

All paths get a token with scope: `https://api.security.microsoft.com/.default`

> **Why not `AzureCliCredential`?** The Azure CLI's own first-party app was never granted `AdvancedHunting.Read` — tokens only carry `user_impersonation`, which the Defender API rejects.
>
> **Why not `DeviceCodeCredential`?** Microsoft rolled out a default CA policy "Block device code flow" from Feb–May 2025. It will be blocked on most tenants.

## M365 Defender API

- Endpoint: `https://api.security.microsoft.com`
- Advanced Hunting: `POST /api/advancedhunting/run`
- Request body: `{"Query": "<KQL>"}`
- Response: `{"Schema": [...], "Results": [...], "Stats": {...}}`

## Required API Permissions

For **InteractiveBrowserCredential** (delegated / this fork's focus):
- Register a **Public client** app in Entra ID (no secret or certificate needed)
- Add API permission: **Microsoft Threat Protection** → `AdvancedHunting.Read` (Delegated)
- Grant admin consent
- Set `AZURE_TENANT_ID` and `AZURE_CLIENT_ID`; leave `AZURE_CLIENT_SECRET` and `AZURE_CLIENT_CERTIFICATE_PATH` unset
- The signed-in user needs **Security Reader** (or equivalent Defender "View Data" role)

For **CertificateCredential / ClientSecretCredential** (application auth):
- App registration needs: **Microsoft Threat Protection** → `AdvancedQuery.Read.All` (Application type, admin consented)
