# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Fork of [trickyfalcon/mcp-defender](https://github.com/trickyfalcon/mcp-defender)** — replaces app-registration certificate/secret auth with `InteractiveBrowserCredential` (auth code + PKCE), so the server authenticates as the signed-in user rather than a service principal. Requires only a public client app registration with `AdvancedHunting.Read` (Delegated) — no certificate or secret.

MCP server for Microsoft Defender Advanced Hunting. Enables AI assistants to execute KQL queries and investigate security events via natural language through the Model Context Protocol.

**Use case**: Users ask questions in natural language → AI translates to KQL → MCP executes against Defender → AI interprets results.

## Key Files

```
src/mcp_defender/server.py   # Entire server — credential init, token fetch, query execution, tool handlers
tests/test_server.py         # Tool schema tests (no live API calls; mock-free, tests list_tools() only)
pyproject.toml               # Entry point: mcp-msdefenderkql → mcp_defender.server:main
HOWTO-ENTRA-APPREG-DELEGATED.md  # Step-by-step Entra ID app registration guide for delegated auth
```

## Architecture

**Tools exposed** (exactly 2 — tests assert this):
- `run_hunting_query` — executes KQL via `POST /api/advancedhunting/run`
- `get_hunting_schema` — fetches available tables/columns from the same API

**Key functions in `server.py`:**
- `get_credential()` — lazy-initialized; checks env vars to pick credential type (see auth priority below)
- `get_access_token()` — gets bearer token, scope `https://api.security.microsoft.com/.default`
- `run_defender_query()` — httpx POST to `https://api.security.microsoft.com/api/advancedhunting/run`

**Authentication priority in `get_credential()` — all require `AZURE_TENANT_ID` + `AZURE_CLIENT_ID`:**

1. **CertificateCredential** — if `AZURE_CLIENT_CERTIFICATE_PATH` is set (optional: `AZURE_CLIENT_CERTIFICATE_PASSWORD`)
2. **ClientSecretCredential** — if `AZURE_CLIENT_SECRET` is set
3. **InteractiveBrowserCredential** — fallback; opens browser on first use, then caches token

> **Why not `AzureCliCredential`?** The Azure CLI's own first-party app was never granted `AdvancedHunting.Read` — tokens only carry `user_impersonation`, which the Defender API rejects.
>
> **Why not `DeviceCodeCredential`?** Microsoft rolled out a default CA policy "Block device code flow" from Feb–May 2025. It will be blocked on most tenants.

## Bundled Claude Code Skill

`.claude/skills/defender-kql/SKILL.md` — loaded automatically when this repo is open in Claude Code. Provides KQL authoring guidance: pre-query schema inspection, `ipv6_is_match()` for IP comparisons, Defender-specific syntax gotchas, and per-table notes.

`.claude/skills/defender-kql-workspace/` — skill evaluation suite. Contains `evals.json`, 3 iterations of 6 evals each (with/without skill), and HTML benchmark reviews. Run evals with `model=sonnet-4.6` and `effort=low`; view HTML results with `start <path>.html` on Windows.

## Commands

```bash
pip install -e ".[dev]"   # install with dev deps
mcp-msdefenderkql         # run the server
pytest                    # run tests (no live API needed)
ruff check .              # lint
mypy src                  # type check
```
