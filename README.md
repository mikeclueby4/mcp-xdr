# mcp-xdr

An MCP (Model Context Protocol) server for Microsoft Defender Advanced Hunting and Microsoft Sentinel. Enables AI assistants to investigate security events using natural language by translating queries to KQL and executing them against Defender or Sentinel.

Batteries and sharp knives included in the source repo: `xdr` skill that self-improves and gets better at writing queries as it goes. Yeah, I'm a little scared, too.

## How It Works

```
User: "Show me suspicious PowerShell activity in the last hour"
  ↓
AI translates to KQL using schema knowledge
  ↓
MCP executes query against Defender or Sentinel API
  ↓
AI interprets and explains the results. You can keep raw output as .tsv files. 
```

Query logs and more is stored under your ~/.mcp-xdr/ folder.

## Features

- **Advanced Hunting**: Execute KQL queries against the Microsoft Graph Security API
- **Microsoft Sentinel**: Execute KQL queries against Log Analytics workspaces (optional)
- **Dynamic Schema Discovery**: Fetch available tables and columns directly from your Defender or Sentinel instance
- **Natural Language Security Investigations**: Let AI translate your questions into KQL
- **Flexible Authentication**: Interactive browser (delegated user auth), certificate, or client secret

## Prerequisites

- Python 3.11+ (or `uv` / `uvx` for zero-install usage)
- Azure AD App Registration — see [HOWTO-ENTRA-APPREG-DELEGATED.md](HOWTO-ENTRA-APPREG-DELEGATED.md) for step-by-step setup

Technically 3.10 works, but please stop using it; it stops receiving security patches soon.

## Required API Permissions

### Interactive browser / delegated auth (recommended)

Register a **Public client** app in Entra ID (no secret or certificate needed):

- API permission: **Microsoft Graph** → `ThreatHunting.Read.All` (Delegated) — grant admin consent
- For Sentinel: **Log Analytics API** → `Data.Read` (Delegated) — grant admin consent
- The signed-in user needs **Security Reader** (or equivalent Defender "View Data" URBAC role)
- Set `AZURE_TENANT_ID` and `AZURE_CLIENT_ID`; leave `AZURE_CLIENT_SECRET` and `AZURE_CLIENT_CERTIFICATE_PATH` unset

See [HOWTO-ENTRA-APPREG-DELEGATED.md](HOWTO-ENTRA-APPREG-DELEGATED.md) for step-by-step setup.

### Service principal (certificate or client secret)

- API permission: **Microsoft Graph** → `ThreatHunting.Read.All` (Application, admin consented)
- For Sentinel: **Log Analytics API** → `Data.Read` (Application, admin consented)

## Configuration

1. Copy `.env.example` to `.env`
2. Fill in your Azure AD credentials and workspace ID:

```bash
# Required: Azure AD app registration
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id

# Microsoft Sentinel — add your Log Analytics workspace ID to enable Sentinel queries
# (Azure Portal → Log Analytics workspaces → your workspace → Overview → Workspace ID)
SENTINEL_WORKSPACE_ID=your-log-analytics-workspace-id

# Authentication — choose ONE, or leave both unset for interactive browser sign-in (recommended)

# Option A: Certificate (service principal)
# AZURE_CLIENT_CERTIFICATE_PATH=/path/to/combined.pem

# Option B: Client secret (service principal)
# AZURE_CLIENT_SECRET=your-client-secret
```

For certificate auth, combine your private key and certificate:

```bash
cat private.key cert.pem > combined.pem
```

## Installation

```bash
# Recommended: install with uv
uv tool install git+https://github.com/mikeclueby4/mcp-xdr

# Or with pip
pip install git+https://github.com/mikeclueby4/mcp-xdr
```

## Usage

### Running the server (which your AI agent normally does)

```bash
# After installing with uv tool install / pip install:
mcp-xdr

# Or run directly without installing (uv handles the venv):
uvx --from git+https://github.com/mikeclueby4/mcp-xdr mcp-xdr

# Test interactively with MCP Inspector:
npx @modelcontextprotocol/inspector mcp-xdr
```

* **I** recommend you to run straight from github, because I keep the repo up to date with dependabot et al.
* **You** have no reason to trust me - and running code straight from a repo is a rapid supply chain threat vector.
* Your choice - you own the security boundary! :-) 

### Claude Code / Claude Desktop Configuration

Add to your MCP settings. Use the `uvx` form so no prior install step is needed:

**Claude Code** — project-level `.claude/settings.json` or user-level `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "defender": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/mikeclueby4/mcp-xdr", "mcp-xdr"],
      "env": {
        "AZURE_TENANT_ID": "your-tenant-id",
        "AZURE_CLIENT_ID": "your-client-id"
      }
    }
  }
}
```

**Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "defender": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/mikeclueby4/mcp-xdr", "mcp-xdr"],
      "env": {
        "AZURE_TENANT_ID": "your-tenant-id",
        "AZURE_CLIENT_ID": "your-client-id"
      }
    }
  }
}
```

Add `"SENTINEL_WORKSPACE_ID": "your-workspace-id"` to `env` to enable Sentinel queries.  
For certificate auth, also add `"AZURE_CLIENT_CERTIFICATE_PATH": "/path/to/combined.pem"`.

## Available Tools

| Tool | Description |
|------|-------------|
| `run_hunting_query` | Execute KQL queries against Defender Advanced Hunting (Microsoft Graph Security API). Returns TSV with a header row. Results over ~10 KB are truncated inline; the full result is written to a tmpfile whose path is reported in a `[MCP-XDR:OVERFLOW]` marker line. |
| `get_schema` | Unified schema discovery. No args: lists all tables across Defender + Sentinel as TSV. With `table_name`: returns column schema and up to 3 sample rows. Optional `source` param (`"defender"` / `"sentinel"`) restricts to one source. |
| `run_sentinel_query` | Execute KQL queries against a Log Analytics workspace (Sentinel). Same TSV/overflow output format. Only available when `SENTINEL_WORKSPACE_ID` is set. |

## Query Log

Every tool call is appended to a daily Markdown log at `~/.mcp-xdr/logs/queries/YYYY-MM-DD.md`. Each entry records the tool name, the query (or schema args), and exactly what the model received — truncated at the overflow boundary for large results. The format is human-readable in any Markdown viewer (result rows are indented 4 spaces, rendering as code blocks).

```
~/.mcp-xdr/
└── logs/
    └── queries/
        ├── 2026-04-16.md
        └── 2026-04-17.md
```

This is useful for reviewing what queries were run in a session, catching surprising results after the fact, and informing updates to the skill's reference documentation.

## Example Natural Language Queries

Once connected to Claude, you can ask:

- *"Show me any suspicious PowerShell activity in the last hour"*
- *"Find devices with failed login attempts"*
- *"What processes are making network connections to external IPs?"*
- *"List all devices that haven't checked in for 7 days"*
- *"Show me failed sign-ins from my Sentinel workspace in the last 24 hours"*

## Claude Code Skill

This repo ships a bundled **`xdr` Claude Code skill** in [`.claude/skills/xdr/`](.claude/skills/xdr/). It is loaded automatically when you open this repository in Claude Code.

The skill provides expert guidance for writing KQL against Defender Advanced Hunting and Sentinel, including:

- Tool routing (Defender vs Sentinel) and pre-query schema inspection workflow
- IP address comparison pitfalls (`ipv6_is_match()` for IPv4-mapped addresses)
- Defender-specific KQL syntax quirks (no ternary, `let`+`join` limitations, double-serialized dynamic columns)
- Table-specific notes for `AIAgentsInfo`, `ExposureGraphNodes`, `EntraIdSignInEvents` (auto updated).
- Entra/AAD table family split between Defender and Sentinel
- **Auto-updating its own reference documentation** on "surprises" learned during operation.  *Please send me some choice PRs on what your agent learns*!

The [`.claude/skills/xdr-workspace/`](.claude/skills/xdr-workspace/) folder contains the skill evaluation suite (6 evals across 3 iterations) used to measure and tune the skill.

## History

This repo started as a fork of [trickyfalcon/mcp-defender](https://github.com/trickyfalcon/mcp-defender).

The upstream repo authenticates as a **service principal** (certificate or client secret). This fork adds and defaults to **`InteractiveBrowserCredential`**: the MCP server authenticates as the signed-in user instead. The app registration then only needs **delegated** permission (`ThreatHunting.Read.All` on Microsoft Graph), and no secret or certificate needs to live in the file system, which reduces blast radius on the app.  

This fork also:
- Migrates from the retired `api.security.microsoft.com` endpoint to the **Microsoft Graph Security API** (`graph.microsoft.com/v1.0/security/runHuntingQuery`)
- Adds **Microsoft Sentinel / Log Analytics** support (`run_sentinel_query`)
- Ships a bundled **Claude Code skill** for expert KQL authoring against both Defender and Sentinel
- **Enables all GitHub public-repo security features** (dependabot, codeql, vuln alerting, etc)

## API Reference

| API | Endpoint |
|-----|----------|
| Defender Advanced Hunting | `POST https://graph.microsoft.com/v1.0/security/runHuntingQuery` |
| Defender Schema | `GET https://graph.microsoft.com/v1.0/security/runHuntingQuery` (schema endpoint) |
| Sentinel / Log Analytics | `POST https://api.loganalytics.azure.com/v1/workspaces/{id}/query` |

## License

MIT
