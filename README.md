# MCP Defender

[![PyPI version](https://badge.fury.io/py/mcp-msdefenderkql.svg)](https://pypi.org/project/mcp-msdefenderkql/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

mcp-name: io.github.trickyfalcon/mcp-msdefenderkql

An MCP (Model Context Protocol) server for Microsoft Defender Advanced Hunting. Enables AI assistants to investigate security events using natural language by translating queries to KQL and executing them against Defender.

## How It Works

```
User: "Show me suspicious PowerShell activity in the last hour"
  ↓
AI translates to KQL using schema knowledge
  ↓
MCP executes query against Defender API
  ↓
AI interprets and explains the results
```

## Features

- **Advanced Hunting**: Execute KQL queries against Defender's Advanced Hunting API
- **Dynamic Schema Discovery**: Fetch available tables and columns directly from your Defender instance
- **Natural Language Security Investigations**: Let AI translate your questions into KQL
- **Flexible Authentication**: Interactive browser (delegated user auth), certificate, or client secret

## Prerequisites

- Python 3.10+
- Azure AD App Registration (see [HOWTO-ENTRA-APPREG-DELEGATED.md](HOWTO-ENTRA-APPREG-DELEGATED.md) for step-by-step setup)

## Required API Permissions

### Interactive browser / delegated auth (recommended)

Register a **Public client** app in Entra ID (no secret or certificate needed):

- API permission: **Microsoft Threat Protection** → `AdvancedHunting.Read` (Delegated) — grant admin consent
- The signed-in user needs **Security Reader** (or equivalent Defender "View Data" role)
- Set `AZURE_TENANT_ID` and `AZURE_CLIENT_ID`; leave `AZURE_CLIENT_SECRET` and `AZURE_CLIENT_CERTIFICATE_PATH` unset

### Service principal (certificate or client secret)

- API permission: **Microsoft Threat Protection** → `AdvancedQuery.Read.All` (Application, admin consented)

## Installation

### From PyPI (Recommended)

```bash
pip install mcp-msdefenderkql
```

### From Source

```bash
# Clone the repository
git clone https://github.com/trickyfalcon/mcp-defender.git
cd mcp-defender

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"
```

## Configuration

1. Copy `.env.example` to `.env`
2. Fill in your Azure AD credentials:

```bash
# Option 1: Interactive browser — opens a browser for sign-in on first use (recommended)
# Requires a public client app registration. See HOWTO-ENTRA-APPREG-DELEGATED.md.
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id

# Option 2: Certificate authentication (service principal / no user required)
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_CERTIFICATE_PATH=/path/to/combined.pem

# Option 3: Client secret (service principal / no user required)
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
```

For certificate auth, combine your private key and certificate:

```bash
cat private.key cert.pem > combined.pem
```

## Usage

### Running the Server

```bash
mcp-msdefenderkql
```

### Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector mcp-msdefenderkql
```

### Claude Desktop Configuration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "defender": {
      "command": "/path/to/mcp-defender/.venv/bin/python",
      "args": ["-m", "mcp_defender.server"],
      "env": {
        "PYTHONPATH": "/path/to/mcp-defender/src",
        "AZURE_TENANT_ID": "your-tenant-id",
        "AZURE_CLIENT_ID": "your-client-id"
      }
    }
  }
}
```

For certificate auth, add `"AZURE_CLIENT_CERTIFICATE_PATH": "/path/to/combined.pem"` to `env`.

## Available Tools

| Tool | Description |
|------|-------------|
| `run_hunting_query` | Execute KQL queries against Advanced Hunting |
| `get_hunting_schema` | Get available tables and columns dynamically |

## Example Natural Language Queries

Once connected to Claude, you can ask:

- *"Show me any suspicious PowerShell activity in the last hour"*
- *"Find devices with failed login attempts"*
- *"What processes are making network connections to external IPs?"*
- *"List all devices that haven't checked in for 7 days"*

## Example KQL Queries

```kql
// Find failed logon attempts
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where Timestamp > ago(24h)
| summarize FailedAttempts = count() by AccountName, DeviceName
| top 10 by FailedAttempts

// Detect suspicious PowerShell
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("encodedcommand", "bypass", "hidden", "downloadstring")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Network connections to external IPs
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where Timestamp > ago(1h)
| summarize ConnectionCount = count() by DeviceName, RemoteIP
| top 20 by ConnectionCount
```

## Claude Code Skill

This repo ships a bundled **`defender-kql` Claude Code skill** in [`.claude/skills/defender-kql/`](.claude/skills/defender-kql/). It is loaded automatically when you open this repository in Claude Code.

The skill provides expert guidance for writing KQL against Defender Advanced Hunting, including:

- Pre-query schema inspection workflow (`get_hunting_schema` + `take 3` live sample)
- IP address comparison pitfalls (`ipv6_is_match()` for IPv4-mapped addresses)
- Defender-specific KQL syntax differences from standard ADX (no ternary, `let`+`join` limitations, double-serialized dynamic columns)
- Table-specific notes for `AIAgentsInfo`, `ExposureGraphNodes`, `EntraIdSignInEvents`, and others

The [`.claude/skills/defender-kql-workspace/`](.claude/skills/defender-kql-workspace/) folder contains the skill evaluation suite (6 evals across 3 iterations) used to measure and tune the skill.

## Development

```bash
# Run tests
pytest

# Lint code
ruff check .

# Type check
mypy src

# Security scan
bandit -r src
```

## API Reference

This server uses the unified M365 Defender API:
- **Endpoint**: `https://api.security.microsoft.com`
- **Advanced Hunting**: `POST /api/advancedhunting/run`

## License

MIT
