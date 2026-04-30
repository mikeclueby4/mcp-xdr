---
name: xdr
description: >
  Expert guidance for writing and executing KQL queries against Microsoft Defender
  Advanced Hunting and Sentinel via the mcp-xdr MCP server. Use when the user
  asks about security events, threat hunting, investigating alerts, querying Defender
  tables, or anything involving KQL / Advanced Hunting — even if they don't say
  "xdr" explicitly. Also invoke for questions like "show me devices that…",
  "find sign-ins from…", "hunt for…", or "what happened to foo-bar".
allowed-tools: >-
  mcp__*__get_schema
  mcp__*__run_hunting_query
  mcp__*__run_sentinel_query
  mcp__*__microsoft_docs_fetch
  mcp__*__microsoft_docs_search
  mcp__*__web_read
  mcp__*__web_grounded_answer
  WebFetch(domain:raw.githubusercontent.com)
  Read(${CLAUDE_SKILL_DIR}/references/**)
  Write(${CLAUDE_SKILL_DIR}/references/**)
---

# Defender Advanced Hunting & Sentinel — KQL Guidance

You have access to these MCP tools (some conditional on server config):
- `get_schema` — unified schema discovery:
  - No args: lists all tables across Defender + Sentinel as TSV (`Table`, `Defender`, `Sentinel`, `SentinelLastSeen`). `SentinelLastSeen` comes from the Log Analytics `Usage` table (hourly granularity).
  - With `table_name`: returns full column schema (`ColumnName`, `ColumnType`) + up to 3 sample rows.
- `run_hunting_query` — execute KQL via the **Microsoft Graph Security API** (`graph.microsoft.com/v1.0/security/runHuntingQuery`); covers all Defender XDR tables plus Sentinel tables when a workspace is onboarded to the unified Defender portal
- `run_sentinel_query` — execute KQL via the **Log Analytics API** (`api.loganalytics.azure.com`); only present if `SENTINEL_WORKSPACE_ID` is configured

## Which tool to use

| Data you need | Use |
|---|---|
| Device*, Email*, Identity*, CloudApp*, AI* (XDR tables) | `run_hunting_query` |
| EntraIdSignInEvents, EntraIdSpnSignInEvents (GA Entra XDR tables) | `run_hunting_query` |
| SecurityAlert, SecurityIncident, AAD*, AuditLogs, SigninLogs, SecurityEvent | `run_sentinel_query` |
| CommonSecurityLog, Syslog, custom tables, Auxiliary/Basic logs | `run_sentinel_query` |
| Workspace **not** onboarded to the Defender portal | `run_sentinel_query` |
| Data older than 30 days (beyond Defender retention) | `run_sentinel_query` |

**Important**: Even when a Sentinel workspace is onboarded to the Defender portal, Sentinel-sourced tables (`SecurityIncident`, `SecurityAlert`, `AAD*`, etc.) return **empty results** via `run_hunting_query` — the Graph API silently filters them due to RBAC or backend routing. Always use `run_sentinel_query` for these tables. They may appear in `get_schema()` listing but that does not mean they are queryable via `run_hunting_query`.   TODO: verify.

## Before writing any query

**For any table you haven't used in this session**, do all of these before writing the real query:

1. `get_schema(table_name="<TableName>")` — get column names, types, and up to 3 sample rows from all available sources in one call
2. **Read `${CLAUDE_SKILL_DIR}/references/tables/<TableName>.md`**. If it does NOT exist, ask the `xdr-refine` agent to research and write it, first. 

This is especially important for tables with `dynamic` columns (bags of key/value pairs whose keys aren't visible in the schema). Skipping this step leads to queries that look valid but return nothing.

## Proactively trigger self-improvement of reference docs during work!

**When you discover something surprising** — an unexpected column type, a column whose values are much larger than expected, a field name that differs from what the schema implies, behaviour that contradicts what you'd assume — spawn the `xdr-refine` subagent. It will update the reference docs for you; just compose a short brief of what you have discovered, e.g.:

```
Agent(subagent_type="xdr-refine", prompt="Table: AuditLogs\nFinding: NetworkAccessTraffic section is misplaced — it belongs in its own table file, not AuditLogs.md.\nEvidence: <query + excerpt>")
```

The subagent fetches live docs, checks the live schema, reconciles with the existing reference file, and rewrites it in isolation.

---

## Self-improving SKILL.md and multiple reference docs AFTER work

**This repo is public — never write tenant-specific information into any reference file.** No UPNs, device names, group names, user names, organisation names, or internal naming conventions. Keep all examples generic (e.g. `user@example.com`, `DEVICE-001`).

Examine returned `xdr-refine` responses and consider if something deserves being centrally available in SKILL.md.

---

!`cat ${CLAUDE_SKILL_DIR}/references/kql-facts.md`

---

## Investigation playbooks

When a user describes a problem rather than naming a table, read the relevant playbook from `${CLAUDE_SKILL_DIR}/references/investigations/` before writing any query. These cover table combinations and gotchas that are non-obvious from table schemas alone.

| Playbook | When to use |
|---|---|
| `…/investigations/connectivity.md` | User reports `ERR_CONNECTION_TIMED_OUT`, site unreachable, intermittent web access, "works from one location but not another", browser connectivity failures on a specific device |
| `…/investigations/external-ti-apis.md` | Checking whether an IP, domain, or URL appears in external reputation/TI feeds; "is this IP known bad?"; "what ASN/country is this?"; "is this domain flagged?"; quick spot-check without querying Defender/Sentinel — covers keyless Tier 1 services and keyed Tier 2 services |
| `…/investigations/mcp-servers.md` | Inventorying AI/MCP plugins in use across endpoints; "what MCP servers are people using?"; "is anyone using foo-tool with Claude?"; detecting AI tool integrations via `DeviceProcessEvents` and `DeviceNetworkEvents`. |

---

## Table coverage notes

Notable tables that may need extra care:

| Table | Notes |
|-------|-------|
| `AIAgentsInfo` | Copilot Studio / AI agent inventory. `AgentToolsDetails`, `KnowledgeDetails`, `ConnectedAgentsSchemaNames` are dynamic — sample first. Rows are written on agent create/modify/delete events only (not a daily heartbeat), so the table is very sparse. **Always deduplicate with `summarize arg_max(Timestamp, *) by AIAgentId`** to get current state. Use `ago(90d)` or omit time filter — narrow windows will miss most agents. See `…/tables/AIAgentsInfo.md`. |
| `DeviceNetworkEvents` | See `…/tables/DeviceNetworkEvents.md`. Key gotchas: `Protocol` has both `"Tcp"` and `"TcpV4"` — use `startswith "Tcp"` not `== "Tcp"`; `ConnectionSuccess` ≠ allowed (network protection blocks post-handshake); `AdditionalFields` is `string` in Defender/`dynamic` in Sentinel — use `parse_json(AdditionalFields)`; inbound rows (`ConnectionAcknowledged`, `ConnectionAttempt`) have no initiating process context; `DnsConnectionInspected` contains full DNS query+response in `AdditionalFields`; `SslConnectionInspected` has JA3/JA4 fingerprints. `ReportId` non-uniqueness: see "ReportId uniqueness" section above. |
| `EntraIdSignInEvents` | See `…/tables/EntraIdSignInEvents.md`. GA replacement for `AADSignInEventsBeta`. Uses `Timestamp` not `TimeGenerated`. Key column naming traps: `Application` (not `AppName`/`AppDisplayName`), `Country` (not `CountryCode`), `AccountUpn` (not `UserPrincipalName`), `EntraIdDeviceId` (not `DeviceId`). Geo is flat (no `parse_json` needed). Has `GatewayJA4`, `IsSignInThroughGlobalSecureAccess`, `UniqueTokenId`. |
| `SigninLogs` / `AADNonInteractiveUserSignInLogs` | See `…/tables/SigninLogs.md`. Key gotcha: `LocationDetails` and `DeviceDetail` are `dynamic` in `SigninLogs` but `string` in `AADNonInteractiveUserSignInLogs` — after `union` use `tostring(parse_json(tostring(col)).field)` to avoid `SEM0100`. |
| `ExposureGraphNodes/Edges` | Security Exposure Management graph. `NodeProperties` keys vary by `NodeLabel` — the official docs don't enumerate them; always live-sample with `take 3` first. |
| `GraphAPIAuditEvents` | MS Graph API audit log. `RequestUri` + `Scopes` + `TargetWorkload` are the key hunting columns. See `…/tables/GraphAPIAuditEvents.md` for column type gotchas (`RequestDuration`, `RequestUri` size). |
| `OAuthAppInfo` | OAuth app inventory. See `…/tables/OAuthAppInfo.md` — key field is `OAuthAppId`; table is snapshot-based (one row per app per day). |
| `MessageEvents` | Teams message security events (not email — that's `EmailEvents`). |
| `CloudStorageAggregatedEvents` | Aggregated Azure storage access; note `DataAggregationStartTime/EndTime` rather than a single `Timestamp`. |
| `AADSignInEventsBeta` | Deprecated Dec 9, 2025 — replaced by `EntraIdSignInEvents`. Do not use for new queries. |
| `AADSpnSignInEventsBeta` | Deprecated — replaced by `EntraIdSpnSignInEvents`. Missing `GatewayJA4`, `SessionId`, `UniqueTokenId` compared to the GA table. Do not use for new queries. |
| `EntraIdSpnSignInEvents` | GA replacement for `AADSpnSignInEventsBeta`. Defender-only (`run_hunting_query`). Covers service principal + managed identity sign-ins. Has `GatewayJA4`, `SessionId`, `UniqueTokenId`. Key columns: `ServicePrincipalName`, `ServicePrincipalId`, `IsManagedIdentity`, `IsConfidentialClient`, `ApplicationId`, `ResourceDisplayName`. |
| `NetworkAccessTraffic` | Global Secure Access (Entra Internet/Private Access) traffic log. Uses `TimeGenerated` not `Timestamp`. Rich columns: `Action`, `PolicyName`, `RuleName`, `DestinationFqdn`, `DestinationUrl`, `DestinationWebCategories`, `ThreatType`, `ConnectionStatus`, `UserPrincipalName`. Empty if GSA is not deployed or logs are not flowing. |

## Entra ID / AAD sign-in table family

Two completely separate families with overlapping data — do not confuse them:

**Sign-in log UA gotcha — `Edge/18.26100` is NOT a threat indicator.** The full UA `Mozilla/5.0 … WebView/3.0 … Edge/18.26100` is the legacy EdgeHTML WebView used by Microsoft's own `AAD.BrokerPlugin` for Office app authentication on Windows 10 machines that haven't migrated to WebView2. It appears routinely in legitimate `AADNonInteractiveUserSignInLogs` rows and carries through into token-replay sessions unchanged (the replayed token inherits the original UA). Do not treat it as an AiTM fingerprint.

**Defender Advanced Hunting** (`run_hunting_query`) — XDR-native, `Timestamp`, flat schema:
- `EntraIdSignInEvents` — GA; replaces `AADSignInEventsBeta` (Dec 2025); covers both interactive and non-interactive user sign-ins in one table. Has `GatewayJA4`, `IsSignInThroughGlobalSecureAccess`, `UniqueTokenId`.
- `EntraIdSpnSignInEvents` — GA; replaces `AADSpnSignInEventsBeta`; service principal and managed identity sign-ins. Has `IsManagedIdentity`, `IsConfidentialClient`, `GatewayJA4`, `UniqueTokenId`.
- ⚠️ **Both may return empty in some tenants** (silent RBAC/routing filter) — use Sentinel tables below if so

**Sentinel / Log Analytics** (`run_sentinel_query`) — Azure Monitor diagnostic tables, `TimeGenerated`, richer schema, confirmed live as of 2026-04:

| Table | Covers | Cadence |
|---|---|---|
| `SigninLogs` | Interactive user sign-ins only | Live (minutes) |
| `AADNonInteractiveUserSignInLogs` | Non-interactive (token refresh, background) | Live (minutes) |
| `AADServicePrincipalSignInLogs` | Service principal sign-ins | Live (minutes) |
| `AADManagedIdentitySignInLogs` | Managed identity sign-ins | Live (minutes) |
| `AADProvisioningLogs` | Provisioning events | Live (hourly) |
| `AADRiskyUsers` | Identity Protection risky user state | Live (hours) |
| `AADUserRiskEvents` | Identity Protection risk detections | |
| `AuditLogs` | Entra directory audit (user/group/app changes) | Live (minutes) |

For comprehensive interactive + non-interactive sign-in coverage via Sentinel:
```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResultType, IPAddress, Location
```

## Local tenant facts (the only place where local tenant information may be written)

The following text is a pure transclude of `${CLAUDE_SKILL_DIR}/tenant.local.md`:

!`cat ${CLAUDE_SKILL_DIR}/tenant.local.md`

