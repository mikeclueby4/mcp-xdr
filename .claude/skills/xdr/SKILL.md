---
name: xdr
description: >
  Expert guidance for writing and executing KQL queries against Microsoft Defender
  Advanced Hunting via the mcp-xdr MCP server. Use this skill whenever the user
  asks about security events, threat hunting, investigating alerts, querying Defender
  tables, or anything involving KQL / Advanced Hunting — even if they don't say
  "xdr" explicitly. Also invoke for questions like "show me devices that…",
  "find sign-ins from…", "hunt for…", or "what happened to <entity>".
allowed-tools:
  - mcp__*__get_schema
  - mcp__*__run_hunting_query
  - mcp__*__run_sentinel_query
  - mcp__*__microsoft_docs_fetch
  - mcp__*__microsoft_docs_search
  - mcp__*__web_read              # web-utility-belt uses a tool-less subagent to filter nasties
  - mcp__*__web_grounded_answer
  - WebFetch(domain:raw.githubusercontent.com, path:raw/MicrosoftDocs/**)  # direct fetch of markdown docs as last resort
  - Read({baseDir}/references/**)
  - Write({baseDir}/references/**)
---

# Defender Advanced Hunting & Sentinel — KQL Guidance

You have access to these MCP tools (some conditional on server config):
- `get_schema` — unified schema discovery:
  - No args: lists all tables across Defender + Sentinel as TSV (`Table`, `Defender`, `Sentinel`, `SentinelLastSeen`, `SentinelMB`). `SentinelLastSeen`/`SentinelMB` come from the Log Analytics `Usage` table (30-day window, hourly granularity).
  - With `table_name`: returns full column schema (`ColumnName`, `ColumnType`) + up to 3 sample rows. Queries both sources by default; use `source="defender"` or `source="sentinel"` to restrict.
- `run_hunting_query` — execute KQL via the **Microsoft Graph Security API** (`graph.microsoft.com/v1.0/security/runHuntingQuery`); covers all Defender XDR tables plus Sentinel tables when a workspace is onboarded to the unified Defender portal
- `run_sentinel_query` — execute KQL via the **Log Analytics API** (`api.loganalytics.azure.com`); only present if `SENTINEL_WORKSPACE_ID` is configured

## Which tool to use

| Data you need | Use |
|---|---|
| Device*, Email*, Identity*, CloudApp*, AI* (XDR tables) | `run_hunting_query` |
| SecurityAlert, SecurityIncident, AAD*, AuditLogs, SigninLogs, SecurityEvent | `run_sentinel_query` |
| CommonSecurityLog, Syslog, custom tables, Auxiliary/Basic logs | `run_sentinel_query` |
| Workspace **not** onboarded to the Defender portal | `run_sentinel_query` |
| Data older than 30 days (beyond Defender retention) | `run_sentinel_query` |

**Important**: Even when a Sentinel workspace is onboarded to the Defender portal, Sentinel-sourced tables (`SecurityIncident`, `SecurityAlert`, `AAD*`, etc.) return **empty results** via `run_hunting_query` — the Graph API silently filters them due to RBAC or backend routing. Always use `run_sentinel_query` for these tables. They may appear in `get_schema()` listing with `Defender=yes` (schema discovery) but that does not mean they are queryable via `run_hunting_query`.

When unsure which tool: call `get_schema()` with no args first — the `Defender` and `Sentinel` columns tell you exactly which source has the table. Tables with `Sentinel=yes` use `run_sentinel_query`; tables with only `Defender=yes` use `run_hunting_query`.

`getschema` works in both:
- `run_hunting_query("TableName | getschema")` for Defender tables
- `run_sentinel_query("TableName | getschema")` for Log Analytics tables

## Before writing any query

**For any table you haven't used in this session**, do all of these before writing the real query:

1. `get_schema(table_name="<TableName>")` — get column names, types, and up to 3 sample rows from all available sources in one call
2. **Read `${CLAUDE_SKILL_DIR}/references/tables/<TableName>.md`** if it exists — accumulated learnings about column types, gotchas, and high-value columns that are not obvious from the schema alone. Do steps 1–2 in parallel.

This is especially important for tables with `dynamic` columns (bags of key/value pairs whose keys aren't visible in the schema). Skipping this step leads to queries that look valid but return nothing.

**For tables with complex dynamic columns** — particularly `ExposureGraphNodes`, `ExposureGraphEdges`, `AIAgentsInfo`, `CloudAppEvents` — also fetch the live Microsoft reference for that table. The docs help with column types and general structure; for dynamic columns like `NodeProperties` whose keys aren't enumerated in the docs, the `take 3` live sample (step 2 above) remains essential.

## Proactively trigger self-improvement of reference docs during work!

**When you discover something surprising** — an unexpected column type, a column whose values are much larger than expected, a field name that differs from what the schema implies, behaviour that contradicts what you'd assume — spawn the `xdr-refine` subagent while you work. It will update the reference docs for you; just compose a short brief of what you have discovered, e.g.:

```
Agent(subagent_type="xdr-refine", prompt="Table: AuditLogs\nFinding: NetworkAccessTraffic section is misplaced — it belongs in its own table file, not AuditLogs.md.\nEvidence: <query + excerpt>")
```

The subagent fetches live docs, checks the live schema, reconciles with the existing reference file, and rewrites it in isolation. 

You can either continue your work, or wait for the subagent to provide updated guidance, as appropriate.

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
| `…/investigations/external-ti-apis.md` | Checking whether an IP, domain, or URL appears in external reputation/TI feeds; "is this IP known bad?"; "what ASN/country is this?"; "is this domain flagged?"; quick spot-check without querying Defender/Sentinel — covers keyless Tier 1 services and keyed Tier 2 services (AbuseIPDB, VirusTotal, GreyNoise, AlienVault OTX, IPQualityScore, IPinfo) |

---

## Table coverage notes

Notable tables that may need extra care:

| Table | Notes |
|-------|-------|
| `AIAgentsInfo` | Copilot Studio / AI agent inventory. `AgentToolsDetails`, `KnowledgeDetails`, `ConnectedAgentsSchemaNames` are dynamic — sample first. Data is sparse/snapshot-style — `ago(3d)` typically returns 0 rows; use `ago(90d)` or omit the time filter. |
| `DeviceNetworkEvents` | See `…/tables/DeviceNetworkEvents.md`. Key gotchas: `Protocol` has both `"Tcp"` and `"TcpV4"` — use `startswith "Tcp"` not `== "Tcp"`; `ConnectionSuccess` ≠ allowed (network protection blocks post-handshake); `AdditionalFields` is double-serialized JSON string; inbound rows have no initiating process context. `ReportId` non-uniqueness: see "ReportId uniqueness" section above. |
| `EntraIdSignInEvents` | GA replacement for `AADSignInEventsBeta`. Has `GatewayJA4` (TLS fingerprint) and `IsSignInThroughGlobalSecureAccess` (populated when Global Secure Access is deployed). Schema uses `Timestamp` not `TimeGenerated`; columns like `AccountUpn`/`EntraIdDeviceId`. If empty, fall back to `SigninLogs` + `AADNonInteractiveUserSignInLogs` via `run_sentinel_query`. |
| `ExposureGraphNodes/Edges` | Security Exposure Management graph. `NodeProperties` keys vary by `NodeLabel` — the official docs don't enumerate them; always live-sample with `take 3` first. |
| `GraphAPIAuditEvents` | MS Graph API audit log. `RequestUri` + `Scopes` + `TargetWorkload` are the key hunting columns. See `…/tables/GraphAPIAuditEvents.md` for column type gotchas (`RequestDuration`, `RequestUri` size). |
| `OAuthAppInfo` | OAuth app inventory. See `…/tables/OAuthAppInfo.md` — key field is `OAuthAppId`; table is snapshot-based (one row per app per day). |
| `MessageEvents` | Teams message security events (not email — that's `EmailEvents`). |
| `CloudStorageAggregatedEvents` | Aggregated Azure storage access; note `DataAggregationStartTime/EndTime` rather than a single `Timestamp`. |
| `AADSignInEventsBeta` | Deprecated Dec 9, 2025 — replaced by `EntraIdSignInEvents`. Do not use for new queries. |
| `NetworkAccessTraffic` | Global Secure Access (Entra Internet/Private Access) traffic log. Uses `TimeGenerated` not `Timestamp`. Rich columns: `Action`, `PolicyName`, `RuleName`, `DestinationFqdn`, `DestinationUrl`, `DestinationWebCategories`, `ThreatType`, `ConnectionStatus`, `UserPrincipalName`. Empty if GSA is not deployed or logs are not flowing. |

## Entra ID / AAD sign-in table family

Two completely separate families with overlapping data — do not confuse them:

**Defender Advanced Hunting** (`run_hunting_query`) — XDR-native, `Timestamp`, flat schema:
- `EntraIdSignInEvents` — replaces `AADSignInEventsBeta` (Dec 2025); covers both interactive and non-interactive in one table
- ⚠️ **May return empty in some tenants** (silent RBAC/routing filter) — use Sentinel tables below if so

**Sentinel / Log Analytics** (`run_sentinel_query`) — Azure Monitor diagnostic tables, `TimeGenerated`, richer schema, confirmed live as of 2026-04:

| Table | Covers | Cadence |
|---|---|---|
| `SigninLogs` | Interactive user sign-ins only | Live (minutes) |
| `AADNonInteractiveUserSignInLogs` | Non-interactive (token refresh, background) | Live (minutes) |
| `AADServicePrincipalSignInLogs` | Service principal sign-ins | Live (minutes) |
| `AADManagedIdentitySignInLogs` | Managed identity sign-ins | Live (minutes) |
| `AADProvisioningLogs` | Provisioning events | Live (hourly) |
| `AADRiskyUsers` | Identity Protection risky user state | Live (hours) |
| `AADUserRiskEvents` | Identity Protection risk detections | ⚠️ Last seen 2026-03-20 — may be stale or quiet |
| `AuditLogs` | Entra directory audit (user/group/app changes) | Live (minutes) |

For comprehensive interactive + non-interactive sign-in coverage via Sentinel:
```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResultType, IPAddress, Location
```

## Sentinel Log Analytics tables (`run_sentinel_query`)

When `SENTINEL_WORKSPACE_ID` is set, the following tables are available via `run_sentinel_query`. Use `run_sentinel_query("<Table> | getschema")` to see columns. Unlike Defender tables, these use `TimeGenerated` not `Timestamp` as the time column.

```
AADManagedIdentitySignInLogs   AADNonInteractiveUserSignInLogs  AADProvisioningLogs
AADRiskyUsers                  AADServicePrincipalSignInLogs    AADUserRiskEvents
AlertEvidence                  AlertInfo                        Anomalies
AuditLogs                      AzureActivity                    BehaviorAnalytics
CloudAppEvents                 DeviceEvents                     DeviceFileCertificateInfo
DeviceFileEvents               DeviceImageLoadEvents            DeviceInfo
DeviceLogonEvents              DeviceNetworkEvents              DeviceNetworkInfo
DeviceProcessEvents            DeviceRegistryEvents             EmailAttachmentInfo
EmailEvents                    EmailPostDeliveryEvents          EmailUrlInfo
Heartbeat                      IdentityDirectoryEvents          IdentityInfo
IdentityLogonEvents            IdentityQueryEvents              MicrosoftPurviewInformationProtection
OfficeActivity                 Operation                        SecurityAlert
SecurityEvent                  SecurityIncident                 SentinelAudit
SentinelHealth                 SigninLogs                       ThreatIntelIndicators
UrlClickEvents                 Usage                            UserPeerAnalytics
```

Note: many of these are duplicates of Defender XDR tables (Defender ingests into Sentinel). For XDR tables, `run_hunting_query` has richer query support and fresher data; `run_sentinel_query` gives access to longer retention and older data.


## Local tenant facts (the only place where local tenant information may be written)

The following text is a pure transclude of `${CLAUDE_SKILL_DIR}/tenant.local.md`:

!`cat ${CLAUDE_SKILL_DIR}/tenant.local.md`

