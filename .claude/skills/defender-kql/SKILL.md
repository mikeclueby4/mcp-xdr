---
name: defender-kql
description: >
  Expert guidance for writing and executing KQL queries against Microsoft Defender
  Advanced Hunting via the mcp-defender MCP server. Use this skill whenever the user
  asks about security events, threat hunting, investigating alerts, querying Defender
  tables, or anything involving KQL / Advanced Hunting — even if they don't say
  "defender-kql" explicitly. Also invoke for questions like "show me devices that...",
  "find sign-ins from...", "hunt for...", or "what happened to <entity>".
allowed-tools:
  - get_hunting_schema   # Defender Advanced Hunting schema discovery
  - run_hunting_query    # Defender XDR + Sentinel (when workspace onboarded) KQL via Graph API
  - run_sentinel_query   # Sentinel-only tables via Log Analytics API (if SENTINEL_WORKSPACE_ID set)
  - get_sentinel_tables  # list Log Analytics workspace tables (if SENTINEL_WORKSPACE_ID set)
  - microsoft_docs_fetch # for fetching official Defender Advanced Hunting docs (if configured)
  - web_read             # fallback for fetching docs if microsoft_docs_fetch isn't available
  - WebFetch(domain:raw.githubusercontent.com, path:raw/MicrosoftDocs/**)  # direct fetch of markdown docs as last resort
  - Read({baseDir}/references/**)
  - Write({baseDir}/references/tables/**)
---

# Defender Advanced Hunting & Sentinel — KQL Guidance

You have access to these MCP tools (some conditional on server config):
- `get_hunting_schema` — fetch Defender Advanced Hunting table schema
- `run_hunting_query` — execute KQL via the **Microsoft Graph Security API** (`graph.microsoft.com/v1.0/security/runHuntingQuery`); covers all Defender XDR tables plus Sentinel tables when a workspace is onboarded to the unified Defender portal
- `run_sentinel_query` — execute KQL via the **Log Analytics API** (`api.loganalytics.azure.com`); only present if `SENTINEL_WORKSPACE_ID` is configured
- `get_sentinel_tables` — list all tables in the Log Analytics workspace; only present if `SENTINEL_WORKSPACE_ID` is configured

## Which tool to use

| Data you need | Use |
|---|---|
| Device*, Email*, Identity*, CloudApp*, AI* (XDR tables) | `run_hunting_query` |
| SecurityAlert, SecurityIncident, AAD*, AuditLogs, SigninLogs, SecurityEvent | `run_sentinel_query` |
| CommonSecurityLog, Syslog, custom tables, Auxiliary/Basic logs | `run_sentinel_query` |
| Workspace **not** onboarded to the Defender portal | `run_sentinel_query` |
| Data older than 30 days (beyond Defender retention) | `run_sentinel_query` |

**Important**: Even when a Sentinel workspace is onboarded to the Defender portal, Sentinel-sourced tables (`SecurityIncident`, `SecurityAlert`, `AAD*`, etc.) return **empty results** via `run_hunting_query` — the Graph API silently filters them due to RBAC or backend routing. Always use `run_sentinel_query` for these tables. `get_hunting_schema()` may list them (they appear in schema discovery) but that does not mean they are queryable via `run_hunting_query`.

When unsure which tool: try `get_sentinel_tables` first — if the table is listed there, use `run_sentinel_query`. If not found there, use `run_hunting_query`.

`getschema` works in both:
- `run_hunting_query("TableName | getschema")` for Defender tables
- `run_sentinel_query("TableName | getschema")` for Log Analytics tables

## Before writing any query

**For any table you haven't used in this session**, do all of these before writing the real query:

1. `get_hunting_schema(table_name="<TableName>")` — get column names and types
2. `run_hunting_query("TableName | take 3")` — see real data shapes and value formats
3. **Read `references/tables/<TableName>.md`** if it exists — accumulated learnings about column types, gotchas, and high-value columns that are not obvious from the schema alone. Do steps 1–3 in parallel.

This is especially important for tables with `dynamic` columns (bags of key/value pairs whose keys aren't visible in the schema). Skipping this step leads to queries that look valid but return nothing.

The base directory for this skill is `!echo ${CLAUDE_SKILL_DIR}`.

**When you discover something surprising** — an unexpected column type, a column whose values are much larger than expected, a field name that differs from what the schema implies, behaviour that contradicts what you'd assume — write it to `references/tables/<TableName>.md` immediately (create the file if it doesn't exist). Tersely state what IS (leave reasoning freedom for future AI readers), and when relevant, a minimal KQL example showing working pattern. This keeps the knowledge base growing across sessions. Document audience is yourself, the AI agent.

**This repo is public — never write tenant-specific information into any reference file.** No UPNs, device names, group names, user names, organisation names, or internal naming conventions. Keep all examples generic (e.g. `user@example.com`, `DEVICE-001`).

**For tables with complex dynamic columns** — particularly `ExposureGraphNodes`, `ExposureGraphEdges`, `AIAgentsInfo`, `CloudAppEvents` — also fetch the live Microsoft reference for that table. The docs help with column types and general structure; for dynamic columns like `NodeProperties` whose keys aren't enumerated in the docs, the `take 3` live sample (step 2 above) remains essential.

The target URL pattern is:
```
https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-<tablename-lowercase>-table
```

Fetch docs using whichever method is available, in priority order:

**1. MS Learn MCP** (best — structured markdown, no !INCLUDE gaps):
Look for a tool named `microsoft_docs_fetch` in your available tools. Call it with the learn.microsoft.com URL above.
If not yet configured, suggest the user add it — it's public, no auth needed:
```bash
claude mcp add --transport http microsoft-learn https://learn.microsoft.com/api/mcp
```

**2. raw.githubusercontent.com** (good fallback — raw markdown, free):
The defender-xdr docs source is in `MicrosoftDocs/defender-docs`. Try:
```
https://raw.githubusercontent.com/MicrosoftDocs/defender-docs/public/defender-xdr/advanced-hunting-<tablename-lowercase>-table.md
```
Caveat: `!INCLUDE` directives appear as literal text rather than being expanded. For most table reference pages the core schema content is inline, so this is usually fine.

**3. `web_read`** (web-utility-belt MCP) — fetch the markdown-ified page as a last resort.

---

## CRITICAL: IP address comparisons

**Never use string equality (`==`) or string-based joins on IP address columns.**

IPv4 addresses are increasingly logged in IPv6-mapped form: `::ffff:1.2.3.4`. A plain `IPAddress == "1.2.3.4"` will silently miss these rows — no error, just wrong (incomplete) results.

**Always use `ipv6_is_match()`:**

```kql
// Single IP
| where ipv6_is_match(IPAddress, "1.2.3.4")

// CIDR range — netmask is IPv6 prefix length, NOT the IPv4 prefix length
// Convert: IPv6 prefix = IPv4 prefix + 96
//   /8  → 104,  /16 → 112,  /24 → 120,  /32 → 128
// Example: 10.0.0.0/8 in IPv4 → ipv6_is_match(IP, "10.0.0.0", 104)
| where ipv6_is_match(IPAddress, "10.0.0.0", 104)

// Joining two tables on IP
| join kind=inner (
    OtherTable
    | extend IPKey = IPAddress
) on $left.SrcIP == $right.IPKey   // WRONG — use mv-expand + ipv6_is_match instead

// Better join pattern:
TableA
| join kind=inner TableB on $left.SrcIP == $right.DstIP  // only safe if both came from same source
// If unsure, normalize first:
| extend NormalizedIP = iff(IPAddress startswith "::ffff:", substring(IPAddress, 7), IPAddress)
```

When joining two tables on IPs where you can't guarantee format consistency, normalize both sides first or use `ipv6_is_match` in a post-join `where`.

---

## Defender KQL syntax gotchas

These diverge from standard ADX/KQL and will silently produce parse errors or wrong results:

**No ternary operator** — `condition ? a : b` is not supported. Use `iff()`:
```kql
// WRONG — parse error
| extend Label = IsBlocked ? "Blocked" : "Active"
// RIGHT
| extend Label = iff(IsBlocked, "Blocked", "Active")
```

**`let` + `union`/`join` causes parse errors** — Defender KQL does not support `union` or `join` downstream of a `let` subquery. This catches people writing before/after comparisons with two `let` windows joined together:
```kql
// WRONG — parse error
let Baseline = TableA | where Timestamp between (ago(30d) .. ago(3d));
let Recent   = TableA | where Timestamp > ago(3d);
Baseline | join kind=inner Recent on AppId  // fails
// also fails with: Baseline | union Recent

// RIGHT for before/after comparisons — use evaluate pivot() on a Period column:
TableA
| where Timestamp > ago(30d)
| extend Period = iff(Timestamp > ago(3d), "Recent", "Baseline")
| summarize Events=count() by AppId, Period
| evaluate pivot(Period, sum(Events))
| extend SpikeRatio = iff(todouble(Baseline) > 0, round(todouble(Recent) / todouble(Baseline), 2), todouble(999))

// RIGHT for multi-table queries — run as separate queries
TableA | where ...
// -- and separately --
TableB | where ...
```

**Double-serialized dynamic columns** — some dynamic columns (e.g. `NodeProperties`, `AgentToolsDetails`) are stored as JSON-encoded strings, not native dynamic objects. Direct property access returns null; wrap with `tostring()` first:
```kql
// WRONG — returns null
| extend val = NodeProperties.rawData.exposureScore
// RIGHT
| extend props = parse_json(tostring(NodeProperties))
| extend val = tostring(props.rawData.exposureScore)
```

**`ReportId` uniqueness differs by table family** — two completely different semantics, same column name:

| Table family | Type | Unique? | Join key |
|---|---|---|---|
| All `Device*` tables (MDE-sourced) | `long` | **No** — local counter | `ReportId` + `DeviceName` + `Timestamp` |
| `Email*`, `Identity*`, `CloudAppEvents`, `UrlClickEvents` (MDO/MDI/MDCA) | `string` (GUID) | Yes — globally unique per event | `ReportId` alone is safe |

Device tables with `ReportId: long` (all require the three-column composite for safe joins):
`DeviceEvents`, `DeviceFileEvents`, `DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceNetworkEvents`, `DeviceNetworkInfo`, `DeviceInfo`, `DeviceFileCertificateInfo`

Tables with **no** `ReportId`: `AlertInfo`, `AlertEvidence`, `DeviceTvmSoftwareInventory`, `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSecureConfigurationAssessment` — these use `AlertId`, `DeviceId+CveId`, etc.

```kql
// WRONG — joining Device tables on ReportId alone gives duplicate explosion
DeviceNetworkEvents
| join kind=inner AlertEvidence on ReportId

// RIGHT for Device tables
DeviceNetworkEvents
| join kind=inner AlertEvidence on ReportId, DeviceName, Timestamp

// OK for email/identity tables — ReportId is a GUID and globally unique
EmailEvents
| join kind=inner EmailAttachmentInfo on ReportId
```

---

## Investigation playbooks

When a user describes a problem rather than naming a table, read the relevant playbook from `references/investigations/` before writing any query. These cover table combinations and gotchas that are non-obvious from table schemas alone.

| Playbook | When to use |
|---|---|
| `references/investigations/connectivity.md` | User reports `ERR_CONNECTION_TIMED_OUT`, site unreachable, intermittent web access, "works from one location but not another", browser connectivity failures on a specific device |

---

## General KQL hygiene

**Time filter** — always include one; default to last 3 days unless the user specifies otherwise:
```kql
| where Timestamp > ago(3d)
```

**Limit columns** — use `project` to return only what's needed; Defender tables are wide and raw rows waste context:
```kql
| project Timestamp, DeviceName, AccountUpn, ActionType, AdditionalFields
```

**Summarize over raw rows** — for large tables (`DeviceEvents`, `DeviceNetworkEvents`, `EmailEvents`), prefer aggregation unless the user needs individual events:
```kql
| summarize Count=count() by DeviceName, ActionType
| sort by Count desc
```

**Large result sets** — if a query returns more rows than fit comfortably in context, spawn a subagent to ingest and summarize the output. Always use `model: "haiku"` for these — the task is pure reading/summarization, not reasoning, and Haiku is faster and cheaper for it.

**Dynamic column access** — use `tostring()`, `toint()`, `parse_json()`, and `bag_keys()` to work with dynamic columns safely:
```kql
| extend parsed = parse_json(AdditionalFields)
| extend ProcessName = tostring(parsed.ProcessName)
```

---

## Table coverage notes

The tenant has these notable tables that may need extra care:

| Table | Notes |
|-------|-------|
| `AIAgentsInfo` | Copilot Studio / AI agent inventory. `AgentToolsDetails`, `KnowledgeDetails`, `ConnectedAgentsSchemaNames` are dynamic — sample first. Data is sparse/snapshot-style — `ago(3d)` typically returns 0 rows; use `ago(90d)` or omit the time filter. |
| `DeviceNetworkEvents` | See `references/tables/DeviceNetworkEvents.md`. Key gotchas: `Protocol` has both `"Tcp"` and `"TcpV4"` — use `startswith "Tcp"` not `== "Tcp"`; `ConnectionSuccess` ≠ allowed (network protection blocks post-handshake); `AdditionalFields` is double-serialized JSON string; inbound rows have no initiating process context. `ReportId` non-uniqueness: see "ReportId uniqueness" section above. |
| `EntraIdSignInEvents` | GA replacement for `AADSignInEventsBeta`. Has `GatewayJA4` (TLS fingerprint) and `IsSignInThroughGlobalSecureAccess` — tenant uses Global Secure Access. |
| `ExposureGraphNodes/Edges` | Security Exposure Management graph. `NodeProperties` keys vary by `NodeLabel` — the official docs don't enumerate them; always live-sample with `take 3` first. |
| `GraphAPIAuditEvents` | MS Graph API audit log. `RequestUri` + `Scopes` + `TargetWorkload` are the key hunting columns. See `references/tables/GraphAPIAuditEvents.md` for column type gotchas (`RequestDuration`, `RequestUri` size). |
| `OAuthAppInfo` | OAuth app inventory. See `references/tables/OAuthAppInfo.md` — key field is `OAuthAppId`; table is snapshot-based (one row per app per day). |
| `MessageEvents` | Teams message security events (not email — that's `EmailEvents`). |
| `CloudStorageAggregatedEvents` | Aggregated Azure storage access; note `DataAggregationStartTime/EndTime` rather than a single `Timestamp`. |
| `EntraIdSignInEvents` | **Defender table — returns empty via `run_hunting_query` in this tenant** (silent RBAC filter, same as SecurityIncident). Use `SigninLogs` + `AADNonInteractiveUserSignInLogs` via `run_sentinel_query` instead. Schema differs: `Timestamp` not `TimeGenerated`, columns like `AccountUpn`/`EntraIdDeviceId`. |
| `AADSignInEventsBeta` | Deprecated Dec 9, 2025 — replaced by `EntraIdSignInEvents`. Also returns empty via `run_hunting_query`. Do not use for new queries. |
| `Device*` tables (`DeviceNetworkEvents`, `DeviceEvents`, `DeviceInfo`, `DeviceProcessEvents`, etc.) | **Also return empty via `run_hunting_query` in this tenant** — same silent RBAC/routing filter as EntraIdSignInEvents. Despite being MDE-sourced XDR tables (not Sentinel-native), they must be queried via `run_sentinel_query`. Confirmed via `Usage` table: these tables have substantial daily ingest. Always verify with `Usage` if `run_hunting_query` returns unexpected empty results. |
| `NetworkAccessTraffic` | Global Secure Access (Entra Internet/Private Access) traffic log. Uses `TimeGenerated` not `Timestamp`. Rich columns: `Action`, `PolicyName`, `RuleName`, `DestinationFqdn`, `DestinationUrl`, `DestinationWebCategories`, `ThreatType`, `ConnectionStatus`, `UserPrincipalName`. **Empty in this tenant** — GSA not deployed or logs not flowing. |

## Entra ID / AAD sign-in table family

Two completely separate families with overlapping data — do not confuse them:

**Defender Advanced Hunting** (`run_hunting_query`) — XDR-native, `Timestamp`, flat schema:
- `EntraIdSignInEvents` — replaces `AADSignInEventsBeta` (Dec 2025); covers both interactive and non-interactive in one table
- ⚠️ **Both return empty in this tenant** — use Sentinel tables below instead

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
