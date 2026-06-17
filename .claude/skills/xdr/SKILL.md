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

---

## Which tool to use

| Data you need | Use |
|---|---|
| Device*, Email*, Identity*, CloudApp*, AI* (XDR tables) | `run_hunting_query` |
| EntraIdSignInEvents, EntraIdSpnSignInEvents (GA Entra XDR tables) | `run_hunting_query` |
| SecurityAlert, SecurityIncident (workspace **onboarded** to Defender portal) | `run_hunting_query` or `run_sentinel_query` — both work |
| AAD*, AuditLogs, SigninLogs, SecurityEvent | `run_sentinel_query` |
| CommonSecurityLog, Syslog, custom tables, Auxiliary/Basic logs | `run_sentinel_query` |
| Workspace **not** onboarded to the Defender portal | `run_sentinel_query` |
| Data older than 30 days (beyond Defender retention) | `run_sentinel_query` |

**`SecurityIncident` / `SecurityAlert` via `run_hunting_query`:** when the Sentinel workspace is onboarded to the unified Defender portal, these tables are queryable via `run_hunting_query` and return real data (verified 2026-05). If the workspace is *not* onboarded, they will be absent or return empty — use `run_sentinel_query` in that case. `AAD*`, `SigninLogs`, and other Azure Monitor diagnostic tables are **not** exposed via the Graph API regardless of onboarding status — always use `run_sentinel_query` for those.

---

## Before writing a KQL query

**For all tables you intend to use**: do BOTH of these **before** writing the real KQL query:

1. `get_schema(table_name="<TableName>")` — get column names, types, and up to 3 sample rows from all available sources in one call
2. **Read `${CLAUDE_SKILL_DIR}/references/tables/<TableName>.md`**. Note: `references/` is **below the xdr skill folder**.
3. If the reference doc for the table does NOT exist: FIRST ask the `xdr-refine` subagent to research and write it. THEN read its result.

Why get_schema + read reference?
- Defender/Sentinel schemas have evolved a lot since your training cutoff.
- Sentinel tables schemas are tenant-specific - the user controls ingestion.
- Sentinel is a full SIEM and can carry data from 3rd party sources.

---

## Self-improving SKILL.md and reference docs

**This repo is public — never write tenant-specific information into any reference file.** No UPNs, device names, group names, user names, organisation names, or internal naming conventions. Keep all examples generic (e.g. `user@example.com`, `DEVICE-001`).

Examine returned `xdr-refine` responses and consider if something deserves being centrally available in `SKILL.md`, `kql-facts.md` or `tenant.local.md`.

---

@references/kql-facts.md

---

## Investigation playbooks

When a user describes a problem rather than naming a table, read the relevant playbook from `${CLAUDE_SKILL_DIR}/references/investigations/` before writing any query. These cover table combinations and gotchas that are non-obvious from table schemas alone.

| Playbook | When to use |
|---|---|
| `…/investigations/connectivity.md` | User reports `ERR_CONNECTION_TIMED_OUT`, site unreachable, intermittent web access, "works from one location but not another", browser connectivity failures on a specific device |
| `…/investigations/external-ti-apis.md` | Checking whether an IP, domain, or URL appears in external reputation/TI feeds; "is this IP known bad?"; "what ASN/country is this?"; "is this domain flagged?"; quick spot-check without querying Defender/Sentinel — covers keyless Tier 1 services and keyed Tier 2 services |
| `…/investigations/mcp-servers.md` | Inventorying AI/MCP plugins in use across endpoints; "what MCP servers are people using?"; "is anyone using foo-tool with Claude?"; detecting AI tool integrations via `DeviceProcessEvents` and `DeviceNetworkEvents`. |
| `…/investigations/uptime-as-patch-proxy.md` | "When did this server last reboot?"; "how stale is our Windows patching?"; "which servers haven't rebooted in N days?"; fleet-wide patch-staleness floor without WSUS/SCCM access. |
| `…/investigations/device-health-compliance-drift.md` | Fleet health snapshot: Defender AV versions, real-time protection and behavior monitoring state, Intune compliance/managed state, DLP config validity, offline duration. "Which devices have real-time protection off?"; "show me our compliance posture"; "which devices are seasonally offline?"; "what Defender version is the fleet running?"; "are all workstations Intune-compliant?". |
| `…/investigations/eol-client-versions.md` | EOL OS detection via sign-in logs and DeviceInfo. Covers Windows (via `Edge/18.<build>` WAM broker UA), macOS and iOS (MSAL UAs), Android (Dalvik UAs), and Defender-enrolled endpoints. "Which users are on Windows 10?"; "find EOL iOS devices signing in"; "show me all clients on unsupported OS versions"; "build an EOL outreach list"; "which apps are being used from EOL devices?". Includes reusable KQL recipe and DeviceInfo complement query. |
| `…/investigations/dns-resolver-health.md` | Fleet-wide DNS resolution problems, intermittent SERVFAIL, "Outlook autodiscover slow at login", suspected per-server DNS misconfiguration, asymmetric DNS errors between resolvers, stale forwarder/upstream-cache hypotheses. Also fires when a "VPN/wifi/connectivity" investigation reveals DNS-error asymmetry as the root cause. Includes `DnsConnectionInspected` event-source pitfalls, the canary-name strategy, and TTL-haircut as smoking-gun evidence for upstream forwarders. |

---

## Table coverage notes

Tables with a `…/tables/<Name>.md` reference file: read that file before writing queries — gotchas, sample patterns, and Defender/Sentinel divergence are documented there. The entries below are redirect traps (steer away from stale training-data table names) and one-liners for tables that lack a reference file.

### Deprecated / renamed — do not use for new queries

| Old name | Use instead |
|----------|-------------|
| `AADSignInEventsBeta` | `EntraIdSignInEvents` (GA Dec 2025) |
| `AADSpnSignInEventsBeta` | `EntraIdSpnSignInEvents` (GA; has `GatewayJA4`, `SessionId`, `UniqueTokenId`) |
| `ThreatIntelligenceIndicator` | `ThreatIntelIndicators` (ingestion stopped 2025-07-31; retiring 2026-05-31) — see `…/tables/ThreatIntelligenceIndicator.md` |

### Tables with reference files — see the file, not this section

`AIAgentsInfo` · `Anomalies` · `BehaviorAnalytics` · `UserPeerAnalytics` · `CampaignInfo` · `CloudStorageAggregatedEvents` · `DeviceNetworkEvents` · `DeviceProcessEvents` · `DeviceLogonEvents` · `DeviceFileEvents` · `DeviceRegistryEvents` · `DeviceImageLoadEvents` · `DeviceEvents` · `DeviceInfo` · `DeviceNetworkInfo` · `DeviceFileCertificateInfo` · `EmailEvents` · `EmailAttachmentInfo` · `EmailUrlInfo` · `EmailPostDeliveryEvents` · `EntraIdSignInEvents` · `EntraIdSpnSignInEvents` · `SigninLogs` · `GraphAPIAuditEvents` · `OAuthAppInfo` · `SecurityAlert` · `SecurityEvent` · `SecurityIncident` · `ThreatIntelIndicators` · `ThreatIntelObjects` · `CloudAppEvents` · `CloudAuditEvents` · `IdentityInfo` · `IdentityAccountInfo` · `IdentityLogonEvents` · `IdentityDirectoryEvents` · `IdentityQueryEvents` · `AuditLogs` · `AzureActivity` · `OfficeActivity` · `StorageBlobLogs` · `DeviceTvm*` · `DeviceBaselineCompliance*` · `ExposureGraphNodes` (covers both `ExposureGraphNodes` + `ExposureGraphEdges`) · `UrlClickEvents` · `MessageEvents` (covers both `MessageEvents` + `MessageUrlInfo`) · `MicrosoftPurviewInformationProtection` · `FileMaliciousContentInfo`

### Tables without reference files — inline notes

| Table | Notes |
|-------|-------|
| `AlertInfo` / `AlertEvidence` | Normalized alert layer aggregating detections from all Defender products. `AlertInfo` has one row per alert; `AlertEvidence` has one row per entity (file, process, IP, user, etc.) tied to that alert. Join on `AlertId`. Both Defender and Sentinel. |
| `NetworkAccessTraffic` | Global Secure Access (Entra Internet/Private Access) traffic log. Not present in all tenants. Uses `TimeGenerated`. Key columns: `Action`, `PolicyName`, `DestinationFqdn`, `DestinationWebCategories`, `ThreatType`. |

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

