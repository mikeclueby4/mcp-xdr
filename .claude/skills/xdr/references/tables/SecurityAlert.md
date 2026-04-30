# SecurityAlert

**Source**: Sentinel / Log Analytics (SentinelSolution: `Security`). Also visible in Defender Advanced Hunting via `run_hunting_query`, but **query via `run_sentinel_query` only** — `run_hunting_query` returns empty results for this table even when the workspace is onboarded to the Defender portal (RBAC/backend routing filter).  
**Time column**: `TimeGenerated`.  
**Volume**: moderate — one row per alert fired by any connected security product.

## Purpose

Aggregates security alerts from all products writing to the workspace: MDE (`MDATP`), MDO (`OATP`), MCAS, MDI (`Azure Advanced Threat Protection`), Entra ID Protection (`IPC`), and Sentinel Analytics Rules (`ASI Scheduled Alerts`, `ASI NRT Alerts`). Primary table for cross-product alert triage and SOAR correlation. Feed into `SecurityIncident` via alert grouping.

## Key columns

| Column | Notes |
|---|---|
| `SystemAlertId` | Globally unique alert GUID — primary join key to `SecurityIncident` |
| `AlertName` / `DisplayName` | Same value in practice |
| `AlertSeverity` | `"High"`, `"Medium"`, `"Low"`, `"Informational"` |
| `Status` | `"New"`, `"InProgress"`, `"Resolved"` |
| `ProviderName` | Short product code (`MDATP`, `OATP`, `MCAS`, `ASI Scheduled Alerts`, `ASI NRT Alerts`, `IPC`, `Azure Advanced Threat Protection`) |
| `ProductName` | Human-readable product name; one-to-one with `ProviderName` |
| `VendorOriginalId` | Product-specific alert ID (not globally unique across products) |
| `StartTime` / `EndTime` | Alert event window — may differ substantially from `TimeGenerated` (ingestion time) |
| `CompromisedEntity` | Device name or UPN of the primary entity — useful for quick triage |
| `Tactics` | MITRE tactic string; comma-separated when multiple (e.g. `"Persistence, Collection"`) — **not** a JSON array |
| `Techniques` | JSON-encoded string array of MITRE technique IDs (e.g. `'["T1078","T1114"]'`) — use `parse_json(Techniques)` then `mv-expand` |
| `SubTechniques` | Same format as `Techniques`; sparsely populated in practice |
| `Entities` | JSON string array of entity objects (accounts, IPs, hosts, mailMessages, mailboxes) — see below |
| `ExtendedProperties` | JSON string object; structure varies by `ProviderName` — see below |
| `ExtendedLinks` | JSON string array of `{Href, Category, Label, Type}` objects; present for `OATP` and some MDE alerts; blank for `ASI *` alerts |
| `RemediationSteps` | JSON string array of remediation text blocks; present for `MDATP` alerts (~510 of 1422 in sample); blank for Sentinel Analytics Rule alerts |
| `AlertLink` | Direct URL to the alert in the Defender/Sentinel portal |
| `IsIncident` | Always `false` in this table — incidents are in `SecurityIncident` |

## String-encoded JSON columns

All of `Entities`, `ExtendedProperties`, `ExtendedLinks`, `RemediationSteps`, and `Techniques`/`SubTechniques` are **`string`-typed** in both Defender and Sentinel sources. `gettype()` returns `"string"`. Use `parse_json(col)` (no `tostring()` wrapper needed — already a string).

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where isnotempty(Entities)
| extend ents = parse_json(Entities)
| mv-expand Entity = ents
| extend EntityType = tostring(Entity.Type)
| where EntityType == "account"
| extend UPN = tostring(Entity.UserPrincipalName)
| project TimeGenerated, AlertName, AlertSeverity, UPN, CompromisedEntity
```

### Entities structure

Each element in the `Entities` array is a JSON object with a `"Type"` discriminator field:

| `Type` | Key fields |
|---|---|
| `"account"` | `Name`, `UPNSuffix`, `UserPrincipalName`, `AccountName`, `IsDomainJoined`, `DisplayName` |
| `"ip"` | `Address` |
| `"host"` | `HostName`, `NetBiosName`, `OSFamily`, `OSVersion`, `MdatpDeviceId`, `AadDeviceId`, `RiskScore`, `RbacGroupName` |
| `"mailMessage"` | `Recipient`, `Sender`, `SenderIP`, `P2Sender`, `NetworkMessageId`, `Subject`, `ReceivedDate`, `Source` |
| `"mailbox"` | `MailboxPrimaryAddress`, `Upn`, `RiskLevel` |
| `"cloud-application"` | (minimal fields) |
| `"process"` | `ProcessId`, `CommandLine` |
| `"file"` | `Name`, `Directory` |

Array uses `$id` references — some fields may reference earlier elements by `$id` rather than repeating them inline.

### ExtendedProperties structure

Content varies by `ProviderName`:

- **`ASI Scheduled Alerts` / `ASI NRT Alerts`**: contains `Query`, `OriginalQuery`, `Query Period`, `Trigger Operator`, `Trigger Threshold`, `Search Query Results Overall Count`, `Data Sources`, `Analytics Template Id`, `Analytic Rule Ids`, `Analytic Rule Name`, `Event Grouping`, `ProcessedBySentinel`, `Alert generation status`. The `Query` field holds the full KQL that fired the alert — useful for understanding detection logic.
- **`OATP`**: contains `InvestigationName`, `Status`, `ProcessedBySentinel`.
- **`MDATP`**: contains `IncidentId`, `OriginSource`, `Category`, `DetectionSource`, `AssignedTo`, `Determination`, `Classification`, `ThreatName`, `ThreatFamilyName`, `MicrosoftDefenderAtp.InvestigationState`, `LastUpdated`.

Pre-filter before parsing:
```kql
| where ExtendedProperties has "Analytics Template Id"  // Sentinel analytics rules only
| extend ep = parse_json(ExtendedProperties)
| extend RuleName = tostring(ep["Analytic Rule Name"])
| extend TriggerCount = toint(ep["Search Query Results Overall Count"])
```

### Techniques / Tactics

`Tactics` is a plain comma-separated string. `Techniques` and `SubTechniques` are JSON string arrays:

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where isnotempty(Techniques)
| extend techs = parse_json(Techniques)
| mv-expand Tech = techs
| summarize Count=count() by tostring(Tech), AlertSeverity
| sort by Count desc
```

## ProviderName / ProductName mapping (confirmed 2026-04)

| ProviderName | ProductName |
|---|---|
| `MDATP` | `Microsoft Defender Advanced Threat Protection` |
| `ASI Scheduled Alerts` | `Azure Sentinel` |
| `ASI NRT Alerts` | `Azure Sentinel` |
| `OATP` | `Office 365 Advanced Threat Protection` |
| `MCAS` | `Microsoft Cloud App Security` |
| `Azure Advanced Threat Protection` | `Azure Advanced Threat Protection` |
| `IPC` | `Azure Active Directory Identity Protection` |

## Status lifecycle

`"New"` → `"InProgress"` → `"Resolved"`. Filtering `Status != "Resolved"` is the standard open-alert view.

## Join to SecurityIncident

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where Status != "Resolved"
| join kind=inner (
    SecurityIncident
    | where TimeGenerated > ago(7d)
    | mv-expand AlertIds = parse_json(AlertIds)
    | project IncidentNumber, Title, Severity, tostring(AlertIds)
) on $left.SystemAlertId == $right.AlertIds
| project TimeGenerated, AlertName, AlertSeverity, IncidentNumber, Title
```

Note: `SecurityIncident.AlertIds` is a **native dynamic array** (confirmed `gettype()` = `"array"`), not a string. `mv-expand AlertIds` works directly without `parse_json()`. The `parse_json(AlertIds)` in the example above is redundant but harmless.

## Common hunting patterns

### All active high/medium alerts by entity
```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertSeverity in ("High", "Medium")
| where Status != "Resolved"
| summarize AlertCount=count(), Tactics=make_set(Tactics) by CompromisedEntity, ProviderName, AlertSeverity
| sort by AlertCount desc
```

### Extract firing analytics rule name from Sentinel-sourced alerts
```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where ProviderName in ("ASI Scheduled Alerts", "ASI NRT Alerts")
| extend ep = parse_json(ExtendedProperties)
| extend RuleName = tostring(ep["Analytic Rule Name"]), TriggerCount = toint(ep["Search Query Results Overall Count"])
| summarize Count=count(), MaxTriggerCount=max(TriggerCount) by RuleName, AlertSeverity
| sort by Count desc
```

### Accounts appearing in alerts
```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where Entities has "account"
| extend ents = parse_json(Entities)
| mv-expand Entity = ents
| where tostring(Entity.Type) == "account"
| extend UPN = tostring(Entity.UserPrincipalName)
| where isnotempty(UPN)
| summarize AlertCount=dcount(SystemAlertId), Severities=make_set(AlertSeverity) by UPN
| sort by AlertCount desc
```

## Columns not in live schema (docs vs reality)

- `SourceSystem`, `WorkspaceSubscriptionId`, `WorkspaceResourceGroup`, `ConfidenceLevel`, `ConfidenceScore`, `SourceComputerId`, `ResourceId`: all present in live schema — mostly blank in practice for Sentinel analytics rule alerts.
- `IsIncident`: always `false` here — use `SecurityIncident` for incident-level data.
- `_BilledSize`, `_IsBillable`: Log Analytics system columns present in the table but not in the `get_schema` output.

## Notes

- `RemediationSteps` is a JSON string array (not plain text) even though it reads as prose. `parse_json(RemediationSteps)[0]` gives the first block.
- `ExtendedLinks` is blank for `ASI *` provider alerts; only populated for `OATP` and some `MDATP` alerts.
- `SubTechniques` observed blank across all rows in this tenant's 30-day sample — populated only when detection rules emit them.
- Alert deduplication: the same `VendorOriginalId` can appear multiple times if an alert is updated — use `SystemAlertId` (GUID) for uniqueness, and `arg_max(TimeGenerated, *) by SystemAlertId` for current state.
