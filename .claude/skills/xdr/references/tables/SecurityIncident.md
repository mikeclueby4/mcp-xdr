# SecurityIncident

**Source**: Sentinel / Log Analytics (SentinelSolution: `SecurityInsights`). Visible in `get_schema()` under both Defender and Sentinel — **query via `run_sentinel_query` only**. `run_hunting_query` returns empty results even when workspace is onboarded to the Defender portal.  
**Time column**: `TimeGenerated`.  
**Volume**: update-heavy — one row per state change, not one row per incident. Same `IncidentNumber` produces many rows over its lifetime.

## Purpose

Incident-level aggregation table. Each incident groups one or more `SecurityAlert` rows. Tracks lifecycle (status, classification), ownership, MITRE tactics/techniques, and linked alert/bookmark IDs.

## Deduplication — critical

`TimeGenerated` is the modification timestamp, not creation time. The same incident can have dozens of rows.

**Always deduplicate for current state:**
```kql
SecurityIncident
| where TimeGenerated > ago(90d)
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
```

Use `LastModifiedTime` as the sort key inside `arg_max`, not `TimeGenerated` — they are equivalent in practice but `LastModifiedTime` is semantically correct.

## Identity columns

| Column | Notes |
|---|---|
| `IncidentNumber` | Sequential int — human-facing ID shown in portal. **Primary stable key.** |
| `IncidentName` | GUID (ARM resource name). Appears in `IncidentUrl` path. Not human-readable. |
| `ProviderIncidentId` | Numeric ID assigned by the provider (e.g. Defender incident number). Matches the number in `providerIncidentUrl` inside `AdditionalData`. Differs from `IncidentNumber`. |
| `ProviderName` | Source of the incident — confirmed value: `"Microsoft XDR"`. |

## Enum columns (confirmed values, 2026-04)

### Status
`"New"`, `"Active"`, `"Closed"` — confirmed live. Note: docs list `New/Active/Closed`; sample confirms all three are in use.

### Severity
`"High"`, `"Medium"`, `"Low"`, `"Informational"`

### Classification (only populated when Status == "Closed")
`"TruePositive"`, `"BenignPositive"`, `"FalsePositive"`, `"Undetermined"` — blank when not closed.

### ClassificationReason (confirmed values)
`"SuspiciousActivity"` (TruePositive), `"SuspiciousButExpected"` (BenignPositive), `"InaccurateData"` (FalsePositive). Blank for `Undetermined` and all open incidents.

### ClassificationComment
Free-text string. Set by analyst at close time. Not enumerated.

## Dynamic columns

All dynamic columns are **native dynamic** in both Defender and Sentinel sources — `gettype()` = `"array"` or `"dictionary"`. No `parse_json(tostring())` needed.

| Column | Type | Notes |
|---|---|---|
| `AlertIds` | array | GUIDs — join to `SecurityAlert.SystemAlertId`. Requires `mv-expand` before joining. |
| `RelatedAnalyticRuleIds` | array | GUIDs of analytics rules that triggered the constituent alerts. |
| `BookmarkIds` | array | Hunting bookmark GUIDs. Often empty `[]`. |
| `Labels` | array | Tag strings added to the incident. Often empty `[]`. |
| `Comments` | array | Objects with `message`, `createdTimeUtc`, `lastModifiedTimeUtc`, `author` (object with `name`, `email`, `objectId`, `userPrincipalName`). Often empty `[]`. |
| `Tasks` | array | Task objects. Observed empty `[]` in practice. |
| `Owner` | dictionary | `{objectId, email, assignedTo, userPrincipalName}` — blank strings when unassigned. |
| `AdditionalData` | dictionary | `{alertsCount, bookmarksCount, commentsCount, alertProductNames (array), tactics (array), techniques (array), providerIncidentUrl (string)}` |

### AdditionalData.tactics vs SecurityAlert.Tactics

`AdditionalData.tactics` is a **native dynamic array** (e.g. `["InitialAccess"]`) — direct indexing works, no parsing needed.  
This differs from `SecurityAlert.Tactics`, which is a **comma-separated string**.

```kql
// Expand tactics from incident
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| mv-expand Tactic = AdditionalData.tactics
| summarize count() by tostring(Tactic)
```

## Join to SecurityAlert

`AlertIds` is a native dynamic array of `SystemAlertId` GUIDs. Must `mv-expand` before joining:

```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| join kind=inner (
    SecurityAlert
    | where TimeGenerated > ago(30d)
    | project SystemAlertId, AlertName, AlertSeverity, ProviderName, CompromisedEntity
) on $left.AlertId == $right.SystemAlertId
| project IncidentNumber, Title, Severity, Status, AlertName, AlertSeverity, ProviderName, CompromisedEntity
```

## Time columns

| Column | Meaning |
|---|---|
| `TimeGenerated` | When this specific row was written (= modification event time) |
| `CreatedTime` | When incident was first created |
| `FirstActivityTime` | Earliest event time across all constituent alerts |
| `LastActivityTime` | Latest event time across constituent alerts |
| `FirstModifiedTime` | First modification after creation |
| `LastModifiedTime` | Most recent modification — use as dedup key |
| `ClosedTime` | Populated only when `Status == "Closed"` |

## Routing note

`run_hunting_query` silently returns empty results for this table in all tested configurations, including when the workspace is onboarded to the Defender unified portal. Always use `run_sentinel_query`.

## Common patterns

### Open incidents by severity
```kql
SecurityIncident
| where TimeGenerated > ago(90d)
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| where Status != "Closed"
| summarize count() by Severity
| sort by count_ desc
```

### Analytics rule efficiency (incidents by rule)
```kql
SecurityIncident
| where TimeGenerated > ago(90d)
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| where Status == "Closed"
| mv-expand RuleId = RelatedAnalyticRuleIds
| summarize 
    Total = count(),
    TruePos = countif(Classification == "TruePositive"),
    FalsePos = countif(Classification == "FalsePositive"),
    Benign = countif(Classification == "BenignPositive")
  by tostring(RuleId)
| extend FidelityPct = round(100.0 * TruePos / Total, 1)
| sort by Total desc
```

### Owner assignment — extract user
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| where isnotempty(Owner.email)
| extend AssignedTo = tostring(Owner.assignedTo)
| summarize OpenCount = countif(Status != "Closed") by AssignedTo
| sort by OpenCount desc
```
