# Anomalies

## Overview

Sentinel-native ML/UEBA anomaly detection table. Populated by two rule types:
- **UEBA anomalies** — entity-focused behavioral baselines (from `BehaviorAnalytics`), names prefixed `UEBA `
- **Customizable ML rules** — statistical/ML templates trained on specific data patterns (OfficeActivity, SecurityEvent, CommonSecurityLog, etc.)

**Sentinel-only.** Always query via `run_sentinel_query`. Queryable via `run_hunting_query` (appears in Defender schema) but use Sentinel for primary work. `SentinelSolution = SecurityInsights`.

**Basic log.** Queries are more expensive — pre-filter aggressively with `TimeGenerated` and `AnomalyTemplateName` before accessing dynamic columns.

## Key identifiers

- `Id` (string) — GUID per anomaly row; globally unique.
- `RuleId` / `AnomalyTemplateId` — same value for built-in rules; `RuleId` identifies the analytics rule instance, `AnomalyTemplateId` the underlying template.
- `RuleName` / `AnomalyTemplateName` — same value for built-in rules. Human-readable anomaly type.
- `WorkspaceId` / `TenantId` — both contain the Log Analytics workspace GUID.

## Score

`Score` (real, 0–1). Higher = greater deviation. Low scores (< 0.3) are common and often noise. The same value appears in `AnomalyDetails.Score`.

## Time columns

- `TimeGenerated` — when the anomaly row was written (use for time filtering)
- `StartTime` / `EndTime` — the activity window the anomaly covers (can be hours before `TimeGenerated`)

## Entity context columns (top-level)

Flat columns extracted from the primary entity — present when the anomaly has a clear actor/target:

| Column | Notes |
|---|---|
| `UserName` | Short username only (no domain) |
| `UserPrincipalName` | Full UPN |
| `SourceIpAddress` | String — use `IPV6_MATCH()` for IP comparisons |
| `SourceDevice` | Device name |
| `DestinationIpAddress` | String — same caveat |
| `DestinationDevice` | Device name |

`SourceLocation` and `DestinationLocation` are native dynamic dicts with `CountryName` (lowercase) and `City` (lowercase). Example: `{"CountryName":"netherlands","City":"schiphol"}`.

## Tactics / Techniques

Both `Tactics` and `Techniques` are **typed `string`** in the schema but contain JSON arrays at rest. Use `parse_json()` before indexing or `mv-expand`.

```kql
Anomalies
| where TimeGenerated > ago(7d)
| extend TacticsList = parse_json(Tactics)
| mv-expand Tactic = TacticsList
| summarize Count=count() by tostring(Tactic)
| sort by Count desc
```

Pre-filter with `Tactics has "Persistence"` (cheap bloom filter) before parsing.

## RuleStatus

Observed values: `"Production"` and `""` (blank). Blank occurs on UEBA rules that don't set a status. Do not filter on `RuleStatus == "Production"` unless you intend to exclude UEBA rows.

## Dynamic columns

All dynamic columns are **native dynamic** (no `parse_json(tostring())` needed for top-level access). However, several contain nested structures worth noting.

### AnomalyReasons

Array of reason objects. Each element:
```json
{
  "Name": "FirstTimeUserPerformedAction",
  "Value": "True",
  "Type": "string",
  "IsAnomalous": true,
  "TypicalObservations": { "Description": "..." }
}
```

Primary anomaly reason is the first element. `IsAnomalous: true` marks the contributing factors.

```kql
Anomalies
| where TimeGenerated > ago(7d)
| mv-expand Reason = AnomalyReasons
| where tobool(Reason.IsAnomalous) == true
| summarize Count=count() by tostring(Reason.Name)
| sort by Count desc
```

### AnomalyDetails

Dict with template metadata and full Observables list:
```json
{
  "TemplateId": "<guid>",
  "TemplateName": "...",
  "TemplateVersion": "3.4.7",
  "AlgorithmName": "",
  "Observables": [...],
  "Score": 0.61
}
```
`Observables` is the complete list of all features scored, not just the anomalous ones. `AnomalyReasons` is the filtered subset (anomalous only) — prefer it for triage.

### ActivityInsights / UserInsights / DeviceInsights

Native dynamic dicts at the top-level column level — direct property access works.

**Important**: `ExtendedProperties` (another dynamic column) duplicates these three as **JSON-encoded strings** inside its bag. If you access them via `ExtendedProperties.ActivityInsights`, you get a string — parse with `parse_json(tostring(ExtendedProperties.ActivityInsights))`. Prefer the top-level columns instead.

`ActivityInsights` keys vary by rule type. UEBA example:
```json
{
  "FirstTimeUserPerformedAction": "True",
  "ActionUncommonlyPerformedInTenant": "False",
  "UserCreated": "..."
}
```
Boolean-flag values are **strings** (`"True"`/`"False"`), same pattern as `BehaviorAnalytics.ActivityInsights`.

`UserInsights` UEBA example:
```json
{
  "AccountDisplayName": "...",
  "AccountDomain": "...",
  "AccountObjectID": "<guid>",
  "OnPremisesSID": "S-1-5-21-..."
}
```

`DeviceInsights` UEBA example:
```json
{
  "DeviceType": "Desktop",
  "UserAgent": "..."
}
```

### Entities

Native dynamic array of entity objects using `$id`/`$ref` JSON reference syntax. Entities can cross-reference each other via `{"$ref": "N"}`. Entity types observed: `account`, `ip`. Each entity has a `Type` key.

```kql
Anomalies
| where TimeGenerated > ago(7d)
| mv-expand Entity = Entities
| where tostring(Entity.Type) == "account"
| project TimeGenerated, AnomalyTemplateName, Score,
          UPN = tostring(Entity.UPNSuffix),
          UserId = tostring(Entity.AadUserId)
```

Note: `$ref` elements contain only `{"$ref": "N"}` — skip them when iterating:
```kql
| where isnotempty(tostring(Entity.Type))
```

### ExtendedLinks

Native dynamic array of blade-link objects. The `DetailBladeInputs` key contains a **KQL query string** (the raw source query that generated the anomaly). Useful for drilling into the underlying events.

```kql
Anomalies
| where TimeGenerated > ago(7d)
| where AnomalyTemplateName == "Anomalous user activities in Office Exchange"
| mv-expand Link = ExtendedLinks
| extend SourceQuery = tostring(Link.DetailBladeInputs)
| project TimeGenerated, UserPrincipalName, Score, SourceQuery
```

### ExtendedProperties

Native dynamic dict. Contains `RuleId`, `RuleName`, `RuleStatus`, `RuleConfigVersion` (redundant with top-level columns) plus double-serialized copies of `ActivityInsights`, `UserInsights`, `DeviceInsights` as strings. Use top-level columns instead — they are already parsed.

### SourceLocation / DestinationLocation

Native dynamic dicts. Keys: `CountryName` (lowercase), `City` (lowercase). No standardised casing — use `=~` for comparisons.

## Join to BehaviorAnalytics

For UEBA anomalies, the `ExtendedLinks[0].DetailBladeInputs` contains a pre-built KQL query filtering `BehaviorAnalytics` by `UserPrincipalName` and `TimeGenerated`. Use it as a template for drilldown. Alternatively join directly:

```kql
Anomalies
| where TimeGenerated > ago(7d)
| where AnomalyTemplateName startswith "UEBA"
| join kind=inner (
    BehaviorAnalytics
    | where TimeGenerated > ago(7d)
    | where InvestigationPriority > 0
) on UserPrincipalName
```

`AccountObjectID` from `UserInsights` joins to `IdentityInfo.AccountObjectId` for enrichment.

## Discontinued rules (as of 2026-03-08)

- `Domain generation algorithm (DGA) on DNS domains`
- `Potential domain generation algorithm (DGA) on next-level DNS Domains`

These were discontinued due to low quality results. Rows may still exist historically but no new rows are generated.

## Hunting patterns

### High-scoring anomalies triage

```kql
Anomalies
| where TimeGenerated > ago(7d)
| where Score >= 0.7
| project TimeGenerated, AnomalyTemplateName, Score, UserPrincipalName,
          SourceIpAddress, Description
| sort by Score desc
```

### Top anomaly types by volume

```kql
Anomalies
| where TimeGenerated > ago(30d)
| summarize Count=count(), AvgScore=avg(Score), Users=dcount(UserPrincipalName)
    by AnomalyTemplateName
| sort by Count desc
```

### Anomalies feeding into SecurityIncident / SecurityAlert

`Anomalies` rows do not directly join to `SecurityAlert` or `SecurityIncident` via a shared key. Correlation is by `UserPrincipalName` + overlapping `TimeGenerated` window. If the anomaly fired an analytics rule that produced an alert, check `SecurityAlert` where `AlertName` contains the `RuleName`.

## Source data per rule type

UEBA rules derive from `BehaviorAnalytics`. ML rules draw from various sources:
- `OfficeActivity` (Exchange workload) — "Anomalous user activities in Office Exchange"
- `SecurityEvent` (Windows logon/process events) — brute force, login volume rules
- `AzureActivity` — "Anomalous Azure operations", "Anomalous Code Execution", "Anomalous Data Destruction"
- `CommonSecurityLog` (PAN VPN) — beaconing, Palo Alto download/upload rules
- `AwsCloudTrail` — AWS-specific rules (S3, STS, IAM, CloudTrail)
- `GcpAuditLog` — GCP IAM rules
- `Okta_CL` — Okta sign-in/MFA rules
