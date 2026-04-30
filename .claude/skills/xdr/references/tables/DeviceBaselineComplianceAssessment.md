# DeviceBaselineComplianceAssessment

**Preview table** — MDE-sourced only. Defender Advanced Hunting (`run_hunting_query`) only; Sentinel returns 400. Snapshot semantics (one row per device+configuration assessment).

## Purpose

Per-device baseline compliance state. One row per (`DeviceId`, `ConfigurationId`). Indicates whether each device meets each security configuration check in the assigned baseline profile. Contains no human-readable configuration metadata — join to `DeviceBaselineComplianceAssessmentKB` on `ConfigurationId` for names, descriptions, and remediation guidance.

## Schema (live, 2026-04)

| Column | Type | Notes |
|---|---|---|
| `DeviceId` | `string` | MDE device ID |
| `DeviceName` | `string` | FQDN |
| `OSPlatform` | `string` | OS platform string |
| `OSVersion` | `string` | OS version |
| `ConfigurationId` | `string` | FK to `DeviceBaselineComplianceAssessmentKB.ConfigurationId` |
| `ProfileId` | `string` | Baseline profile ID assigned to the device |
| `IsCompliant` | `bool` | `true` = device meets the configuration requirement |
| `IsApplicable` | `bool` | `true` = this configuration applies to the device. Always filter `IsApplicable == true` — many configs are OS-specific and will be false for non-matching platforms. |
| `IsExempt` | `bool` | `true` = device has been explicitly exempted from this check |
| `Source` | `dynamic` | Native array of strings — registry paths/check locations (same as KB table) |
| `RecommendedValue` | `dynamic` | Native array — expected condition strings (same as KB table) |
| `CurrentValue` | `dynamic` | Native array — actual detected values on this device |
| `AssessmentMethod` | `string` | `"Automatic"` or `"NotSupported"` |
| `MachineGroup` | `string` | MDE machine group (Defender-only column, absent from Sentinel) |
| `TenantId` | `string` | Ingestion artifact |
| `Type` | `string` | Always `"DeviceBaselineComplianceAssessment"` — ingestion artifact |
| `SourceSystem` | `string` | Always `"DeviceBaselineComplianceAssessment"` — ingestion artifact |

**Docs omit**: `AssessmentMethod`, `MachineGroup`, `TenantId`, `Type`, `SourceSystem` — all present in live schema.

**Docs list `IsCompliant` as `nullable bool`** — live schema shows `bool`. The official example query filters on string `"0"` which is incorrect; use `== false`.

## Dynamic columns — native arrays

`Source`, `RecommendedValue`, `CurrentValue` are all native dynamic arrays. No `parse_json()` needed. Direct indexing and `mv-expand` work:

```kql
// Compare current vs recommended for multi-key configs
| mv-expand with_itemindex=i Source to typeof(string), RecommendedValue to typeof(string), CurrentValue to typeof(string)
| project DeviceName, ConfigurationId, i, Source, RecommendedValue, CurrentValue
```

## No Timestamp

No `Timestamp` or `TimeGenerated` column. This is a compliance state snapshot, not an event stream. Omit time filters.

## Key filter: IsApplicable

Always include `| where IsApplicable == true` for compliance gap analysis. Many configurations are Windows-specific; macOS/Linux devices will have a large number of `IsApplicable == false` rows that should not count as non-compliant.

## Standard query — compliance gap by device

```kql
DeviceBaselineComplianceAssessment
| where IsApplicable == true
| where IsCompliant == false
| where IsExempt == false
| summarize
    NonCompliantCount = count(),
    Configs = make_set(ConfigurationId, 50)
  by DeviceId, DeviceName, OSPlatform, ProfileId
| sort by NonCompliantCount desc
```

## Standard join with KB table

See `DeviceBaselineComplianceAssessmentKB.md` for the join pattern that brings in `ConfigurationName`, `ConfigurationCategory`, `RemediationOptions`, etc.

```kql
DeviceBaselineComplianceAssessment
| where IsApplicable == true
| where IsCompliant == false
| where IsExempt == false
| join kind=inner DeviceBaselineComplianceAssessmentKB on ConfigurationId
| project
    DeviceId, DeviceName, OSPlatform,
    ConfigurationId, ConfigurationName,
    ConfigurationCategory, ConfigurationBenchmark,
    CurrentValue, RecommendedValue,
    RemediationOptions
```

## Compliance summary by benchmark

```kql
DeviceBaselineComplianceAssessment
| where IsApplicable == true
| where IsExempt == false
| join kind=inner (
    DeviceBaselineComplianceAssessmentKB
    | project ConfigurationId, ConfigurationBenchmark
  ) on ConfigurationId
| summarize
    Total = count(),
    Compliant = countif(IsCompliant == true),
    NonCompliant = countif(IsCompliant == false)
  by ConfigurationBenchmark
| extend ComplianceRate = round(100.0 * Compliant / Total, 1)
| sort by ComplianceRate asc
```

## Table availability note

Table is present in the live Defender schema but may be empty in tenants where no baseline compliance profiles have been assigned to devices via MDE. Both `DeviceBaselineComplianceAssessment` and `DeviceBaselineComplianceAssessmentKB` are Preview-status as of 2026-04.
