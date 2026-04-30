# DeviceBaselineComplianceAssessmentKB

**Preview table** — MDE-sourced only. Defender Advanced Hunting (`run_hunting_query`) only; Sentinel returns 400. No `Timestamp` column — static reference catalog.

## Purpose

Knowledge base / reference catalog for baseline compliance configurations. One row per `ConfigurationId`. Contains human-readable names, descriptions, remediation guidance, and benchmark metadata. Has no device-level data — pair with `DeviceBaselineComplianceAssessment` (join on `ConfigurationId`) to get per-device compliance status.

## Schema (live, 2026-04)

| Column | Type | Notes |
|---|---|---|
| `ConfigurationId` | `string` | Primary key, e.g. `"18.1.3"`, `"9.2.6"`. Format mirrors CIS section numbers. |
| `ConfigurationName` | `string` | Short display name, includes CIS level prefix e.g. `"(L1) Ensure ..."`, `"(L2) Ensure ..."`. |
| `ConfigurationDescription` | `string` | HTML markup (`<p>`, `<code>` tags) — strip if rendering as plain text. |
| `ConfigurationRationale` | `string` | HTML markup. Explains the risk/rationale behind the configuration. |
| `ConfigurationCategory` | `string` | GPO/registry category grouping (see below for known values). |
| `BenchmarkProfileLevels` | `dynamic` | Native array of strings. Values: `"Level 1 - Domain Controller"`, `"Level 1 - Member Server"`, `"Level 2 - Domain Controller"`, `"Level 2 - Member Server"`. Some configs apply to all four; some only L2. |
| `CCEReference` | `string` | Common Configuration Enumeration ID (e.g. `"CCE-33216-3"`). Can be empty string. |
| `RemediationOptions` | `string` | HTML markup (`<div>`, `<p>`, `<code>`, `<strong>` tags). Contains GP path and impact. Strip tags for non-HTML display. |
| `ConfigurationBenchmark` | `string` | `"CIS"`, `"Microsoft"`, or `"STIG"` (confirmed values, 2026-04). |
| `Source` | `dynamic` | Native array of strings. Registry paths (lowercased `hkey_local_machine\\...`) or other check locations. Can have 1–13+ elements for configs with multiple registry keys. |
| `RecommendedValue` | `dynamic` | Native array of strings. Condition strings e.g. `"Equals '0'"`, `"Greater than or equal '16384'"`. Same length as `Source`. |
| `AssessmentMethod` | `string` | `"Automatic"` (majority) or `"NotSupported"`. |
| `TenantId` | `string` | Internal — populated by ingestion pipeline. |
| `Type` | `string` | Always `"DeviceBaselineComplianceAssessmentKB"` — ingestion artifact. |
| `SourceSystem` | `string` | Always `"DeviceBaselineComplianceAssessmentKB"` — ingestion artifact. |

**Docs omit**: `AssessmentMethod`, `TenantId`, `Type`, `SourceSystem` — present in live schema but not in official docs.

## Dynamic columns — all native arrays

`BenchmarkProfileLevels`, `Source`, and `RecommendedValue` are all `gettype()` = `"array"`. Array indexing works directly — **no `parse_json()` needed**:

```kql
// Works — native dynamic array
| extend FirstSource = tostring(Source[0])
| extend FirstRecommended = tostring(RecommendedValue[0])
| extend FirstLevel = tostring(BenchmarkProfileLevels[0])

// mv-expand also works directly
| mv-expand Level = BenchmarkProfileLevels to typeof(string)
```

Note: `bag_keys()` returns empty on arrays (only works on dicts) — this is expected, not an error.

## ConfigurationBenchmark values (confirmed 2026-04)

| Value | Count | Notes |
|---|---|---|
| `CIS` | 616 | CIS Benchmarks (Center for Internet Security) |
| `Microsoft` | 326 | Microsoft security baselines |
| `STIG` | 204 | DISA STIGs |

Total: 1,146 rows.

## ConfigurationCategory

`ConfigurationCategory` uses a mix of GPO policy path segments and STIG SRG codes. STIG entries use `SRG-OS-NNNNNN-GPOSNN-NNN` format. CIS/Microsoft entries use human-readable GPO section names. High-frequency categories (top 10): `User Rights Assignment` (74), `Computer Configuration` (55), several STIG SRG codes (~34 each), `Advanced Audit Policy Configuration` (30), `MSS (Legacy)` (27), `Internet Communication settings` (27).

## Relationship to DeviceBaselineComplianceAssessment

`DeviceBaselineComplianceAssessmentKB` is the metadata half; `DeviceBaselineComplianceAssessment` is the per-device compliance data half. They share:
- `ConfigurationId` — primary join key
- `Source` — same registry paths (for cross-checking current vs recommended)
- `RecommendedValue` — same recommended condition strings

`DeviceBaselineComplianceAssessment` adds: `DeviceId`, `DeviceName`, `IsCompliant`, `IsApplicable`, `IsExempt`, `CurrentValue`, `ProfileId`, `OSPlatform`, `OSVersion`.

**Standard join pattern — non-compliant configs with remediation:**

```kql
let Profile = "";  // set to a specific ProfileId, or remove the filter
DeviceBaselineComplianceAssessment
| where isempty(Profile) or ProfileId == Profile
| where IsApplicable == true
| where IsCompliant == false
| where IsExempt == false
| join kind=inner DeviceBaselineComplianceAssessmentKB on ConfigurationId
| project
    DeviceId,
    DeviceName,
    ConfigurationId,
    ConfigurationName,
    ConfigurationCategory,
    ConfigurationBenchmark,
    BenchmarkProfileLevels,
    CurrentValue,
    RecommendedValue,
    RemediationOptions
| sort by DeviceName asc, ConfigurationId asc
```

Note: the web-sourced example queries use `IsCompliant == "0"` and `IsExempt == "0"` (string comparison). Live schema confirms both columns are `bool` — use `== false` for correctness.

## No Timestamp — static reference table

No `Timestamp` or `TimeGenerated` column. Do not add time filters. The table is a static catalog of configuration definitions, not an event stream.

## HTML in text columns

`ConfigurationDescription`, `ConfigurationRationale`, and `RemediationOptions` contain HTML markup (`<p>`, `<div>`, `<code>`, `<strong>`, `<ol>`, `<li>` etc.). If using these columns for display, strip tags:

```kql
// Strip HTML tags — crude but functional for single-line display
| extend CleanName = replace_regex(ConfigurationDescription, @"<[^>]+>", "")
```

For full remediation instructions, prefer rendering as HTML rather than plain text.

## AssessmentMethod: NotSupported rows

69 configurations have `AssessmentMethod == "NotSupported"`. These cannot be automatically assessed by MDE. Filter them out for compliance gap analysis unless tracking unsupported scope:

```kql
| where AssessmentMethod == "Automatic"
```

## ConfigurationId format

Mirrors CIS benchmark section numbering (e.g. `"18.1.3"`, `"9.2.6"`). STIG entries may use different formats. This is a string — do not cast to numeric.

## Filtering by benchmark level

To get only Level 1 or Level 2 configs:

```kql
// Level 1 only (both DC and Member Server)
| where BenchmarkProfileLevels has "Level 1"

// Level 2 only
| where BenchmarkProfileLevels has "Level 2"

// Domain Controllers only
| where BenchmarkProfileLevels has "Domain Controller"
```

`has` operates on the JSON-serialized array string — efficient (bloom filter). Equivalent to checking if any element contains the substring.
