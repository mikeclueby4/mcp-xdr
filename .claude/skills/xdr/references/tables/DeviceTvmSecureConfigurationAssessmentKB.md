# DeviceTvmSecureConfigurationAssessmentKB

## Overview

TVM knowledge base / lookup table — one row per `ConfigurationId` (security configuration definition). Contains human-readable names, descriptions, risk context, remediation steps, and benchmark mappings. Does **not** contain device-level data.

Always join to `DeviceTvmSecureConfigurationAssessment` on `ConfigurationId` — do not query this table standalone for compliance analysis.

## Schema

| Column | Type | Notes |
|---|---|---|
| `ConfigurationId` | string | `scid-NNNN` — primary key, unique per row |
| `ConfigurationImpact` | real | 1–10 impact score (same value as in the assessment table) |
| `ConfigurationName` | string | Short display name |
| `ConfigurationDescription` | string | Full description including HTML markup |
| `RiskDescription` | string | Description of the risk if non-compliant |
| `ConfigurationCategory` | string | `Application`, `OS`, `Network`, `Accounts`, `Security controls`, `Firmware` |
| `ConfigurationSubcategory` | string | More specific grouping (e.g. `Antivirus`, `Firewall`) |
| `ConfigurationBenchmarks` | dynamic | Array of benchmark strings — see values below |
| `Tags` | dynamic | Array of label strings — see values below |
| `RemediationOptions` | string | **HTML-formatted** remediation steps (contains `<b>`, `<ol>`, `<li>`, `<a>` tags) — not plain text |

## Dynamic columns

`ConfigurationBenchmarks` and `Tags` are native dynamic arrays of strings. Direct indexing works; no `parse_json()` needed.

```kql
// Filter by benchmark
DeviceTvmSecureConfigurationAssessmentKB
| where ConfigurationBenchmarks has "CIS"
// Or using mv-expand for per-benchmark rows:
| mv-expand ConfigurationBenchmarks
| where tostring(ConfigurationBenchmarks) == "CIS"
```

## ConfigurationBenchmarks confirmed values

`CIS`, `STIG`, `MS`, `NIST`

CIS and STIG are by far the most common. Not all configurations are tagged to a benchmark.

## Tags confirmed values

`UserImpactAssessment`, `HumanOperatedRansomware`, `covid19`

Tags are sparse — most rows have an empty `Tags` array. `UserImpactAssessment` indicates applying the configuration may affect end users. `HumanOperatedRansomware` marks configurations relevant to ransomware attack paths.

## RemediationOptions format

Contains HTML, not plain text. Use `tostring()` to inspect; strip tags if rendering in non-HTML contexts. Content typically includes Group Policy paths, Intune configuration steps, and registry values.

## Sentinel-only columns

`RelatedMitreTechniques` (dynamic) and `RelatedMitreTactics` (dynamic) exist **only in Sentinel** — they are absent from the Defender schema. Querying them via `run_hunting_query` causes a semantic error. Use `run_sentinel_query` when MITRE mapping is needed.

```kql
// Sentinel only — MITRE technique enrichment
DeviceTvmSecureConfigurationAssessmentKB
| where RelatedMitreTechniques has "T1548"
| project ConfigurationId, ConfigurationName, RelatedMitreTechniques, RelatedMitreTactics
```

## No Timestamp in Defender

`Timestamp` and `TimeGenerated` are absent from the Defender schema. This is a static reference table, not a time-series. Omit time filters entirely.

## Standard join pattern

```kql
DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1 and IsCompliant == 0
| join kind=leftouter (
    DeviceTvmSecureConfigurationAssessmentKB
    | project ConfigurationId, ConfigurationName, ConfigurationDescription, RiskDescription, Tags, ConfigurationImpact
) on ConfigurationId
| project DeviceName, OSPlatform, ConfigurationName, ConfigurationCategory, ConfigurationSubcategory,
          ConfigurationImpact, RiskDescription, Tags
| sort by ConfigurationImpact desc
```

## Companion tables

- `DeviceTvmSecureConfigurationAssessment` — device compliance state; join on `ConfigurationId`
