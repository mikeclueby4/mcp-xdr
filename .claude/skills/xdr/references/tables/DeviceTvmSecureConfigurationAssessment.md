# DeviceTvmSecureConfigurationAssessment

## Overview

TVM (Threat and Vulnerability Management) snapshot table — one row per (DeviceId, ConfigurationId) reflecting the current compliance state of each security configuration check per device. Source: Microsoft Defender for Endpoint (MDE required). Defender-primary; Sentinel variant exists but was empty in tested environment.

Join to `DeviceTvmSecureConfigurationAssessmentKB` on `ConfigurationId` to get the human-readable configuration name, description, risk, and remediation steps.

No `ReportId` column — not in the Device* event table family.

## Snapshot semantics

`Timestamp` is present but reflects the latest assessment time, not an event log. The table stores the most recent compliance state per device per configuration — do not treat it as an event stream or count rows as events. Distinct `Timestamp` values nearly equal distinct `DeviceId` values per `ConfigurationId`, confirming one-row-per-device semantics.

Do **not** apply narrow time windows — snapshot rows are written on assessment cycles, not continuously. Omit time filters entirely or use a broad window.

## Key columns

| Column | Type | Notes |
|---|---|---|
| `DeviceId` | string | MDE device identifier |
| `DeviceName` | string | FQDN |
| `OSPlatform` | string | `Windows11`, `Windows10`, `WindowsServer2022`, `macOS`, `Linux`, `iOS`, `Android`, etc. |
| `Timestamp` | datetime | Assessment timestamp (snapshot time) |
| `ConfigurationId` | string | `scid-NNNN` — join key to KB table |
| `ConfigurationCategory` | string | `Application`, `OS`, `Network`, `Accounts`, `Security controls`, `Firmware` |
| `ConfigurationSubcategory` | string | e.g. `Antivirus`, `Firewall`, `Attack Surface Reduction`, `Bitlocker`, `EDR`, `Credential Guard` |
| `ConfigurationImpact` | real | 1–10; higher = more impactful to Secure Score |
| `IsCompliant` | bool | `true` = configuration is correctly applied |
| `IsApplicable` | bool | `true` = configuration is relevant to this device/OS. **Always filter `IsApplicable == 1`** — many configurations are Windows-specific and appear not applicable on macOS (~87%), iOS (~99%), etc. |
| `IsExpectedUserImpact` | bool | `true` = applying this configuration would have user-facing impact |
| `Context` | dynamic | Configuration-specific detail values — see section below |
| `MachineGroup` | string | Defender-only; MDE machine group name. May be blank if machine groups are not configured. |

## Context column — nested array structure

`Context` is a native dynamic column (`gettype()` = `"array"`). Its structure is unusual:

- Outer array always has **one element** at index 0
- `Context[0]` is itself an array of string values providing configuration-specific details

```kql
// To access context values:
| extend CtxValues = Context[0]          // inner array
| extend FirstValue = tostring(Context[0][0])  // first value as string
```

Example values by ConfigurationId (illustrative, not exhaustive):
- `scid-2010` (Defender Antivirus enabled): `Context[0]` = `["0"]` — numeric status code
- `scid-2011` (Antivirus version): `Context[0]` = `["<EngineVersion>", "<DefVersion>", "<DefTimestamp>", "<PlatformVersion>"]`
- `scid-2510/2511/2512` (ASR rules): `Context[0]` = `["Block"]` or `["Audit"]` — current rule mode

The KB table does not document Context schemas per ConfigurationId; interpret by inspecting live rows for the specific `scid` of interest.

## ConfigurationCategory confirmed values

`Application`, `OS`, `Network`, `Accounts`, `Security controls`, `Firmware`

Subcategory examples by category:
- `Security controls`: `Antivirus`, `Attack Surface Reduction`, `EDR`, `Firewall`, `Bitlocker`, `SmartScreen`, `Credential Guard`, `Exploit Guard`, `Onboard Devices`
- `Application`: `Adobe Acrobat`, `Google Chrome`, `Microsoft Office`, `Internet Explorer`, `Security Control`
- `OS`: `Services`, `Shares`

## Standard query pattern

```kql
// Non-compliant applicable configurations, enriched from KB
DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1 and IsCompliant == 0
| join kind=leftouter (
    DeviceTvmSecureConfigurationAssessmentKB
    | project ConfigurationId, ConfigurationName, ConfigurationDescription, RiskDescription, Tags, ConfigurationImpact
) on ConfigurationId
| project DeviceName, OSPlatform, ConfigurationId, ConfigurationName, ConfigurationCategory,
          ConfigurationSubcategory, ConfigurationImpact, RiskDescription, Tags
| sort by ConfigurationImpact desc
```

```kql
// Count non-compliant devices per configuration, highest-impact first
DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1 and IsCompliant == 0
| summarize NonCompliantDevices=dcount(DeviceId) by ConfigurationId, ConfigurationCategory, ConfigurationSubcategory, ConfigurationImpact
| join kind=leftouter (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName) on ConfigurationId
| sort by ConfigurationImpact desc, NonCompliantDevices desc
```

## Cross-table joins

- `DeviceTvmSecureConfigurationAssessmentKB` on `ConfigurationId` — always join for readable names, descriptions, remediation
- `DeviceInfo` on `DeviceId` — for machine group, OS version detail, join type enrichment
- `DeviceTvmSoftwareVulnerabilities` on `DeviceId` — combine compliance gaps with CVE exposure per device

## Defender vs Sentinel

`MachineGroup` is Defender-only (absent from Sentinel schema). `RelatedMitreTechniques` and `RelatedMitreTactics` are Sentinel-only columns — they live in `DeviceTvmSecureConfigurationAssessmentKB`, not this table.
