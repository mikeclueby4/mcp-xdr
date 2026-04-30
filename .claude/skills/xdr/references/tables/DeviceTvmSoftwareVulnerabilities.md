# DeviceTvmSoftwareVulnerabilities

TVM snapshot: one row per (DeviceId, SoftwareName, SoftwareVersion, CveId). Populated by MDE only. Defender-only table (Sentinel schema exists but rows absent in most tenants). Replaced `DeviceTvmSoftwareInventoryVulnerabilities`.

---

## No time column in Defender

**No `Timestamp` column.** Using `| where Timestamp > ago(...)` causes a semantic error. The Sentinel variant adds `TimeGenerated`. In Defender, omit the time filter entirely or use `Ingestion_time()` as a proxy.

Rows are a current-state snapshot, not an event log — no time filter needed for most use cases.

---

## Snapshot accumulation caveat

Same as `DeviceTvmSoftwareInventory`: rows accumulate — old versions are never deleted. `dcount(DeviceId)` per CVE overstates current exposure. Join `DeviceTvmSoftwareEvidenceBeta` (on `DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion`) and filter `todatetime(LastSeenTime) > ago(14d)` for current state.

---

## Key columns

| Column | Type | Notes |
|---|---|---|
| `DeviceId` | string | Primary join key |
| `DeviceName` | string | FQDN |
| `OSPlatform` | string | e.g. `Windows11`, `WindowsServer2022`, `macOS`, `Android` — multi-platform |
| `SoftwareVendor` | string | Lowercase |
| `SoftwareName` | string | Lowercase |
| `SoftwareVersion` | string | Dot-separated string |
| `CveId` | string | Join key to `DeviceTvmSoftwareVulnerabilitiesKB` |
| `VulnerabilitySeverityLevel` | string | `Critical`, `High`, `Medium`, `Low` — based on CVSS + threat landscape |
| `RecommendedSecurityUpdate` | string | Often blank even when patches exist |
| `RecommendedSecurityUpdateId` | string | Often blank |
| `CveTags` | dynamic | Array; typically `[]`; known values: `ZeroDay`, `NoSecurityUpdate` |
| `CveMitigationStatus` | string | Defender-only; blank in practice (always empty in confirmed tenants) |
| `AadDeviceId` | string | Defender-only; absent in Sentinel |
| `MachineGroup` | string | Defender-only; RBAC group |

No `ReportId`. No `AdditionalFields`. No dynamic columns requiring `parse_json()` except `CveTags` (native array — direct `mv-expand` works).

---

## Primary join: DeviceTvmSoftwareInventory

Join key: `DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion`

```kql
DeviceTvmSoftwareInventory
| where EndOfSupportStatus == "EOS Version"
| join kind=inner DeviceTvmSoftwareVulnerabilities
    on DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
| where VulnerabilitySeverityLevel in ("Critical", "High")
| summarize CVEs=dcount(CveId) by DeviceName, SoftwareName, SoftwareVersion
| sort by CVEs desc
```

---

## KB enrichment join: DeviceTvmSoftwareVulnerabilitiesKB

Join on `CveId` for CVSS score, EPSS score, exploit availability, description.

```kql
DeviceTvmSoftwareVulnerabilities
| join kind=inner (
    DeviceTvmSoftwareVulnerabilitiesKB
    | where IsExploitAvailable == true
    | project CveId, CvssScore, EpssScore, VulnerabilityDescription
) on CveId
| summarize Devices=dcount(DeviceId) by CveId, CvssScore, EpssScore, VulnerabilitySeverityLevel
| sort by CvssScore desc
```

`EpssScore` and `CvssVector` are Defender-only columns in the KB table (absent in Sentinel schema). `EpssScore` is `real` (0–1 probability of exploitation). `CveSupportability` values: `Supported`, `NotSupported`, `SupportedInPremium`.

---

## Sentinel vs Defender schema

| Column | Defender | Sentinel |
|---|---|---|
| `MachineGroup` | present | absent |
| `AadDeviceId` | present | absent |
| `CveMitigationStatus` | present (blank) | absent |
| `TimeGenerated` | absent | present |
| `Timestamp` | absent | absent |

---

## CveTags: native dynamic array

`CveTags` is a native dynamic array — no `parse_json()` needed. Typically `[]`. Filter non-empty:

```kql
| where array_length(CveTags) > 0
| mv-expand Tag=CveTags
| where Tag == "ZeroDay"
```

---

## Defender-only table note

This table is populated by MDE. No rows in Sentinel in most tenants even when Sentinel schema is present. Always query via `run_hunting_query`.

---

## Cross-reference: DeviceTvmInfoGathering

For zero-day mitigation queries (e.g. Log4Shell), join this table with `DeviceTvmInfoGathering` on `DeviceId` to correlate CVE presence with mitigation/workaround state. `DeviceTvmInfoGathering` carries per-device configuration state (AV mode, ASR rules, TLS settings, vulnerability-specific flags) that this table does not.
