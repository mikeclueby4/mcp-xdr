# DeviceTvmSoftwareVulnerabilitiesKB

CVE knowledge base used by `DeviceTvmSoftwareVulnerabilities`. One row per CVE (global, not per-device). Join on `CveId` to enrich device vulnerability rows with CVSS, EPSS, exploit flag, and description.

Populated by MDE. Present in both Defender and Sentinel schemas; Sentinel rows may be empty in practice.

---

## Key columns

| Column | Type | Defender | Sentinel | Notes |
|---|---|---|---|---|
| `CveId` | string | yes | yes | Join key |
| `CvssScore` | real | yes | yes | 0–10 |
| `CvssVector` | string | yes | no | Full CVSS vector string |
| `IsExploitAvailable` | bool | yes | yes | Public exploit known |
| `VulnerabilitySeverityLevel` | string | yes | yes | `Critical`/`High`/`Medium`/`Low` |
| `EpssScore` | real | yes | no | Exploit Prediction Scoring System, 0–1 |
| `CveSupportability` | string | yes | no | `Supported`, `NotSupported`, `SupportedInPremium` |
| `LastModifiedTime` | datetime | yes | yes | |
| `PublishedDate` | datetime | yes | yes | |
| `VulnerabilityDescription` | string | yes | yes | AI-generated summary in many rows |
| `AffectedSoftware` | dynamic | yes | yes | Native array of CPE strings |

---

## AffectedSoftware: native dynamic array

`AffectedSoftware` is a native dynamic array of CPE strings (e.g. `["microsoft:windows_10"]`). Direct `mv-expand` works; no `parse_json()` needed.

```kql
DeviceTvmSoftwareVulnerabilitiesKB
| where IsExploitAvailable == true
| mv-expand AffectedSoftware
| summarize CVEs=dcount(CveId) by tostring(AffectedSoftware)
| sort by CVEs desc
```

---

## Primary usage pattern

Enrich `DeviceTvmSoftwareVulnerabilities` with exploit/EPSS data:

```kql
DeviceTvmSoftwareVulnerabilities
| join kind=inner (
    DeviceTvmSoftwareVulnerabilitiesKB
    | where IsExploitAvailable == true
    | project CveId, CvssScore, EpssScore
) on CveId
| summarize Devices=dcount(DeviceId) by CveId, CvssScore, EpssScore, VulnerabilitySeverityLevel
| sort by EpssScore desc
```

Prioritise by `EpssScore` (exploitation probability) over `CvssScore` (theoretical severity) for realistic triage.
