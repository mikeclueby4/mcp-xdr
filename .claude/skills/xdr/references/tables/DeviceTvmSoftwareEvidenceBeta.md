# DeviceTvmSoftwareEvidenceBeta

**Beta table** — name and column names may change when it graduates to GA. Queries using this table may break without notice.

Companion to `DeviceTvmSoftwareInventory`: provides file-system and registry evidence for where each software detection was found. One row per `(DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion)`. MDE-only — empty without MDE deployment.

No `DeviceName`. Join to `DeviceTvmSoftwareInventory` or `DeviceInfo` on `DeviceId` to get device name.

---

## Key columns

| Column | Type | Notes |
|---|---|---|
| `DeviceId` | string | Join key; no `DeviceName` |
| `SoftwareVendor` | string | Lowercase (e.g. `microsoft`, `7-zip`) |
| `SoftwareName` | string | Lowercase, underscore-separated (same convention as `DeviceTvmSoftwareInventory`) |
| `SoftwareVersion` | string | Dot-separated string |
| `RegistryPaths` | dynamic | Array of registry key paths where software was detected; can be empty `[]` |
| `DiskPaths` | dynamic | Array of file paths where software was detected; can be empty `[]` |
| `LastSeenTime` | string | Stored as string — use `todatetime(LastSeenTime)` for time comparisons |
| `MachineGroup` | string | RBAC group name |

No `Timestamp`. No `ReportId`. No CVE data.

---

## Dynamic columns

`RegistryPaths` and `DiskPaths` are **native dynamic arrays** — direct indexing works without `parse_json(tostring(...))`:

```kql
| extend FirstDiskPath = DiskPaths[0]
| extend FirstRegPath  = RegistryPaths[0]
| mv-expand DiskPath = DiskPaths to typeof(string)
```

Either array can be empty `[]` for a given row. Empirically: ~58% of rows have disk evidence only, ~24% registry only, ~20% both.

---

## Linux evidence — DiskPaths contains RPM queries, not file paths

On Linux devices, `DiskPaths` entries may be RPM query commands rather than file paths:

```
rpm -qa --qf '%{NAME}:%{Sourcerpm}:\n' | grep Chromium | cut -f 1 -d ':' | xargs rpm -qid
```

Do not assume `DiskPaths` values are always file system paths. Filter to Windows paths before doing path-based analysis (e.g. `has ":\\"` ).

---

## Relationship to DeviceTvmSoftwareInventory

`DeviceTvmSoftwareInventory` carries vulnerability/EOS metadata and `DeviceName`; this table carries the physical evidence (paths). Typical join:

```kql
DeviceTvmSoftwareInventory
| where SoftwareName == "openssl"
| join kind=inner DeviceTvmSoftwareEvidenceBeta
    on DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
| mv-expand DiskPath = DiskPaths to typeof(string)
| project DeviceName, SoftwareVersion, DiskPath, RegistryPaths
```

---

## LastSeenTime is a string

Arithmetic on `LastSeenTime` requires explicit cast:

```kql
| where todatetime(LastSeenTime) > ago(7d)
| extend AgeDays = datetime_diff('day', now(), todatetime(LastSeenTime))
```

---

## Finding software by install path

```kql
DeviceTvmSoftwareEvidenceBeta
| mv-expand DiskPath = DiskPaths to typeof(string)
| where DiskPath has "\\AppData\\"   // user-scoped installs
| join kind=inner (DeviceInfo | project DeviceId, DeviceName) on DeviceId
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, DiskPath
```

---

## Beta caveats

- Table name and column names are subject to change at GA graduation.
- `TenantId`, `Type`, `SourceSystem` columns appear in schema but are blank in practice — Defender system metadata.
- Defender-only: not available via `run_sentinel_query`.
