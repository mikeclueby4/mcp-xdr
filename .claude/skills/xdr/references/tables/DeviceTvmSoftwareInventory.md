# DeviceTvmSoftwareInventory

TVM snapshot table: installed software per device with EOS metadata. Companion `DeviceTvmSoftwareVulnerabilities` holds CVE rows. Populated by MDE only — empty without MDE deployment.

Replaced the older `DeviceTvmSoftwareInventoryVulnerabilities` table.

---

## Critical: rows accumulate, no timestamp

**No `Timestamp` or `LastSeen` column.** TVM retains every version ever observed — old rows are never deleted on update. A device with 12 OpenSSL rows has seen 12 versions over its lifetime, not 12 simultaneous installs.

Consequences:
- `dcount(DeviceName)` per version overcounts — most "affected" devices may have already updated
- CVE joins explode: N versions × M CVEs × K devices >> actual current exposure
- `max(SoftwareVersion)` as a currency proxy **fails** when multiple real installs coexist (e.g. Python 3.11 user install + Python 3.14 system install — `max()` hides the vulnerable one)

**To approximate current state**, join `DeviceTvmSoftwareEvidenceBeta` on `DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion` and filter by `LastSeenTime` (string — requires `todatetime()`):

```kql
DeviceTvmSoftwareInventory
| where SoftwareName == "openssl"
| join kind=inner DeviceTvmSoftwareEvidenceBeta
    on DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
| where todatetime(LastSeenTime) > ago(14d)
| summarize Versions=make_set(SoftwareVersion) by DeviceName
```

**Ground truth for "is this binary actively loaded/running?"**:
- `DeviceImageLoadEvents` — DLL mapped into a process within the query window
- `DeviceProcessEvents` — executable ran

Use TVM for fleet-wide discovery; `DeviceTvmSoftwareEvidenceBeta.LastSeenTime` to approximate currency; image-load/process events to confirm active exposure.

---

## Primary join: DeviceTvmSoftwareVulnerabilities

Join key: `SoftwareVendor, SoftwareName, SoftwareVersion` (+ `DeviceId` for device-scoped joins). The join table carries `CveId`, `VulnerabilitySeverityLevel`, `RecommendedSecurityUpdate`, etc.

```kql
DeviceTvmSoftwareInventory
| where SoftwareName == "openssl"
| join kind=inner DeviceTvmSoftwareVulnerabilities
    on DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
| project DeviceName, SoftwareVersion, CveId, VulnerabilitySeverityLevel
```

---

## Key columns

| Column | Type | Notes |
|---|---|---|
| `DeviceId` | string | Primary join key |
| `DeviceName` | string | FQDN |
| `SoftwareVendor` | string | Lowercase (e.g. `microsoft`, `google`) |
| `SoftwareName` | string | Lowercase, underscore-separated (e.g. `visual_c++`, `.net_framework`) |
| `SoftwareVersion` | string | Dot-separated string — no numeric sort without `split()` |
| `EndOfSupportStatus` | string | See enum table below |
| `EndOfSupportDate` | datetime | Branch/product EOL date, not row age |
| `ProductCodeCpe` | string | CPE 2.3 name; literal `"Not Available"` (title-case) for unregistered software |
| `OSPlatform` | string | e.g. `Windows11`, `WindowsServer2022`, `macOS`, `Linux`, `Android`, `iOS` |
| `OSVersion` | string | Full build string |
| `OSArchitecture` | string | e.g. `x64` |
| `MachineGroup` | string | RBAC group name; present in Defender schema, absent in Sentinel schema |

No `ReportId` — join to device tables via `DeviceId` or `DeviceName`.

Sentinel variant adds `TimeGenerated` (datetime); Defender variant lacks it. Neither has `Timestamp`.

**For physical evidence (disk paths, registry keys) and last-seen time:** join to `DeviceTvmSoftwareEvidenceBeta` on `DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion`. That table has no `DeviceName` — get it from here.

---

## EndOfSupportStatus values

Confirmed via live data (2026-04):

| Value | Meaning |
|---|---|
| *(empty string)* | Supported / no EOS data |
| `Upcoming EOS Version` | This version branch approaching EOL (shown up to 6 months ahead) |
| `EOS Version` | This version branch past EOL — no patches for this version |
| `Upcoming EOS Software` | Entire product approaching EOL |
| `EOS Software` | Entire product discontinued — no patches at all |

**`EOS Version` vs `EOS Software`**: `EOS Version` means an upgrade path exists; `EOS Software` means the whole product is discontinued.

`EndOfSupportDate` is the branch/product EOL date, not a row timestamp.

EOS metadata is populated for Windows, macOS, and Android software (confirmed live 2026-04). Linux and iOS coverage appears sparse.

---

## ProductCodeCpe: "Not Available" casing

The literal sentinel value is `"Not Available"` (title-case), not `"not available"` as official docs state. Filter with:

```kql
| where ProductCodeCpe != "Not Available"
// or case-insensitive:
| where ProductCodeCpe !~ "not available"
```

---

## Coverage gaps

TVM only discovers software with MSI/WMI registration or a known CPE mapping. Zip-extracted or portable binaries are invisible.

---

## Sentinel vs Defender schema

| Column | Defender | Sentinel |
|---|---|---|
| `MachineGroup` | present | absent |
| `TimeGenerated` | absent | present |
| `Timestamp` | absent | absent |

No dynamic columns in this table — no `parse_json()` needed anywhere.
