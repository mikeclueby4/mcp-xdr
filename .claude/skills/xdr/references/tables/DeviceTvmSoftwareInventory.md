# DeviceTvmSoftwareInventory (and DeviceTvmSoftwareVulnerabilities)

TVM snapshot tables: installed software + CVEs per device. Populated by MDE only — empty if MDE is not deployed.

Replaced the older `DeviceTvmSoftwareInventoryVulnerabilities` table.

---

## Critical: rows accumulate, no timestamp in this table

**No `Timestamp` or `LastSeen` column here.** TVM retains every version ever observed — old rows are never deleted on update. A device with 12 OpenSSL rows has seen 12 versions over its lifetime, not 12 simultaneous installs.

Consequences:
- `dcount(DeviceName)` per version overcounts — most "affected" devices have already updated
- CVE joins explode: N versions × M CVEs × K devices >> actual current exposure
- `max(SoftwareVersion)` as a currency proxy **fails** when multiple real installs coexist (e.g. Python 3.11 user install + Python 3.14 system install — `max()` hides the vulnerable one)

**To approximate current state**, join `DeviceTvmSoftwareEvidenceBeta` on `DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion` and filter by `LastSeenTime` (string — requires `todatetime()`). Rows with a recent `LastSeenTime` are likely still installed; absent rows were likely removed.

```kql
DeviceTvmSoftwareInventory
| where SoftwareName == "openssl"
| join kind=inner DeviceTvmSoftwareEvidenceBeta
    on DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
| where todatetime(LastSeenTime) > ago(14d)
| summarize Versions=make_set(SoftwareVersion) by DeviceName
```

**Ground truth for "is this binary actively loaded/running?"** requires yet another table:
- `DeviceImageLoadEvents` — DLL mapped into a process within the query window
- `DeviceProcessEvents` — executable ran

Use TVM for fleet-wide discovery; `DeviceTvmSoftwareEvidenceBeta.LastSeenTime` to approximate currency; image-load/process events to confirm active exposure.

---

## EndOfSupportStatus values

Full enum per the MDE export API docs (confirmed against live data 2026-04):

| Value | Meaning |
|---|---|
| *(empty / `None`)* | Supported |
| `Upcoming EOS Version` | This specific version branch is approaching EOL (shown up to 6 months in advance) |
| `EOS Version` | This specific version branch is past EOL — no patches for this version |
| `Upcoming EOS Software` | The entire software product is approaching EOL |
| `EOS Software` | The entire software product is past EOL — no patches at all |

**`EOS Version` vs `EOS Software`**: `EOS Version` means a newer supported version exists (upgrade path available); `EOS Software` means the whole product is discontinued (no upgrade path within the same product).

`EndOfSupportDate` is the branch/product EOL date, not a row timestamp.

---

## Coverage gaps

TVM only discovers software with MSI/WMI registration or a known CPE mapping. Zip-extracted or portable binaries are invisible regardless of how many DLLs they load.

End-of-support capability is currently available only for Windows products.

---

## Key columns

| Column | Type | Notes |
|---|---|---|
| `DeviceId` | string | Primary join key |
| `DeviceName` | string | FQDN |
| `SoftwareVendor` | string | Lowercase (e.g. `microsoft`, `google`) |
| `SoftwareName` | string | Lowercase, underscore-separated (e.g. `visual_c++`, `.net_framework`) |
| `SoftwareVersion` | string | Dot-separated string — no numeric sort without `split()` |
| `EndOfSupportStatus` | string | See enum table above |
| `EndOfSupportDate` | datetime | Branch/product EOL date, not row age |
| `ProductCodeCpe` | string | CPE 2.3 name; `'not available'` (literal string) for unregistered software |
| `OSPlatform` | string | e.g. `Windows11`, `WindowsServer2022` |
| `OSVersion` | string | Full build string |
| `OSArchitecture` | string | e.g. `x64` |
| `MachineGroup` | string | RBAC group name; present in Defender schema, absent in Sentinel schema |

No `ReportId` — join to device tables via `DeviceId` or `DeviceName`.

Sentinel variant adds `TimeGenerated` (datetime); Defender variant lacks it. Neither has `Timestamp`.

**For physical evidence (disk paths, registry keys) and last-seen time:** join to `DeviceTvmSoftwareEvidenceBeta` on `DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion`. That table has no `DeviceName` — get it from here.
