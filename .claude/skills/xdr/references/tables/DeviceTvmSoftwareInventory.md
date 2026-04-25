# DeviceTvmSoftwareInventory (and DeviceTvmSoftwareVulnerabilities)

TVM snapshot tables: installed software + CVEs per device.

---

## Critical: no timestamp, rows accumulate across updates

**Neither table has a `Timestamp` or `LastSeen` column.** Despite presenting as a current-state snapshot, TVM retains all versions it has ever observed for a device — old rows are never deleted when software updates. A device with 12 OpenSSL rows has had 12 different versions detected over its lifetime, not 12 simultaneous installs.

There is **no reliable built-in way to filter to "currently installed"** from TVM alone — no date, no install-path, no distinguishing column other than `SoftwareVersion`. The schema is identical across all historical rows for the same (`DeviceName`, `SoftwareName`).

Consequences:
- `dcount(DeviceName)` per version overcounts — most "affected" devices have already updated
- CVE joins explode: N versions × M CVEs × K devices >> actual current exposure
- `max(SoftwareVersion)` as a currency proxy **fails** when multiple real installs coexist (e.g. Python 3.11 user install + Python 3.14 system install — both genuinely present, `max()` hides the vulnerable one)

**Ground truth for "is this DLL/binary actually loaded/running?" requires a different table:**
- `DeviceImageLoadEvents` — confirms a DLL was mapped into a process within the query window
- `DeviceProcessEvents` — confirms an executable ran

Use TVM for fleet-wide discovery; use image-load/process events to confirm active exposure.

---

## Reducing TVM to approximate current state

When cross-tenant analysis or lack of runtime telemetry forces TVM-only queries, `make_set` per device exposes all versions so you can reason about them:

```kql
DeviceTvmSoftwareInventory
| where SoftwareName == "openssl"
| summarize Versions=make_set(SoftwareVersion) by DeviceName
```

For CVE joins, filter the vuln table to only versions that still appear in TVM (all of them will), then deduplicate at the device level:

```kql
DeviceTvmSoftwareVulnerabilities
| where SoftwareName == "openssl"
| summarize 
    Severities=make_set(VulnerabilitySeverityLevel),
    CVEs=dcount(CveId)
  by DeviceName
```

---

## EndOfSupportStatus values

| Value | Meaning |
|---|---|
| *(empty)* | Supported |
| `Upcoming EOS Version` | Branch EOL approaching |
| `EOS Version` | Branch EOL passed — no patches |

`EndOfSupportDate` is the branch EOL date, not a row timestamp.

---

## Coverage gaps

TVM only discovers software with MSI/WMI registration or a known CPE mapping. Zip-extracted or portable binaries are invisible regardless of how many DLLs they load.

---

## Key columns

| Column | Type | Notes |
|---|---|---|
| `DeviceName` | string | |
| `DeviceId` | string | Use with `DeviceName` for joins |
| `SoftwareName` | string | Lowercase, underscore-separated |
| `SoftwareVersion` | string | Dot-separated string — no numeric sort without `split()` |
| `EndOfSupportStatus` | string | See above |
| `EndOfSupportDate` | datetime | Branch EOL date, not row age |
| `ProductCodeCpe` | string | CPE; absent for unregistered software |
| `OSPlatform` | string | `Windows11`, `WindowsServer2022`, etc. |
