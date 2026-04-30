# DeviceTvmHardwareFirmware

Hardware and firmware inventory from Microsoft Defender Vulnerability Management (MDVM). One row per `(DeviceId, ComponentType)` — pure snapshot, no event stream. Populated by MDE only; no Sentinel mirror.

## Key facts

- **No `Timestamp` column** — using it causes a semantic error. No time filter possible or needed.
- **One row per `(DeviceId, ComponentType)`** — confirmed 1:1, no accumulation.
- **No `ReportId`** — join to other tables via `DeviceId` only.
- **Defender-only** — not present in Sentinel. Query via `run_hunting_query`.

## ComponentType values (confirmed 2026-04)

Exactly three values in practice:

| ComponentType | What it covers | ComponentVersion | AdditionalFields keys |
|---|---|---|---|
| `Hardware` | System board / platform | Firmware/UEFI release string | `SystemSKU`, `BaseBoardManufacturer`, `BaseBoardProduct`, `BaseBoardVersion`, `DeviceFamily`, `SystemFamily` |
| `Bios` | BIOS/UEFI firmware | BIOS version string | `BIOSReleaseDate` (datetime string), `BIOSLastDetected` (datetime string) |
| `Processor` | CPU | **blank** — not populated | `ThreadsCount` (int), `Family` (string) |

Note: `ComponentVersion` is blank for `Processor` rows. BIOS version lives in `ComponentVersion`; CPU version/stepping is not surfaced.

## AdditionalFields

Native dynamic (`bag_keys()` works directly — no `parse_json()` needed). The `@odata.type` wrapper key is present in raw rows but is excluded from `bag_keys()` output. Type-annotation sibling keys (e.g. `ThreadsCount@odata.type`) also appear — ignore them when iterating keys.

```kql
// Direct property access works
DeviceTvmHardwareFirmware
| where ComponentType == "Bios"
| extend BiosDate = tostring(AdditionalFields.BIOSReleaseDate)
| extend LastSeen = tostring(AdditionalFields.BIOSLastDetected)
```

```kql
// Processor ThreadsCount
DeviceTvmHardwareFirmware
| where ComponentType == "Processor"
| extend Threads = toint(AdditionalFields.ThreadsCount)
```

## Typical hunting patterns

**BIOS version inventory — find devices on old firmware:**
```kql
DeviceTvmHardwareFirmware
| where ComponentType == "Bios"
| summarize Devices=dcount(DeviceId) by Manufacturer, ComponentName, ComponentVersion
| sort by Devices desc
```

**Devices running a specific BIOS version:**
```kql
DeviceTvmHardwareFirmware
| where ComponentType == "Bios"
| where ComponentVersion contains "N2VET29W"
| project DeviceId, DeviceName, ComponentVersion, AdditionalFields
```

**BIOS age — find devices with firmware older than N days:**
```kql
DeviceTvmHardwareFirmware
| where ComponentType == "Bios"
| extend BiosDate = todatetime(AdditionalFields.BIOSReleaseDate)
| where BiosDate < ago(730d)
| project DeviceId, DeviceName, Manufacturer, ComponentName, ComponentVersion, BiosDate
| sort by BiosDate asc
```

**Processor inventory:**
```kql
DeviceTvmHardwareFirmware
| where ComponentType == "Processor"
| summarize Devices=dcount(DeviceId) by ComponentName, ComponentFamily, Manufacturer
| sort by Devices desc
```

**Hardware platform summary — join all three types per device:**
```kql
let hw = DeviceTvmHardwareFirmware | where ComponentType == "Hardware"
    | project DeviceId, DeviceName, Platform=ComponentName, DeviceFamily=tostring(AdditionalFields.DeviceFamily);
let bios = DeviceTvmHardwareFirmware | where ComponentType == "Bios"
    | project DeviceId, BiosVersion=ComponentVersion, BiosDate=todatetime(AdditionalFields.BIOSReleaseDate);
let cpu = DeviceTvmHardwareFirmware | where ComponentType == "Processor"
    | project DeviceId, CpuName=ComponentName, CpuFamily=ComponentFamily;
hw
| join kind=leftouter bios on DeviceId
| join kind=leftouter cpu on DeviceId
| project DeviceId, DeviceName, Platform, DeviceFamily, BiosVersion, BiosDate, CpuName, CpuFamily
```

## Cross-table joins

- Join `DeviceId` to `DeviceInfo` for OS version, machine group, join type, and other device metadata.
- Join `DeviceId` to `DeviceTvmSoftwareVulnerabilities` for software CVEs on the same device.
- No `ReportId` in this table — cannot join to `AlertEvidence`.

## Column notes

- `Manufacturer` is lowercase (e.g. `"microsoft"`, `"lenovo"`, `"intel"`, `"amd"`) — use case-insensitive comparison (`=~`) or `tolower()` when filtering.
- `ComponentName` for virtual machines is `"virtual_machine"` (underscore, lowercase) for `Hardware` type, and `"virtual_machine_firmware"` for `Bios` type.
- `MachineGroup` column in live schema is present but blank — machine group resolution comes from `DeviceInfo`.
- `TenantId`, `Type`, `SourceSystem` are system columns; `Type` = `"DeviceTvmHardwareFirmware"`.
