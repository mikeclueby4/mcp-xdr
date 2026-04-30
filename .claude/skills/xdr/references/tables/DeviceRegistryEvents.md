# DeviceRegistryEvents

Registry create/modify/delete events from MDE-enrolled endpoints. Windows-only table — no macOS/Linux registry equivalent.

Source: Defender XDR + Sentinel (same data). Use `Timestamp` (Defender) or `TimeGenerated` (Sentinel).

## ActionType (confirmed 2026-04, exactly 4 values)

| ActionType | Volume | Description |
|---|---|---|
| `RegistryValueSet` | Highest | Value created or modified |
| `RegistryKeyCreated` | High | Key created |
| `RegistryKeyDeleted` | High | Key deleted |
| `RegistryValueDeleted` | High | Value deleted |

No `RegistryKeyRenamed` or `RegistryValueRenamed` — renames appear as delete + create pairs.

## RegistryValueType

Named types: `None`, `Dword`, `String`, `Binary`, `ExpandString`, `Qword`, `MultiString`.

**Negative integer values also appear** (e.g. `-65520`, `-65518`, `-65529`, `-65519`, `-57326`). These map to internal Windows property store types (device property keys) used in `HKLM\SYSTEM\...\Properties\{GUID}\NNNN` paths. Not documented. Filter with `toint(RegistryValueType) >= 0` to exclude them when enumerating named types only.

## Previous* columns — population by ActionType (confirmed 2026-04)

| ActionType | PreviousRegistryKey | PreviousRegistryValueName | PreviousRegistryValueData |
|---|---|---|---|
| `RegistryKeyCreated` | blank | blank | blank |
| `RegistryKeyDeleted` | populated (original key path) | blank | blank |
| `RegistryValueDeleted` | populated | populated (~99%) | populated (~84%) |
| `RegistryValueSet` | blank | populated when renaming value | populated (~12%, prior data) |

For `RegistryKeyDeleted`: `PreviousRegistryKey` holds the deleted key path; `RegistryKey` is blank.
For `RegistryValueDeleted`/`RegistryValueSet`: current `RegistryKey` is always the key; `PreviousRegistry*` holds pre-change state.

## No AdditionalFields column

`DeviceRegistryEvents` does not have an `AdditionalFields` column. No dynamic column parsing needed.

## Schema notes

- `ProcessUniqueId` — **absent from live schema** despite appearing in official docs (confirmed 2026-04). Same pattern as other Device* tables. Do not use.
- `InitiatingProcessUniqueId` — present and well-populated (string, Windows Process Start Key). Use for process-chain correlation across Device* tables without PID-reuse ambiguity.
- `ReportId` — `long`, local counter. **Not globally unique.** Always join on `ReportId + DeviceName + Timestamp` (see kql-facts.md ReportId section).
- `AppGuardContainerId` — blank for most rows; populated only when registry action occurs inside an Application Guard container.
- `IsInitiatingProcessRemoteSession` / `InitiatingProcessRemoteSessionDeviceName` / `InitiatingProcessRemoteSessionIP` — populated when initiating process ran in an RDP session.
- `InitiatingProcessSessionId` — Windows logon session ID; join with `DeviceLogonEvents` on `DeviceId + InitiatingProcessSessionId` to find the associated logon.
- `InitiatingProcessSHA256` — often blank per official docs; prefer `InitiatingProcessSHA1`.

## Defender vs Sentinel

Schema is identical between Defender and Sentinel for this table. No `dynamic` columns — all columns are `string`, `long`, `datetime`, or `bool`. No `parse_json()` needed.

## Hunting patterns

### Persistence via Run keys
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
  )
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountUpn
| sort by Timestamp desc
```

### Services and drivers (T1543)
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\"
| where RegistryValueName in ("ImagePath", "ServiceDll", "Start", "Type")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Process-chain linking via InitiatingProcessUniqueId
```kql
// Find all registry writes by a specific process, then join to process tree
let SuspiciousProc = DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName == "suspicious.exe"
    | project ProcessUniqueId, DeviceId, DeviceName, FileName, ProcessCommandLine;
SuspiciousProc
| join kind=inner (
    DeviceRegistryEvents
    | where Timestamp > ago(1d)
    | project Timestamp, DeviceId, DeviceName, ActionType, RegistryKey,
        RegistryValueName, RegistryValueData, InitiatingProcessUniqueId
) on DeviceId, $left.ProcessUniqueId == $right.InitiatingProcessUniqueId
```

### Detect RegistryValueType negative-integer rows (device property store noise)
```kql
// Filter out internal device property store writes when hunting for named-type changes
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where toint(RegistryValueType) >= 0  // exclude negative internal types
```

## Cross-table joins

- Join to `DeviceProcessEvents` on `DeviceId + InitiatingProcessUniqueId == ProcessUniqueId` to get the full process context for a registry writer.
- Join to `DeviceLogonEvents` on `DeviceId + InitiatingProcessSessionId` to find the session that spawned the writing process.
- Join to `AlertEvidence` on `ReportId, DeviceName, Timestamp` (three-column composite — see kql-facts.md).
- `InitiatingProcessAccountObjectId` → `IdentityInfo` on `AccountObjectId` for user enrichment.
