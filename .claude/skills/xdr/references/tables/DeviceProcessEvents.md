# DeviceProcessEvents

MDE-sourced process creation log. One row per `ProcessCreated` event. Available in both Defender Advanced Hunting (`run_hunting_query`) and Sentinel (`run_sentinel_query`).

**Time column:** `Timestamp` (Defender), `TimeGenerated` (Sentinel — also present but equals `Timestamp`).

## ActionType

Only one value observed in practice:

| Value | Description |
|---|---|
| `ProcessCreated` | A new process was spawned |

## Key columns

| Column | Type | Notes |
|---|---|---|
| `FileName` | string | Process image file name only (no path) |
| `FolderPath` | string | Full path including file name |
| `ProcessCommandLine` | string | Always populated for MDE-enrolled endpoints; contrast with `SecurityEvent.CommandLine` which requires explicit audit policy |
| `ProcessId` | long | PID — reused after process exit; not unique without `ProcessCreationTime` |
| `ProcessCreationTime` | datetime | Use with `ProcessId` for reliable process identity |
| `ProcessUniqueId` | string | Long integer string equal to Windows Process Start Key — stable unique ID; use this over `ProcessId` alone for process-chain linking |
| `InitiatingProcessUniqueId` | string | Start Key of the parent; enables building full process trees |
| `ProcessIntegrityLevel` | string | See values below; blank for non-Windows |
| `ProcessTokenElevation` | string | See values below; blank for non-Windows |
| `InitiatingProcessSignerType` | string | See values below |
| `InitiatingProcessSignatureStatus` | string | See values below |
| `ReportId` | long | **Not unique** — local device counter. Safe join key only as composite: `ReportId + DeviceName + Timestamp` |
| `AdditionalFields` | **string** (Defender) / **dynamic** (Sentinel) | JSON object; see section below |
| `LogonId` | long | Logon session ID — unique per device per boot only |
| `AppGuardContainerId` | string | Non-empty when process ran inside Application Guard container |

## ProcessIntegrityLevel values (confirmed)

| Value | Notes |
|---|---|
| (blank) | macOS/Linux — integrity levels are Windows-only |
| `System` | SYSTEM-level integrity |
| `Medium` | Standard user-launched process |
| `Low` | Sandboxed/internet-launched process |
| `High` | Elevated (admin) |
| `Invalid` | Rare; malformed or stripped token |

## ProcessTokenElevation values (confirmed)

| Value | Notes |
|---|---|
| `TokenElevationTypeDefault` | Standard token; UAC not involved or not applicable |
| `None` | Non-Windows (macOS/Linux) |
| `TokenElevationTypeLimited` | Split token, running with limited privileges (UAC applied, not elevated) |
| `TokenElevationTypeFull` | Full admin token (elevated via UAC) |

## InitiatingProcessSignerType values (confirmed)

| Value | Notes |
|---|---|
| `OsVendor` | Signed by OS vendor (Microsoft on Windows) |
| `OsVendorApplication` | Signed application distributed by OS vendor |
| `Unknown` | Unsigned or unverifiable signer |

## InitiatingProcessSignatureStatus values (confirmed)

| Value |
|---|
| `Valid` |
| `Unsigned` |
| `Unknown` |
| `Invalid` |

## AdditionalFields — structure and serialization

**Defender**: typed `string` (confirmed via `gettype()` = `"string"`), contains a JSON object. Use `parse_json(AdditionalFields)` — result is a native `dictionary`. Do NOT use `parse_json(tostring(AdditionalFields))` — the double-wrap is redundant here (it is a string, not a dynamic, so `tostring()` is a no-op but `parse_json()` works directly).

**Sentinel**: typed `dynamic` — direct property access works without `parse_json()`.

**Cross-platform portability:** `parse_json(AdditionalFields)` is safe in both sources (in Defender it parses the string; in Sentinel it is a no-op on a dynamic). Avoid `parse_json(tostring(AdditionalFields))` — the `tostring()` of a dynamic in Sentinel produces a JSON string then re-parses it (CPU-expensive).

### Known AdditionalFields keys (confirmed from live data)

**Windows:**

| Key | Type | Notes |
|---|---|---|
| `DesktopName` | string | Window station and desktop, e.g. `"WinSta0\\Default"`, `"winsta0\\Winlogon"`, `"Service-0x0-...\\sbox_..."` |

**macOS/Linux (POSIX enrichment):**

| Key | Type | Notes |
|---|---|---|
| `ProcessPosixEffectiveUser` | object | `{Sid, Name, DomainName, LogonId, AadUserUpn, PosixUserId, PrimaryPosixGroup:{Name, PosixGroupId}}` |
| `ProcessPosixEffectiveGroup` | object | `{Name, PosixGroupId}` |
| `ProcessPosixRealUser` | object | Same structure as EffectiveUser |
| `ProcessPosixProcessGroupId` | long | POSIX process group ID |
| `ProcessPosixSessionId` | long | POSIX session ID |
| `ProcessPosixFilePermissions` | array | e.g. `["None"]` |
| `ProcessCurrentWorkingDirectory` | string | Working directory of created process |
| `InitiatingProcessPosixEffectiveUser` | object | Same structure as ProcessPosixEffectiveUser |
| `InitiatingProcessPosixEffectiveGroup` | object | `{Name, PosixGroupId}` |
| `InitiatingProcessPosixRealUser` | object | Same structure |
| `InitiatingProcessPosixProcessGroupId` | long | |
| `InitiatingProcessPosixSessionId` | long | |
| `InitiatingProcessPosixFilePermissions` | array | |
| `InitiatingProcessCurrentWorkingDirectory` | string | Working directory of initiating process |

POSIX fields are only present on macOS/Linux events. The `AccountName`, `AccountSid`, `AccountUpn` top-level columns are also populated for macOS/Linux from the Entra ID identity of the logged-in user.

### Accessing POSIX fields

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where isnotempty(AdditionalFields) and AdditionalFields != "[]"
| extend af = parse_json(AdditionalFields)
| where isnotnull(af.ProcessPosixEffectiveUser)  // macOS/Linux only
| extend PosixUser = tostring(af.ProcessPosixEffectiveUser.Name)
| extend PosixUserId = toint(af.ProcessPosixEffectiveUser.PosixUserId)
| extend Cwd = tostring(af.ProcessCurrentWorkingDirectory)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, PosixUser, PosixUserId, Cwd
```

## ProcessUniqueId for process tree linking

`ProcessUniqueId` and `InitiatingProcessUniqueId` are Windows Process Start Keys — long integer strings that survive PID reuse. Use these to join parent-child relationships reliably:

```kql
// Build a 2-level process chain: grandparent → parent → child
let Procs = DeviceProcessEvents
| where Timestamp > ago(1d) and DeviceName == "DEVICE-001"
| project ProcessUniqueId, InitiatingProcessUniqueId, ProcessId,
    FileName, ProcessCommandLine, ProcessCreationTime;
Procs
| join kind=leftouter (
    Procs | project ParentUniqueId=ProcessUniqueId, ParentFile=FileName,
        GrandParentUniqueId=InitiatingProcessUniqueId
) on $left.InitiatingProcessUniqueId == $right.ParentUniqueId
| join kind=leftouter (
    Procs | project GpUniqueId=ProcessUniqueId, GpFile=FileName
) on $left.GrandParentUniqueId == $right.GpUniqueId
| project ProcessCreationTime, GpFile, ParentFile, FileName, ProcessCommandLine
```

## ReportId — not unique; composite key required

`ReportId` is a per-device counter that resets. Do NOT join on `ReportId` alone.

```kql
// RIGHT — three-column composite
DeviceProcessEvents
| join kind=inner AlertEvidence
    on ReportId, DeviceName, Timestamp
```

## Remote session context (RDP/VDI)

Four columns identify whether a process ran under a remote session:

| Column | Notes |
|---|---|
| `IsInitiatingProcessRemoteSession` | bool; true if parent ran via RDP |
| `InitiatingProcessRemoteSessionDeviceName` | Source device of the RDP client |
| `InitiatingProcessRemoteSessionIP` | Source IP of the RDP client |
| `IsProcessRemoteSession` | bool; true if created process itself is in an RDP session |
| `ProcessRemoteSessionDeviceName` | Source device for the created process's session |
| `ProcessRemoteSessionIP` | Source IP for the created process's session |
| `InitiatingProcessSessionId` | Windows session ID of parent (0 = session 0/SYSTEM) |
| `CreatedProcessSessionId` | Windows session ID of created process |

## Cross-platform notes

- `ProcessIntegrityLevel`, `ProcessTokenElevation`, `InitiatingProcessSignerType`, `InitiatingProcessSignatureStatus`, `AppGuardContainerId`, `DesktopName` in `AdditionalFields` — Windows only.
- POSIX fields in `AdditionalFields` — macOS/Linux only.
- `FolderPath` uses backslashes on Windows, forward slashes on macOS/Linux.
- `FileName` on macOS/Linux has no `.exe` suffix — do not filter with `.exe` for cross-platform queries.
- `SHA256` is often blank per docs — prefer `SHA1` for hash-based lookups.

## IdentityInfo enrichment

`AccountObjectId` is the Entra ID object ID — join to `IdentityInfo` on `AccountObjectId` for department, job title, etc.

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| join kind=leftouter (
    IdentityInfo | summarize arg_max(Timestamp, *) by AccountObjectId
) on AccountObjectId
| project Timestamp, DeviceName, AccountUpn, Department, JobTitle, FileName, ProcessCommandLine
```

## Common hunting patterns

### Unsigned processes launched by signed parents
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessSignatureStatus == "Valid"
    and ProcessIntegrityLevel in ("High", "System")
| join kind=inner (
    DeviceFileCertificateInfo
    | where IsTrusted == false or SignatureType == "None"
    | project SHA1, IsTrusted, SignerType
) on SHA1
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Elevated token processes (UAC bypass candidates)
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessTokenElevation == "TokenElevationTypeFull"
    and InitiatingProcessTokenElevation != "TokenElevationTypeFull"
| project Timestamp, DeviceName, AccountUpn, InitiatingProcessFileName,
    FileName, ProcessCommandLine, ProcessIntegrityLevel
| sort by Timestamp desc
```

### macOS/Linux: processes running as root
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where isnotempty(AdditionalFields) and AdditionalFields != "[]"
| extend af = parse_json(AdditionalFields)
| where toint(af.ProcessPosixEffectiveUser.PosixUserId) == 0
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    InitiatingFile=InitiatingProcessFileName,
    InitiatingCmd=InitiatingProcessCommandLine
```
