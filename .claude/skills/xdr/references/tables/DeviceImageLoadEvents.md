# DeviceImageLoadEvents

MDE-sourced table. Records DLL/image load events on enrolled endpoints (Windows).

**Source**: Defender XDR + Sentinel (same data). Use `Timestamp` (Defender) or `TimeGenerated` (Sentinel).

## ActionType

Single value: `ImageLoaded`. No filtering by ActionType needed.

## Schema notes

- **No `AdditionalFields` column** — no dynamic column parsing needed.
- `ProcessUniqueId` — **absent from live schema** despite appearing in official docs (confirmed 2026-04). Same pattern as all other Device* tables. Do not use.
- `InitiatingProcessUniqueId` — present, well-populated (string, Windows Process Start Key). Use for process-chain linking across Device* tables.
- `ReportId` — `long`, local counter. Not globally unique. Join on `ReportId + DeviceName + Timestamp` (see kql-facts.md).
- `SHA256` / `InitiatingProcessSHA256` — often blank per official docs; prefer SHA1 for lookups.
- `AppGuardContainerId` — blank unless load occurred inside an Application Guard container.
- `IsInitiatingProcessRemoteSession` / `InitiatingProcessRemoteSessionDeviceName` / `InitiatingProcessRemoteSessionIP` — populated when initiating process ran in an RDP session.
- `InitiatingProcessSessionId` — Windows logon session ID; join to `DeviceLogonEvents` on `DeviceId + InitiatingProcessSessionId`.

## Defender vs Sentinel

Schema identical between sources. No `dynamic` columns — all are `string`, `long`, `datetime`, or `bool`. No `parse_json()` needed anywhere.

## File columns

`FileName` + `FolderPath` describe the loaded DLL. Hash columns (`SHA1`, `SHA256`, `MD5`) + `FileSize` describe the DLL on disk.

## Cross-table joins

- `DeviceFileCertificateInfo` via `SHA1` — get signer/publisher/certificate validity for the loaded DLL. Essential for unsigned-DLL hunting.
- `DeviceProcessEvents` via `DeviceId + InitiatingProcessUniqueId == ProcessUniqueId` — full process tree for the loader.
- `AlertEvidence` via `ReportId, DeviceName, Timestamp` (three-column composite).
- `InitiatingProcessAccountObjectId` → `IdentityInfo.AccountObjectId` for user enrichment.

## Hunting patterns

### DLL loaded from non-system/writable path (sideloading / hijacking)
```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where not(FolderPath has_any (
    @"C:\Windows\", @"C:\Program Files\", @"C:\Program Files (x86)\"
  ))
| project Timestamp, DeviceName, FileName, FolderPath, SHA1,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### Trusted binary loading unsigned/untrusted DLL (sideloading signal)
```kql
// Join to DeviceFileCertificateInfo to check signature
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| join kind=inner (
    DeviceFileCertificateInfo
    | where IsTrusted == false or isempty(Signer)
    | project SHA1, Signer, IsTrusted, IsRootSignerMicrosoft
) on SHA1
| project Timestamp, DeviceName, FileName, FolderPath, Signer, IsTrusted,
    InitiatingProcessFileName, InitiatingProcessFolderPath
| sort by Timestamp desc
```

### DLL loaded from user-writable AppData/Temp locations
```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (@"\AppData\", @"\Temp\", @"\Downloads\", @"\Users\Public\")
| summarize Count=count(), Devices=dcount(DeviceName) by FileName, FolderPath, InitiatingProcessFileName
| sort by Count asc  // low count = unusual = higher priority
```

### DLL shadow: same DLL name loaded from system path AND non-system path across fleet
```kql
// Identify DLL names that appear in both expected and unexpected locations
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| extend IsSystemPath = FolderPath has_any (@"C:\Windows\", @"C:\Program Files\")
| summarize
    SystemLoads = countif(IsSystemPath),
    NonSystemLoads = countif(not(IsSystemPath)),
    NonSystemPaths = make_set_if(FolderPath, not(IsSystemPath), 20)
  by FileName
| where NonSystemLoads > 0 and SystemLoads > 0
| sort by NonSystemLoads desc
```

### Process-chain: find all DLLs loaded by a suspicious process
```kql
let SuspiciousPIDs = DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName =~ "suspicious.exe"
    | project ProcessUniqueId, DeviceId;
SuspiciousPIDs
| join kind=inner (
    DeviceImageLoadEvents
    | where Timestamp > ago(1d)
    | project Timestamp, DeviceId, FileName, FolderPath, SHA1, InitiatingProcessUniqueId
) on DeviceId, $left.ProcessUniqueId == $right.InitiatingProcessUniqueId
| project Timestamp, FileName, FolderPath, SHA1
| sort by Timestamp asc
```
