# DeviceFileEvents

MDE-sourced table. Records file creation, deletion, modification, and rename events on enrolled endpoints (Windows, macOS, Linux).

**Source**: Defender only (`run_hunting_query`). Also available in Sentinel via workspace onboarding.
**Time column**: `Timestamp` (Defender), `TimeGenerated` (Sentinel — both columns present in schema).

## ActionType values (confirmed live, 2026-04)

| ActionType | Notes |
|---|---|
| `FileCreated` | Highest volume by far |
| `FileDeleted` | |
| `FileRenamed` | `PreviousFileName` / `PreviousFolderPath` populated |
| `FileModified` | |

`FileOriginUrl`, `FileOriginReferrerUrl`, `FileOriginIP` are only populated on `FileCreated` events where the file was downloaded (browser / network origin tracking).

## ReportId — composite key required

`ReportId` is `long` (local counter, not globally unique). Safe join key: `ReportId + DeviceName + Timestamp`. See kql-facts.md.

## ProcessUniqueId — docs/schema mismatch

Official docs list `ProcessUniqueId` as a column. It is **absent from the live schema** as of 2026-04 — querying it throws a semantic error. `InitiatingProcessUniqueId` IS present and populated. Use `InitiatingProcessUniqueId` for process-chain linking.

## AdditionalFields

**Type divergence**: `string` in Defender, `dynamic` in Sentinel. Use `parse_json(AdditionalFields)` in both — Defender auto-parses the JSON string; no `tostring()` wrapper needed.

### Windows events

For Windows events `AdditionalFields` only contains `FileType`:

```json
{"FileType":"PortableExecutable"}
```

**Known `FileType` values** (confirmed live): `PortableExecutable`, `Image`, `Shebang`, `Zip`, `PDF`, `Gzip`, `Compound`, `MachODylib`, `MachOBundle`, `MachOExecutable`, `SevenZip`, `Tar`, `Rtf`, `CompiledAppleScript`, `Unknown`, `Error`.

```kql
// Filter by file type — pre-filter on string before parse_json for efficiency
DeviceFileEvents
| where Timestamp > ago(7d)
| where AdditionalFields has "PortableExecutable"
| extend af = parse_json(AdditionalFields)
| where tostring(af.FileType) == "PortableExecutable"
```

### macOS/Linux events

For macOS/Linux, `AdditionalFields` is much richer — includes POSIX identity context for the initiating process AND file permissions:

```json
{
  "InitiatingProcessPosixEffectiveUser": {
    "Sid": "S-1-5-18", "Name": "root", "DomainName": "DEVICE-001",
    "LogonId": 0, "PosixUserId": 0,
    "PrimaryPosixGroup": {"Name": "wheel", "PosixGroupId": 0}
  },
  "InitiatingProcessPosixEffectiveGroup": {"Name": "wheel", "PosixGroupId": 0},
  "InitiatingProcessPosixRealUser": { ... },
  "InitiatingProcessPosixProcessGroupId": 51569,
  "InitiatingProcessPosixSessionId": 26540,
  "InitiatingProcessCurrentWorkingDirectory": "/",
  "InitiatingProcessPosixFilePermissions": ["None"],
  "FilePosixPermissions": ["None"],
  "FileType": "Shebang"
}
```

Key difference from `DeviceProcessEvents`: `FilePosixPermissions` is present here (file-level permissions), in addition to the initiating process POSIX fields.

```kql
// Detect root-initiated file creation on macOS/Linux
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where AdditionalFields has "PosixUserId"  // cheap pre-filter
| extend af = parse_json(AdditionalFields)
| where toint(af.InitiatingProcessPosixEffectiveUser.PosixUserId) == 0
```

## RequestProtocol values (confirmed live, 2026-04)

`Local` and `Unknown` are the only observed values in this tenant. Docs state possible values: `Unknown`, `Local`, `SMB`, `NFS`. `RequestSourceIP`, `RequestAccountName`, `RequestAccountDomain`, `ShareName` only populated for remote (SMB/NFS) file access.

## File hashes

SHA1 is the most reliably populated hash. SHA256 is often empty per official docs — prefer SHA1 for lookups. MD5 also available. Hashes may be absent if file is locked, in remote storage, compressed, or virtual.

```kql
// Hash lookup — prefer SHA1
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
```

## File origin tracking (download provenance)

`FileOriginUrl`, `FileOriginReferrerUrl`, `FileOriginIP` only populated when MDE tracks a download origin. Only on `FileCreated`. Not all file creations have origin data — always filter with `isnotempty()`.

```kql
// Downloaded executables from web
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where isnotempty(FileOriginUrl)
| extend af = parse_json(AdditionalFields)
| where tostring(af.FileType) == "PortableExecutable"
| project Timestamp, DeviceName, FileName, FolderPath, FileOriginUrl, FileOriginReferrerUrl, InitiatingProcessFileName
| sort by Timestamp desc
```

## Sensitivity labels

`SensitivityLabel` and `SensitivitySubLabel` populated when MIP/Purview labels are applied to files. `IsAzureInfoProtectionApplied` (bool) indicates AIP encryption. Only populated when labeling is configured in the tenant.

## Remote session context

`IsInitiatingProcessRemoteSession` (bool), `InitiatingProcessRemoteSessionDeviceName`, `InitiatingProcessRemoteSessionIP` — populated when the initiating process runs in an RDP session. Useful for detecting lateral movement via RDP file staging.

## Cross-table joins

- Join to `DeviceProcessEvents` via `InitiatingProcessUniqueId` to get full process tree context
- Join to `AlertEvidence` via `ReportId + DeviceName + Timestamp` (not `ReportId` alone)
- Join to `DeviceFileCertificateInfo` via `SHA1` to get signer/certificate details for files
- `InitiatingProcessAccountObjectId` → join to `IdentityInfo` on `AccountObjectId` for user enrichment

## Common hunting patterns

```kql
// Suspicious file creation in startup/persistence locations
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FolderPath has_any (
    @"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    @"\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    @"C:\Windows\System32\",
    @"C:\Windows\SysWOW64\"
  )
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp desc

// Files renamed (potential ransomware pattern — extension change)
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileRenamed"
| extend OldExt = tostring(split(PreviousFileName, ".")[-1])
| extend NewExt = tostring(split(FileName, ".")[-1])
| where OldExt != NewExt
| summarize Count=count(), Devices=dcount(DeviceName) by NewExt, InitiatingProcessFileName
| sort by Count desc

// Executable drops by scripting engines
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where AdditionalFields has "PortableExecutable"
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "python.exe", "python3", "bash", "sh", "zsh")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| sort by Timestamp desc
```
