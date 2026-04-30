# DeviceEvents

**Source**: Microsoft Defender for Endpoint (MDE). Not available if MDE is not deployed.  
**Time column**: `Timestamp` (Defender), also has `TimeGenerated` (Sentinel).  
**Volume**: Very high — commonly the largest Device* table. Always aggregate or filter before inspecting raw rows.

## Purpose

Catch-all table for miscellaneous device events not covered by the more specialized Device* tables. Covers security controls (Defender AV, Exploit Guard, ASR, AppControl, DPAPI, SmartScreen), process API calls, named pipes, WMI, scheduled tasks, firewall, USB, LDAP, DNS responses, credential-access telemetry, PowerShell/script content, driver/service loads, and more.

## Key gotchas

### ProcessUniqueId absent from live schema
Official docs list `ProcessUniqueId` as a column — it is **absent from the live schema** (confirmed 2026-04). Same pattern as all other Device* tables. `InitiatingProcessUniqueId` IS present.

### AdditionalFields: string in Defender, dynamic in Sentinel
`AdditionalFields` is `string`-typed in Defender (`gettype()` returns `"string"`) and `dynamic` in Sentinel. Use `parse_json(AdditionalFields)` in both — it parses the string in Defender and is a no-op on a native dynamic in Sentinel. Do NOT use `parse_json(tostring(AdditionalFields))` — wasteful in Sentinel.

The Defender parsed result has an `@odata.type` wrapper key but property access still works normally:
```kql
| extend af = parse_json(AdditionalFields)
| extend CallerPid = toint(af.CallerProcessID)
```

Pre-filter with `AdditionalFields has "keyword"` before `parse_json()` for high-volume ActionTypes — bloom filter is cheap.

### ReportId is a local counter, not globally unique
`ReportId` is `long`. For cross-table joins, always use the composite `ReportId + DeviceName + Timestamp`. See kql-facts.md.

### %%NNNN message codes in some AdditionalFields
Some ActionTypes (e.g. `UserAccountModified`) contain `%%NNNN` Windows message codes in string fields (e.g. `"DisplayName":"%%1793"` = value not changed). These are raw Windows message table references — not decoded at ingestion. Compare on the literal code string.

## ActionType taxonomy

85 confirmed ActionType values (live, 2026-04). Grouped by category:

### Credential / memory access
| ActionType | Key AdditionalFields |
|---|---|
| `DpapiAccessed` | `CallerProcessID`, `Flags`, `MasterKeyGUID`, `OperationType` (`SPCryptProtect`/`SPCryptUnprotect`), `ReturnValue` |
| `NtAllocateVirtualMemoryApiCall` | `BaseAddress`, `RegionSize`, `ProtectionMask` |
| `NtAllocateVirtualMemoryRemoteApiCall` | `IntegrityLevel` |
| `NtProtectVirtualMemoryApiCall` | (blank in practice) |
| `NtMapViewOfSectionRemoteApiCall` | — |
| `CreateRemoteThreadApiCall` | `IntegrityLevel` |
| `ReadProcessMemoryApiCall` | `TotalBytesCopied` |
| `WriteToLsassProcessMemory` | `TotalBytesCopied` |
| `OpenProcessApiCall` | `DesiredAccess` |
| `SetThreadContextRemoteApiCall` | — |
| `ProcessPrimaryTokenModified` | `TokenModificationProperties` (nested JSON string — use `parse_json(tostring(af.TokenModificationProperties))`), `OriginalTokenIntegrityLevel`, `CurrentTokenIntegrityLevel`, `SystemTokenPointer`, `OriginalTokenPrivEnabled`, `OriginalTokenPrivPresent` |
| `AsrLsassCredentialTheftBlocked` | `IsAudit`, `RuleId` |
| `AsrLsassCredentialTheftAudited` | `IsAudit`, `RuleId` |
| `GetClipboardData` | (blank) |
| `SensitiveFileRead` | (blank) |
| `ScreenshotTaken` | (blank) |
| `GetAsyncKeyStateApiCall` | — |

### Named pipes / WMI / network
| ActionType | Key AdditionalFields |
|---|---|
| `NamedPipeEvent` | `PipeName`, `FileOperation` (`File created`/`File opened`), `NamedPipeEnd` (`Client`/`Server`), `DesiredAccess`, `RemoteClientsAccess`, `SessionId`, `ThreadId` |
| `WmiBindEventFilterToConsumer` | `Consumer`, `Ess`, `Namespace`, `PossibleCause` (full WMI subscription strings) |
| `ProcessCreatedUsingWmiQuery` | `ClientMachine`, `IsRemoteMachine` |
| `LdapSearch` | `AttributeList` (array), `ScopeOfSearch`, `SearchFilter` |
| `DnsQueryResponse` | `DnsQueryString`, `DnsQueryResult` (array of JSON strings — each element is itself a JSON string; needs second `parse_json()`: `parse_json(tostring(af.DnsQueryResult[0]))`), `ClientProcessName`, `ClientProcessId` |

### Drivers / services / scheduled tasks
| ActionType | Key AdditionalFields |
|---|---|
| `DriverLoad` | `ImageBase`, `ImageMD5`, `ImageName` (device path), `ImageSHA1`, `ImageSHA256`, `UserSid` |
| `ServiceInstalled` | `ServiceName`, `ServiceType`, `ServiceStartType`, `ServiceAccount` |
| `ScheduledTaskCreated` | `TaskName`, `TaskContent` (JSON string — use `parse_json(tostring(af.TaskContent))`), `SubjectUserName` |
| `ScheduledTaskUpdated` | same as Created |
| `ScheduledTaskDeleted` | `TaskName`, `SubjectUserName` |

### PowerShell / scripts / AppControl
| ActionType | Key AdditionalFields |
|---|---|
| `PowerShellCommand` | `Command` |
| `ScriptContent` | `ScriptContent` (full script text — can be large; pre-filter with `AdditionalFields has "pattern"`) |
| `AppControlCodeIntegrityOriginAudited` | `AuditEnabled`, `DefenderTrust`, `ManagedInstallerEnabled`, `PassesManagedInstaller`, `PassesSmartlocker`, `PolicyID`, `PolicyName`, `SmartlockerEnabled`, `StatusCode` |
| `AppControlCodeIntegritySigningInformation` | `IssuerName`, `PublisherName`, `SignatureType`, `ValidatedSigningLevel`, `VerificationError`, `Hash`, `Signature`, `Flags` |
| `AppControlCIScriptAudited` | `Sha1CatalogHash`, `Sha256CatalogHash`, `UserWriteable`, `MarkOfTheWeb`, `IsOnRemovableMedia` |
| `AppControlCodeIntegrityPolicyAudited` | — |
| `AppControlExecutableAudited` | `Fqbn` (publisher fully-qualified binary name, or `"-"` if unsigned) |
| `AppControlPolicyApplied` | — |
| `ClrUnbackedModuleLoaded` | `ModuleILPathOrName`, `ModuleFlags`, `ModuleId`, `AssemblyId`, `ClrInstanceId` |

### Antivirus / Exploit Guard
| ActionType | Key AdditionalFields |
|---|---|
| `AntivirusDetection` | `ThreatName`, `WasExecutingWhileDetected`, `Action`, `WasRemediated`, `ResourceSchema`, `ReportSource`, `DetectionGuid`, `IsPassiveMode` |
| `AntivirusReport` | `WasExecutingWhileDetected` |
| `AntivirusScanCompleted` | — |
| `AntivirusScanCancelled` | — |
| `TamperingAttempt` | `TamperingAction` (e.g. `RegistryModification`), `Status` (`Ignored`/`Blocked`), `Target`, `OriginalValue`, `TamperingAttemptedValue` |
| `ExploitGuardChildProcessAudited` | `ChildCommandLine`, `IsAudit` |
| `ExploitGuardChildProcessBlocked` | `ChildCommandLine`, `IsAudit` |
| `ExploitGuardWin32SystemCallBlocked` | — |
| `ExploitGuardNetworkProtectionBlocked` | `IsAudit`, `ResponseCategory`, `DisplayName` |
| `ExploitGuardNetworkProtectionAudited` | same |
| `ExploitGuardAcgEnforced` | — |
| `ExploitGuardNonMicrosoftSignedBlocked` | — |
| `ExploitGuardLowIntegrityImageBlocked` | — |
| `ControlledFolderAccessViolationAudited` | `IsAudit`, `RuleId` |
| `ControlFlowGuardViolation` | — |
| `AsrUntrustedExecutableBlocked` | — |
| `AsrPsexecWmiChildProcessBlocked` | — |
| `AsrPsexecWmiChildProcessAudited` | — |
| `AsrOfficeCommAppChildProcessBlocked` | — |
| `AsrExecutableEmailContentBlocked` | — |
| `SafeDocFileScan` | — |

### Browser / SmartScreen
| ActionType | Key AdditionalFields |
|---|---|
| `BrowserLaunchedToOpenUrl` | `SafeLinksUrl` (full Defender SafeLinks redirect URL), `SafeLinksMessageId`, `SafeLinksRecipient` |
| `SmartScreenUrlWarning` | `Experience`, `ApplicationName` |
| `SmartScreenUserOverride` | `Allow`, `ResponseCategory`, `UserSid`, `ApplicationName` |

### USB / PnP
| ActionType | Key AdditionalFields |
|---|---|
| `PnpDeviceConnected` | `ClassName`, `ClassId`, `DeviceId`, `DeviceDescription`, `VendorIds` (array) |
| `PnpDeviceAllowed` | — |
| `UsbDriveMounted` | `DriveLetter`, `BusType`, `ProductName`, `ProductRevision`, `Manufacturer`, `Volume`, `LoggedOnUsers` (array of UPNs) |
| `UsbDriveUnmounted` | — |
| `UsbDriveDriveLetterChanged` | — |
| `BluetoothPolicyTriggered` | — |

### Firewall
| ActionType | Key AdditionalFields |
|---|---|
| `FirewallInboundConnectionBlocked` | (blank in practice — use `RemoteIP`/`RemotePort`/`LocalPort` top-level columns) |
| `FirewallOutboundConnectionBlocked` | (blank in practice) |
| `FirewallInboundConnectionToAppBlocked` | — |

### Account / group changes
| ActionType | Key AdditionalFields |
|---|---|
| `UserAccountCreated` | — |
| `UserAccountModified` | `SamAccountName`, `DisplayName`, `PasswordLastSet`, `OldUacValue`, `NewUacValue`, `UserAccountControl` — string fields may contain `%%NNNN` codes meaning "not changed" |
| `UserAccountPasswordResetAttempt` | — |
| `UserAccountAddedToLocalGroup` | `GroupName`, `GroupDomainName`, `GroupSid` |
| `UserAccountRemovedFromLocalGroup` | — |
| `SecurityGroupCreated` | — |
| `SecurityGroupDeleted` | — |
| `AuditPolicyModification` | `AuditPolicyChanges` (%%NNNN coded), `CategoryId`, `SubcategoryGuid`, `SubcategoryId` |

### Remote desktop
| ActionType | Key AdditionalFields |
|---|---|
| `RemoteDesktopConnection` | `Protocol` (e.g. `"TCP"`) |

### Certificate services
| ActionType | Key AdditionalFields |
|---|---|
| `CertificateServicesLoadedTemplate` | `TemplateInternalName`, `TemplateVersion`, `TemplateSchemaVersion`, `TemplateOID`, `TemplateDSObjectFQDN`, `DCDNSName`, `TemplateContent` (full template text), `SecurityDescriptor` |
| `CertificateServicesApprovedCertificateRequest` | — |
| `CertificateServicesReceivedCertificateRequest` | — |

### macOS-specific
| ActionType | Key AdditionalFields |
|---|---|
| `PlistPropertyModified` | `PlistProperty`, `Value`, `PreviousValue` |

### App Guard
| ActionType | Key AdditionalFields |
|---|---|
| `AppGuardCreateContainer` | — |
| `AppGuardResumeContainer` | — |

### Misc
| ActionType | Key AdditionalFields |
|---|---|
| `ShellLinkCreateFileEvent` | `FileSizeInBytes`, `VolumeGuidPath`, `IsOnRemovableMedia`, `ShellLinkRunAsAdmin`, `ShellLinkShowCommand` |
| `TvmAxonTelemetryEvent` | — |
| `OtherAlertRelatedActivity` | — |

## Column population by ActionType

Most columns are sparsely populated — which columns are populated depends on ActionType:

- **File columns** (`FileName`, `FolderPath`, `SHA1`, `SHA256`, `MD5`, `FileSize`, `FileOriginUrl`, `FileOriginIP`): populated for file-related ActionTypes (e.g. `SensitiveFileRead`, `DriverLoad`)
- **Account columns** (`AccountDomain`, `AccountName`, `AccountSid`): populated for user-context events
- **Process columns** (`ProcessId`, `ProcessCommandLine`, `ProcessCreationTime`, `ProcessTokenElevation`, `LogonId`): populated when the event is about a created/affected process (not the initiating process — that's in `InitiatingProcess*`)
- **Registry columns** (`RegistryKey`, `RegistryValueName`, `RegistryValueData`): populated for registry-related ActionTypes
- **Network columns** (`RemoteIP`, `RemotePort`, `LocalIP`, `LocalPort`, `RemoteUrl`, `RemoteDeviceName`): populated for network/firewall ActionTypes
- `CreatedProcessSessionId`/`IsProcessRemoteSession`/`ProcessRemoteSessionDeviceName`/`ProcessRemoteSessionIP`: populated when `ProcessId` is populated

## AdditionalFields: nested JSON strings in some keys

Some ActionType fields embed a *second* JSON object as a string within `AdditionalFields`:

- `ScheduledTaskCreated`/`ScheduledTaskUpdated`.`TaskContent` — JSON string, needs second `parse_json(tostring(...))`
- `ProcessPrimaryTokenModified`.`TokenModificationProperties` — JSON string
- `DnsQueryResponse`.`DnsQueryResult` — array of JSON strings; each element is a JSON string

Pattern:
```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| where Timestamp > ago(7d)
| extend af = parse_json(AdditionalFields)
| extend tc = parse_json(tostring(af.TaskContent))
| extend Cmd = tostring(tc.Actions.Exec.Command)
```

```kql
// DnsQueryResponse — parse the array elements
DeviceEvents
| where ActionType == "DnsQueryResponse"
| where Timestamp > ago(7d)
| extend af = parse_json(AdditionalFields)
| mv-expand Answer = af.DnsQueryResult
| extend r = parse_json(tostring(Answer))
| extend DnsQueryType = tostring(r.DnsQueryType), Result = tostring(r.Result)
```

## Common hunting patterns

### Credential theft / LSASS
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("WriteToLsassProcessMemory", "ReadProcessMemoryApiCall", "AsrLsassCredentialTheftBlocked", "OpenProcessApiCall")
| extend af = parse_json(AdditionalFields)
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, af
```

### Suspicious named pipe (lateral movement / injection)
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "NamedPipeEvent"
| extend af = parse_json(AdditionalFields)
| where tostring(af.NamedPipeEnd) == "Server" 
    and not(InitiatingProcessFileName in~ ("svchost.exe", "services.exe", "lsass.exe"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, af
```

### Scheduled task persistence
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated")
| extend af = parse_json(AdditionalFields)
| extend TaskName = tostring(af.TaskName)
| where not(TaskName startswith "\\Microsoft\\")
| extend tc = parse_json(tostring(af.TaskContent))
| extend Cmd = tostring(tc.Actions.Exec.Command)
| project Timestamp, DeviceName, TaskName, Cmd, InitiatingProcessCommandLine
```

### WMI event subscription
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "WmiBindEventFilterToConsumer"
| extend af = parse_json(AdditionalFields)
| project Timestamp, DeviceName, Consumer=tostring(af.Consumer), Ess=tostring(af.Ess), Namespace=tostring(af.Namespace)
```

### PowerShell command logging
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "PowerShellCommand"
| extend af = parse_json(AdditionalFields)
| extend Cmd = tostring(af.Command)
| where Cmd has_any ("Invoke-Expression", "IEX", "DownloadString", "WebClient", "EncodedCommand", "bypass")
| project Timestamp, DeviceName, AccountName, Cmd, InitiatingProcessCommandLine
```

### USB drive mount with user
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "UsbDriveMounted"
| extend af = parse_json(AdditionalFields)
| project Timestamp, DeviceName, Drive=tostring(af.DriveLetter), Product=tostring(af.ProductName), Users=af.LoggedOnUsers
```

### Antivirus detections (not just reports)
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AntivirusDetection"
| extend af = parse_json(AdditionalFields)
| project Timestamp, DeviceName, ThreatName=tostring(af.ThreatName), WasRemediated=tobool(af.WasRemediated), FileName, FolderPath, InitiatingProcessFileName
```

## Cross-table joins

- **`DeviceFileCertificateInfo`** on `SHA1` — verify trust of `DriverLoad` / `ServiceInstalled` file hashes
- **`DeviceProcessEvents`** on `DeviceId + InitiatingProcessId + InitiatingProcessCreationTime` — get full process context for the initiating process
- **`DeviceLogonEvents`** on `DeviceId + LogonId` — correlate events to user sessions
- **`AlertEvidence`** on `ReportId, DeviceName, Timestamp` — link events to alerts (composite key required)
- **`IdentityInfo`** on `InitiatingProcessAccountObjectId` — enrich with user attributes
