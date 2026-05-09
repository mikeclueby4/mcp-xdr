# DeviceTvmInfoGathering

**Source**: Defender-only (MDE/Defender Vulnerability Management). Not present in Sentinel.
**Docs**: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvminfogathering-table

TVM assessment events: per-device configuration state, attack surface posture, AV health, ASR rules, TLS/SSL/crypto settings, zero-day mitigations.

## Schema

| Column | Type | Notes |
|---|---|---|
| `Timestamp` | datetime | Record generation time (assessment cycle) |
| `LastSeenTime` | datetime | Last time the device was seen by the service |
| `DeviceId` | string | |
| `DeviceName` | string | |
| `OSPlatform` | string | e.g. `Windows11`, `Windows10` |
| `AdditionalFields` | dynamic | Bag of all gathered fields — see below |
| `MachineGroup` | string | |

## AdditionalFields — encoding

`gettype(AdditionalFields)` = `"dictionary"` — **native dynamic**. Direct property access works without `parse_json()`:

```kql
| where AdditionalFields.TlsClient10 == "Enabled"
| where AdditionalFields.AvMode == "0"
```

The `@odata.type` wrapper key is present in Defender rows but does not block property access.

### Exception: AvScanResults is a nested JSON string

`AdditionalFields.AvScanResults` is `gettype()` = `"string"` — a JSON string within the bag. Access inner fields with a second parse:

```kql
| extend scanParsed = parse_json(tostring(AdditionalFields.AvScanResults))
| extend quickStatus = tostring(scanParsed.Quick.ScanStatus)
// Structure: {"Quick":{"ScanStatus":"Completed","ErrorCode":null,"Timestamp":"..."},"Full":null,"Custom":null}
```

## Snapshot semantics

One row per device per assessment cycle. Does **not** behave like an event log — rows represent current state at `Timestamp`. No deduplication needed for point-in-time queries; for current state across devices use the most recent `Timestamp`.

No `ReportId` column. Join to other tables on `DeviceId`.

## Key AdditionalFields keys (confirmed via DeviceTvmInfoGatheringKB, 2026-04)

### Defender Antivirus (igid-100+)
| Field | Values | Notes |
|---|---|---|
| `AvMode` | `"0"` Active, `"1"` Passive, `"4"` EDR Blocked | String type despite numeric appearance |
| `AvSignatureVersion` | e.g. `"1.351.679.0"` | |
| `AvEngineVersion` | e.g. `"1.1.18700.3"` | |
| `AvPlatformVersion` | e.g. `"4.18.2109.6"` | |
| `AvScanResults` | Nested JSON string (see above) | |
| `CloudProtectionState` | e.g. `"2"` | |
| `AvModeDataRefreshTime` | datetime string | |
| `AvIsSignatureUptoDate` | `"True"`/`"False"` | |
| `AvIsEngineUptodate` | `"True"`/`"False"` | |
| `AvIsPlatformUptodate` | `"True"`/`"False"` | |
| `AvSignatureUpdateTime` | datetime string | When the signature was last updated on the device |
| `AvEngineUpdateTime` | datetime string | When the engine was last updated |
| `AvPlatformUpdateTime` | datetime string | When the platform was last updated |
| `AvSignatureRing` | e.g. `"2"` | Ring for gradual AV rollout |
| `AvPlatformRing` | e.g. `"2"` | |
| `AvEngineRing` | e.g. `"1"` | |

Cross-platform equivalents prefixed `XplatAv*` and `Wdav*` cover macOS/Linux AV state.

### TLS/SSL protocol settings (igid-1 through igid-10)
Each key: `"Enabled"`, `"Disabled"`, or `"DisabledByDefault"`. `null` = not configured.

| Field | Notes |
|---|---|
| `TlsClient10`, `TlsClient11`, `TlsClient12` | Windows TLS client settings |
| `TlsServer10`, `TlsServer11`, `TlsServer12` | Windows TLS server settings |
| `SslClient20`, `SslClient30`, `SslServer20`, `SslServer30` | SSL settings (legacy) |

### Crypto / .NET (igid-11 through igid-18)
Values `"0"` or `"1"`. Registry-backed .NET strong crypto flags:
`SchUseStrongCrypto35`, `SchUseStrongCrypto35Wow6432`, `SchUseStrongCrypto40`, `SchUseStrongCrypto40Wow6432`, `SystemDefaultTlsVersions35`, `SystemDefaultTlsVersions40`, etc.

### ASR rule states (igid-121 through igid-167 range)
Values: `"Off"`, `"Block"`, `"Warn"`, `"Unknown"`. One field per rule, e.g.:
`AsrExecutableEmailContent`, `AsrOfficeChildProcess`, `AsrLsassCredentialTheft`, `AsrRansomware`, `AsrUntrustedExecutable`, `AsrPsexecWmiChildProcess`, `AsrUntrustedUsbProcess`, `AsrVulnerableSignedDriver`, `AsrBlockWebshellCreation`, `AsrBlockCopiedOrImpersonatedSystemTools`, `AsrBlockSafeModeReboot`.

### Vulnerability mitigation flags
| Field | Values | CVE |
|---|---|---|
| `Log4j_CVE_2021_44228` | `"true"`/`"false"`/`null` | null = not vulnerable |
| `Log4JEnvironmentVariableMitigation` | `"True"`, `"RebootRequired"`, `"False"` | |
| `Log4jLocalScanVulnerable` | `"true"`/`"false"`/`null` | |
| `LocalCveScannerExecuted` | CVE ID string | e.g. `"CVE-2021-44228"` |
| `Spring4Shell_CVE_2022_22965` | `"true"`/`"false"`/`null` | |
| `CVE_2022_30190_Mitigated` | e.g. `"true"` | |
| `CVE_2022_41040_Mitigated` | `"Mitigated"`, `"NotMitigated"`, `"NotApplicable"` | |

### Other
| Field | Values |
|---|---|
| `IsWindowsLtscVersionRunning` | `"True"`/`"False"` |
| `EBPFStatus` | `"True"`/`"False"` |
| `Bootiful_Mind_status` | `"Found"`, `"NotFound"`, `"Unknown"` |

## Companion KB table

`DeviceTvmInfoGatheringKB` is the metadata catalog for this table — maps `FieldName` → description + categories + data structure. Use it to discover available fields before writing `AdditionalFields`-based queries.

```kql
// Discover all TLS-related fields
DeviceTvmInfoGatheringKB
| where Categories contains "tls"
| project FieldName, Description, DataStructure
```

## Example queries

```kql
// Devices with legacy TLS 1.0/1.1 enabled (server or client)
DeviceTvmInfoGathering
| where AdditionalFields.TlsClient10 == "Enabled"
    or AdditionalFields.TlsServer10 == "Enabled"
    or AdditionalFields.TlsClient11 == "Enabled"
    or AdditionalFields.TlsServer11 == "Enabled"
| project Timestamp, DeviceName, OSPlatform,
    TlsC10 = tostring(AdditionalFields.TlsClient10),
    TlsS10 = tostring(AdditionalFields.TlsServer10),
    TlsC11 = tostring(AdditionalFields.TlsClient11),
    TlsS11 = tostring(AdditionalFields.TlsServer11)

// Devices with AV not in active mode
DeviceTvmInfoGathering
| where AdditionalFields.AvMode != "0"
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceName, OSPlatform, AvMode=tostring(AdditionalFields.AvMode)

// Log4Shell: devices with mitigation pending reboot or not applied
// (join with DeviceTvmSoftwareVulnerabilities for confirmed vulnerable)
DeviceTvmInfoGathering
| where AdditionalFields.Log4JEnvironmentVariableMitigation in ("RebootRequired", "False")
| join kind=inner (
    DeviceTvmSoftwareVulnerabilities
    | where CveId == "CVE-2021-44228"
) on DeviceId
| summarize any(DeviceName), any(AdditionalFields.Log4JEnvironmentVariableMitigation) by DeviceId

// AV signature ring distribution
DeviceTvmInfoGathering
| summarize Devices=dcount(DeviceId) by SigRing=tostring(AdditionalFields.AvSignatureRing)
| sort by Devices desc
```

## Join targets

- `DeviceTvmSoftwareVulnerabilities` on `DeviceId` — correlate config state with CVE exposure
- `DeviceInfo` on `DeviceId` — enrich with machine group, OS version, join type
- `DeviceTvmSecureConfigurationAssessment` on `DeviceId` — cross-reference security baselines

No `ReportId` in this table.
