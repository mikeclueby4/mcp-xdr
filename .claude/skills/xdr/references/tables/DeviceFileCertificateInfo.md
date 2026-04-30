# DeviceFileCertificateInfo

MDE-sourced table. Certificate metadata for files observed on enrolled endpoints — one row per unique (DeviceId, SHA1) combination seen in a scan/verification cycle.

**Source**: Defender XDR + Sentinel. Use `Timestamp` (Defender) or `TimeGenerated` (Sentinel).

## Purpose

Lookup table for signature/certificate attributes keyed on `SHA1`. Not a primary event stream — rows represent certificate verification results, not file events. Join from `DeviceFileEvents` or `DeviceImageLoadEvents` via `SHA1`.

## Schema notes

- **No `AdditionalFields` column**. No dynamic columns. All columns are `string`, `bool`, `datetime`, or `long`. No `parse_json()` needed anywhere.
- Schema is identical between Defender and Sentinel sources.
- `ReportId` — `long`, local counter, not globally unique. Composite join key: `ReportId + DeviceName + Timestamp` (see kql-facts.md). Rarely needed — `SHA1` is the natural join key for this table.
- `ProcessUniqueId` — absent from live schema (same as all Device* tables). Do not reference.
- `CrlDistributionPointUrls` — typed `string` in both Defender and Sentinel. Content is a JSON-encoded array string: `["http://crl.example.com/..."]`. Use `parse_json()` if you need to extract individual URLs.

## Key boolean columns

| Column | Meaning |
|---|---|
| `IsSigned` | File has a signature (embedded or catalog) |
| `IsTrusted` | WinVerifyTrust passed (valid chain, not revoked, known root) |
| `IsRootSignerMicrosoft` | Root CA is Microsoft AND file is included in Windows |

`IsTrusted == false` with `IsSigned == true` = signature present but broken/untrusted — high-value hunting signal.

## SignatureType values (confirmed live, 2026-04)

| Value | Meaning |
|---|---|
| `Embedded` | Authenticode signature inside the file (PE/MSI/script) |
| `Catalog` | Signature in an external Windows catalog file |

No other values observed. `Embedded` is higher volume than `Catalog` in practice.

## Cross-table joins

- `DeviceFileEvents` via `SHA1` — certificate details for files written/modified on disk
- `DeviceImageLoadEvents` via `SHA1` — certificate details for loaded DLLs (primary use case)
- Both source tables produce one `SHA1` per event; this table may have multiple rows per `SHA1` across devices — use `summarize arg_max(Timestamp, *) by SHA1` if you want one cert record per hash

## Hunting patterns

### Unsigned/untrusted DLL loads (sideloading / hijacking)
```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| join kind=inner (
    DeviceFileCertificateInfo
    | where Timestamp > ago(7d)
    | where IsTrusted == false or IsSigned == false
    | project SHA1, Signer, IsTrusted, IsSigned, IsRootSignerMicrosoft
) on SHA1
| project Timestamp, DeviceName, FileName, FolderPath,
    Signer, IsTrusted, IsSigned,
    InitiatingProcessFileName, InitiatingProcessFolderPath
| sort by Timestamp desc
```

### Non-Microsoft signed files loaded from System32 (potential hijack)
```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FolderPath has @"C:\Windows\System32\"
| join kind=inner (
    DeviceFileCertificateInfo
    | where Timestamp > ago(7d)
    | where IsRootSignerMicrosoft == false
    | project SHA1, Signer, IsTrusted, IsRootSignerMicrosoft
) on SHA1
| project Timestamp, DeviceName, FileName, Signer, IsTrusted,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### Untrusted files created on endpoints (check downloads/drops)
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| join kind=inner (
    DeviceFileCertificateInfo
    | where Timestamp > ago(7d)
    | where IsTrusted == false
    | project SHA1, Signer, IsSigned, CertificateExpirationTime
) on SHA1
| project Timestamp, DeviceName, FileName, FolderPath, SHA1,
    Signer, IsSigned, CertificateExpirationTime,
    InitiatingProcessFileName, FileOriginUrl
| sort by Timestamp desc
```

### Certificate expiry hunting (identify expired-cert files in use)
```kql
DeviceFileCertificateInfo
| where Timestamp > ago(7d)
| where CertificateExpirationTime < now()
| where IsTrusted == true  // was trusted but now expired
| summarize Devices=dcount(DeviceName), Files=dcount(SHA1) by Signer, Issuer, CertificateExpirationTime
| sort by CertificateExpirationTime asc
```
