# EmailAttachmentInfo

**Source**: Microsoft Defender for Office 365 (MDO)  
**Time column**: `Timestamp` (also has `TimeGenerated` — same value, Sentinel artifact)  
**ReportId**: `string` — composite format `<NetworkMessageId>-<counter>-<SHA256>-<N>`, not a bare GUID. Globally unique per attachment event.  
**Prerequisite**: Defender for Office 365 deployed. Without it, table is empty.

## What it covers

One row per attachment per email delivery event. Multiple attachments on the same message = multiple rows with the same `NetworkMessageId`. Join to `EmailEvents` on `NetworkMessageId` for delivery context.

## Schema highlights

| Column | Type | Notes |
|---|---|---|
| `NetworkMessageId` | string | M365 GUID per message. Primary join key to all Email* tables. |
| `SenderFromAddress` | string | FROM header sender — visible to recipient. |
| `SenderDisplayName` | string | Display name of sender. |
| `SenderObjectId` | string | Entra object ID — only populated for internal senders. |
| `RecipientEmailAddress` | string | Final recipient after DL expansion. |
| `RecipientObjectId` | string | Entra object ID of recipient. |
| `FileName` | string | Attachment file name including extension. |
| `FileType` | string | Extension without dot (e.g. `pdf`, `docx`). |
| `FileExtension` | string | Extension with dot (e.g. `.pdf`). Redundant with `FileType`. |
| `SHA256` | string | SHA-256 hash. Almost always populated despite docs claiming "usually not populated". **No SHA1 column exists** — docs mention SHA1 but it is absent from live schema. |
| `FileSize` | long | Size in bytes. |
| `ThreatTypes` | string | Comma-separated: `Malware`, `Phish`. Use `has`, not `==`. Empty = clean. |
| `ThreatNames` | string | Detection name (e.g. malware family). |
| `DetectionMethods` | string | **String-encoded JSON** — e.g. `{"Malware":["ATP Safe Attachments"]}`. Access via `parse_json(DetectionMethods)`. |
| `ReportId` | string | Composite format — see header. |

No `AdditionalFields` column. No dynamic-typed columns.

## Key patterns

### SHA256 pivot to endpoint
```kql
let MaliciousHashes =
    EmailAttachmentInfo
    | where Timestamp > ago(7d)
    | where isnotempty(ThreatTypes)
    | distinct SHA256;
DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA256 in (MaliciousHashes)
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
```

### Malicious attachment investigation
```kql
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where isnotempty(ThreatTypes)
| extend methods = parse_json(DetectionMethods)
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    FileName, FileType, SHA256, ThreatTypes, ThreatNames,
    PhishMethods=tostring(methods.Phish), MalwareMethods=tostring(methods.Malware)
| sort by Timestamp desc
```

### Join to EmailEvents for delivery context
```kql
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Malware"
| join kind=inner EmailAttachmentInfo on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, FileName, FileType, SHA256, ThreatNames
```

## Cross-table joins

| Table | Join key | Purpose |
|---|---|---|
| `EmailEvents` | `NetworkMessageId` | Delivery action, subject, auth — always join for full context |
| `EmailUrlInfo` | `NetworkMessageId` | URLs in same message |
| `EmailPostDeliveryEvents` | `NetworkMessageId` | ZAP / post-delivery remediation |
| `DeviceFileEvents` | `SHA256` | Endpoint exposure to the same file |
| `IdentityInfo` | `RecipientObjectId` → `AccountObjectId` | Recipient metadata |

## Gotchas

- **SHA256 is almost always populated** — docs claiming it's "usually not populated" are inaccurate. Use `SHA256`; SHA1 column does not exist.
- **One row per attachment**: 3 attachments = 3 rows with same `NetworkMessageId`. Use `dcount(NetworkMessageId)` to count messages.
- **`ThreatTypes`** is comma-separated — use `has` not `==`.
- **`DetectionMethods`** is string-encoded JSON — always `parse_json()`.
- **`ReportId`** is a composite string, not a bare GUID.
