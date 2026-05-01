# MessageEvents + MessageUrlInfo

Teams message security tables. Both are **Defender-only** (Sentinel returns 400). Requires Microsoft Defender for Office 365 deployment.

## Relationship

`MessageEvents` — one row per Teams message at delivery time, with security verdict and recipient details.
`MessageUrlInfo` — one row per URL extracted from a Teams message.

**Join key**: `TeamsMessageId` (links both tables). Note that `ReportId` is per-row unique but differs between the two tables — do NOT join on `ReportId` across these tables.

```kql
MessageEvents
| where Timestamp > ago(7d)
| join kind=inner (
    MessageUrlInfo
    | where Timestamp > ago(7d)
) on TeamsMessageId
| project Timestamp, TeamsMessageId, SenderEmailAddress, Url, UrlDomain, ThreatTypes, DeliveryAction
```

## Key column notes

### Column name discrepancies (docs vs live schema)

Official docs use different names than the live schema. Use the live schema names:

| Docs name | Live schema name |
|---|---|
| `MessageFormatType` | `MessageType` |
| `MessageFormatSubtype` | `MessageSubtype` |
| `MessageSubject` | `Subject` |
| (not documented) | `ThreadName` |
| `LastEditedTime` docs say `string` | `datetime` in live schema |

### ThreadType confirmed values (2026-04)

`chat`, `meeting`, `topic`, `space`. All rows in practice have `ThreadSubType = "None"` or `ThreadSubType = "PrivateChannel"`.

### MessageType and MessageSubtype confirmed values (2026-04)

`MessageType`: `RichText`, `Text`
`MessageSubtype`: `Html`, blank (for `Text`), `Media_CallRecording`, `Media_CallTranscript`

### SenderType confirmed value

`User` is the only confirmed value in practice.

### DeliveryAction and DeliveryLocation

`DeliveryAction`: `Delivered`, `Blocked` (per docs)
`DeliveryLocation`: `Teams` (all observed rows in this tenant)

### ThreatTypes / DetectionMethods / ConfidenceLevel

In benign tenants these are blank for virtually all rows. `ThreatTypes` is a plain string (not JSON). `DetectionMethods` and `ConfidenceLevel` are typed `dynamic` but contain no data when no threat is detected. Do not filter on these columns for volume counts — in practice they will be empty on >99% of rows.

### RecipientDetails — native dynamic array

`RecipientDetails` is a **native dynamic array** — direct indexing works, no `parse_json()` needed. Each element is a native dynamic dict with `@odata.type` wrapper key (harmless). Fields per element: `RecipientSmtpAddress`, `RecipientDisplayName`, `RecipientObjectId`, `RecipientType`.

```kql
// Expand recipients
MessageEvents
| where Timestamp > ago(7d)
| mv-expand rd = RecipientDetails
| extend
    RecipientEmail   = tostring(rd.RecipientSmtpAddress),
    RecipientName    = tostring(rd.RecipientDisplayName),
    RecipientObjId   = tostring(rd.RecipientObjectId),
    RecipientType    = tostring(rd.RecipientType)
```

`RecipientType` confirmed value: `"User"`.

### IsOwnedThread

`true` when the thread is owned by the scanned organization. Only org-owned messages can be remediated. External guest threads or external-org-initiated chats show `false`.

### TeamsMessageId format

Path-like string: `/chats/<threadid>/messages/<messageid>` or `/teams/<groupid>/channels/<channelid>/messages/<messageid>`. The trailing numeric segment is the message timestamp in milliseconds (same value as `MessageId`).

### ReportId format (MessageUrlInfo)

Composite string: `<guid>_<long-integer>`, e.g. `5dcfca8a-dc77-476c-d61a-08dea692e982_8274917758738722559`. Multiple URLs from the same message produce distinct `ReportId` values. Do NOT attempt single-column `ReportId` joins across the two tables — use `TeamsMessageId` instead.

### MessageUrlInfo: ThreatTypes absent from live schema

Official docs list `ThreatTypes` as a column in `MessageUrlInfo` but it is **absent from the live schema** (2026-05). Querying it causes a semantic error. Threat verdict is only on `MessageEvents`.

### Always-empty columns (confirmed 2026-05)

Both tables: `TenantId`, `SourceSystem` are always blank despite being in the schema.

## Hunting patterns

```kql
// Messages with URLs from external senders
MessageEvents
| where Timestamp > ago(7d)
| where IsExternalThread == true
| join kind=inner (
    MessageUrlInfo
    | where Timestamp > ago(7d)
) on TeamsMessageId
| project Timestamp, SenderEmailAddress, ThreadType, Url, UrlDomain, ThreatTypes, DeliveryAction

// External sender volume by domain
MessageEvents
| where Timestamp > ago(30d)
| where IsExternalThread == true
| extend SenderDomain = tostring(split(SenderEmailAddress, "@")[1])
| summarize Messages=count(), dcount(ThreadId) by SenderDomain
| sort by Messages desc

// Blocked messages (require MDO threat verdicts to be present)
MessageEvents
| where Timestamp > ago(30d)
| where DeliveryAction == "Blocked"
| project Timestamp, SenderEmailAddress, ThreadType, ThreatTypes, DetectionMethods, ConfidenceLevel
```

## Cross-table context

- `UrlClickEvents` covers user clicks on URLs in Teams messages (`Workload == "Teams"`). Join to `MessageUrlInfo` on `Url` or to `MessageEvents` on `TeamsMessageId` for full message+click context.
- `SenderObjectId` joins to `IdentityInfo.AccountObjectId` for sender identity enrichment.
