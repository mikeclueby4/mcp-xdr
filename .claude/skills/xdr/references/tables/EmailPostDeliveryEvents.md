# EmailPostDeliveryEvents

**Source**: Microsoft Defender for Office 365 (MDO)  
**Time column**: `Timestamp`  
**ReportId**: `string` (GUID) — unique per event  
**Prerequisite**: Defender for Office 365 deployed. Without it, table is empty.

## What it covers

One row per post-delivery action on a message. Captures ZAP (Zero-hour Auto Purge), manual admin remediation, and Dynamic Delivery processing. High-volume `Dynamic Delivery` rows are noise for threat hunting — filter out when looking for actual remediations.

## Schema highlights

| Column | Type | Notes |
|---|---|---|
| `NetworkMessageId` | string | Join key to all Email* tables. |
| `InternetMessageId` | string | RFC 5322 Message-ID header. |
| `SenderFromAddress` | string | FROM header sender. |
| `SenderDisplayName` | string | Sender display name. |
| `RecipientEmailAddress` | string | Recipient. |
| `Timestamp` | datetime | When the post-delivery action occurred. |
| `ActionType` | string | What triggered the row. See values below. |
| `Action` | string | The action taken on the message. See values below. |
| `ActionTrigger` | string | `AdminAction`, `AutomatedAction`, `ZAP`. |
| `ActionResult` | string | Outcome: `Success`, `Failed`. |
| `ThreatTypes` | string | Abbreviated comma-separated values: `Phish`/`PHS`, `Malware`/`MAL`. Use `has` not `==`. |
| `ThreatNames` | string | Detection name. |
| `DetectionMethods` | string | **String-encoded JSON** — same as `EmailEvents`. Blank on non-threat ActionTypes (e.g. `Dynamic Delivery`). |
| `DeliveryLocation` | string | Where the message was at time of this action. |
| `ReportId` | string | Per-event GUID. |

### ActionType confirmed values
`Phish ZAP`, `Malware ZAP`, `Spam ZAP`, `Manual remediation`, `Automated Remediation`, `Dynamic Delivery`, `Redelivery`

`Dynamic Delivery` is the highest-volume row type (Safe Attachments processing artifact) — filter with `ActionType != "Dynamic Delivery"` for remediation hunts.

### Action confirmed values
`None`, `Moved to quarantine`, `Quarantine release`, `Add message info only`, `Reprocessed`, `Soft delete`

## Key patterns

### ZAP events (messages cleaned after delivery)
```kql
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType in ("Phish ZAP", "Malware ZAP", "Spam ZAP")
| join kind=leftouter (
    EmailEvents | where Timestamp > ago(7d)
    | project NetworkMessageId, SenderFromAddress, Subject, DeliveryAction, LatestDeliveryAction
) on NetworkMessageId
| project Timestamp, ActionType, Action, ActionResult, RecipientEmailAddress,
    SenderFromAddress, Subject, ThreatTypes, ThreatNames
| sort by Timestamp desc
```

### Manual admin remediations
```kql
EmailPostDeliveryEvents
| where Timestamp > ago(30d)
| where ActionType == "Manual remediation"
| summarize Count=count(), Actions=make_set(Action) by RecipientEmailAddress, ThreatTypes
| sort by Count desc
```

### Messages remediated but action failed
```kql
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType != "Dynamic Delivery"
| where ActionResult == "Failed"
| project Timestamp, ActionType, Action, RecipientEmailAddress, NetworkMessageId, ThreatTypes
```

## Cross-table joins

| Table | Join key | Purpose |
|---|---|---|
| `EmailEvents` | `NetworkMessageId` | Original delivery verdict, subject, sender, auth |
| `EmailAttachmentInfo` | `NetworkMessageId` | Attachments in the remediated message |
| `EmailUrlInfo` | `NetworkMessageId` | URLs in the remediated message |

## Gotchas

- **`Dynamic Delivery`** rows dominate volume and are not threat events — always filter `ActionType != "Dynamic Delivery"` for remediation hunting.
- **`ThreatTypes`** uses abbreviated forms in live data (`PHS`, `MAL`) alongside documented values — use `has` not `==`.
- **`DetectionMethods`** is string-encoded JSON; empty/blank on `Dynamic Delivery` and `Redelivery` rows.
- **One row per post-delivery action**: a message with multiple remediation steps = multiple rows.
- **`Timestamp`** here is the action time, not delivery time — join to `EmailEvents` for the original delivery timestamp.
