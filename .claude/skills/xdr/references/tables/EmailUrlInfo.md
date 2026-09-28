# EmailUrlInfo

**Source**: Microsoft Defender for Office 365 (MDO)  
**Time column**: `Timestamp` — present and directly filterable (confirmed live + official docs; do not assume otherwise). Semantics: **URL-extraction/processing time, not delivery time** — verified 3–319s *earlier* than the matching `EmailEvents.Timestamp` (same `NetworkMessageId`) across a sample campaign. Pad time windows accordingly when time-filtering this table directly.  
**ReportId**: `string` (GUID) — unique per event  
**Prerequisite**: Defender for Office 365 deployed.

## What it covers

One row per URL extracted from an email. Multiple rows per message (one per URL). Join to `EmailEvents` via `NetworkMessageId`.

## Schema highlights

| Column | Type | Notes |
|---|---|---|
| `NetworkMessageId` | string | Join key to `EmailEvents`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents`. |
| `Url` | string | Full URL extracted from the message. |
| `UrlDomain` | string | Domain portion of `Url`. |
| `UrlLocation` | string | Where in the message: `Body`, `Header`, `Attachment`, `QRCode`, `Subject`. `QRCode` = URL decoded from embedded QR image — key signal for QR-phishing. |
| `ReportId` | string | Per-event GUID. |
| `UrlChainId` | string | **Defender only.** Shared ID across all hops in a redirect chain. |
| `UrlChainPosition` | int | **Defender only.** 0-based hop index within the redirect chain. Position 0 = first URL shown to user. |

`UrlChainId`/`UrlChainPosition` are absent from Sentinel schema. No dynamic/JSON columns — no `parse_json()` needed.

## Key patterns

### QR-phishing hunt
```kql
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlLocation == "QRCode"
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(7d)
    | where DeliveryAction != "Blocked"
    | project DeliveryTs=Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction
) on NetworkMessageId
// rename EmailEvents.Timestamp to DeliveryTs before the join — see gotchas
| project DeliveryTs, SenderFromAddress, RecipientEmailAddress, Subject, Url, UrlDomain, DeliveryAction
```

### URL redirect chain analysis
```kql
EmailUrlInfo
| where Timestamp > ago(7d)
| where isnotempty(UrlChainId)
| summarize ChainLength=max(UrlChainPosition)+1, Urls=make_list(Url) by UrlChainId, NetworkMessageId
| where ChainLength > 1
| sort by ChainLength desc
```

### URLs from delivered phish
```kql
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| join kind=inner EmailUrlInfo on NetworkMessageId
| summarize count() by Url, UrlDomain, UrlLocation
| sort by count_ desc
```

## Cross-table joins

| Table | Join key | Purpose |
|---|---|---|
| `EmailEvents` | `NetworkMessageId` | Delivery verdict, sender, recipient, threat types |
| `EmailAttachmentInfo` | `NetworkMessageId` | Attachments in same message |
| `EmailPostDeliveryEvents` | `NetworkMessageId` | Post-delivery actions |
| `UrlClickEvents` | `Url` or `NetworkMessageId` | Whether users clicked the URL |

## Gotchas

- **Multiple rows per message** — use `dcount(NetworkMessageId)` to count distinct messages, not `count()`.
- **`UrlChainId`/`UrlChainPosition`** are Defender-only; absent in Sentinel.
- **`UrlLocation == "QRCode"`** is a documented value for URLs decoded from QR code images in email body.
- **`Timestamp` = extraction time, not delivery time.** It precedes the matching `EmailEvents.Timestamp` (same `NetworkMessageId`) by seconds to several minutes. Fine for a first-pass time-filtered sweep of URLs (cheaper than always joining to `EmailEvents`), but don't report it to a user as "when the email arrived."
- **Join-then-project silently keeps the wrong Timestamp.** `EmailUrlInfo | join EmailEvents on NetworkMessageId | project Timestamp` resolves to the *left* table's column (extraction time) per standard KQL join column-collision rules — it looks like delivery time but isn't. Rename one side before projecting: `EmailUrlInfo | join kind=inner (EmailEvents | project DeliveryTs=Timestamp, NetworkMessageId, ...) on NetworkMessageId`.
