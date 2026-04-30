# EmailUrlInfo

**Source**: Microsoft Defender for Office 365 (MDO)  
**Time column**: none — join to `EmailEvents` on `NetworkMessageId` for time  
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
| where UrlLocation == "QRCode"
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(7d)
    | where DeliveryAction != "Blocked"
) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url, UrlDomain, DeliveryAction
```

### URL redirect chain analysis
```kql
EmailUrlInfo
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
- No time column — always join to `EmailEvents` to apply time filters.
