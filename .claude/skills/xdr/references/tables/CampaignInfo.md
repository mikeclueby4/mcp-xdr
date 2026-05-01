# CampaignInfo

**Source**: Microsoft Defender for Office 365 (MDO)  
**Time column**: `Timestamp`  
**Prerequisite**: MDO deployed. Table is empty without it.  
**Platform**: Defender-only — Sentinel returns no rows (confirmed).

## What it covers

One row per campaign member message. Each row links a `CampaignId` (MDO-identified email campaign) to a specific `NetworkMessageId` (individual delivery event). One campaign → many rows, one per recipient message.

## Schema

| Column | Type | Notes |
|---|---|---|
| `CampaignId` | string | MDO campaign identifier. Dot-separated hex, format `XXXXXXXX.XXXXXXXX.XXXXXXXX.XXXXXXXX.NNNNN`. Not a GUID. |
| `CampaignName` | string | MDO-assigned name, typically `<CampaignType>.<CampaignId prefix>` e.g. `Phish.43FED949` |
| `CampaignType` | string | Confirmed values: `Phish`, `Malware`. Likely also `Spam`. |
| `CampaignSubType` | string | Brand/service being impersonated or malware family. Confirmed: `OneDrive`, `365`, `Amazon`, `Microsoft`, `Office`, `DocuSign`. Blank when unknown. |
| `NetworkMessageId` | string | M365 GUID — primary join key to `EmailEvents` |
| `RecipientEmailAddress` | string | Recipient after DL expansion — matches `EmailEvents.RecipientEmailAddress` |
| `ReportId` | string | **Not a GUID** — composite string: `<CampaignId>:0:<NetworkMessageId>-<long>-<long>`. Do not join to other tables via ReportId. |

## Key join: CampaignInfo → EmailEvents

Join on `NetworkMessageId` (and optionally `RecipientEmailAddress`) to get full delivery metadata. `CampaignId` is NOT present in `EmailEvents` — the lookup must go through `NetworkMessageId`.

```kql
CampaignInfo
| where Timestamp > ago(30d)
| where CampaignType == "Phish"
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(30d)
    | project NetworkMessageId, RecipientEmailAddress, DeliveryAction,
              LatestDeliveryAction, SenderFromAddress, Subject, ThreatTypes
) on NetworkMessageId
| project Timestamp, CampaignId, CampaignName, CampaignSubType,
          SenderFromAddress, RecipientEmailAddress, Subject,
          DeliveryAction, LatestDeliveryAction
| sort by Timestamp desc
```

## Campaign scope query

```kql
// Summarize campaigns: scope, types, recipient count
CampaignInfo
| where Timestamp > ago(30d)
| summarize
    MessageCount=count(),
    Recipients=dcount(RecipientEmailAddress),
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp)
    by CampaignId, CampaignName, CampaignType, CampaignSubType
| sort by MessageCount desc
```

## Gotchas

- **One row per recipient message** — same `CampaignId` × same message sent to N recipients = N rows. Use `dcount(NetworkMessageId)` for distinct message count.
- **`ReportId` is a composite non-GUID string** — do not attempt to join to `AlertEvidence` or any other table via `ReportId`. Use `NetworkMessageId` instead.
- **`CampaignId` is not in `EmailEvents`** — there is no direct campaign column in `EmailEvents`. Must join through `NetworkMessageId`.
- **Sentinel empty** — querying via `run_sentinel_query` returns no rows even when MDO data is present. Use `run_hunting_query` only.
- Table is in Preview (as of docs); schema or row semantics may change.
