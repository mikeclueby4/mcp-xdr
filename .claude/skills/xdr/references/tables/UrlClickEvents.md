# UrlClickEvents

Safe Links click telemetry from Microsoft Defender for Office 365. One row per click event on a rewritten (Safe Links) URL. Requires MDO deployment — table returns no results without it.

Both Defender and Sentinel. Defender: `Timestamp`. Sentinel: `TimeGenerated` (same value).

`ReportId` is a GUID string — globally unique per click event. Single-column join is safe.

## Key columns

| Column | Type | Notes |
|---|---|---|
| `Timestamp` | datetime | Click time |
| `Url` | string | Final destination URL (after Safe Links unwrapping) |
| `ActionType` | string | See enum below |
| `AccountUpn` | string | Clicking user |
| `Workload` | string | Source product: `Email`, `Teams`, `Office`, `Copilot` |
| `AppName` | string | Specific app: `Mail`, `Microsoft Outlook`, `Teams-Desktop`, `Teams iOS Client`, `Microsoft Word`, etc. |
| `NetworkMessageId` | string | Email message GUID. Blank for Teams/Office clicks. **Not joinable** for clicks from Drafts/Sent — see note below. |
| `ThreatTypes` | string | Plain string verdict, e.g. `"Phish"`, `"Malware"`. Blank when benign. |
| `DetectionMethods` | string | JSON-encoded dict of `{ThreatType: [method, ...]}`, e.g. `{"Phish":["URL malicious reputation"]}`. Blank when benign. Use `parse_json(DetectionMethods)` to access — it is `string`-typed. |
| `IsClickedThrough` | bool | True = user clicked "Continue anyway" on the Safe Links warning page |
| `UrlChain` | string | JSON-encoded string array of redirect chain URLs. `string`-typed — use `parse_json(UrlChain)` to access individual hops. |
| `IPAddress` | string | Clicking user's public IP. May be IPv6 — use `ipv6_is_match()` for comparisons. |
| `ReportId` | string | GUID — globally unique per click. Safe single-column join. |
| `SourceId` | string | Usually equals `NetworkMessageId` for email; blank for Teams/Office clicks. |

## ActionType confirmed values (2026-04)

| Value | Meaning |
|---|---|
| `ClickAllowed` | URL was allowed (benign or no verdict) |
| `ClickBlocked` | URL blocked at click time (malicious verdict) |
| `UrlErrorPage` | Rendering error or URL unreachable |
| `ClickBlockedByTenantPolicy` | Blocked by Tenant Allow/Block List policy |

## Column encoding gotchas

**`UrlChain` is a JSON string array stored as `string`** — not a `dynamic` column. Parse before indexing:
```kql
| extend chain = parse_json(UrlChain)
| extend FirstHop = tostring(chain[0])
| extend LastHop  = tostring(chain[array_length(chain)-1])
```

**`DetectionMethods` is a JSON string dict stored as `string`** — not `dynamic`. Parse to access methods:
```kql
| extend dm = parse_json(DetectionMethods)
| extend PhishMethods = dm["Phish"]
```

**`ThreatTypes` is a plain string**, not JSON — direct `== "Phish"` comparison is correct:
```kql
| where ThreatTypes has "Phish"
```

## Joining to Teams message tables

For `Workload == "Teams"` clicks, `NetworkMessageId` is blank. Join to `MessageEvents` or `MessageUrlInfo` via `Url` or via `TeamsMessageId` if available on the click row. See `MessageEvents.md` for the join key and column details.

## NetworkMessageId join limitations

`NetworkMessageId` is **blank for Teams and Office clicks** (only populated for email).

For clicks originating from **Drafts or Sent items**, `NetworkMessageId` is either absent or assigned a default value. These rows **cannot be reliably joined** to `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, or `EmailPostDeliveryEvents`.

## Joining to email tables

When `NetworkMessageId` is populated (email clicks), join to the Email* family:
```kql
UrlClickEvents
| where Timestamp > ago(7d)
| where Workload == "Email"
| where isnotempty(NetworkMessageId)
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(7d)
    | project NetworkMessageId, SenderFromAddress, Subject, DeliveryAction
) on NetworkMessageId
```

Note: `EmailUrlInfo` also joins on `NetworkMessageId` and has the URL entities — use it for pre-click URL context. `UrlClickEvents` = post-click Safe Links verdict.

## Hunting patterns

**Phish clicks allowed through (highest priority hunting signal):**
```kql
UrlClickEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where ActionType == "ClickAllowed" or IsClickedThrough == true
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, NetworkMessageId, IPAddress
| sort by Timestamp desc
```

**Anomaly detection — per-user click spike:**
```kql
UrlClickEvents
| where Timestamp > ago(14d)
| summarize 
    DailyClicks = count(),
    UniqueUrls = dcount(Url),
    BlockedCount = countif(ActionType in ("ClickBlocked", "ClickBlockedByTenantPolicy"))
    by AccountUpn, bin(Timestamp, 1d)
| where DailyClicks > 50 or BlockedCount > 3
```

**Teams URL click investigation (Workload filter needed — no NetworkMessageId):**
```kql
UrlClickEvents
| where Timestamp > ago(7d)
| where Workload == "Teams"
| where isnotempty(ThreatTypes)
| project Timestamp, AccountUpn, AppName, Url, ActionType, ThreatTypes
```
