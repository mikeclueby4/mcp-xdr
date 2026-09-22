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
| `IPAddress` | string | Clicking user's public IP. May be IPv6 — use `IPV6_MATCH()` for comparisons. |
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

## `ThreatTypes` is NOT retroactively backfilled — critical hunting gotcha

Confirmed live (2026-09): a user clicked a phishing URL. The `UrlClickEvents` row recorded `ActionType == "ClickAllowed"`, `ThreatTypes` empty, `IsClickedThrough == 0` — i.e. looked completely benign at click time. ~24h later Defender for Office 365 raised a High-severity alert ("A potentially malicious URL click was detected", `Category = InitialAccess`, `ServiceSource = Microsoft Defender for Office 365`) for that exact click. **The `UrlClickEvents` row was never updated** — `ThreatTypes` stayed blank permanently. The verdict only exists in the `AlertInfo`/`AlertEvidence` layer, not in the click row.

Tenant-scale evidence for how weak `ThreatTypes` is as a primary filter: over a 7-day window, 4042 total clicks, **0** had populated `ThreatTypes`, while 9 had `ActionType startswith "ClickBlocked"`. A healthy tenant can show `ThreatTypes` as near-universally empty even while active malicious clicks exist.

**Implication: `where isnotempty(ThreatTypes)` or `where ThreatTypes has "Phish"` alone will MISS retroactively-detected malicious clicks — including the Microsoft official docs sample query for this table, which leads with the same `ThreatTypes has "Phish"` filter. Do not trust `ThreatTypes` as the sole hunting signal for malicious clicks; it only reflects the verdict known at click time (Safe Links time-of-click detonation), not post-click reclassification.**

Contrast with `EmailEvents.ThreatTypes`, which behaves the **opposite** way: it IS rewritten in place on reclassification (see `EmailEvents.md` — `OriginalThreatTypes` preserves the delivery-time verdict there). Do not assume the two tables' same-named `ThreatTypes` column shares mutability semantics.

Correct approach: filter on `ActionType` (`ClickBlocked*` values) OR `IsClickedThrough == true`, AND separately correlate to `AlertInfo`/`AlertEvidence` by `AccountUpn` + time window to catch retroactive detections:
```kql
// Layer 1 — click-time signal (ActionType/IsClickedThrough), NOT ThreatTypes alone
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType startswith "ClickBlocked" or IsClickedThrough == true or isnotempty(ThreatTypes)
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, ThreatTypes, NetworkMessageId, IPAddress

// Layer 2 — retroactive detections that never touched the click row.
// AlertInfo/AlertEvidence carries the delayed verdict; UrlClickEvents does not.
AlertInfo
| where Timestamp > ago(7d)
| where ServiceSource == "Microsoft Defender for Office 365"
| where Category == "InitialAccess"
| join kind=inner (AlertEvidence | where Timestamp > ago(7d)) on AlertId
| join kind=inner (UrlClickEvents | where Timestamp > ago(8d)) on $left.AccountUpn == $right.AccountUpn
| project AlertTime = Timestamp, Title, Severity, AccountUpn, Url, ClickTime = Timestamp1
```

## `has` vs `contains` on `Url` / `UrlChain` — do not use `has` for domain search

Confirmed live (2026-09): `| where Url has "baddomain.com"` returned **zero** rows on data where `| where Url contains "baddomain"` returned 5. Cause: `has` is term-indexed (matches only whole alphanumeric tokens ≥3 chars, per [Kusto string operators](https://learn.microsoft.com/kusto/query/datatypes-string-operators)). When the payload domain is embedded inside a URL-encoded open-redirect wrapper — e.g. `https://www.google.com/url?q=https%3A%2F%2Fbaddomain.com%3F...` — percent-encoding (`%3A%2F%2F`) means the tokenizer never produces `baddomain.com` as a standalone term, so `has` silently cannot match it. This is the official documented behavior of `has` on any column, not a `UrlClickEvents`-specific bug — but it bites hard here because `Url`/`UrlChain` payloads are routinely percent-encoded.

**Rule: use `contains` (or `matches regex`) — never `has` — when searching for a domain or substring inside `Url` or `UrlChain`.** Reserve `has` only for exact, unencoded whole-domain matches you've already confirmed are not URL-encoded.

```kql
// WRONG — silently misses percent-encoded payload domains
UrlClickEvents | where Url has "example-bad-domain.com"

// RIGHT
UrlClickEvents | where Url contains "example-bad-domain.com"
```

**Open-redirect laundering pattern**: attackers wrap the real malicious destination in a high-reputation domain's open-redirect endpoint (`google.com/url?q=`, and similar patterns on other trusted redirector services) specifically so Safe Links evaluates the *wrapper* domain's reputation and returns `ClickAllowed`. Don't trust the top-level `Url` domain — parse `UrlChain` and inspect/decode the redirect target parameter:
```kql
UrlClickEvents
| where Timestamp > ago(7d)
| extend chain = parse_json(UrlChain)
| mv-expand hop = chain
| extend hop_s = tostring(hop)
| extend query_ = tostring(parse_url(hop_s).["Query Parameters"])
| extend decoded_target = url_decode(query_)
| where decoded_target contains "example-bad-domain.com"
```
`url_decode()` is confirmed as the correct Kusto/ADX function name (percent-decoding); verified against official [`url_decode()`](https://learn.microsoft.com/kusto/query/url-decode-function) docs.

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

⚠️ **Do not lead with `ThreatTypes has "Phish"`** — confirmed live to miss real incidents where the malicious verdict arrived retroactively via `AlertInfo` and the click row itself was never updated (see `ThreatTypes` section above; this is also the flaw in Microsoft's own official sample query for this table). Use `ActionType`/`IsClickedThrough` as the primary signal, and treat `ThreatTypes` as a bonus enrichment, not a filter:
```kql
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType startswith "ClickBlocked" or IsClickedThrough == true
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, ThreatTypes, NetworkMessageId, IPAddress
| sort by Timestamp desc
```
Then separately run the `AlertInfo`/`AlertEvidence` correlation query above to catch clicks that were allowed at click time but reclassified later.

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
| where ActionType startswith "ClickBlocked" or IsClickedThrough == true or isnotempty(ThreatTypes)
| project Timestamp, AccountUpn, AppName, Url, ActionType, IsClickedThrough, ThreatTypes
```
