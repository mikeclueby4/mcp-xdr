# EmailEvents

**Source**: Microsoft Defender for Office 365 (MDO)  
**Time column**: `Timestamp` (also has `TimeGenerated` — same value, Sentinel artifact)  
**ReportId**: `string` (GUID) — globally unique per event; safe to join on alone  
**Prerequisite**: Defender for Office 365 deployed. Without it, table is empty.

## What it covers

One row per email delivery event. Covers inbound, outbound, and intra-org mail. Represents delivery state at processing time; `LatestDeliveryLocation` / `LatestDeliveryAction` reflect post-delivery remediation.

## Schema highlights

| Column | Type | Notes |
|---|---|---|
| `NetworkMessageId` | string | M365-internal GUID per message. Primary join key to `EmailAttachmentInfo`, `EmailUrlInfo`, `EmailPostDeliveryEvents`. One row per recipient — same `NetworkMessageId` can appear multiple times for multi-recipient mail. |
| `InternetMessageId` | string | RFC 5322 `Message-ID` header — set by sending system. Not unique across recipients or retries. |
| `SenderMailFromAddress` | string | MAIL FROM / envelope sender (Return-Path). Used for SPF evaluation. |
| `SenderFromAddress` | string | FROM header — visible to recipient. May differ from `SenderMailFromAddress` in bulk/forwarded mail. |
| `SenderFromDomain` / `SenderMailFromDomain` | string | Domain portions of the above. Divergence = common in bulk/newsletter senders (envelope uses bounce subdomain); also key indicator for domain spoofing detection. |
| `SenderIPv4` / `SenderIPv6` | string | Last-hop sending MTA IP. Use `IPV6_MATCH()` for comparisons — never string equality. |
| `SenderObjectId` | string | Entra object ID of sender — only populated for internal senders. |
| `RecipientEmailAddress` | string | Final recipient after DL expansion. |
| `RecipientObjectId` | string | Entra object ID of recipient. |
| `EmailDirection` | string | `Inbound`, `Outbound`, `Intra-org`, `Unknown` |
| `DeliveryAction` | string | `Delivered`, `Junked`, `Blocked`, `Replaced` — at-processing verdict |
| `DeliveryLocation` | string | `Inbox/folder`, `Junk folder`, `Quarantine`, `On-premises/external`, `Dropped`, `Failed`, `Deleted items`, `Forwarded` |
| `LatestDeliveryAction` | string | Post-delivery state after admin/automated remediation. Values include `Delivered`, `Junked`, `Blocked`, `Moved to quarantine`, `Quarantine release`, `Soft delete`, `None`, `Add message info only`. Not in Streaming API. |
| `LatestDeliveryLocation` | string | Post-delivery location. Not in Streaming API. |
| `ThreatTypes` | string | Comma-separated: `Spam`, `Phish`, `Malware`. Empty = clean. Multiple values possible (e.g. `"Spam, Phish"`). **Mutable** — see retroactive-rewrite section below. |
| `ThreatNames` | string | Specific detection names (e.g. malware family). |
| `DetectionMethods` | string | **String-encoded JSON** — e.g. `{"Spam":["Bulk"],"Phish":["Mailbox intelligence impersonation"]}`. Keys are threat categories; values are arrays of method names. Access via `parse_json(DetectionMethods)`. **Mutable** — see retroactive-rewrite section below. |
| `AuthenticationDetails` | string | **String-encoded JSON** — e.g. `{"SPF":"pass","DKIM":"pass","DMARC":"pass","CompAuth":"pass"}`. Access via `parse_json(AuthenticationDetails)`. |
| `ConfidenceLevel` | string | SCL for spam (`-1`, `0`, `1`, `5`, `6`, `9`) or `High`/`Low` for phishing verdicts. **Mutable** — see retroactive-rewrite section below. |
| `OriginalThreatTypes` | string | Same format as `ThreatTypes`, frozen at delivery time — **immutable**. Official column, documented by Microsoft. Blank means the message was genuinely clean when the filtering stack made its delivery decision, even if `ThreatTypes` later shows a verdict. |
| `OriginalDetectionMethods` | string | **String-encoded JSON**, same shape as `DetectionMethods`, frozen at delivery time — **immutable**. Access via `parse_json()`. |
| `OriginalConfidenceLevel` | string | Same format as `ConfidenceLevel`, frozen at delivery time — **immutable**. |
| `BulkComplaintLevel` | int | BCL 0–9; higher = more likely complaint-generating bulk mail. |
| `EmailAction` | string | Action applied to the message (e.g. `Move message to junk mail folder`, `send to quarantine`, `No action taken`). |
| `EmailActionPolicy` | string | Policy that triggered the action. Values: `Antispam`, `Antispam bulk mail`, `Antispam high-confidence spam`, `Antispam high-confidence phish`, `Antispam phishing`, `Anti-phishing spoof`, `Anti-phishing user impersonation`, `Anti-phishing domain impersonation`, `Anti-phishing graph impersonation`, `Anti-malware`, `Safe Attachments`, `Outbound spam`, `Enterprise Transport Rules (ETR)` |
| `EmailActionPolicyGuid` | string | GUID of the triggering policy. |
| `OrgLevelAction` / `OrgLevelPolicy` | string | Action and policy at org level. `OrgLevelAction` enum: `Allow`, `Block`. Confirmed live `OrgLevelPolicy` values: `Exchange transport rule`, `Sender domain list (Safe domain / Blocked domain)`, `Sender address list (Safe sender / Blocked sender)`, `Tenant Allow/Block List sender email address block`, `Tenant Allow/Block List URL block`, `IP region filter from policy`, `Quarantine release`. An `Allow` action here overrides anti-phish/anti-spam verdicts and is the primary answer to "why did this reach the inbox despite a bad verdict?" — see policy-override triage below. |
| `UserLevelAction` / `UserLevelPolicy` | string | Action and policy from recipient's mailbox policy. `UserLevelAction` enum: `Allow`, `Block`. Confirmed live `UserLevelPolicy` values: `Sender address list (Safe sender / Blocked sender)`, `Sender domain list (User override)` — i.e. the recipient's own Safe Senders list, distinct from an org-level allow. |
| `AttachmentCount` / `UrlCount` | int | Counts at processing time. |
| `EmailLanguage` | string | ISO language code of detected content. |
| `EmailClusterId` | long | Heuristic clustering ID grouping similar messages. Useful for campaign hunting. |
| `ExchangeTransportRule` | string | ETR name/GUID if a transport rule matched. Also exposed in `AdditionalFields.TransportRuleGuid`. |
| `Subject` | string | Email subject line. |
| `To` | dynamic | Array of full To-header addresses (RFC display format). Native dynamic in both sources. |
| `Cc` | dynamic | Array of Cc-header addresses. Native dynamic in both sources. |
| `AdditionalFields` | string | **String-encoded JSON** in Defender source (`gettype()` = `"string"`); `dynamic` in Sentinel. Access via `parse_json(AdditionalFields)`. Contains e.g. `TransportRuleGuid`. |
| `ForwardingInformation` | string | Populated when mail was forwarded; contains forwarding rule/address info. |
| `DistributionList` | string | Top-level DL the message was sent to (if applicable). |
| `Context` | string | Additional context flags. |
| `ThreatClassification` | string | Higher-level classification (e.g. `Contact establishment`, `Invoice`). Sparse — only populated for social engineering patterns. |
| `IsFirstContact` | bool | True if this is the first time the recipient received mail from this sender. |
| `RecipientDomain` | string | Domain portion of `RecipientEmailAddress`. |
| `EmailSize` | long | Message size in bytes. |

## Column encoding gotchas

`AuthenticationDetails`, `DetectionMethods`, and `AdditionalFields` are **string-encoded JSON** in the Defender source (confirmed via `gettype()` = `"string"`). Always access via `parse_json()`:

```kql
// AuthenticationDetails
| extend auth = parse_json(AuthenticationDetails)
| where tostring(auth.SPF) == "fail" or tostring(auth.DMARC) == "fail"

// DetectionMethods
| extend methods = parse_json(DetectionMethods)
| where array_length(methods.Phish) > 0

// AdditionalFields
| extend af = parse_json(AdditionalFields)
| extend TransportRuleGuid = tostring(af.TransportRuleGuid)
```

In Sentinel, `AdditionalFields` schema type is `dynamic` — but `parse_json(tostring(...))` is safe in both sources.

## `ThreatTypes`/`DetectionMethods`/`ConfidenceLevel` are retroactively rewritten — `Original*` columns hold delivery-time truth

`EmailEvents` carries two parallel verdict column sets:
- `ThreatTypes`, `DetectionMethods`, `ConfidenceLevel` — **mutable**; reflect the CURRENT verdict, rewritten in place when Microsoft reclassifies a message after delivery (e.g. a URL/file detonation or campaign correlation completes hours later).
- `OriginalThreatTypes`, `OriginalDetectionMethods`, `OriginalConfidenceLevel` — **immutable**; the verdict known AT DELIVERY TIME. Officially documented columns (not internal-only).

This is the **opposite failure mode from `UrlClickEvents.ThreatTypes`** (see that table's reference — its `ThreatTypes` is *never* backfilled, verdict only ever lands in `AlertInfo`/`AlertEvidence`). In `EmailEvents`, the same-named column silently gets rewritten in place instead. Do not assume verdict-column mutability behaves consistently across tables — always check for an `Original*`/frozen counterpart before trusting a "final" read.

**Why this matters — classic analyst trap.** A query like:
```kql
EmailEvents | where ThreatTypes has "Phish" and DeliveryLocation == "Inbox/folder"
```
reads as "known-bad mail delivered anyway → policy failure." That conclusion is usually wrong. Confirmed live: messages matching this filter with a high-confidence detection method (URL/file detonation reputation, Campaign) overwhelmingly had **blank `OriginalThreatTypes`** — i.e. genuinely clean at delivery, reclassified hours later by asynchronous detonation. The mail system behaved correctly; the verdict didn't exist yet at delivery time. Conversely, messages that WERE flagged at delivery (`OriginalThreatTypes` populated) and still reached the inbox skew toward heuristic detections (`Impersonation user`, `Impersonation domain`, `Mailbox intelligence impersonation`) — many tenants deliberately deliver these with a safety tip rather than quarantine.

**Rules:**
- "What did the mail system know when it made the delivery decision?" → `OriginalThreatTypes` / `OriginalDetectionMethods` / `OriginalConfidenceLevel`.
- "What do we know about this message now?" → `ThreatTypes` / `DetectionMethods` / `ConfidenceLevel`.
- **Blank `OriginalThreatTypes` + populated `ThreatTypes` = retroactive reclassification** (clean at delivery). This is the signature of a late verdict, not a policy failure.
- To check whether a delivered threat was subsequently cleaned up, compare `DeliveryLocation` vs `LatestDeliveryLocation` and inspect `LatestDeliveryAction` (values: `Delivered`, `Junked`, `Blocked`, `None`, `Quarantine release`; historically also `Moved to quarantine`/`Soft delete`/`Add message info only` — not all values may appear in every tenant sample). ZAP (zero-hour auto purge) is the usual mechanism moving mail out of the inbox after a late verdict.
- Never conclude "policy let known-bad mail through" from `ThreatTypes` alone — always cross-check `OriginalThreatTypes`.
- `LatestDeliveryLocation`/`LatestDeliveryAction` are **not available in the Streaming API** (per official docs); if consuming via Streaming API into a SIEM, use `summarize arg_max(TimeGenerated, *) by NetworkMessageId, RecipientEmailAddress` to get the latest record per email/recipient instead.

```kql
// Corrected triage: separate "flagged at delivery" from "clean at delivery, reclassified later"
EmailEvents
| where Timestamp > ago(30d) and EmailDirection == "Inbound"
| where ThreatTypes has "Phish" and DeliveryLocation == "Inbox/folder"
| extend KnownAtDelivery = iff(isnotempty(OriginalThreatTypes), "flagged at delivery", "clean at delivery - reclassified later")
| extend CleanedUp = iff(DeliveryLocation != LatestDeliveryLocation, "yes", "no")
| summarize count() by KnownAtDelivery, CleanedUp, LatestDeliveryLocation
```

## Policy-override columns — answer "why was this delivered?"

`OrgLevelAction`/`OrgLevelPolicy` and `UserLevelAction`/`UserLevelPolicy` explain why a message got its disposition — essential when investigating "why did this phish reach the inbox?" An allow-list override (`OrgLevelAction == "Allow"` from a Safe sender/domain policy, or a Tenant Allow/Block List entry) will deliver mail that anti-phish would otherwise have quarantined. Always project these columns before concluding a detection "failed" — the detection may have fired correctly and been overridden by policy.

```kql
// Separate override-driven delivery from policy-driven delivery for inbox-delivered phish
EmailEvents
| where Timestamp > ago(30d) and EmailDirection == "Inbound"
| where ThreatTypes has "Phish" and DeliveryLocation == "Inbox/folder"
| summarize count() by OrgLevelAction, OrgLevelPolicy, UserLevelAction, UserLevelPolicy
| sort by count_ desc
```

## Key patterns

### Phishing / spoofing hunt
`ThreatTypes` is the CURRENT verdict (may be a retroactive rewrite); include `OriginalThreatTypes` alongside it so results distinguish "caught at delivery" from "reclassified after the fact" — see retroactive-rewrite section above.
```kql
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| extend auth = parse_json(AuthenticationDetails)
| extend methods = parse_json(DetectionMethods)
| project Timestamp, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, LatestDeliveryAction,
    ThreatTypes, OriginalThreatTypes,
    SPF=tostring(auth.SPF), DMARC=tostring(auth.DMARC),
    PhishMethods=tostring(methods.Phish)
| sort by Timestamp desc
```

### FROM/MAIL-FROM domain divergence (bulk senders vs spoofing)
```kql
// SenderFromDomain != SenderMailFromDomain is common for legitimate bulk mail
// (envelope bounce domain differs from display domain).
// Combine with auth failures and ThreatTypes for spoofing signal.
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromDomain != SenderMailFromDomain
| where isnotempty(SenderFromDomain) and isnotempty(SenderMailFromDomain)
| extend auth = parse_json(AuthenticationDetails)
| where tostring(auth.DMARC) == "fail"
| project Timestamp, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress, ThreatTypes, DeliveryAction
```

### Post-delivery remediation — delivered then quarantined
This pattern naturally captures the "clean at delivery, reclassified later" population (ZAP): `ThreatTypes` will be populated but `OriginalThreatTypes` is typically blank for these rows.
```kql
EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction == "Delivered"
| where LatestDeliveryAction in ("Moved to quarantine", "Soft delete", "Junked")
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
    Subject, ThreatTypes, OriginalThreatTypes, DeliveryAction, LatestDeliveryAction, LatestDeliveryLocation
```

### Join to attachments for malware investigation
```kql
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Malware"
| join kind=inner EmailAttachmentInfo on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject,
    FileName, FileType, SHA256, ThreatNames, DetectionMethods
```

### First-contact phish (BEC precursor)
```kql
EmailEvents
| where Timestamp > ago(7d)
| where IsFirstContact == true
| where ThreatTypes has "Phish" or ThreatClassification != ""
| project Timestamp, SenderFromAddress, SenderDisplayName, RecipientEmailAddress,
    Subject, ThreatTypes, ThreatClassification, IsFirstContact, DeliveryAction
```

### Campaign pivot via EmailClusterId
```kql
// Find all messages in same cluster as a known-bad message
let BadCluster = EmailEvents
    | where Timestamp > ago(30d)
    | where NetworkMessageId == "known-bad-id"
    | project EmailClusterId;
EmailEvents
| where Timestamp > ago(30d)
| join kind=inner BadCluster on EmailClusterId
| summarize Count=count(), Recipients=make_set(RecipientEmailAddress) by SenderFromAddress, Subject, DeliveryAction
```

## Cross-table joins

| Table | Join key | Purpose |
|---|---|---|
| `EmailAttachmentInfo` | `NetworkMessageId` | Attachment details, SHA256, file type |
| `EmailUrlInfo` | `NetworkMessageId` | URLs embedded in email |
| `EmailPostDeliveryEvents` | `NetworkMessageId` | Post-delivery actions (ZAP, admin remediation) |
| `UrlClickEvents` | `NetworkMessageId` | User clicks on links from this email |
| `AlertEvidence` | `NetworkMessageId` | Alert correlation |
| `CampaignInfo` | `NetworkMessageId` | MDO campaign membership — `CampaignId` is NOT a column in `EmailEvents`; must join via `NetworkMessageId` |
| `IdentityInfo` | `RecipientObjectId` or `SenderObjectId` → `AccountObjectId` | User metadata (department, job title) |

`NetworkMessageId` is the canonical join key across all Email* tables. `ReportId` (GUID) is also unique per event and can join to `AlertEvidence`.

## Gotchas

- **One row per recipient**: a message sent to N recipients produces N rows with the same `NetworkMessageId` but different `RecipientEmailAddress`. Aggregate by `NetworkMessageId` when counting distinct messages.
- **`SenderFromDomain` != `SenderMailFromDomain`** is normal for legitimate bulk/newsletter senders (envelope uses bounce subdomain). Do not treat divergence alone as an IOC; combine with auth failures.
- **`AuthenticationDetails`, `DetectionMethods`, `AdditionalFields`** are string-encoded JSON in Defender source — always use `parse_json()`.
- **`LatestDeliveryLocation`/`LatestDeliveryAction`** reflect post-delivery state and are NOT available in the Streaming API. For at-processing state use `DeliveryAction`/`DeliveryLocation`.
- **`ThreatTypes`** is a comma-separated string — use `has` not `==` for filtering: `| where ThreatTypes has "Phish"`.
- **`ThreatTypes`/`DetectionMethods`/`ConfidenceLevel` are mutable and get retroactively rewritten** when a message is reclassified after delivery (async detonation, campaign correlation). Never conclude "policy failure" from these alone — always cross-check `OriginalThreatTypes`/`OriginalDetectionMethods`/`OriginalConfidenceLevel` (immutable, frozen at delivery). Blank `Original*` + populated current = late verdict, not a delivery-time miss. See dedicated section above.
- **`OrgLevelAction`/`UserLevelAction` == `Allow`** can override an anti-phish/anti-spam block and explain "why did known-bad mail reach the inbox" without any detection failure. Always project `OrgLevelPolicy`/`UserLevelPolicy` alongside verdict columns when triaging inbox-delivered threats.
- **`SenderIPv4`/`SenderIPv6`** are separate columns (unlike some other tables). Check both when hunting by sender IP. Always use `IPV6_MATCH()` for comparison.
- **`To`/`Cc`** are native dynamic arrays in both sources; RFC display format strings inside (e.g. `["Display Name <user@example.com>"]`).
- **`IsFirstContact`** is `bool` — filter with `== true`, not `has`.
- **`Context`** is sparsely populated; not documented with fixed enum values.
