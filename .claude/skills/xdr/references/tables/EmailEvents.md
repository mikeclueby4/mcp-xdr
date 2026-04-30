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
| `SenderIPv4` / `SenderIPv6` | string | Last-hop sending MTA IP. Use `ipv6_is_match()` for comparisons — never string equality. |
| `SenderObjectId` | string | Entra object ID of sender — only populated for internal senders. |
| `RecipientEmailAddress` | string | Final recipient after DL expansion. |
| `RecipientObjectId` | string | Entra object ID of recipient. |
| `EmailDirection` | string | `Inbound`, `Outbound`, `Intra-org`, `Unknown` |
| `DeliveryAction` | string | `Delivered`, `Junked`, `Blocked`, `Replaced` — at-processing verdict |
| `DeliveryLocation` | string | `Inbox/folder`, `Junk folder`, `Quarantine`, `On-premises/external`, `Dropped`, `Failed`, `Deleted items`, `Forwarded` |
| `LatestDeliveryAction` | string | Post-delivery state after admin/automated remediation. Values include `Delivered`, `Junked`, `Blocked`, `Moved to quarantine`, `Quarantine release`, `Soft delete`, `None`, `Add message info only`. Not in Streaming API. |
| `LatestDeliveryLocation` | string | Post-delivery location. Not in Streaming API. |
| `ThreatTypes` | string | Comma-separated: `Spam`, `Phish`, `Malware`. Empty = clean. Multiple values possible (e.g. `"Spam, Phish"`). |
| `ThreatNames` | string | Specific detection names (e.g. malware family). |
| `DetectionMethods` | string | **String-encoded JSON** — e.g. `{"Spam":["Bulk"],"Phish":["Mailbox intelligence impersonation"]}`. Keys are threat categories; values are arrays of method names. Access via `parse_json(DetectionMethods)`. |
| `AuthenticationDetails` | string | **String-encoded JSON** — e.g. `{"SPF":"pass","DKIM":"pass","DMARC":"pass","CompAuth":"pass"}`. Access via `parse_json(AuthenticationDetails)`. |
| `ConfidenceLevel` | string | SCL for spam (`-1`, `0`, `1`, `5`, `6`, `9`) or `High`/`Low` for phishing verdicts. |
| `BulkComplaintLevel` | int | BCL 0–9; higher = more likely complaint-generating bulk mail. |
| `EmailAction` | string | Action applied to the message (e.g. `Move message to junk mail folder`, `send to quarantine`, `No action taken`). |
| `EmailActionPolicy` | string | Policy that triggered the action. Values: `Antispam`, `Antispam bulk mail`, `Antispam high-confidence spam`, `Antispam high-confidence phish`, `Antispam phishing`, `Anti-phishing spoof`, `Anti-phishing user impersonation`, `Anti-phishing domain impersonation`, `Anti-phishing graph impersonation`, `Anti-malware`, `Safe Attachments`, `Outbound spam`, `Enterprise Transport Rules (ETR)` |
| `EmailActionPolicyGuid` | string | GUID of the triggering policy. |
| `OrgLevelAction` / `OrgLevelPolicy` | string | Action and policy at org level. |
| `UserLevelAction` / `UserLevelPolicy` | string | Action and policy from recipient's mailbox policy. |
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

## Key patterns

### Phishing / spoofing hunt
```kql
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| extend auth = parse_json(AuthenticationDetails)
| extend methods = parse_json(DetectionMethods)
| project Timestamp, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, LatestDeliveryAction,
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
```kql
EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction == "Delivered"
| where LatestDeliveryAction in ("Moved to quarantine", "Soft delete", "Junked")
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
    Subject, ThreatTypes, DeliveryAction, LatestDeliveryAction, LatestDeliveryLocation
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
| `IdentityInfo` | `RecipientObjectId` or `SenderObjectId` → `AccountObjectId` | User metadata (department, job title) |

`NetworkMessageId` is the canonical join key across all Email* tables. `ReportId` (GUID) is also unique per event and can join to `AlertEvidence`.

## Gotchas

- **One row per recipient**: a message sent to N recipients produces N rows with the same `NetworkMessageId` but different `RecipientEmailAddress`. Aggregate by `NetworkMessageId` when counting distinct messages.
- **`SenderFromDomain` != `SenderMailFromDomain`** is normal for legitimate bulk/newsletter senders (envelope uses bounce subdomain). Do not treat divergence alone as an IOC; combine with auth failures.
- **`AuthenticationDetails`, `DetectionMethods`, `AdditionalFields`** are string-encoded JSON in Defender source — always use `parse_json()`.
- **`LatestDeliveryLocation`/`LatestDeliveryAction`** reflect post-delivery state and are NOT available in the Streaming API. For at-processing state use `DeliveryAction`/`DeliveryLocation`.
- **`ThreatTypes`** is a comma-separated string — use `has` not `==` for filtering: `| where ThreatTypes has "Phish"`.
- **`SenderIPv4`/`SenderIPv6`** are separate columns (unlike some other tables). Check both when hunting by sender IP. Always use `ipv6_is_match()` for comparison.
- **`To`/`Cc`** are native dynamic arrays in both sources; RFC display format strings inside (e.g. `["Display Name <user@example.com>"]`).
- **`IsFirstContact`** is `bool` — filter with `== true`, not `has`.
- **`Context`** is sparsely populated; not documented with fixed enum values.
