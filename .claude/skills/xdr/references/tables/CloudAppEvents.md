# CloudAppEvents

**Source**: Microsoft Defender for Cloud Apps (MDCA) app connector  
**Time column**: `Timestamp` (also has `TimeGenerated` — same value, Sentinel artifact)  
**ReportId**: `string` (GUID) — globally unique per event; safe to join on alone  
**Prerequisite**: MDCA deployed + Microsoft 365 app connector enabled (Settings > Cloud apps > App connectors > Microsoft 365 activities checkbox). Without this, table is empty.

## What it covers

Enriched audit logs from all SaaS apps connected via MDCA app connectors:

- Microsoft 365 apps (ApplicationId 11161): Exchange Online, SharePoint Online, OneDrive, Teams, Dynamics 365, Viva Engage, Power Automate, Power BI
- Microsoft Exchange Online (20893), SharePoint Online (20892), OneDrive for Business (15600) — also appear as separate ApplicationIds
- Microsoft Azure (12260)
- Microsoft 365 Copilot Chat (53016)
- Third-party connectors: Dropbox, Salesforce, GitHub, Atlassian, etc.

All rows have `AuditSource = "Defender for Cloud Apps app connector"` in tenants using only the app connector (no access/session proxy). If Conditional Access App Control is deployed, additional values appear: "Defender for Cloud Apps access control" / "Defender for Cloud Apps session control".

## Schema highlights

| Column | Type | Notes |
|---|---|---|
| `ActionType` | string | High-cardinality; values are M365 unified audit operation names (e.g. `FileRead`, `MailItemsAccessed`, `FileDownloadedFromBrowser`). |
| `Application` | string | Human name of the app (e.g. `"Microsoft 365"`, `"Microsoft Exchange Online"`). |
| `ApplicationId` | int | MDCA numeric app ID — not the Entra app (client) ID. |
| `AppInstanceId` | int | Used to compute MDCA App-connector-ID. Formula: `binary_or(binary_shift_left(AppInstanceId, 20), ApplicationId)`. In many tenants AppInstanceId is 0 for all rows, making this redundant. |
| `AccountObjectId` | string | Entra object ID (GUID). Reliable join key to `IdentityInfo.AccountObjectId`. May be empty for service/application actors. |
| `AccountId` | string | MDCA-internal identifier — may be Entra object ID, UPN, or other depending on app. Less reliable than `AccountObjectId` for cross-table joins. |
| `AccountType` | string | `Regular`, `Admin`, `System`, `Application` |
| `OAuthAppId` | string | Entra client app ID (OAuth 2.0). Populated when `AccountType == "Application"` (service/app identity acting on behalf of user). Join to `OAuthAppInfo.OAuthAppId` for app metadata. Sparse for user (`Regular`/`Admin`) rows. |
| `IPAddress` | string | May be IPv4 or IPv6. Use `ipv6_is_match()` for comparisons — see kql-facts. |
| `IPCategory` | string | `VPN`, `Cloud provider`, `Internal`, or empty |
| `IPTags` | dynamic | Array of strings — ISP/provider tags from MDCA enrichment (e.g. `"Microsoft Corporation"`, `"Anonymous proxy"`). Native dynamic array; direct indexing works. |
| `IsAnonymousProxy` | bool | MDCA-derived from IP reputation. |
| `ActivityType` | string | Coarser grouping than `ActionType`. Values observed: `Basic`, `Run`, `Edit`, `Read`, `Create`, `Delete`, `Failed`. Not always populated. |
| `ActivityObjects` | dynamic | Array of objects involved. **See encoding note below.** |
| `RawEventData` | dynamic | Full source audit record as native dynamic object. Direct property access works: `RawEventData.Operation`, `RawEventData.UserId`, `RawEventData.Workload`, etc. Rich — contains workload-specific fields not surfaced in top-level columns. |
| `AdditionalFields` | dynamic | MDCA-added enrichment. Native dynamic. |
| `UserAgentTags` | dynamic | Array of strings. Observed values: `"Native client"`, `"Outdated browser"`, `"Outdated operating system"`, `"Robot"`. |
| `UncommonForUser` | dynamic | Array of strings naming attributes that are unusual for this user. Empty array `[]` = event evaluated but nothing unusual. Empty string `""` = low-security event, not evaluated. Negative value in `LastSeenForUser` = first time seen. Strings inside are the attribute names (e.g. `["UserAgent", "ISP"]`). |
| `LastSeenForUser` | dynamic | JSON object — keys are attribute names, values are int days since last seen (0 = today, -1 = first seen, N = N days ago). Has `@odata.type` prefix field — access via `parse_json(tostring(LastSeenForUser))` if needed. |
| `SessionData` | dynamic | MDCA session ID for Conditional Access App Control sessions. Empty/`{}` in tenants using only the app connector (not proxy/session control). |
| `IsExternalUser` | bool | True if the actor's account does not belong to the tenant's domain. |
| `IsImpersonated` | bool | True if the action was performed by one user impersonating another. |

## ActivityObjects encoding — important

The `ActivityObjects` column stores an array. The **raw array** shows double-serialized JSON strings (each element is a JSON-encoded string), but **KQL indexing (`ActivityObjects[0]`) auto-parses** them into a dictionary. Direct property access via index works:

```kql
// Works — KQL auto-parses the double-serialized element on indexing
| extend actor = ActivityObjects[0]
| extend actorName = tostring(actor.Name)
| extend actorId = tostring(actor.Id)
```

Do not call `parse_json()` on the indexed element — it is already a dictionary. The `@odata.type` prefix key may appear on numeric fields (e.g. `"ApplicationId@odata.type": "#Int64"`) — these are type hints and can be ignored.

Each element has: `Type` (e.g. `"User"`, `"File"`, `"Task"`, `"Email"`, `"Structured object"`, `"Property"`, `"Account"`), `Role` (e.g. `"Actor"`, `"Target object"`, `"Parameter"`), `Name`, `Id`.

## RawEventData

Native dynamic object — no double-serialization. Direct property access:

```kql
| extend op = tostring(RawEventData.Operation)
| extend workload = tostring(RawEventData.Workload)
| extend userId = tostring(RawEventData.UserId)
| extend recordType = toint(RawEventData.RecordType)
```

`RawEventData.Operation` often matches `ActionType` but can diverge (MDCA maps/renames some operations). For workload-specific fields (e.g. SharePoint `Site`, Teams `ChatThreadId`, Exchange `MailboxOwnerUPN`), `RawEventData` is the only source.

## Key patterns

### Filter by app and action
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams" and ActionType == "ReactedToMessage"
| extend reactionType = tostring(RawEventData.MessageReactionType)
| summarize Count=count() by reactionType
```

### Find anomalous user activity (MDCA enrichment)
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where array_length(UncommonForUser) > 0
| project Timestamp, AccountDisplayName, Application, ActionType, UncommonForUser, LastSeenForUser, IPAddress, CountryCode
| sort by Timestamp desc
```

### OAuth app (service principal) activity
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where AccountType == "Application" and isnotempty(OAuthAppId)
| summarize Count=count() by OAuthAppId, Application, ActionType
| sort by Count desc
// Join to OAuthAppInfo for app name/publisher:
// | join kind=leftouter (OAuthAppInfo | project OAuthAppId, OAuthAppName) on OAuthAppId
```

### Join to IdentityInfo for user context
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where isnotempty(AccountObjectId)
| join kind=leftouter (
    IdentityInfo
    | where Timestamp > ago(7d)
    | project AccountObjectId, Department, JobTitle, City
) on AccountObjectId
```

### Extract actor from ActivityObjects
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| extend actor = ActivityObjects[0]
| where tostring(actor.Role) == "Actor"
| extend actorName = tostring(actor.Name)
| extend actorId = tostring(actor.Id)
```

## Cross-table joins

- **`OAuthAppInfo`** — join on `OAuthAppId` to get OAuth app metadata (publisher, permissions). Relevant when `AccountType == "Application"`.
- **`IdentityInfo`** — join on `AccountObjectId` for user department, job title, manager.
- **`AlertEvidence`** — `ReportId` (GUID) joins safely; `CloudAppEvents.ReportId` is globally unique.
- **`EntraIdSignInEvents`** — no direct join key; correlate via `AccountObjectId` + time window.

## Common ActionType values (observed, not exhaustive)

File operations: `FileRead`, `FileAccessed`, `FileModified`, `FileRenamed`, `FileDeleted`, `FileCreated`, `FileMoved`, `FileRecycled`, `FilePreviewed`, `FileSyncDownloadedFull`, `FileSyncUploadedFull`, `FileDownloaded`, `FileDownloadedFromBrowser`, `FileModifiedExtended`, `FileAccessedExtended`, `FileCreatedOnRemovableMedia`, `SensitivityLabeledFileOpened`

Exchange: `MailItemsAccessed`, `FolderBind`, `AttachmentAccess`, `MoveToDeletedItems`, `SoftDelete`, `Update`, `Create`, `Move`, `MessageReadReceiptReceived`

Other: `Search`, `Validate`, `DlpRuleMatch`/`DLPRuleMatch` (note: two capitalizations appear — normalize with `tolower()` if grouping), `PlanListRead`

## Gotchas

- `DlpRuleMatch` and `DLPRuleMatch` both appear as distinct `ActionType` values. Always normalize: `| extend ActionTypeLower = tolower(ActionType)` when grouping DLP events.
- `SessionData` is empty in tenants using only the MDCA app connector (not Conditional Access App Control proxy).
- `AccountId` is not always the Entra object ID — use `AccountObjectId` for cross-table joins.
- `OAuthAppId` here is the Entra client app ID (OAuth 2.0 `client_id`). In `OAuthAppInfo`, the primary key is also `OAuthAppId` — same field, direct join.
- `ApplicationId` is MDCA's internal numeric app ID, not the Entra application ID. Do not join `ApplicationId` to Entra app registrations.
- `AppInstanceId` is 0 for all rows in tenants with only a single connector instance per app — the `binary_or` formula in the docs only produces meaningful results when multiple instances exist.
- Both `Timestamp` and `TimeGenerated` are present (identical values). Use `Timestamp` for Defender queries; `TimeGenerated` in Sentinel/Log Analytics queries. 
