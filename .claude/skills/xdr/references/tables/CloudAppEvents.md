# CloudAppEvents

**Source**: Microsoft Defender for Cloud Apps (MDCA) app connector  
**Time column**: `Timestamp` (also has `TimeGenerated` — same value, Sentinel artifact)  
**ReportId**: `string` (GUID) — format `{TenantNumericId}_{ApplicationId}_{EventGuid}`; globally unique per event; safe to join on alone  
**Prerequisite**: MDCA deployed + Microsoft 365 app connector enabled (Settings > Cloud apps > App connectors > Microsoft 365 activities checkbox). Without this, table is empty.

## What it covers

Enriched audit logs from all SaaS apps connected via MDCA app connectors:

- Microsoft 365 apps (ApplicationId 11161): Exchange Online, SharePoint Online, OneDrive, Teams, Dynamics 365, Viva Engage, Power Automate, Power BI
- Microsoft Exchange Online (20893), SharePoint Online (20892), OneDrive for Business (15600), Microsoft Teams (28375) — also appear as separate ApplicationIds
- Microsoft Azure (12260), Microsoft 365 Copilot Chat (53016)
- Third-party connectors: Dropbox, Salesforce, GitHub, Atlassian, etc.

All rows have `AuditSource = "Defender for Cloud Apps app connector"` in tenants using only the app connector (no access/session proxy). If Conditional Access App Control is deployed, additional values appear: `"Defender for Cloud Apps access control"` / `"Defender for Cloud Apps session control"`.

## Schema highlights

| Column | Type | Notes |
|---|---|---|
| `ActionType` | string | High-cardinality; values are M365 unified audit operation names (e.g. `FileRead`, `MailItemsAccessed`, `FileDownloadedFromBrowser`). |
| `ActivityType` | string | Broader category: `Basic`, `Download`, `Edit`, `Synctolocal`, `Run`, `Read`, `Create`, `Delete`, `Failed`, `View`. Not always populated. |
| `Application` | string | Human name of the app (e.g. `"Microsoft 365"`, `"Microsoft Exchange Online"`). |
| `ApplicationId` | int | MDCA numeric app ID — not the Entra app (client) ID. |
| `AppInstanceId` | int | `0` in most tenants (non-zero when multiple connectors for same app). Combine: `binary_or(binary_shift_left(AppInstanceId, 20), ApplicationId)` to get MDCA App-connector-ID. |
| `AccountObjectId` | string | Entra object ID (GUID). Reliable join key to `IdentityInfo.AccountObjectId`. May be empty for service/application actors. |
| `AccountId` | string | MDCA-internal identifier — may be Entra object ID, UPN, or other depending on app. Less reliable than `AccountObjectId` for cross-table joins. |
| `AccountType` | string | `Regular`, `Admin`, `System`, `Application` |
| `OAuthAppId` | string | Entra client app ID (OAuth 2.0). Populated when `AccountType == "Application"`. Also populated for `Regular` (user) rows when an OAuth app performed the operation on behalf of the user via delegation. Sparse overall for user rows but always present when an OAuth app is involved. Join to `OAuthAppInfo.OAuthAppId`. |
| `IPAddress` | string | May be IPv4 or IPv6. Use `IPV6_MATCH()` for comparisons. |
| `IPCategory` | string | `VPN`, `Corporate`, `Cloud provider`, `Internal`, or empty |
| `IPTags` | dynamic | Array of strings — ISP/provider tags from MDCA enrichment. **Sparse/empty in many tenants.** |
| `ISP` | string | Column name is `ISP` (uppercase) — some docs show `Isp` which is wrong. |
| `IsAnonymousProxy` | bool | MDCA-derived from IP reputation. |
| `ActivityObjects` | dynamic | Array of objects. **Serialization differs by source** — see encoding note below. |
| `RawEventData` | dynamic | Full source audit record. Native dynamic in both sources; `@odata.type` wrapper present in Defender rows only — does not affect field access. |
| `AdditionalFields` | dynamic | MDCA-added enrichment (e.g. `{"IsSatelliteProvider": false}`). Native dynamic in both sources. Defender rows may include `@odata.type` wrapper key; Sentinel rows do not. Both safe to access directly. |
| `UserAgentTags` | dynamic | Array of strings: `"Native client"`, `"Outdated browser"`, `"Outdated operating system"`, `"Robot"`. Sparse. |
| `UncommonForUser` | dynamic | Array of anomalous attribute names. `[]` = enriched, no anomalies. `""` = low-value event, skipped. Negative `LastSeenForUser` value = first time seen. |
| `LastSeenForUser` | dynamic | Keys are attribute names, values are int days since last seen (`0` = today, `-1` = first time, `N` = N days ago). **Serialization differs by source** — see note below. |
| `SessionData` | dynamic | MDCA session ID for Conditional Access App Control sessions. Empty/`{}` in tenants using only the app connector. |
| `IsExternalUser` | bool | True if actor's account does not belong to the tenant domain. |
| `IsImpersonated` | bool | True if action was performed by one user impersonating another. |

## ActivityObjects — serialization differs by source

`ActivityObjects` is a native `dynamic` array in both Defender and Sentinel, but **element serialization differs**:

- **Defender**: elements are JSON-encoded strings (double-serialized). `parse_json(tostring(element))` required.
- **Sentinel**: elements are native JSON objects. Direct property access works.

```kql
// Defender — must parse each element
| extend actor = parse_json(tostring(ActivityObjects[0]))
| extend actorName = tostring(actor.Name)

// Sentinel — direct access works
| extend actorName = tostring(ActivityObjects[0].Name)

// Cross-source safe (union of Defender + Sentinel, or unknown source):
// mv-expand + tostring + parse_json is safe in both cases
| mv-expand RawObj = ActivityObjects
| extend Obj = parse_json(tostring(RawObj))
| where tostring(Obj.Role) == "Actor"
| project Timestamp, ActionType, ActorName=tostring(Obj.Name), ActorId=tostring(Obj.Id)
```

Each element has: `Type` (e.g. `"User"`, `"File"`, `"Folder"`, `"Task"`, `"Email"`, `"Email folder"`, `"Structured object"`, `"Property"`, `"Account"`), `Role` (e.g. `"Actor"`, `"Target object"`, `"Parameter"`, `"To"`, `"From"`), `Name`, `Id`. File/folder elements may also have `ServiceObjectType`.

## LastSeenForUser — serialization differs by source

- **Defender**: `{"@odata.type": "#microsoft.graph.security.dynamicColumnValue", "ActionType@odata.type": "#Int64", "ActionType": 0, ...}` — odata-typed wrapper. Use `parse_json(tostring(LastSeenForUser))` to access cleanly.
- **Sentinel**: `{"ActionType":0,"ISP":0,...}` — plain dict, no wrapper. Direct property access works.

`parse_json(tostring(LastSeenForUser))` is safe in both sources and is the recommended pattern for portability.

## RawEventData

Native dynamic object in both sources — no double-serialization. Direct property access:

```kql
| extend op = tostring(RawEventData.Operation)
| extend workload = tostring(RawEventData.Workload)
| extend userId = tostring(RawEventData.UserId)
| extend recordType = toint(RawEventData.RecordType)
```

`RawEventData.Operation` often matches `ActionType` but can diverge (MDCA maps/renames some operations). Workload-specific fields not surfaced in top-level columns:

- **Endpoint workload** (`Workload:"Endpoint"`): `DeviceName`, `MDATPDeviceId` (→ `DeviceInfo.DeviceId`), `FileSize`, `FileExtension`, `Sha1`, `Sha256`, `PolicyMatchInfo` (nested JSON string), `SensitiveInfoTypeData` (nested JSON string)
- **SharePoint/OneDrive**: `AppAccessContext` (nested JSON string — OAuth delegated access context), `IsManagedDevice` (bool), `IsManagedDevice` also present in Exchange rows
- **General**: `Workload` (`"Endpoint"`, `"OneDrive"`, `"SharePoint"`, `"Exchange"`, `"SecurityComplianceCenter"`, etc.)

Defender rows: `RawEventData` prefixed with `{"@odata.type":"#microsoft.graph.security.dynamicColumnValue",...}` — this metadata key does not interfere with field access. Sentinel rows: no `@odata.type` wrapper.

## Key patterns

### Filter by app and action
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams" and ActionType == "ReactedToMessage"
| extend ReactionType = tostring(RawEventData.MessageReactionType)
| summarize Count=count() by ReactionType
```

### Find anomalous user activity (MDCA enrichment)
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where array_length(parse_json(tostring(UncommonForUser))) > 0
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

### OAuth-delegated user activity (Regular AccountType with OAuthAppId)
```kql
// OAuthAppId is populated for Regular users when an OAuth app performed the action on their behalf
CloudAppEvents
| where Timestamp > ago(7d)
| where AccountType == "Regular" and isnotempty(OAuthAppId)
| summarize Count=count() by OAuthAppId, Application, ActionType
| sort by Count desc
```

### Join to IdentityInfo for user context
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where isnotempty(AccountObjectId)
| join kind=leftouter (
    IdentityInfo
    | summarize arg_max(Timestamp, *) by AccountObjectId
    | project AccountObjectId, Department, JobTitle, City
) on AccountObjectId
```

### Endpoint workload — correlate file events to device
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where tostring(RawEventData.Workload) == "Endpoint"
| extend DeviceName = tostring(RawEventData.DeviceName)
| extend Sha256 = tostring(RawEventData.Sha256)
| project Timestamp, AccountDisplayName, ActionType, DeviceName, Sha256, ObjectName
```

## Cross-table joins

- **`OAuthAppInfo`** — join on `OAuthAppId` to get OAuth app metadata (publisher, permissions). Relevant for `AccountType == "Application"` rows AND for `Regular` user rows where an OAuth app performed the operation.
- **`IdentityInfo`** — join on `AccountObjectId`. Use `arg_max(Timestamp, *) by AccountObjectId` to deduplicate.
- **`AlertEvidence`** — join on `ReportId` (GUID, globally unique) or `AccountObjectId`.
- **`DeviceInfo`** — `RawEventData.MDATPDeviceId` → `DeviceInfo.DeviceId` for endpoint workload events.
- **`EntraIdSignInEvents`** — no direct join key; correlate via `AccountObjectId` + time window.

## Common ActionType values (observed, not exhaustive)

File: `FileRead`, `FileAccessed`, `FileModified`, `FileRenamed`, `FileDeleted`, `FileCreated`, `FileMoved`, `FileRecycled`, `FilePreviewed`, `FileSyncDownloadedFull`, `FileSyncUploadedFull`, `FileDownloaded`, `FileDownloadedFromBrowser`, `FileModifiedExtended`, `FileAccessedExtended`, `FileCreatedOnRemovableMedia`, `SensitivityLabeledFileOpened`

Exchange: `MailItemsAccessed`, `FolderBind`, `AttachmentAccess`, `MoveToDeletedItems`, `SoftDelete`, `Update`, `Create`, `Move`, `MessageReadReceiptReceived`

Other: `Search`, `Validate`, `DlpRuleMatch`/`DLPRuleMatch` (two capitalizations — normalize with `tolower()`), `PlanListRead`, `ReactedToMessage` (Teams)

## Gotchas

- `ActivityObjects` element serialization **differs by source**: Defender = double-serialized strings (need `parse_json(tostring(...))`); Sentinel = native objects (direct access works). Use `mv-expand` + `parse_json(tostring(...))` for cross-source portability.
- `LastSeenForUser` serialization **differs by source**: Defender has `@odata.type` wrapper keys; Sentinel has plain dict. `parse_json(tostring(LastSeenForUser))` is safe in both.
- `AdditionalFields` is native dynamic in both sources; Defender rows may carry an `@odata.type` wrapper key alongside the data. Direct property access (e.g. `.IsSatelliteProvider`) works in both.
- `RawEventData` is native dynamic in both sources. Defender rows have an `@odata.type` prefix key that does not affect field access.
- `DlpRuleMatch` and `DLPRuleMatch` both appear as distinct `ActionType` values. Normalize: `| extend ActionTypeLower = tolower(ActionType)` when grouping DLP events.
- `ISP` column is uppercase — docs sometimes show `Isp` which is wrong.
- `IPTags`, `UserAgentTags`, `SessionData` are sparse/empty in most rows unless MDCA inline proxy is active.
- `LastSeenForUser` and `UncommonForUser` populated only for high-value events — check for non-empty before relying on them.
- `SessionData` is empty in tenants using only the MDCA app connector (not Conditional Access App Control proxy).
- `AccountId` is not always the Entra object ID — use `AccountObjectId` for cross-table joins.
- `OAuthAppId` here is the Entra client app ID (OAuth 2.0 `client_id`). In `OAuthAppInfo`, the primary key is also `OAuthAppId` — same field, direct join.
- `OAuthAppId` is sparse overall but present for **both** `AccountType == "Application"` (app-only) and `AccountType == "Regular"` (OAuth-delegated user access). Always filter `isnotempty(OAuthAppId)` rather than combining with `AccountType` if investigating OAuth app activity broadly.
- `ApplicationId` is MDCA's internal numeric app ID, not the Entra application ID. Do not join `ApplicationId` to Entra app registrations.
- `AppInstanceId` is `0` in all rows in most tenants — non-zero only when multiple connectors for the same app are configured.
- Both `Timestamp` and `TimeGenerated` present (identical values). Use `Timestamp` for Defender queries; `TimeGenerated` for Sentinel queries.
