# BehaviorAnalytics and UserPeerAnalytics

Sentinel UEBA output tables. Both are Sentinel-only (solution: `BehaviorAnalyticsInsights`). Query via `run_sentinel_query`. Both appear in Defender Advanced Hunting schema listing but return correct results either way.

## BehaviorAnalytics

One row per analyzed activity/event. UEBA ingests from multiple sources (sign-in logs, audit logs, SecurityEvent, DeviceLogonEvents, AzureActivity, etc.) and enriches each event with behavioral anomaly signals stored in three dynamic fields.

**Prerequisite:** UEBA must be enabled and configured in the Sentinel workspace.

### Schema notes

- `TimeGenerated` — event occurrence time. `TimeProcessed` — when UEBA engine processed it.
- `ActivityType` — high-level category. `ActionType` — normalized action name. Values are not a fixed enum; they reflect the source event type. Confirmed values include:
  - `ActivityType`: `Logon`, `LogOn`, `FailedLogOn`, `ProcessTracking`, `Administrative`, `Policy`, `GroupManagement`, `UserManagement`, `ApplicationManagement`, `RoleManagement`
  - `ActionType`: `Logon_Success`, `Logon_Failure_Session expired`, `LogOn_Success`, `Sign-in`, `Process Creation`, `SpecialPrivilegesLogon`, `ExplicitCredentialsLogon`, `Add member to group`, `Update user`, etc.
  - Note: casing inconsistency between `Logon`/`LogOn` ActivityType values is as-observed in live data — not a schema bug.
- `EventSource` — original log source category (e.g., `Authentication`, `SecurityEvent`).
- `NativeTableName` — original Log Analytics table the event came from (e.g., `AADServicePrincipalSignInLogs`, `SecurityEvent`).
- `UserName` / `UserPrincipalName` — reliably populated (~99.5% fill on rows with `InvestigationPriority > 0`); blank on some service-principal or system rows.
- `ActorName` / `ActorPrincipalName` — sparsely populated (actor vs target context); do not rely on as primary identity fields. Use `UsersInsights.AccountObjectID` for object ID.
- `InvestigationPriority` — `int`, 0–10. 0 = benign/baseline; 10 = highly anomalous. Most rows are 0. Filter `InvestigationPriority > 0` for anomaly-focused hunting.
- `SourceSystem` — source log category (e.g., `AAD`, `Azure`, `MicrosoftAzure`), not the original table name.

### Dynamic columns — all native dynamic (no parse_json needed)

`UsersInsights`, `DevicesInsights`, `ActivityInsights` are all `gettype()` = `"dictionary"` — direct property access works. `bag_keys()` works on all three. No `parse_json(tostring())` needed.

#### UsersInsights keys (confirmed live)
`AccountDisplayName`, `AccountDomain`, `AccountObjectID`, `OnPremisesSID`, `BlastRadius` (Low/Medium/High), `IsDormantAccount`, `IsLocalAdmin`, `IsNewAccount`, `UserId`, `UserType`

`AccountObjectID` is the primary join key to `UserPeerAnalytics` and `IdentityInfo`.

#### DevicesInsights keys (confirmed live)
`GeoCity`, `GeoCountry`, `ISP`, `Browser`, `DeviceFamily`, `DeviceType`, `OperatingSystem`, `UserAgent`, `UserAgentFamily`, `ThreatIntelIndicatorDescription`, `ThreatIntelIndicatorType`

Not all keys are populated on every row; the set depends on the source event.

#### ActivityInsights keys (confirmed live)
Boolean flags (string `"True"`/`"False"`) — examples:
`ActionUncommonlyPerformedByUser`, `ActionUncommonlyPerformedAmongPeers`, `FirstTimeUserPerformedAction`, `ActionUncommonlyPerformedInTenant`, `FirstTimeActionPerformedInTenant`, `AppUncommonlyUsedByUser`, `AppUncommonlyUsedAmongPeers`, `FirstTimeUserUsedApp`, `CountryUncommonlyConnectedFromByUser`, `CountryUncommonlyConnectedFromAmongPeers`, `FirstTimeUserConnectedFromCountry`, `DeviceUncommonlyUsedByUser`, `DeviceUncommonlyUsedAmongPeers`, `FirstTimeUserConnectedFromDevice`, `ISPUncommonlyUsedByUser`, `BrowserUncommonlyUsedByUser`, `UncommonHighVolumeOfActions`, `UnusualNumberOfAADConditionalAccessFailures`, `UnusualNumberOfUsersAddedToGroup`

Scalar context keys also present: `Resource`, `App`, `LastTimeUserPerformedAction` (timestamp string), `EventResult`, `EventResultDetails`, `LogonMethod`, `EventCount`, `MandatoryLabel`, `NewProcessName`, `ParentProcessName`, etc. — schema varies by `ActivityType`.

ActivityInsights boolean flags are **strings** (`"True"`/`"False"`), not booleans. Filter with `== "True"`.

### Hunting patterns

```kql
// High-priority anomalies: filter and extract key signals
BehaviorAnalytics
| where TimeGenerated > ago(7d)
| where InvestigationPriority > 3
| extend
    AccountObjectID = tostring(UsersInsights.AccountObjectID),
    AccountName     = tostring(UsersInsights.AccountDisplayName),
    Country         = tostring(DevicesInsights.GeoCountry),
    TIType          = tostring(DevicesInsights.ThreatIntelIndicatorType),
    UncommonAction  = tostring(ActivityInsights.ActionUncommonlyPerformedByUser),
    UncommonCountry = tostring(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    Resource        = tostring(ActivityInsights.Resource)
| project TimeGenerated, ActivityType, ActionType, AccountName, UserName,
          SourceIPAddress, Country, TIType, UncommonAction, UncommonCountry,
          Resource, InvestigationPriority
| sort by InvestigationPriority desc

// Impossible travel / new country — first-time country per user
BehaviorAnalytics
| where TimeGenerated > ago(7d)
| where tostring(ActivityInsights.FirstTimeUserConnectedFromCountry) == "True"
| extend Country = tostring(DevicesInsights.GeoCountry)
| project TimeGenerated, UserName, SourceIPAddress, Country,
          ActivityType, ActionType, InvestigationPriority
| sort by InvestigationPriority desc

// Threat intel hit on source IP
BehaviorAnalytics
| where TimeGenerated > ago(7d)
| where isnotempty(tostring(DevicesInsights.ThreatIntelIndicatorType))
| extend TIType = tostring(DevicesInsights.ThreatIntelIndicatorType),
         TIDesc = tostring(DevicesInsights.ThreatIntelIndicatorDescription)
| project TimeGenerated, UserName, SourceIPAddress, TIType, TIDesc,
          ActivityType, InvestigationPriority
| sort by InvestigationPriority desc
```

---

## UserPeerAnalytics

Peer-group table: for each user, a ranked list of their closest behavioural peers (users with similar activity patterns). Updated on a periodic schedule — not an event stream.

### Schema notes

- `UserId` — Entra object ID of the subject user (GUID, no `urn:` prefix).
- `PeerUserId` — Entra object ID of the peer user.
- `Rank` — peer similarity rank, 1 = closest. Observed range: 1–20.
- `UserPrincipalName`, `UserName`, `PeerUserPrincipalName`, `PeerUserName` — **always blank** in live data (confirmed). Join to `IdentityInfo` on `AccountObjectId` to resolve names.
- `AADTenantId` — the Entra tenant ID (may differ from `TenantId` in multi-tenant setups).
- Table is update-append: the same (UserId, PeerUserId, Rank) combination appears in multiple rows across different `TimeGenerated` values. **Deduplicate with `summarize arg_max(TimeGenerated, *) by UserId, PeerUserId`** before analysis.

### Join key: BehaviorAnalytics → UserPeerAnalytics

The join key is `UsersInsights.AccountObjectID` (from BehaviorAnalytics) == `UserPeerAnalytics.UserId`. Note: `BehaviorAnalytics.UserId` does not exist as a top-level column — extract from the dynamic field.

```kql
// Find peers of anomalous users to widen investigation scope
let AnomalousUsers =
    BehaviorAnalytics
    | where TimeGenerated > ago(7d)
    | where InvestigationPriority > 5
    | extend AccountObjectID = tostring(UsersInsights.AccountObjectID)
    | where isnotempty(AccountObjectID)
    | distinct AccountObjectID;
// Get their top-5 peers, deduplicated
UserPeerAnalytics
| where TimeGenerated > ago(14d)
| summarize arg_max(TimeGenerated, *) by UserId, PeerUserId
| where UserId in (AnomalousUsers)
| where Rank <= 5
| join kind=leftouter (
    IdentityInfo
    | summarize arg_max(TimeGenerated, AccountUpn, AccountDisplayName) by AccountObjectId
) on $left.PeerUserId == $right.AccountObjectId
| project UserId, PeerUserId, Rank, AccountUpn, AccountDisplayName
| sort by UserId, Rank asc

// Resolve names for both subject and peer via IdentityInfo
UserPeerAnalytics
| where TimeGenerated > ago(14d)
| summarize arg_max(TimeGenerated, *) by UserId, PeerUserId
| where Rank <= 3
| join kind=leftouter (
    IdentityInfo | summarize arg_max(TimeGenerated, AccountUpn) by AccountObjectId
) on $left.UserId == $right.AccountObjectId
| rename AccountUpn to SubjectUPN
| join kind=leftouter (
    IdentityInfo | summarize arg_max(TimeGenerated, AccountUpn) by AccountObjectId
) on $left.PeerUserId == $right.AccountObjectId
| rename AccountUpn to PeerUPN
| project SubjectUPN, PeerUPN, Rank
| sort by SubjectUPN, Rank asc
```

---

## Cross-table notes

- `IdentityInfo` is the standard enrichment join for both tables: join on `AccountObjectId` (IdentityInfo) == `UsersInsights.AccountObjectID` (BehaviorAnalytics) or `UserId`/`PeerUserId` (UserPeerAnalytics).
- `SecurityAlert` / `SecurityIncident` may reference `InvestigationPriority` for the same entities — correlate via `AccountObjectID` if hunting across both.
- `BehaviorAnalytics.NativeTableName` can be used to trace the original source event back to its native table for cross-investigation.
