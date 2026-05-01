# AlertInfo + AlertEvidence

These two tables are tightly coupled: `AlertInfo` has one row per alert; `AlertEvidence` has one row per entity per alert. Join on `AlertId`. Both tables are present in Defender and Sentinel.

No `ReportId` column in either table.

---

## AlertInfo

One row per alert. Covers all Defender product sources plus Sentinel analytics alerts.

### Schema (Defender + Sentinel)

| Column | Type | Notes |
|---|---|---|
| `Timestamp` / `TimeGenerated` | datetime | Same value; both populated in both sources |
| `AlertId` | string | Unique per alert. Source-prefix encoded (see below) |
| `Title` | string | Alert name |
| `Category` | string | Single MITRE tactic string (not a JSON array) — e.g. `"Persistence"`, `"InitialAccess"` |
| `Severity` | string | `"High"`, `"Medium"`, `"Low"`, `"Informational"` |
| `ServiceSource` | string | Which product generated the alert (see below) |
| `DetectionSource` | string | Detection engine within the product |
| `AttackTechniques` | string | **JSON array string** — e.g. `'["Valid Accounts (T1078)","Cloud Accounts (T1078.004)"]'` |
| `MachineGroup` | string | **Defender-only** (N/A in Sentinel) |
| `SentinelWorkspaceIds` | string | **Defender-only** (N/A in Sentinel) |

**`Category` in AlertInfo is a plain string** — not a JSON array. `AttackTechniques` IS a JSON array string. Use `parse_json(AttackTechniques)` + `mv-expand` to work with individual techniques.

### AlertId prefix encoding

`AlertId` prefix encodes the source product (confirmed live):

| Prefix | Source |
|---|---|
| `sn` | Microsoft Sentinel analytics alert |
| `fa` | Microsoft Defender for Office 365 |
| `ca` | Microsoft Defender for Cloud Apps |
| `da` | Microsoft Defender for Endpoint |
| `aa` | Microsoft Defender for Identity |

Useful for filtering alerts by product without joining to `ServiceSource`:
```kql
AlertInfo
| where Timestamp > ago(7d)
| where AlertId startswith "da"   // MDE alerts only
```

### ServiceSource confirmed values

`Microsoft Sentinel`, `Microsoft Defender for Office 365`, `Microsoft Defender for Cloud Apps`, `Microsoft Defender for Endpoint`, `Microsoft Defender for Identity`

### DetectionSource confirmed values

`Scheduled Alerts`, `NRT Alerts`, `Microsoft Defender for Office 365`, `Cloud App Security`, `Custom TI`, `Antivirus`, `Microsoft Defender for Identity`

### Category confirmed values (MITRE tactic names, single string)

`Persistence`, `InitialAccess`, `CommandAndControl`, `Execution`, `Collection`, `SuspiciousActivity`, `CredentialAccess`, `DefenseEvasion`, `PrivilegeEscalation`, `Exfiltration`, `Impact`, `Discovery`, `Malware`

---

## AlertEvidence

One row per entity per alert. The flat columns (`FileName`, `AccountUpn`, `DeviceId`, `RemoteIP`, etc.) are populated based on `EntityType` — most are blank for a given row.

### Schema (Defender + Sentinel)

| Column | Type D | Type S | Notes |
|---|---|---|---|
| `Timestamp` / `TimeGenerated` | datetime | datetime | |
| `AlertId` | string | string | Join key to `AlertInfo` |
| `Title` | string | string | Duplicates AlertInfo.Title |
| `Categories` | string | string | **JSON array string** — e.g. `'["Persistence"]'`. Note: plural, unlike AlertInfo.Category |
| `AttackTechniques` | string | string | JSON array string — same format as AlertInfo.AttackTechniques |
| `ServiceSource` | string | string | |
| `DetectionSource` | string | string | |
| `EntityType` | string | string | Type of entity (see below) |
| `EvidenceRole` | string | string | `"Impacted"` or `"Related"` |
| `EvidenceDirection` | string | string | Usually blank; `"Source"`, `"Destination"`, `"Suspect"`, `"Related"` when populated |
| `Severity` | string | string | Duplicates AlertInfo.Severity |
| `AdditionalFields` | **string** | **dynamic** | Full entity object as JSON (see below) |
| `DeviceId`, `DeviceName` | string | string | Populated for `EntityType == "Machine"` |
| `AccountName`, `AccountDomain`, `AccountSid`, `AccountObjectId`, `AccountUpn` | string | string | Populated for `EntityType == "User"` |
| `FileName`, `FolderPath`, `SHA1`, `SHA256`, `FileSize` | string/long | string/long | Populated for `EntityType == "File"` |
| `RemoteIP`, `RemoteUrl` | string | string | Populated for `EntityType == "Ip"` / `"Url"` |
| `NetworkMessageId`, `EmailSubject` | string | string | Populated for `EntityType == "MailMessage"` |
| `ProcessCommandLine` | string | string | Populated for `EntityType == "Process"` |
| `RegistryKey`, `RegistryValueName`, `RegistryValueData` | string | string | Populated for `EntityType == "RegistryValue"` |
| `Application`, `ApplicationId`, `OAuthApplicationId` | string/int | string/int | Populated for `EntityType == "CloudApplication"` |
| `CloudResource`, `CloudPlatform` | string | string | Cloud entity context |
| `ResourceType`, `ResourceID`, `SubscriptionId` | string | N/A | **Defender-only** |
| `MachineGroup` | string | N/A | **Defender-only** |
| `SentinelWorkspaceIds` | string | N/A | **Defender-only** |

### EntityType confirmed values

`User`, `Machine`, `File`, `Process`, `Ip`, `Url`, `MailMessage`, `MailCluster`, `Mailbox`, `CloudApplication`, `SecurityGroup`, `ActiveDirectoryDomain`, `RegistryValue`

### EvidenceRole and EvidenceDirection

`EvidenceRole`: `"Impacted"` (directly affected entity) or `"Related"` (involved but not primary target).

`EvidenceDirection`: mostly blank. When present: `"Source"`, `"Destination"`, `"Suspect"`, `"Related"`. Only populated for network connection evidence.

### AdditionalFields — serialization divergence

**Defender**: `string` (`gettype()` = `"string"`). Contains full entity JSON object.

**Sentinel**: `dynamic` (`gettype()` = `"dictionary"`). Same content as native dynamic.

Use `parse_json(AdditionalFields)` in both — no `tostring()` wrapper needed (Defender auto-parses the JSON string when fed to `parse_json()`).

The `AdditionalFields` JSON object is the raw entity payload from the alert engine. For `User` entities it contains: `Name`, `NTDomain`, `UPNSuffix`, `Sid`, `AadUserId`, `IsDomainJoined`, `DisplayName`, `Tags` (array), `UserPrincipalName`, `Type`, `Role`. For `Ip` entities: `Address`, `Type`, `Role`.

---

## Key patterns

### Basic alert + evidence join

```kql
AlertInfo
| where Timestamp > ago(7d)
| where Severity == "High"
| join kind=inner AlertEvidence on AlertId
| project Timestamp, AlertId, Title, Category, EntityType, EvidenceRole,
          AccountUpn, DeviceName, RemoteIP, FileName
```

### MITRE technique extraction

Both `AttackTechniques` columns are JSON array strings — use `parse_json()`:

```kql
AlertInfo
| where Timestamp > ago(7d)
| extend Techniques = parse_json(AttackTechniques)
| mv-expand Technique = Techniques to typeof(string)
| summarize AlertCount=dcount(AlertId) by Technique
| sort by AlertCount desc
```

### Find all impacted users across high-severity alerts

```kql
AlertEvidence
| where Timestamp > ago(7d)
| where EntityType == "User" and EvidenceRole == "Impacted"
| join kind=inner (
    AlertInfo | where Severity == "High" | project AlertId, Title, Category
) on AlertId
| summarize Alerts=dcount(AlertId), Titles=make_set(Title) by AccountUpn
| sort by Alerts desc
```

### Cross-reference Device* tables via device evidence

`AlertEvidence` provides `DeviceId` and `DeviceName` for `EntityType == "Machine"` rows. Use these to join to `DeviceProcessEvents`, `DeviceFileEvents`, etc. for surrounding context:

```kql
let AlertDevices = AlertEvidence
    | where Timestamp > ago(1d)
    | where EntityType == "Machine"
    | distinct DeviceId, AlertId;
DeviceProcessEvents
| where Timestamp > ago(1d)
| join kind=inner AlertDevices on DeviceId
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AlertId
```

### AlertEvidence → IdentityInfo enrichment

`AccountObjectId` (Entra Object ID) on `User` entity rows joins to `IdentityInfo.AccountObjectId` for department, manager, etc.

---

## Notable gotchas

**`Category` vs `Categories` naming mismatch**: `AlertInfo.Category` is a single plain string; `AlertEvidence.Categories` is a JSON array string. Accessing `AlertEvidence.Categories` as plain text won't give you a tactic name directly — use `parse_json(Categories)[0]` or `mv-expand`.

**`AttackTechniques` format**: `'["Valid Accounts (T1078)"]'` — each element includes both technique name AND T-number in the same string. Filter with `has "T1078"` for T-number matching, or extract name with `parse_json()`.

**No `ReportId`**: neither table has a `ReportId` column. See the kql-facts.md `ReportId` table for join guidance.

**Alert fanout**: one alert produces 1 `AlertInfo` row but N `AlertEvidence` rows (one per entity). Joining AlertInfo to AlertEvidence and then counting alerts requires `dcount(AlertId)` or `summarize by AlertId` before further aggregation.

**`MachineGroup`, `ResourceType`, `ResourceID`, `SubscriptionId`, `SentinelWorkspaceIds`**: Defender-only columns. Using them in Sentinel queries causes semantic errors.

**`AlertId` prefix `sn`**: Sentinel alerts have AlertIds starting with `sn`. These alerts originate from Sentinel analytics rules, not Defender detection engines. The `ServiceSource` column will be `"Microsoft Sentinel"`.
