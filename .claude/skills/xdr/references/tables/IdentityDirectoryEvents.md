# IdentityDirectoryEvents

**Source**: Microsoft Defender for Identity (MDI). Requires MDI deployed. Both Defender Advanced Hunting and Sentinel. Time column: `Timestamp` (Defender), `TimeGenerated` (Sentinel — both populated with the same value).

Active Directory directory change and system events captured on on-premises domain controllers: group membership changes, password changes, account creation/deletion/disable, attribute edits, DC-targeted execution (PowerShell, WMI, service creation), directory replication, ADCS certificate issuance, private data retrieval (e.g. LAPS), domain trust discovery, SMB file copy.

`Application` is always `"Active Directory"` in observed data — no known variation.

## Schema notes

`DestinationPort` is `int` in Defender, `string` in Sentinel. Use `toint(DestinationPort)` for numeric comparisons in cross-platform queries. Same applies to `Port`.

`ReportId` is a GUID string — globally unique per event; safe to use as join key alone (unlike `Device*` tables).

`AccountObjectId` — the actor's Entra ID object ID. Join to `IdentityInfo` on `AccountObjectId` for enrichment (department, manager, etc.).

## ActionType values (confirmed 2026-04, tenant with MDI on on-prem AD)

| ActionType | ActionTypeInner | Notes |
|---|---|---|
| `Directory Services replication` | `directoryservicesreplication` | Normal DC-DC sync; also triggers on DCSync attacks. Category "Credential Access", MITRE T1003.006 in AdditionalFields when flagged. |
| `PowerShell execution` | `powershellexecution` | Remote PS against DC via WinRM. Category "Lateral Movement". |
| `Domain trusts discovery` | — | LDAP/Kerberos domain trust enumeration. |
| `SMB file copy` | — | File copy to DC share. |
| `Private data retrieval` | `privatedataretrieval` | Access to protected AD attributes (e.g. LAPS passwords). |
| `Group Membership changed` | `groupmembershipchanged` | `AdditionalFields.MembershipChange` = `"added"` or `"removed"`. |
| `Service creation` | `servicecreation` | Remote service created on target. `AdditionalFields.ServiceName`, `AdditionalFields.ServiceCommand`. |
| `ADCS Certificate issuance` | `adcssuccesscertificateissuance` | See ADCS section below. |
| `Account Deleted changed` | — | |
| `User Manager changed` | — | |
| `Account Password changed` | `accountpasswordchanged` | |
| `User Title changed` | — | |
| `Account disabled` | — | |
| `User Phone Number changed` | — | |
| `Account Password change failed` | — | |
| `User Mail changed` | — | |
| `User Account Created` | — | |
| `Account Expiry Time changed` | — | |
| `Account Unlock changed` | — | |
| `WMI execution` | — | |
| `Security Group Created` | — | |
| `Group Policy was created` | — | |

## Column semantics: actor vs target

- `AccountName` / `AccountDomain` / `AccountUpn` / `AccountSid` / `AccountObjectId` / `AccountDisplayName` — the **actor** (who performed the action)
- `TargetAccountUpn` / `TargetAccountDisplayName` — the **subject** (account acted upon), e.g. the account whose group membership changed or password was reset
- `TargetDeviceName` — target device for device-targeted ActionTypes (e.g. `Service creation`)
- `DestinationDeviceName` / `DestinationIPAddress` / `DestinationPort` — the DC that processed the action (server side)
- `DeviceName` / `IPAddress` / `Port` — the source device (client side)

For some ActionTypes (e.g. `Directory Services replication`) the actor columns may be blank; use `AdditionalFields.SourceAccountId` and `AdditionalFields.SourceAccountSid` instead.

## AdditionalFields

Native dynamic (`gettype()` = `"dictionary"`) in both Defender and Sentinel. Direct property access works without `parse_json()`. The `@odata.type` wrapper key (`"#microsoft.graph.security.dynamicColumnValue"`) is present in Defender rows but does not affect property access.

Common keys across most ActionTypes:
- `ActionTypeInner` — lowercase camelCase of the ActionType (e.g. `"groupmembershipchanged"`)
- `Count` — string-typed integer; number of raw events aggregated into this row
- `IsSuccess` — `"True"` / `"False"` (string, not bool). Present on some ActionTypes.
- `Category` — MITRE tactic string, present when MDI flags the event as a threat signal (e.g. `"Credential Access"`, `"Lateral Movement"`, `"Persistence"`)
- `AttackTechniques` — plain comma-separated string of MITRE technique names+IDs (e.g. `"Account Manipulation (T1098)"`)
- `SourceAccountId` / `SourceAccountSid` — actor's AD object GUID and SID
- `TargetAccountId` / `TargetAccountSid` — target account's AD object GUID and SID
- `SourceComputerId` / `SourceComputerObjectGuid` / `SourceComputerSid` / `SourceComputerOperatingSystem` / `SourceComputerOperatingSystemVersion` / `SourceComputerOperatingSystemType`
- `DestinationComputerObjectGuid` / `DestinationComputerOperatingSystem` / `DestinationComputerOperatingSystemVersion` / `DestinationComputerOperatingSystemType`
- `TargetComputerObjectGuid` / `TargetComputerOperatingSystem` etc. — used for device-targeted types (`Service creation`)

ActionType-specific keys:
- `Group Membership changed`: `MembershipChange` = `"added"` or `"removed"`
- `Service creation`: `ServiceName`, `ServiceCommand`
- `ADCS Certificate issuance`: `Attributes` (double-nested — see below), `Disposition`, `Requester`, `RequestId`, `Subject`, `SubjectKeyIdentifier`

### ADCS Certificate issuance — double-nested Attributes

`AdditionalFields.Attributes` is stored as a **JSON-encoded string** (not a nested object). Access inner fields with a second `parse_json()`:

```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "ADCS Certificate issuance"
| extend af = AdditionalFields
| extend AttrsDecoded = parse_json(tostring(af.Attributes))
| project Timestamp, AccountName,
    CertTemplate = tostring(AttrsDecoded.CertificateTemplate),
    Subject      = tostring(af.Subject),
    Requester    = tostring(af.Requester),
    Disposition  = tostring(af.Disposition)
```

`Disposition` value `"3"` = issued successfully.

### Category / AttackTechniques pre-filtering

`Category` and `AttackTechniques` are only populated when MDI has a threat signal associated with the ActionType — they are absent from routine benign events of the same ActionType. Do not use their absence as a benign indicator; use `isnotempty(tostring(AdditionalFields.Category))` to scope queries to MDI-flagged events only.

`AttackTechniques` is a plain comma-separated string (not JSON array). Use `has "T1003"` for cheap bloom-filter pre-filtering before `parse_json()`.

## Sentinel source — AdditionalFields extras

Sentinel rows include additional `ARG.*` and `ACTOR.*` keys not present in Defender rows:
- `ARG.TASK` — human-readable action label (e.g. `"Directory Services replication"`)
- `ACTOR.ACCOUNT` — actor account name
- `ACTOR.ENT*` — additional actor entity fields

These are Sentinel-specific ingestion enrichments; do not rely on them in cross-source queries.

## Hunting patterns

### Sensitive group membership changes
```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Group Membership changed"
| extend MembershipChange = tostring(AdditionalFields.MembershipChange)
| where TargetAccountDisplayName has_any ("Admin", "Domain Admins", "Enterprise Admins", "Schema Admins")
| project Timestamp, AccountName, AccountDomain, TargetAccountUpn,
    TargetAccountDisplayName, MembershipChange, DestinationDeviceName
| sort by Timestamp desc
```

### DCSync detection (replication from non-DC)
```kql
// Legitimate DC-to-DC replication uses the Drsr protocol between known DCs.
// Non-DC source is a strong DCSync signal.
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Directory Services replication"
| where isnotempty(tostring(AdditionalFields.Category))  // MDI flagged it
| project Timestamp, AccountName, AccountSid,
    SrcComputer = DeviceName, SrcIP = IPAddress,
    DstComputer = DestinationDeviceName, DstIP = DestinationIPAddress,
    AttackTechniques = tostring(AdditionalFields.AttackTechniques)
```

### Password resets — who reset whose password
```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Account Password changed"
| project Timestamp, Actor=AccountName, ActorDomain=AccountDomain,
    TargetUpn=TargetAccountUpn, TargetDisplayName=TargetAccountDisplayName,
    DC=DestinationDeviceName
```

### Remote execution on DCs (PowerShell, WMI, service creation)
```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType in ("PowerShell execution", "WMI execution", "Service creation")
| project Timestamp, ActionType, AccountName, AccountDomain,
    SrcDevice=DeviceName, DstDC=DestinationDeviceName,
    ServiceName=tostring(AdditionalFields.ServiceName),
    ServiceCommand=tostring(AdditionalFields.ServiceCommand),
    IsSuccess=tostring(AdditionalFields.IsSuccess)
```

### LAPS / private data retrieval
```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Private data retrieval"
| project Timestamp, AccountName, AccountDomain,
    SrcDevice=DeviceName, DC=DestinationDeviceName
| summarize Count=count(), DCs=make_set(DC) by AccountName, AccountDomain
| sort by Count desc
```

## Cross-table joins

- `IdentityInfo` on `AccountObjectId` — enrich actor with department, manager, job title, enabled status. Use `summarize arg_max(Timestamp, *) by AccountObjectId` on IdentityInfo side.
- `IdentityLogonEvents` on `AccountObjectId` (same actor, nearby time window) — correlate directory changes with logon activity.
- `AlertInfo` / `AlertEvidence` — MDI alerts referencing these events will have entity rows in AlertEvidence matching `AccountSid` or device FQDN.
