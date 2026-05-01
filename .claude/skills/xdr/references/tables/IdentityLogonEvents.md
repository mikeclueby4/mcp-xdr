# IdentityLogonEvents

Identity-layer logon events from two distinct sources:
- **Microsoft Defender for Identity (MDI)**: on-premises AD authentication (Kerberos, NTLM, LDAP)
- **Microsoft Defender for Cloud Apps (MDCA)**: Microsoft online service sign-ins (Azure, M365, Exchange Online, SharePoint, Teams) via OAuth2, SAML, SAS flows

Both Defender and Sentinel. Requires MDI deployment for AD rows; MDCA for cloud rows. Table is empty if neither is deployed.

**Distinct from `DeviceLogonEvents`** which is endpoint-sourced (MDE). `IdentityLogonEvents` covers the identity plane; `DeviceLogonEvents` covers the device plane for the same logon.

`ReportId` is a `string` (GUID) — globally unique per event. Safe to join on alone (unlike Device* tables where `ReportId` is a `long` counter).

## Key columns

| Column | Notes |
|---|---|
| `ActionType` | `LogonSuccess` or `LogonFailed` only |
| `Application` | `Active Directory`, `Microsoft 365`, `Microsoft Exchange Online`, `Microsoft Azure`, `Microsoft SharePoint Online`, `Microsoft Teams` |
| `Protocol` | `Kerberos`, `Ntlm`, or blank (blank = cloud/OAuth flow) |
| `LogonType` | See enum below — very different semantics for AD vs cloud rows |
| `FailureReason` | Populated on `LogonFailed`; often blank on success. Mix of short codes (`WrongPassword`, `AccountLocked`) and long human-readable strings (cloud source). |
| `DeviceName` | Source device (client) for AD rows; often blank for cloud rows |
| `DestinationDeviceName` | DC that processed the authentication (AD rows) |
| `DestinationIPAddress` / `DestinationPort` | DC IP + port (88 = Kerberos, 389 = LDAP) for AD rows |
| `AccountObjectId` | Entra object ID — join key to `IdentityInfo` |
| `Location` | City/country for cloud rows; `INTERNAL_NETWORK` for on-prem AD rows |
| `ISP` | Populated for cloud rows; blank for on-prem |
| `Port` | Source port (int in Defender, **string in Sentinel** — use `toint(Port)`) |
| `DestinationPort` | Same divergence: int in Defender, string in Sentinel |

## ActionType values (confirmed 2026-04)

| ActionType | Count (30d) |
|---|---|
| `LogonSuccess` | ~86k |
| `LogonFailed` | ~48k |

## Protocol values (confirmed 2026-04)

| Protocol | Notes |
|---|---|
| blank | Cloud/OAuth rows (majority of volume) |
| `Kerberos` | AD Kerberos AS/TGS |
| `Ntlm` | AD NTLM |

## LogonType values (confirmed 2026-04)

AD rows use Windows logon type descriptions; cloud rows use OAuth/protocol method strings. These are distinct namespaces in the same column.

**AD-sourced (MDI) LogonType values:**
- `Resource access` — Kerberos TGS resource ticket
- `Failed logon` — failed AD authentication
- `Credentials validation` — NTLM credential check
- `Interactive` — interactive logon
- `Remote desktop` — RDP session

**Cloud-sourced (MDCA) LogonType values (partial, high-volume):**
`OAuth2:Authorize`, `OAuth2:Token`, `SAS:EndAuth`, `SAS:ProcessAuth`, `SAS:BeginAuth`, `Login:login`, `Login:reprocess`, `Login:resume`, `Saml2:processrequest`, `OrgIdWsTrust2:process`, `DeviceAuth:ReprocessTls`, `DeviceAuth:PKeyAuth`, `PermitSso:PermitSso`, `Federation:oauth2msa`, `Rdp:rdp`, `UserInfo:Index`, `Consent:Set`, `Kmsi:kmsi`, `SSPR:end`, and others.

## FailureReason values (confirmed 2026-04)

Blank on `LogonSuccess`. On `LogonFailed`, mix of short AD codes and long cloud strings:
- AD short codes: `Generic`, `WrongPassword`, `AccountLocked`, `UnknownUser`, `OldPassword`, `AccountDisabled`
- Cloud human-readable strings (e.g. `"The account is locked, you've tried to sign in too many times..."`, `"Strong Authentication is required."`, `"Error validating credentials due to invalid username or password."`)

## AdditionalFields — native dynamic in both Defender and Sentinel

`gettype()` = `"dictionary"` in both sources. Direct property access works — no `parse_json()` needed. The `@odata.type` wrapper key is present in Defender rows but does not affect property access.

**AD/MDI rows — key properties:**

| Key | Notes |
|---|---|
| `ActionTypeInner` | Fine-grained type: `failedlogon`, `resourceaccess`, `credentialsvalidation`, `interactivelogon`, `remotedesktop` |
| `KerberosType` | `KerberosAs` (auth service) or `KerberosTgs` (ticket-granting service) |
| `KdcOptions` | KDC flags string (e.g. `"renewableok, canonicalize, renewable, forwardable"`) |
| `Spns` | Target SPNs (e.g. `"krbtgt/DOMAIN"`, `"ldap,cifs"`) |
| `EncryptionType` | e.g. `"aes256ctshmacsha196"` |
| `RequestTicketHash` / `ResponseTicketHash` | Kerberos ticket hashes for TGS rows |
| `IsNtlmV1` | `"true"` / `"false"` string |
| `Count` | Number of events aggregated into this row (string) |
| `Category` | MDI threat category when flagged: `"Initial Access"`, `"Credential Access"`, `"Lateral Movement"` |
| `AttackTechniques` | Comma-separated string (NOT JSON array) when MDI flags a technique, e.g. `"Valid Accounts (T1078), Domain Accounts (T1078.002)"` |
| `SourceComputerId` / `SourceComputerObjectGuid` | Source device GUIDs |
| `SourceComputerSid`, `SourceComputerOperatingSystem`, `SourceComputerOperatingSystemType` | Source device metadata |
| `DestinationComputerObjectGuid`, `DestinationComputerOperatingSystem` | DC metadata |
| `SourceAccountId` / `SourceAccountSid` | Account identifiers (useful when top-level `AccountObjectId` blank) |
| `IsResourceAccountTrustedForUnconstrainedDelegation` | `"True"` / `"False"` string |
| `SourceAccountLastLogonToSourceComputerTime` | Datetime string |
| `IsSourceAccountLocalAdminOnResource` | `"true"` / `"false"` string |

**Cloud/MDCA rows — key properties** (present in Sentinel rows, partially in Defender):
`ARG.CLOUD_SERVICE`, `Request ID`, `Pass-through authentication`, `ACTOR.ALIAS`, `ACTOR.ENTITY_USER`

Note: Sentinel rows for cloud events include `ARG.*` and `ACTOR.*` enrichment keys absent from Defender rows — same pattern as `IdentityDirectoryEvents`.

## UncommonForUser — native dynamic array

`gettype()` = `"array"` in both sources. Contains the names of behavioural features that are unusual for this user (e.g. `["ActivityType", "ActionType", "OSPlatform", "ISP", "UserAgent"]`). Empty array `[]` when nothing unusual. Filter with `array_length(UncommonForUser) > 0` for anomaly hunting.

## LastSeenForUser — native dynamic dict

`gettype()` = `"dictionary"` in both sources. Contains per-feature "days since last seen" counts (as int 0 meaning "first time / not previously seen"). Keys: `ActionType`, `OSPlatform`, `ISP`, `UserAgent`, `CountryCode`, `IPAddress`, `Application`. Defender rows include `@odata.type` wrapper and `FieldName@odata.type: "#Int64"` annotation siblings — ignore these. Access values directly: `toint(LastSeenForUser.IPAddress)`.

## Column type divergences (Defender vs Sentinel)

| Column | Defender | Sentinel |
|---|---|---|
| `Port` | `int` | `string` |
| `DestinationPort` | `int` | `string` |

Use `toint(Port)` and `toint(DestinationPort)` for cross-platform numeric comparisons.

## Sources and data coverage

- **MDI (AD rows)**: on-prem AD authentication only. Requires MDI sensors on DCs. `Protocol` = `Kerberos` or `Ntlm`. `Application` = `Active Directory`. `Location` = `INTERNAL_NETWORK`.
- **MDCA (cloud rows)**: Microsoft online service interactive sign-ins + legacy protocols (ActiveSync etc.). Non-interactive sign-ins not captured here — use `AADNonInteractiveUserSignInLogs` (Sentinel) or `EntraIdSignInEvents` (Defender) instead. `Protocol` = blank. `Location` = city/country.

## Hunting patterns

```kql
// AD brute-force: many failed logons per account
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed" and Application == "Active Directory"
| summarize Failures=count(), Sources=dcount(IPAddress) by AccountUpn, FailureReason
| where Failures > 10
| sort by Failures desc

// MDI-flagged events only (Category/AttackTechniques present)
IdentityLogonEvents
| where Timestamp > ago(7d)
| where isnotempty(tostring(AdditionalFields.Category))
| extend Category = tostring(AdditionalFields.Category), Techniques = tostring(AdditionalFields.AttackTechniques)
| project Timestamp, AccountUpn, DeviceName, DestinationDeviceName, Category, Techniques, LogonType
| sort by Timestamp desc

// Kerberoasting signal: TGS requests flagged by MDI
IdentityLogonEvents
| where Timestamp > ago(7d)
| where tostring(AdditionalFields.KerberosType) == "KerberosTgs"
| where tostring(AdditionalFields.Category) has "Kerberoast"
| project Timestamp, AccountUpn, DeviceName, DestinationDeviceName, AdditionalFields

// Behavioural anomaly: logons unusual for user
IdentityLogonEvents
| where Timestamp > ago(7d)
| where array_length(UncommonForUser) > 0
| extend UnusualDimensions = UncommonForUser
| project Timestamp, AccountUpn, ActionType, Application, IPAddress, Location, UnusualDimensions
| sort by Timestamp desc

// Enrich with IdentityInfo
IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
| join kind=leftouter (
    IdentityInfo | where Timestamp > ago(7d) | summarize arg_max(Timestamp, Department, JobTitle, ManagerUpn) by AccountObjectId
) on AccountObjectId
| project Timestamp, AccountUpn, Department, JobTitle, FailureReason, IPAddress
```

## Cross-table relationships

- **`IdentityInfo`** — enrich on `AccountObjectId` for `Department`, `JobTitle`, `Manager`, `IsAccountEnabled`. See `IdentityInfo.md`.
- **`DeviceLogonEvents`** — endpoint-plane view of the same logon event (MDE-sourced). Correlate on `AccountSid` + `Timestamp` window; do not join on `ReportId` (different GUID namespaces).
- **`IdentityDirectoryEvents`** — companion table for AD object changes and LDAP queries from the same MDI source. Both require MDI deployment.
- **`AlertInfo` / `AlertEvidence`** — MDI alerts link via `AccountUpn` or `AccountObjectId`; no direct `ReportId` join path to `AlertEvidence`.
