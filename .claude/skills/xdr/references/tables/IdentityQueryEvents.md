# IdentityQueryEvents

Directory query events from **Microsoft Defender for Identity (MDI)**:
- **LDAP queries** against AD domain controllers
- **SAMR queries** (Security Account Manager Remote — group/user enumeration)
- **DNS queries** to on-prem DCs (monitored by MDI sensors)

Both Defender and Sentinel. **Requires MDI deployment** — table empty without it. `Application` = `Active Directory` in all observed rows.

`ReportId` is a `string` (GUID) — globally unique per event, safe to join on alone.

## ActionType values (confirmed 2026-04, 30d)

| ActionType | Protocol | Volume |
|---|---|---|
| `DNS query` | `Dns` | High (~223k/30d) |
| `LDAP query` | `Ldap` | Medium (~13k/30d) |
| `SAMR query` | `Samr` | Low (~1.5k/30d) |

## QueryType values by ActionType (confirmed 2026-04)

**DNS query**: `Ns`, `Srv`, `Text`, `Dnskey`, `Axfr`, `Mx`

**LDAP query**: `AllTrustDomains`, `AllObjects`, `AllUsers`, `None`, `AllSecurityPrincipals`, `AllGroups`, `AllComputers`, `AllAccounts`

**SAMR query**: `QueryGroup`, `QueryUser`, `EnumerateUsers`, `EnumerateGroups`

## Key columns

| Column | Notes |
|---|---|
| `ActionType` | See above |
| `QueryType` | Sub-type of query (see above) |
| `QueryTarget` | Name of target entity (group name, DNS name, user, etc.); blank for bulk enum queries |
| `Query` | Full query string — populated for LDAP (human-readable search description), **blank for SAMR** |
| `Protocol` | `Ldap`, `Samr`, or `Dns` |
| `DeviceName` | Source device (client that issued the query) |
| `IPAddress` | Source IP |
| `Port` | Source port (int in Defender, **string in Sentinel** — use `toint(Port)`) |
| `DestinationDeviceName` | DC that processed the query |
| `DestinationIPAddress` | DC IP |
| `DestinationPort` | DC port (int in Defender, **string in Sentinel** — use `toint(DestinationPort)`); 53 for DNS, 389/636 for LDAP, 445 for SAMR |
| `AccountName` / `AccountUpn` / `AccountSid` | Actor — blank when the source is a computer account not associated with a user |
| `AccountObjectId` | Entra object ID — join key to `IdentityInfo` |
| `Location` | `INTERNAL_NETWORK` for on-prem queries |

## AdditionalFields — native dynamic in both Defender and Sentinel

`gettype()` = `"dictionary"` in both sources. Direct property access works — no `parse_json()` needed. Defender rows include the `@odata.type` wrapper key but it does not affect property access.

**Common keys (all ActionTypes):**

| Key | Notes |
|---|---|
| `ActionTypeInner` | Fine-grained type: `ldapquery`, `samrquery`, `dnsquery` |
| `Count` | Aggregation count (string) |
| `Category` | MDI threat category — **only present when MDI flags the event** (e.g. `"Discovery"`) |
| `AttackTechniques` | Comma-separated plain string (NOT JSON array) — only present when MDI flags, e.g. `"Domain Trust Discovery (T1482)"`, `"Permission Groups Discovery (T1069), Account Discovery (T1087)"` |
| `SourceComputerObjectGuid` | Source device GUID (AD object) |
| `SourceComputerId` | Source device ID; fallback format `"computer <IP>"` when device is not domain-joined/known |
| `SourceComputerSid` | Source device SID |
| `SourceComputerOperatingSystem` / `...Version` / `...Type` | Source device OS info |
| `DestinationComputerObjectGuid` / `...OperatingSystem` / `...Type` | DC metadata |

**LDAP-specific keys:**

| Key | Notes |
|---|---|
| `BaseObject` | LDAP base DN (e.g. `"DC=contoso,DC=com"`) |
| `LdapSearchScope` | `"WholeSubtree"`, `"SingleLevel"`, `"BaseObject"` |
| `SearchFilter` | Full LDAP filter string (e.g. `" (objectClass=trustedDomain) "`) |

**SAMR-specific keys:**

| Key | Notes |
|---|---|
| `QueriedUniqueEntityId` | Object ID of the queried group or user |

**Sentinel-only enrichment keys** (absent from Defender rows):
`ARG.TASK`, `FROM.DEVICE`, `TO.DEVICE`, `ACTOR.DEVICE`

## Column type divergences (Defender vs Sentinel)

| Column | Defender | Sentinel |
|---|---|---|
| `Port` | `int` | `string` |
| `DestinationPort` | `int` | `string` |

Use `toint()` for cross-platform numeric comparisons.

## Category / AttackTechniques — MDI-flagged events only

`Category` and `AttackTechniques` in `AdditionalFields` are absent from routine benign events — only populated when MDI has a threat signal. Same pattern as `IdentityDirectoryEvents` and `IdentityLogonEvents`.

`AttackTechniques` is a **comma-separated plain string**, not a JSON array. Use `has "T1069"` for T-number pre-filtering before splitting.

## Hunting patterns

```kql
// LDAP reconnaissance — queries MDI flagged as Discovery
IdentityQueryEvents
| where Timestamp > ago(7d)
| where ActionType == "LDAP query"
| where isnotempty(tostring(AdditionalFields.Category))
| extend Category = tostring(AdditionalFields.Category)
| extend Techniques = tostring(AdditionalFields.AttackTechniques)
| extend SearchFilter = tostring(AdditionalFields.SearchFilter)
| extend BaseObject = tostring(AdditionalFields.BaseObject)
| project Timestamp, DeviceName, IPAddress, DestinationDeviceName, QueryType, SearchFilter, BaseObject, Category, Techniques
| sort by Timestamp desc

// SAMR group enumeration — lateral movement recon
IdentityQueryEvents
| where Timestamp > ago(7d)
| where ActionType == "SAMR query"
| summarize Count=count(), Groups=make_set(QueryTarget,100) by DeviceName, IPAddress, bin(Timestamp, 1h)
| where Count > 5
| sort by Count desc

// All MDI-flagged query events
IdentityQueryEvents
| where Timestamp > ago(7d)
| where isnotempty(tostring(AdditionalFields.Category))
| extend Category = tostring(AdditionalFields.Category)
| extend Techniques = tostring(AdditionalFields.AttackTechniques)
| project Timestamp, ActionType, QueryType, QueryTarget, DeviceName, IPAddress, AccountUpn, Category, Techniques
| sort by Timestamp desc

// LDAP AllObjects or AllUsers — bulk directory enumeration signal
IdentityQueryEvents
| where Timestamp > ago(7d)
| where ActionType == "LDAP query"
| where QueryType in ("AllObjects", "AllUsers", "AllSecurityPrincipals", "AllAccounts")
| summarize Count=count() by DeviceName, IPAddress, QueryType, bin(Timestamp, 1h)
| sort by Count desc

// DNS zone transfer attempts (AXFR) — data exfil signal
IdentityQueryEvents
| where Timestamp > ago(30d)
| where ActionType == "DNS query" and QueryType == "Axfr"
| project Timestamp, DeviceName, IPAddress, QueryTarget, DestinationDeviceName
| sort by Timestamp desc
```

## Cross-table relationships

- **`IdentityInfo`** — enrich `AccountObjectId` for `Department`, `JobTitle`, `IsAccountEnabled`. See `IdentityInfo.md`.
- **`IdentityDirectoryEvents`** — companion MDI table for AD object changes (group membership, user attribute writes, replication). Both require MDI. Common join key: `AccountObjectId`, or correlate source device via `AdditionalFields.SourceComputerObjectGuid`.
- **`IdentityLogonEvents`** — correlate same source device performing recon then authenticating; join on `DeviceName` + `Timestamp` window.
- **`AlertInfo` / `AlertEvidence`** — MDI recon alerts reference `AccountObjectId` or `DeviceName`; no direct `ReportId` join to `AlertEvidence`.
