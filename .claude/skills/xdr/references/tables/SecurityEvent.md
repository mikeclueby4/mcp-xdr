# SecurityEvent

**Source**: Sentinel / Log Analytics only (`run_sentinel_query`). Not queryable via `run_hunting_query` / Graph API.  
**Time column**: `TimeGenerated`  
**SourceSystem**: `OpsManager` (MMA/AMA agent on Windows machines)  
**Solution**: Security / SecurityInsights  
**Basic log**: Yes (cost-tier implications; ingestion-time DCR supported)

Windows Security Event Log data forwarded from Windows machines via the Log Analytics Agent (MMA) or Azure Monitor Agent (AMA). Each row is one Windows Security event. The table is wide (~200 columns) because every possible Security event field has a dedicated column; most columns are empty for any given EventID.

## Key columns

| Column | Type | Notes |
|---|---|---|
| `TimeGenerated` | datetime | Ingestion timestamp (close to event time, not identical) |
| `EventID` | int | Windows Security Event ID — the primary filter |
| `Activity` | string | Always `"<EventID> - <description>"` e.g. `"4624 - An account was successfully logged on."` — redundant with EventID but useful for display |
| `Computer` | string | NetBIOS hostname of the reporting machine |
| `Account` | string | `DOMAIN\username` of the account context for the event (pre-parsed convenience field) |
| `AccountType` | string | `"User"` or `"Machine"` |
| `SubjectUserName` | string | Initiating account username (for events that have Subject/Actor semantics) |
| `SubjectDomainName` | string | Domain of `SubjectUserName` |
| `SubjectLogonId` | string | Hex logon session ID of the initiating account |
| `TargetUserName` | string | Target account username |
| `TargetDomainName` | string | Domain of `TargetUserName` |
| `TargetLogonId` | string | Hex logon session ID of the target logon |
| `LogonType` | int | Logon type integer (2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 10=RemoteInteractive, etc.) |
| `LogonTypeName` | string | `"<int> - <name>"` e.g. `"4 - Batch"` |
| `IpAddress` | string | Source IP for network logons; `-` when unavailable/local |
| `IpPort` | string | Source port; `-` when unavailable |
| `WorkstationName` | string | Source workstation name for network logons |
| `LogonGuid` | string | GUID linking logon events across DC; `00000000-0000-0000-0000-000000000000` for local/batch logons |
| `AuthenticationPackageName` | string | e.g. `"Negotiate"`, `"Kerberos"`, `"NTLM"` |
| `LmPackageName` | string | NTLM sub-package (e.g. `"NTLM V2"`); `-` when not NTLM |
| `NewProcessName` | string | Full path of new process (4688) |
| `NewProcessId` | string | Hex PID of new process (4688) |
| `ParentProcessName` | string | Full path of parent process (4688) |
| `CommandLine` | string | Command line of new process (4688) — **requires audit policy `Include command line in process creation events`; often empty** |
| `TokenElevationType` | string | UAC elevation type as `%%`-code (see below) |
| `PrivilegeList` | string | Whitespace-separated privilege names for 4672/4673 events |
| `ServiceName` | string | Service name (4697) |
| `ServiceFileName` | string | Service binary path (4697) |
| `ServiceType` | string | Hex service type (4697) |
| `ServiceStartType` | int | Integer start type (4697); 2=auto, 3=demand, 4=disabled |
| `ServiceAccount` | string | Account under which service runs (4697) |
| `ObjectName` | string | Path or name of accessed object (4663/4670) |
| `ObjectType` | string | Object type string (e.g. `"File"`, `"Key"`) |
| `AccessMask` | string | Hex access mask (4663) |
| `Status` | string | Hex NTSTATUS code for failure events (4625) |
| `SubStatus` | string | Hex NTSTATUS sub-status for failure events (4625) |
| `FailureReason` | string | `%%`-code for failure reason (see below) |
| `EventData` | string | Raw event XML — populated for events not fully parsed into named columns (~5% of rows); use `parse_xml()` when needed |
| `_ResourceId` | string | Full ARM resource ID of the source VM — reliable system column |

## %%-prefixed values (un-decoded message insertion strings)

Several string columns contain Windows message insertion string codes like `%%1936`, `%%1842`, `%%2313` instead of human-readable text. These are **not decoded at ingestion** — they remain as raw Windows message table references. Sentinel does not render them.

Known codes encountered in this table:

| Code | Column | Meaning |
|---|---|---|
| `%%1936` | `TokenElevationType` | Default token (no elevation / limited token) |
| `%%1937` | `TokenElevationType` | Full token (elevated / unrestricted) |
| `%%1938` | `TokenElevationType` | Limited token (UAC filtered) |
| `%%1842` | (varies) | `"%%1842"` = "Yes" (e.g. ElevatedToken) |
| `%%1843` | (varies) | `"%%1843"` = "No" |
| `%%1833` | (varies) | Restricted admin mode: "No" |
| `%%2313` | `FailureReason` | Unknown user name or bad password |
| `%%2310` | `FailureReason` | Account currently disabled |

In KQL, filter on the `%%`-code literal, not the English description:
```kql
// Find elevated logons (full token)
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where TokenElevationType == "%%1937"
```

For display purposes, use `case()` to decode:
```kql
| extend ElevationType = case(
    TokenElevationType == "%%1936", "Default",
    TokenElevationType == "%%1937", "Elevated",
    TokenElevationType == "%%1938", "Limited",
    TokenElevationType)
```

## EventID hunting reference

Observed in this tenant (as of 2026-04):

| EventID | Description | Key columns |
|---|---|---|
| 4624 | Successful logon | `LogonType`, `TargetUserName`, `IpAddress`, `AuthenticationPackageName`, `LogonGuid` |
| 4625 | Failed logon | `Status`, `SubStatus`, `FailureReason`, `LogonType`, `TargetUserName`, `IpAddress` |
| 4634 | Logoff | `TargetLogonId` — correlates with 4624 |
| 4648 | Logon with explicit credentials | `SubjectUserName`, `TargetUserName`, `TargetServerName`, `IpAddress`, `CallerProcessName` |
| 4672 | Special privileges assigned to new logon | `SubjectUserName`, `PrivilegeList` |
| 4673 | Privileged service called | `SubjectUserName`, `PrivilegeList`, `ServiceName` |
| 4674 | Operation on privileged object | `SubjectUserName`, `ObjectName`, `PrivilegeList` |
| 4688 | New process created | `NewProcessName`, `ParentProcessName`, `CommandLine` (sparse), `TokenElevationType` |
| 4697 | Service installed | `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`, `ServiceAccount` |
| 4700 | Scheduled task enabled | `TaskName` (in `EventData`) |
| 4702 | Scheduled task updated | `TaskName` (in `EventData`) |
| 4662 | Operation performed on directory object | `ObjectName`, `ObjectType`, `AccessMask` |
| 4663 | Access attempt on object | `ObjectName`, `ObjectType`, `AccessMask`, `HandleId` |
| 4670 | Permissions on object changed | `ObjectName`, `SecurityDescriptor` |
| 4798 | User local group membership enumerated | `TargetUserName` — recon indicator |
| 4799 | Security-enabled local group membership enumerated | `TargetUserName` — recon indicator |
| 4904 | Security event source registered | `SubjectUserName`, `ProcessName` |
| 4905 | Security event source unregistered | `SubjectUserName`, `ProcessName` |
| 4946 | Windows Firewall rule added | See `EventData` |
| 4948 | Windows Firewall rule deleted | See `EventData` |

Common EventIDs absent in this tenant (not configured in audit policy, or domain-only):
`4720` (user created), `4722-4726` (account management), `4728`/`4732`/`4756` (group membership), `4740` (account lockout), `4776` (NTLM validation) — these appear on AD domain controllers, not member servers.

## No dynamic columns

All ~200 columns are `string` or `int`. No `parse_json()` is needed anywhere in this table. The high column count exists because every possible Windows Security event field has a dedicated column; most are empty for any given EventID.

## Column sparsity

The table has ~200 columns. The vast majority are empty for any given event — each EventID uses only a subset. Always `project` only relevant columns.

Confirmed always-empty in observed data:
- `ElevatedToken` (blank even for 4688; use `TokenElevationType` instead)
- `CommandLine` (4688) — empty unless the audit policy "Include command line in process creation events" is enabled via GPO/Intune

`IpAddress` is always `"-"` for local/batch logon types where no remote address exists. Filter with `IpAddress != "-"` to isolate network-sourced logons.

`LogonGuid` is `"00000000-0000-0000-0000-000000000000"` for local logons (type 4/5). Only non-zero for Kerberos-authenticated interactive and network logons to a DC.

`EventData` is populated only for events that lack full column parsing (roughly 5% of rows). Contains raw XML from the Windows event log.

## IpAddress gotcha

`IpAddress` in SecurityEvent is a plain string — no automatic IPv6-mapped form observed in this table (unlike Defender XDR tables). Values are either plain IPv4, plain IPv6, or the literal dash `"-"`. Standard `==` comparison is safe for IP equality. Use `IPV6_MATCH()` only if you expect IPv6-mapped IPv4 from specific data sources.

## Account naming conventions

Different events use different column pairs for the actor vs target:

- **Subject** = actor (who initiated): `SubjectUserName` / `SubjectDomainName` / `SubjectLogonId`
- **Target** = affected account: `TargetUserName` / `TargetDomainName` / `TargetLogonId`
- **Account** = pre-parsed `DOMAIN\username` convenience field (always populated, reflects the primary account context per Microsoft's event description)

For 4624: `SubjectUserName` is the authenticating account (often the machine account `$`); `TargetUserName` is the logged-on user.

## Typical hunting queries

```kql
// Failed logons by source IP (last 24h)
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625
| where IpAddress != "-"
| summarize Failures=count(), Accounts=dcount(TargetUserName) by IpAddress
| sort by Failures desc

// New processes — requires CommandLine audit policy enabled
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where isnotempty(CommandLine)
| project TimeGenerated, Computer, Account, NewProcessName, ParentProcessName, CommandLine

// Service installs (persistence watch)
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4697
| project TimeGenerated, Computer, Account, ServiceName, ServiceFileName, ServiceAccount, ServiceStartType

// Recon: local group enumeration bursts
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (4798, 4799)
| summarize Count=count() by Computer, Account, bin(TimeGenerated, 5m)
| where Count > 20
| sort by Count desc

// Explicit credential use (lateral movement)
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4648
| where TargetServerName !in ("localhost", Computer)
| project TimeGenerated, Computer, SubjectUserName, TargetUserName, TargetServerName, IpAddress, CallerProcessName
```

## When to use SecurityEvent vs MDE tables

For MDE-enrolled endpoints, prefer `DeviceLogonEvents` (logon events) and `DeviceProcessEvents` (4688 analogue) — richer enrichment, `InitiatingProcessCommandLine` always populated (when available), and better process-tree context. Use `SecurityEvent` for machines without MDE coverage: Arc-connected servers, domain controllers, and legacy Windows machines covered only by MMA/AMA.

## Join with other tables

- `Computer` maps to `DeviceInfo.DeviceName` (may need `tolower()` normalization and stripping FQDN suffix — SecurityEvent uses short NetBIOS names, DeviceInfo uses short names too but confirm per environment).
- `_ResourceId` is the ARM path for the VM — use `has` for sub-resource filtering: `| where _ResourceId has "/virtualmachines/vm-name"`.
- Correlate 4624 ↔ 4634 via `TargetLogonId` (within the same `Computer`).

## Ingestion notes

- `SourceSystem` = `"OpsManager"` for both MMA and AMA agents.
- `TimeCollected` = agent collection timestamp; `TimeGenerated` = ingestion timestamp. Both differ slightly from the Windows event's original timestamp (not surfaced as a separate column — it is baked into `TimeGenerated`).
- Marked as a **Basic Log** tier table in some workspace configurations — queries may require explicit tier routing or incur different costs.
- Data volume is heavily driven by audit policy. 4688 (process creation) and 4624/4634/4648 (logon) dominate. AD domain controllers will emit 4740, 4720-4726, 4776 etc. that member servers do not.
