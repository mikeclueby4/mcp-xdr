# DeviceLogonEvents

MDE-sourced table. Logon and authentication events on enrolled devices (Windows, macOS, Linux). Available in both Defender Advanced Hunting and Sentinel.

## ActionType values (confirmed live)

| Value | Meaning |
|---|---|
| `LogonSuccess` | Logon completed |
| `LogonAttempted` | Logon initiated (often precedes Success or Failed) |
| `LogonFailed` | Logon rejected |

## LogonType values (confirmed live)

`Interactive`, `RemoteInteractive`, `Network`, `Batch`, `Service`, `CachedInteractive`, `Local`, `Unlock`, `Unknown`

- `Unknown` appears on `LogonAttempted` rows where Windows hasn't yet resolved the logon type.
- `CachedInteractive` = domain logon using cached credentials (offline or no DC contact).
- `RemoteInteractive` = RDP session.
- Docs define `Network` as PsExec or shared resource access (printers, shares).

## FailureReason values (confirmed live)

Appears only on `LogonFailed` rows:
- `InvalidUserNameOrPassword`
- `UnauthorizedLogonType`
- `SamServerError`
- (blank) — reason unavailable

## Protocol values (confirmed live)

`Negotiate`, `NTLM`, `Kerberos`, `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, and blank (most common — blank when protocol not captured or local logon).

## AdditionalFields

`string` in Defender, `dynamic` in Sentinel. In Defender the raw value is a JSON string; `parse_json(AdditionalFields)` parses it in both sources without needing `tostring()` wrapper (the Graph API auto-parses).

**Confirmed keys** (live data, 2026-04):
- `IsLocalLogon` — `bool`: `true` for local logons, `false` for network-sourced logons. Present on virtually all rows.
- `Upn` — `string`: the authenticating user's UPN. Present on `CachedInteractive` logons and some other types. Absent when UPN is not resolved.

In Defender, `parse_json(AdditionalFields)` returns a dictionary with an `@odata.type` wrapper key (`"#microsoft.graph.security.dynamicColumnValue"`) alongside the actual keys — this does **not** block access to `IsLocalLogon` or `Upn` via direct property access.

```kql
// Safe in both Defender and Sentinel
DeviceLogonEvents
| where Timestamp > ago(1d)
| extend af = parse_json(AdditionalFields)
| extend IsLocalLogon = tobool(af.IsLocalLogon)
| extend Upn = tostring(af.Upn)
```

## RemoteIP / RemoteIPType

`RemoteIP` is populated for network-sourced logons. Use `ipv6_is_match()` — not string equality — as IPs may appear in IPv6-mapped form (`::ffff:x.x.x.x`). `RemoteIPType` values include `Public`, `Private`, `Loopback`, `Reserved`.

For local logons, `RemoteIP` is typically `127.0.0.1` or blank.

## Key identity columns

- `AccountDomain` / `AccountName` / `AccountSid` — the account that logged on.
- `LogonId` — Windows logon session ID. Unique per device per boot only; useful for correlating events within a session on the same device (e.g. join to `DeviceProcessEvents` on `LogonId` + `DeviceId`).
- `IsLocalAdmin` — `bool`; `true` if account is a local admin. Blank/false on `LogonAttempted` rows.

## Initiating process columns

Standard MDE `InitiatingProcess*` set. The process that triggered the authentication (typically `lsass.exe`, `svchost.exe`, or an interactive shell). Includes:
- `InitiatingProcessUniqueId` — Process Start Key (long integer string); use for reliable process-chain linking that survives PID reuse.
- `InitiatingProcessSessionId` — Windows session ID of the initiating process.
- `IsInitiatingProcessRemoteSession` / `InitiatingProcessRemoteSessionDeviceName` / `InitiatingProcessRemoteSessionIP` — populated when the initiating process ran under an RDP session.

## ProcessUniqueId — docs vs live schema mismatch

Official docs list `ProcessUniqueId` as a column (Process Start Key for the logon target process). **Confirmed absent from the live schema as of 2026-04-30** — querying it returns a semantic error. Use `InitiatingProcessUniqueId` for process-chain correlation instead.

## ReportId

Type `long` — a local counter, not globally unique. Must use composite (`ReportId` + `DeviceName` + `Timestamp`) to uniquely identify events or join to other Device* tables. See kql-facts.md.

## Platform coverage

Collection not supported on Windows 7 / Windows Server 2008R2. macOS and Linux logon events are collected but field population differs (e.g. `AccountSid` may be absent on non-Windows).

## Common hunting patterns

**Failed logons by account:**
```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
| summarize Failures=count(), Devices=dcount(DeviceName) by AccountName, AccountDomain, FailureReason
| sort by Failures desc
```

**Remote interactive (RDP) logons:**
```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess" and LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, AccountName, AccountDomain, RemoteIP, RemoteDeviceName
| sort by Timestamp desc
```

**Logon session correlation — processes spawned under a logon session:**
```kql
let TargetSession = DeviceLogonEvents
| where Timestamp > ago(1d)
| where AccountName =~ "targetuser" and ActionType == "LogonSuccess"
| project DeviceId, LogonId, LogonTime=Timestamp;
DeviceProcessEvents
| where Timestamp > ago(1d)
| join kind=inner TargetSession on DeviceId, LogonId
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

**Detect accounts logging on as local admin to many devices:**
```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess" and IsLocalAdmin == true
| summarize DeviceCount=dcount(DeviceName) by AccountName, AccountDomain
| where DeviceCount > 5
| sort by DeviceCount desc
```

## Sentinel vs Defender source differences

| Column | Defender type | Sentinel type | Notes |
|---|---|---|---|
| `AdditionalFields` | `string` | `dynamic` | Use `parse_json(AdditionalFields)` in both — no `tostring()` wrapper needed |

`Timestamp` and `TimeGenerated` are both present and equal in value in both sources. Use `Timestamp` for Defender queries, `TimeGenerated` for Sentinel.
