# EntraIdSignInEvents

Defender-only (`run_hunting_query`). GA replacement for `AADSignInEventsBeta` (deprecated Dec 2025). Covers both interactive and non-interactive user sign-ins in one table.

Uses `Timestamp` (not `TimeGenerated`).

## Column name gotchas — common mistakes

| Wrong (from other tables) | Correct in EntraIdSignInEvents |
|---|---|
| `AppName`, `AppDisplayName` | `Application` |
| `AppId` | `ApplicationId` |
| `CountryCode` | `Country` (full country name string, e.g. `"SE"`) |
| `DeviceId` | `EntraIdDeviceId` |
| `UPN`, `UserPrincipalName` | `AccountUpn` |
| `ObjectId`, `UserId` | `AccountObjectId` |

## Key columns

| Column | Type | Notes |
|---|---|---|
| `AccountUpn` | string | Sign-in identity |
| `Application` | string | App display name |
| `ApplicationId` | string | App GUID |
| `LogonType` | string | JSON array, e.g. `["interactiveUser"]` or `["nonInteractiveUser"]` |
| `IPAddress` | string | Use `IPV6_MATCH()` for comparisons |
| `Country` / `State` / `City` | string | Flat geo columns — no parse_json needed |
| `ErrorCode` | int | `0` = success |
| `GatewayJA4` | string | TLS fingerprint; populated when Global Secure Access is deployed |
| `IsSignInThroughGlobalSecureAccess` | bool | Global Secure Access path indicator |
| `EntraIdDeviceId` | string | Device GUID from Entra |
| `DeviceName` | string | Device hostname |
| `DeviceTrustType` | string | Authoritative join type per sign-in: `"Azure AD joined"`, `"Hybrid Azure AD joined"`, `"Azure AD registered"`, blank. Trust over `DeviceInfo.JoinType` when they disagree. |
| `IsManaged` | int | `1` = MDM-enrolled (typically Intune) at sign-in time, `0` = not. Authoritative Intune-management signal. |
| `IsCompliant` | int | `1` = device passed Intune compliance policy at sign-in, `0` = not. |
| `ConditionalAccessPolicies` | string | JSON-encoded — use `parse_json(tostring(...))` |
| `AuthenticationProcessingDetails` | string | JSON-encoded key/value pairs |
| `UniqueTokenId` | string | Token ID for cross-table correlation |
| `ReportId` | string | GUID — globally unique per event |

## Geo columns are flat — no parse_json needed

Unlike `SigninLogs` (Sentinel), geo data is in flat top-level columns, not nested JSON:
```kql
// CORRECT for EntraIdSignInEvents
| project Country, State, City

// WRONG (Sentinel SigninLogs pattern — does not apply here)
| project Country = tostring(parse_json(tostring(LocationDetails)).countryOrRegion)
```

## LogonType filtering

`LogonType` is a JSON array stored as string. Use `contains` not `==`:
```kql
| where LogonType contains "interactiveUser"
| where LogonType contains "nonInteractiveUser"
```

## Authoritative source for device join / management state

`DeviceTrustType`, `IsManaged`, `IsCompliant` are evaluated by Entra at every sign-in — the most reliable per-device source of truth. When `DeviceInfo.JoinType` or `MachineGroup` suggests a different posture, query this table by `EntraIdDeviceId` (which equals `DeviceInfo.AadDeviceId`) and aggregate over a recent window:

```kql
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where EntraIdDeviceId == "<aad-device-id>"
| summarize SignIns=count(),
            ManagedYes=countif(IsManaged==1), ManagedNo=countif(IsManaged==0),
            CompliantYes=countif(IsCompliant==1), CompliantNo=countif(IsCompliant==0),
            TrustTypes=make_set(DeviceTrustType, 5)
```

Devices without an `AadDeviceId` (no Entra identity at all) cannot be queried this way — and cannot be Intune-managed.

## If empty — fallback to Sentinel

Some tenants have RBAC/routing issues that cause `EntraIdSignInEvents` to return no rows via `run_hunting_query`. If so, use `SigninLogs` + `AADNonInteractiveUserSignInLogs` via `run_sentinel_query` (see `SigninLogs.md` for union gotchas).
