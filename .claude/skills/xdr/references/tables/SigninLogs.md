# SigninLogs (+ AADNonInteractiveUserSignInLogs)

Sentinel tables via `run_sentinel_query`. Use `TimeGenerated` (not `Timestamp`).

## union type-mismatch gotcha

`LocationDetails` and `DeviceDetail` have **different types** in the two tables:

| Column | `SigninLogs` | `AADNonInteractiveUserSignInLogs` |
|---|---|---|
| `LocationDetails` | `dynamic` | `string` |
| `DeviceDetail` | `dynamic` | `string` |

After `union`, the merged columns are ambiguous and direct property access fails:
```
SEM0100: 'project' operator: Failed to resolve scalar expression named 'LocationDetails'
```

**Fix:** always wrap in `tostring()` before `parse_json()` — safe regardless of whether the input is dynamic or string:

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| project
    TimeGenerated, UserPrincipalName, AppDisplayName, ResultType, IPAddress,
    Country  = tostring(parse_json(tostring(LocationDetails)).countryOrRegion),
    City     = tostring(parse_json(tostring(LocationDetails)).city),
    OS       = tostring(parse_json(tostring(DeviceDetail)).operatingSystem),
    DeviceId = tostring(parse_json(tostring(DeviceDetail)).deviceId),
    Browser  = tostring(parse_json(tostring(DeviceDetail)).browser)
```

## Key columns

| Column | Notes |
|---|---|
| `UserPrincipalName` | Sign-in identity |
| `IPAddress` | Source IP — use `IPV6_MATCH()` for comparisons |
| `ResultType` | `"0"` = success; non-zero = error code (string, not int) |
| `AppDisplayName` | Application name |
| `LocationDetails` | JSON: `city`, `state`, `countryOrRegion`, `geoCoordinates` |
| `DeviceDetail` | JSON: `deviceId`, `displayName`, `operatingSystem`, `browser`, `isCompliant`, `isManaged`, `trustType` |
| `ConditionalAccessPolicies` | `dynamic` in SigninLogs, `string` in AADNonInteractiveUserSignInLogs — same `tostring()` pattern applies |
| `AuthenticationDetails` | JSON array of auth steps |
| `IsInteractive` | `bool` — `true` for interactive sign-ins only (SigninLogs always true; AADNonInteractive always false) |
| `UniqueTokenIdentifier` | Token ID for cross-table correlation |
| `SessionId` | Session grouping |
| `IsThroughGlobalSecureAccess` | Global Secure Access path indicator |

## ResultType — common codes

`"0"` = success. Common failure codes: `50053` (account locked / malicious IP block), `50126` (wrong password), `50074` (MFA required), `50076` (MFA needed), `70044` (session expired).

## AADNonInteractiveUserSignInLogs-only columns

`SignInEventTypes` (array string, e.g. `["nonInteractiveUser"]`), `ConditionalAccessPoliciesV2` (dynamic, newer format).
