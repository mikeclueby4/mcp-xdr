# EntraIdSpnSignInEvents

Defender-only (`run_hunting_query`). GA replacement for `AADSpnSignInEventsBeta` (deprecated Dec 2025). Covers service principal and managed identity sign-ins. Requires **Entra ID P2 license** to collect and view.

Uses `Timestamp` (not `TimeGenerated`). Sentinel 400 error — no Sentinel variant.

## Schema

| Column | Type | Notes |
|---|---|---|
| `Timestamp` | datetime | Event time |
| `Application` | string | App display name |
| `ApplicationId` | string | App GUID |
| `ServicePrincipalName` | string | SP display name |
| `ServicePrincipalId` | string | SP object GUID |
| `IsManagedIdentity` | bool | `true` = managed identity, `false` = SP with credentials |
| `IsConfidentialClient` | bool | `true` = client secret/cert (daemon flow); `false` = public client |
| `ErrorCode` | int | `0` = success; see https://aka.ms/AADsigninsErrorCodes |
| `CorrelationId` | string | Sign-in event GUID (groups related requests) |
| `RequestId` | string | Individual request GUID |
| `ReportId` | string | GUID — globally unique per event; safe single-column join |
| `UniqueTokenId` | string | Base64url token ID (not a GUID); use for cross-table token correlation |
| `SessionId` | string | Session identifier — populated when `IsConfidentialClient == true`; blank for public-client SPs |
| `ResourceDisplayName` | string | Resource accessed |
| `ResourceId` | string | Resource GUID |
| `ResourceTenantId` | string | Resource tenant GUID (cross-tenant calls: differs from `TenantId`) |
| `TenantId` | string | Signing-in tenant GUID |
| `IPAddress` | string | Use `IPV6_MATCH()` for comparisons |
| `Country` / `State` / `City` | string | Flat geo — no `parse_json()` needed |
| `Latitude` / `Longitude` | string | Geo coordinates as strings |
| `GatewayJA4` | string | TLS fingerprint; populated when Global Secure Access is in path |
| `UserAgent` | string | HTTP User-Agent string of the SP client |

No `AdditionalFields`, no `dynamic`-typed columns — schema is entirely flat.

## IsManagedIdentity / IsConfidentialClient matrix

| `IsManagedIdentity` | `IsConfidentialClient` | Meaning |
|---|---|---|
| `false` | `true` | SP with client secret/cert (most daemon apps) |
| `true` | `true` | Managed identity (system/user-assigned) |
| `false` | `false` | Public client SP (uncommon — no credential) |
| `true` | `false` | Managed identity without confidential flag (rare) |

`IsConfidentialClient == false` rows typically have blank `SessionId`.

## ErrorCode common values

`0` = success. Other values: look up at https://aka.ms/AADsigninsErrorCodes. Confirmed live values: `7000222` (application is disabled / missing app role assignment), `90033` (service unavailable). Failed auth = `ErrorCode != 0`.

## Column name gotchas — vs EntraIdSignInEvents

`EntraIdSpnSignInEvents` has **no** `AccountUpn`, `AccountObjectId`, `EntraIdDeviceId`, `DeviceName`, `DeviceTrustType`, `ConditionalAccessPolicies`, `LogonType`, `IsSignInThroughGlobalSecureAccess` — these are user sign-in columns and do not exist here.

Identity for SPs is in `ServicePrincipalName` / `ServicePrincipalId`, not `AccountUpn`.

## ReportId is GUID — safe single-column join

Unlike `Device*` tables where `ReportId` is a non-unique long, `ReportId` here is a GUID string (same pattern as Email*/Identity* tables). Single-column join is safe.

## Cross-table correlation

- Join to `EntraIdSignInEvents` on `CorrelationId` to find user sign-ins that triggered SP token issuance in the same flow.
- Join to `IdentityInfo` on `ServicePrincipalId == AccountObjectId` for SP metadata enrichment — verify `AccountType == "Application"` to avoid collisions with user object IDs.
- `UniqueTokenId` correlates with `AADServicePrincipalSignInLogs` (Sentinel) on `UniqueTokenIdentifier` for cross-source analysis.
- `ResourceTenantId != TenantId` identifies cross-tenant SP access.

## Hunting patterns

```kql
// Failed SP sign-ins by error code
EntraIdSpnSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| summarize Count=count() by ServicePrincipalName, ErrorCode
| sort by Count desc

// Managed identity sign-ins to unusual resources
EntraIdSpnSignInEvents
| where Timestamp > ago(7d)
| where IsManagedIdentity == true
| summarize Count=count() by ServicePrincipalName, ResourceDisplayName
| sort by Count desc

// SPs signing in from unusual countries
EntraIdSpnSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where Country !in ("SE", "US", "NL")   // adjust to expected countries
| summarize Count=count() by ServicePrincipalName, Country, IPAddress
| sort by Count desc

// Cross-tenant SP access (SP in one tenant accessing another tenant's resource)
EntraIdSpnSignInEvents
| where Timestamp > ago(7d)
| where ResourceTenantId != TenantId
| summarize Count=count() by ServicePrincipalName, ResourceDisplayName, ResourceTenantId
| sort by Count desc
```

## Sentinel equivalent

No direct equivalent in Sentinel schema. For SP sign-in coverage via Sentinel:
- `AADServicePrincipalSignInLogs` — SP sign-ins
- `AADManagedIdentitySignInLogs` — managed identity sign-ins

`UniqueTokenId` in this table corresponds to `UniqueTokenIdentifier` in `AADServicePrincipalSignInLogs`.
