# OAuthAppInfo — Table Notes

## Column names

The app ID column is **`OAuthAppId`** (not `AppId`, `ApplicationId`, or `ClientId`):
```kql
| where OAuthAppId == "3a03d746-2087-4e85-ac2d-5da40dcc9af5"
```

## Snapshot behaviour

The table stores one row per app per day — the same app appears many times across the retention window. Queries that don't deduplicate will return one row per snapshot, not one row per app:
```kql
// Count distinct apps (not snapshots):
| summarize dcount(OAuthAppId)

// Get the latest snapshot per app:
| summarize arg_max(Timestamp, *) by OAuthAppId
```

## `Permissions` column

`Permissions` is a `dynamic` array of objects. Each element has these keys:
- `PermissionType` — `"Application"` or `"Delegated"`
- `PermissionValue` — e.g. `"AuditLog.Read.All"`
- `PrivilegeLevel` — `"High"`, `"Low"`, or `"NA"`
- `TargetAppDisplayName` — e.g. `"Microsoft Graph"`
- `InUse` — `"Not supported"` (field is unreliable; treat as absent)

Expand to filter by permission:
```kql
| mv-expand perm = Permissions
| where tostring(perm.PermissionValue) == "AuditLog.Read.All"
```

## `VerifiedPublisher` column

`VerifiedPublisher` is a `dynamic` object. An empty object `{}` means the publisher is unverified — this is the common case for internal apps.

## Join with CloudAppEvents

`CloudAppEvents` has an `OAuthAppId` column (string, Entra OAuth client_id) on every row where an OAuth app performed the action. Join on `OAuthAppId` to correlate live activity with the app inventory.

## `OAuthAppUserConsentInfo` does not exist — it was never a real table

`OAuthAppUserConsentInfo` **does not exist and never did** — it has zero official documentation, zero web references, and returns a semantic error in every tenant. Do not generate queries against it.

`OAuthAppInfo` (released April 2025, currently in Preview) is the **only** OAuth-related Advanced Hunting table. It requires app governance to be enabled in Microsoft Defender for Cloud Apps.

Per-user consent data is not available in Advanced Hunting at all. To identify which users consented to a specific app:
- Use `SigninLogs` filtered by `AppId` — each successful sign-in represents a user with an active OAuth session
- Use the Microsoft Defender for Cloud Apps portal directly (OAuth apps page shows per-user consent)
