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
