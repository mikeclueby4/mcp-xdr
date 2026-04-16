# AuditLogs

Sentinel table (`run_sentinel_query`). Uses `TimeGenerated`. Covers Entra directory audit events: user/group/app/role changes, PIM activations, authentication validation, and service operations.

## PIM role activation operation names

PIM events use specific operation names — generic terms like "Activate" or "role assignment" do not match. Filter on:

```kql
AuditLogs
| where OperationName has_any (
    "Add member to role in PIM completed",
    "Add eligible member to role in PIM completed",
    "Remove member from role in PIM completed",
    "Add member to role completed"
)
```

**Permanently assigned roles do not generate PIM audit events** — no activate/deactivate entries will appear. If `AuditLogs` shows no PIM events for a user but `IdentityInfo.AssignedRoles` shows a role, the role is permanently (not eligible) assigned.

## The `roles` field in InitiatedBy/TargetResources JSON is not the user's role set

`InitiatedBy` and `TargetResources` are JSON blobs. The `roles` array inside them reflects the roles that were used to *authorize that specific audit operation*, not the user's complete role assignments. It is routinely empty (`[]`) even for users with assigned roles.

```kql
// Parse initiating user details
AuditLogs
| extend Actor = parse_json(tostring(InitiatedBy))
| extend ActorUPN = tostring(Actor.user.userPrincipalName)
| extend ActorRolesInContext = Actor.user.roles  // NOT the user's full role set
```

## Searching by target user

`TargetResources` is a JSON array string — use `has` for substring matching, not direct access:

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where TargetResources has "user@example.com" or InitiatedBy has "user@example.com"
```

## NetworkAccessTraffic — empty when GSA not deployed

`NetworkAccessTraffic` (Sentinel) only contains data when **Global Secure Access (Entra Internet Access / Private Access)** is deployed and the GSA client is active on endpoints. In tenants without GSA, the table exists but is always empty — no error, just no rows. Fall back to `DeviceNetworkEvents` (MDE) for network connectivity questions in that case.
