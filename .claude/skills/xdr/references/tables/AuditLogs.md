# AuditLogs

Sentinel table (`run_sentinel_query`). Uses `TimeGenerated`. Covers Entra directory audit events: user/group/app/role changes, PIM activations, authentication validation, and service operations.

---

## Category values for Entra audit

Primary categories for identity/access audits:

| Category | Covers |
|---|---|
| `RoleManagement` | Direct role assignments, PIM eligible/active changes, PIM policy updates |
| `GroupManagement` | Group lifecycle (create/delete/restore), membership changes (add/remove member/owner) |
| `UserManagement` | User creation/deletion/property changes |
| `ApplicationManagement` | App registration, service principal, OAuth permission changes |
| `Authentication` | MFA validation, SSPR, legacy auth events |

---

## RoleManagement — PIM operation name taxonomy (confirmed live 2026-05)

Each PIM change emits a paired set of rows with the same `CorrelationId`:
- Human row: `InitiatedBy.user.userPrincipalName` populated
- System row: `InitiatedBy.app.displayName == "MS-PIM"`, empty UPN

Filter to the `requested` row when extracting role names — the role `displayName` is reliably present there; on `completed` system rows the `Role` object in `TargetResources` may be missing or partial.

Two distinct event families under `Category == "RoleManagement"` — do not conflate:

**Eligibility changes** (assignment of *who can activate*):

| OperationName | Meaning |
|---|---|
| `Add eligible member to role in PIM requested (timebound)` / `(permanent)` | Eligible assignment created (human row) |
| `Add eligible member to role in PIM completed (timebound)` / `(permanent)` | Eligible assignment created (system row) |
| `Remove eligible member from role in PIM requested ...` / `... completed ...` | Eligible assignment removed |

**Activations** (eligible user actually exercising the role) — these are what daily admin workflow generates:

| OperationName | Meaning |
|---|---|
| `Add member to role requested (PIM activation)` | User clicked Activate (human row) |
| `Add member to role completed (PIM activation)` | Activation took effect (system row) |
| `Add member to role approval requested (PIM activation)` | Activation needs approver (e.g. Global Admin role) |
| `Add member to role request approved (PIM activation)` | Approver granted the activation |
| `Remove member from role requested (PIM deactivate)` / `... completed (PIM deactivate)` | User clicked Deactivate |
| `Remove member from role (PIM activation expired)` | Auto-expiry at end of activation window |

**Direct (non-PIM) assignments:**

| OperationName | Meaning |
|---|---|
| `Add member to role` / `Remove member from role` | Plain direct assignment (also fires alongside PIM activation as a side-effect) |
| `Add role assignment to role definition` / `Remove ...` | Management-plane assignment |
| `Update role setting in PIM` | PIM role policy change (MFA, max duration) |

**Counting actual activations:** filter on `OperationName has "PIM activation" and OperationName has "requested"` — that gives one row per user action. The `Add member to role` plain rows duplicate activations; the `completed` system rows have empty UPN and missing role-name targets in some cases.

**Permanent direct assignments do not generate PIM events** — nothing under `RoleManagement` for those users. Cross-check `IdentityInfo.AssignedRoles` for the always-on grants.

### Canonical query: PIM activations per user (live-tested)

```kql
AuditLogs
| where TimeGenerated > ago(90d)
| where Category == "RoleManagement"
| where OperationName has "PIM activation" and OperationName has "requested"
| extend Actor = parse_json(tostring(InitiatedBy))
| extend ActorUPN = tostring(Actor.user.userPrincipalName)
| extend TargetArr = parse_json(tostring(TargetResources))
// mv-apply extracts Role + User from TargetResources without unrolling the row (see kql-facts.md)
| mv-apply T = TargetArr on (
    summarize
        RoleName  = take_anyif(tostring(T.displayName), tostring(T.type) == "Role"),
        TargetUPN = take_anyif(tostring(T.userPrincipalName), tostring(T.type) == "User")
)
| summarize Activations = count(), Roles = make_set(RoleName), LastActivation = max(TimeGenerated)
    by TargetUPN
| order by Activations desc
```

### Canonical query: current PIM-eligible state from audit history

`IdentityInfo.AssignedRoles` only shows permanent direct grants. To reconstruct *currently eligible* roles, replay add/remove ops keeping the latest per (user, role):

```kql
AuditLogs
| where TimeGenerated > ago(365d)
| where Category == "RoleManagement"
| where OperationName has "eligible" and OperationName has "requested"
| extend IsAdd = iff(OperationName has "Add", 1, 0)
| extend TargetArr = parse_json(tostring(TargetResources))
| mv-apply T = TargetArr on (
    summarize
        RoleName  = take_anyif(tostring(T.displayName), tostring(T.type) == "Role"),
        TargetUPN = take_anyif(tostring(T.userPrincipalName), tostring(T.type) == "User")
)
| where isnotempty(TargetUPN) and isnotempty(RoleName)
| summarize arg_max(TimeGenerated, IsAdd) by TargetUPN, RoleName
| where IsAdd == 1
```

---

## GroupManagement — use an allowed-ops whitelist

`Category == "GroupManagement"` + `has_any("group","member")` without a whitelist captures large volumes of read/OData noise (e.g. `GroupsODataV4_Get`, `Settings_GetSettingsAsync`). In a moderately active tenant, a 7-day window returns ~1,860 rows of which ~1,550 are system reads. Use an explicit allowlist:

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in (
    "Add member to group", "Remove member from group",
    "Add owner to group",  "Remove owner from group",
    "Add group", "Delete group", "Hard Delete group",
    "Restore Group", "Update group"
)
| where Result =~ "success"
```

---

## Role-assignable groups: membership changes appear as GroupManagement, NOT RoleManagement

When role access is granted through a role-assignable group (common PIM/JIT hardening pattern), the audit event is `Category == "GroupManagement"` / `OperationName == "Add member to group"` — there is **no** corresponding `RoleManagement` event. A complete Entra ID role audit requires both queries:

1. `Category == "RoleManagement"` — direct assignments and PIM eligible/active changes
2. Group membership allowlist above — for group-based role grants

Cross-reference the group `displayName` against known role-assignable group naming conventions (e.g. `PAG-T*`, `PAM-*`) to identify which membership changes represent effective role changes.

---

## Parsing InitiatedBy and TargetResources

Both columns are JSON blobs stored as strings — parse before access. `TargetResources` is an array of typed objects (one per entity touched by the operation): `"Role"`, `"User"`, `"ServicePrincipal"`, `"Group"`, `"Directory"`, `"Request"`, `"Other"`. A single PIM event commonly carries 5–6 elements.

```kql
// Actor
| extend Actor    = parse_json(tostring(InitiatedBy))
| extend ActorUPN = tostring(Actor.user.userPrincipalName)   // empty for SP/MS-PIM actors
| extend ActorApp = tostring(Actor.app.displayName)           // populated for SP/MS-PIM actors
```

**Use `mv-apply`, not `mv-expand`, when extracting from `TargetResources`.** `mv-expand` unrolls one row per array element (5–6× row multiplication, then a re-summarize to pivot back). `mv-apply` runs a sub-pipeline per row and returns the aggregated columns inline — same row count, no pivot step:

```kql
| extend TargetArr = parse_json(tostring(TargetResources))
| mv-apply T = TargetArr on (
    summarize
        RoleName  = take_anyif(tostring(T.displayName),       tostring(T.type) == "Role"),
        TargetUPN = take_anyif(tostring(T.userPrincipalName), tostring(T.type) == "User"),
        GroupName = take_anyif(tostring(T.displayName),       tostring(T.type) == "Group")
)
```

`take_anyif(value, predicate)` returns the value from the first array element matching the predicate, or null. Add one expression per type you need.

**`Target.displayName` semantics depend on `Target.type`:** for `type == "Role"` it's the role name; for `type == "User"` it's the user's display name (NOT the role). Mixing them up is the most common bug — always pair the value-extractor with the type-predicate.

**The `roles` array inside `InitiatedBy`/`TargetResources`** reflects roles used to *authorize that specific audit operation*, not the user's complete role assignments. It is routinely empty (`[]`) even for users with assigned roles.

---

## Searching by target user

`TargetResources` is a JSON array string — use `has` for substring matching rather than parsing when you only need to filter:

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where TargetResources has "user@example.com" or InitiatedBy has "user@example.com"
```

---

## PIM role activation operation names (quick filter reference)

```kql
AuditLogs
| where OperationName in (
    "Add member to role in PIM completed",
    "Add eligible member to role in PIM completed",
    "Remove member from role in PIM completed",
    "Remove eligible member from role in PIM completed",
    "Add member to role completed"
)
```
