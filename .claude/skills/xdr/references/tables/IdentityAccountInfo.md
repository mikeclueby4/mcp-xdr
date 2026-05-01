# IdentityAccountInfo

Defender-only. Account property snapshot from identity sources (Entra ID, on-prem AD). Not an event stream — one row per account per update cycle. Sentinel 400 errors.

## Snapshot cadence and deduplication

New row written on change detection **or** after 24 hours. Use `ago(7d)` minimum; always deduplicate:

```kql
IdentityAccountInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, *) by AccountUpn
```

`ReportId` is a GUID string (Identity* family — globally unique per snapshot write, not a join key for cross-table correlation).

## SourceProvider values (confirmed)

`AzureActiveDirectory`, `ActiveDirectory`. Use to distinguish cloud-only vs on-prem-synced accounts.

## Type values

`User`, `ServiceAccount` (docs). Only `User` confirmed in live data.

## AccountStatus values

`Enabled`, `Disabled`, `Deleted`.

## Dynamic columns

All are **native dynamic** — direct indexing and `mv-expand` work without `parse_json()`.

| Column | Type | Content |
|---|---|---|
| `GroupMembership` | array | Group **display name strings** (not IDs/GUIDs) |
| `AssignedRoles` | array | Permanently assigned Entra directory role names |
| `EligibleRoles` | array | PIM-eligible roles (not yet activated) |
| `EnrolledMfas` | array | MFA methods and status objects |
| `Tags` | array | MDI-assigned tags |
| `AdditionalFields` | dynamic | Sparse; structure varies |

`GroupMembership` contains display names — not usable for authoritative group membership checks. If you need GUIDs, use `AuditLogs` or Graph API.

`AssignedRoles` captures permanently assigned roles only. PIM activations are not reflected here until the activation write updates this snapshot. For point-in-time role state, use `AuditLogs` PIM activation events.

`EnrolledMfas`, `EligibleRoles`, and `AdditionalFields` may be empty arrays or blank depending on tenant configuration.

## Docs vs live schema discrepancy

Official docs list `DefenderRiskLevel` (int) and `DefenderRiskUpdateTime` (datetime) — **absent from live schema**. Do not reference in queries until confirmed present via `get_schema()`.

`TenantMembershipType` (docs: `Guest`/`Member`) is present in schema but blank in practice in some tenants.

Live schema includes `TimeGenerated` and `SourceSystem` (Log Analytics system columns) — these appear even though the table is Defender-only (no Sentinel rows). Use `Timestamp` for time filtering.

## IdentityInfo vs IdentityAccountInfo

These are distinct tables with overlapping data:

| | `IdentityInfo` | `IdentityAccountInfo` |
|---|---|---|
| Source | Defender + Sentinel | Defender-only |
| Primary key | `AccountObjectId` | `AccountId` / `SourceProviderAccountId` |
| Identity linking | N/A | `IdentityId` links to the owning identity entity |
| Roles | `AssignedRoles` (permanently assigned) | `AssignedRoles` + `EligibleRoles` (PIM) |
| Risk | `RiskLevel`, `RiskStatus` | `SourceProviderRiskLevel` (string), `CriticalityLevel` (int) |

`IdentityInfo` is the standard enrichment join for alert/event tables via `AccountObjectId`. Use `IdentityAccountInfo` when you need PIM-eligible roles, MFA enrollment state, identity-link metadata, or multi-source account federation context.

## Join patterns

```kql
// Enrich events with account metadata
SomeEventTable
| where Timestamp > ago(1d)
| join kind=leftouter (
    IdentityAccountInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, Department, JobTitle, AssignedRoles, GroupMembership, AccountStatus)
      by AccountUpn
) on AccountUpn

// Find accounts with privileged roles
IdentityAccountInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, *) by AccountUpn
| where array_length(AssignedRoles) > 0
| mv-expand Role = AssignedRoles
| project AccountUpn, DisplayName, Department, Role = tostring(Role), AccountStatus

// Find PIM-eligible accounts (not yet activated)
IdentityAccountInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, *) by AccountUpn
| where array_length(EligibleRoles) > 0
| mv-expand EligibleRole = EligibleRoles
| project AccountUpn, EligibleRole = tostring(EligibleRole), AccountStatus
```

## IdentityId and account federation

`IdentityId` links multiple accounts (e.g. on-prem AD + Entra ID for the same person) to a single identity entity. `IsPrimary = true` marks the canonical account for the identity. `IdentityLinkType` values: `Manual`, `StrongId` (system-detected via strong identifiers like SID match).
