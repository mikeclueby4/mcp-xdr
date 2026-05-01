# CloudAuditEvents

**Status**: Preview (as of 2026-05)  
**Source**: Microsoft Defender for Cloud — control plane audit events for cloud infrastructure  
**Time column**: `Timestamp` (also `TimeGenerated` — same value, Log Analytics artifact)  
**Prerequisite**: Microsoft Defender for Cloud deployed and integrated with Defender XDR. Without it, table is empty.  
**Sentinel**: Defender-only. Sentinel returns HTTP 400.

## What it covers

Control-plane audit events from cloud infrastructure platforms:
- **Azure**: Azure Resource Manager activity log (`AuditSource = "Azure"`, `DataSource = "Azure Logs"`)
- **AWS**: AWS CloudTrail (`DataSource = "AWS"`)
- **GCP**: Google Cloud Audit Logs (`DataSource = "GCP"`)
- **Kubernetes**: Kubernetes API audit log (`DataSource = "Kubernetes Audit"`)

Distinct from `CloudAppEvents` (MDCA SaaS app connector events) — `CloudAuditEvents` covers cloud infrastructure control-plane, not SaaS application activity.

## Schema highlights

| Column | Notes |
|---|---|
| `ActionType` | Values: `CloudAuditEventCreate`, `CloudAuditEventRead`, `CloudAuditEventUpdate`, `CloudAuditEventDelete`, `CloudAuditEventOther`, `CloudAuditEventGet`. **Docs claim `Create/Read/Update/Delete/Other/Unknown` without the `CloudAuditEvent` prefix — those are wrong.** Use live values. |
| `AuditSource` | Platform: `"Azure"`, `"AWS"`, `"GCP"`, `"Kubernetes"`, etc. |
| `DataSource` | More specific source: `"Azure Logs"`, etc. |
| `OperationName` | Full ARM/API operation name (e.g. `Microsoft.Compute/virtualMachines/write`). High cardinality. |
| `AzureResourceId` | Full ARM resource path — Azure rows only. **Docs list this as `ResourceId` — wrong column name.** |
| `AwsResourceName` | AWS ARN — AWS rows only. |
| `GcpFullResourceName` | GCP resource name — GCP rows only. |
| `Account` | For Azure rows: subscription GUID (not a UPN). For other platforms: varies. Actor identity lives in `RawEventData` — see below. |
| `IPAddress` | Client IP. Azure rows: populated from `httpRequest.clientIpAddress`. Use `ipv6_is_match()` for comparisons. |
| `ISP` | Column name is `ISP` (uppercase) — docs show `Isp` which is wrong. Blank in Azure rows. |
| `UserAgent` | Blank in Azure rows. Populated for other platforms/ActionTypes. |
| `RawEventData` | **Native dynamic** (confirmed `bag_keys()` works, `gettype()` = `"dictionary"`). Full source audit record. Rich for Azure rows — see fields below. `@odata.type` wrapper key present but harmless. |
| `AdditionalFields` | **Always null** in observed Azure rows (`gettype()` = null). Do not rely on it. |
| `ReportId` | `string` GUID — globally unique per event; safe single-column join. |

## RawEventData — Azure rows

Native dynamic. Key top-level fields:

| Field | Notes |
|---|---|
| `operationName` | Lowercase copy of `OperationName` |
| `status` | `"Succeeded"`, `"Failed"`, etc. |
| `subStatus` | HTTP status code string |
| `eventCategory` | `"Administrative"`, `"ServiceHealth"`, etc. |
| `principalOid` | Actor object ID (Entra object ID) — most reliable caller identity field |
| `principalPuid` | Actor PUID — often blank for service principals |
| `applicationId` | Service principal app ID when action performed by SP |
| `subscriptionId` | Subscription GUID |
| `resourceUri` | Full ARM resource path (same as `AzureResourceId`) |
| `correlationId` | ARM correlation ID (same as `ReportId` for Azure rows) |
| `httpRequest` | **JSON string** (nested) — requires `parse_json(tostring(RawEventData.httpRequest))`. Fields: `clientIpAddress`, `method`, `url`, `clientRequestId` |
| `claims` | **JSON string** (nested) — requires `parse_json(tostring(RawEventData.claims))`. Full JWT claims: `oid`, `appid`, `iss`, `idtyp`, `wids`, etc. |
| `authorization` | **JSON string** (nested) — requires `parse_json(tostring(RawEventData.authorization))`. Fields: `scope`, `action`, `evidence.role`, `evidence.roleDefinitionId`, `evidence.principalId` |
| `properties` | JSON string (nested) — resource-specific payload |

`RawEventData.caller` is **always blank** for Azure rows in observed data — use `principalOid` instead.

## Actor identity pattern (Azure)

```kql
CloudAuditEvents
| where Timestamp > ago(1d)
| where AuditSource == "Azure"
| extend PrincipalOid = tostring(RawEventData.principalOid)
| extend AppId = tostring(RawEventData.applicationId)
// Decode claims for UPN (user rows) — claims is a JSON string
| extend ClaimsJson = parse_json(tostring(RawEventData.claims))
| extend Upn = tostring(ClaimsJson["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"])
| extend IdentityType = tostring(ClaimsJson.idtyp)  // "app" or "user"
```

## ResourceId pattern (Azure)

```kql
// Filter by subscription
CloudAuditEvents
| where AzureResourceId has "/subscriptions/00000000-0000-0000-0000-000000000000/"

// Filter by resource type
CloudAuditEvents
| where OperationName startswith "Microsoft.Compute/virtualMachines/"
```

## Authorization evidence — RBAC role decoding

```kql
CloudAuditEvents
| where Timestamp > ago(7d)
| where AuditSource == "Azure"
| extend AuthZ = parse_json(tostring(RawEventData.authorization))
| extend RoleName = tostring(AuthZ.evidence.role)
| extend RoleDefId = tostring(AuthZ.evidence.roleDefinitionId)
| where isnotempty(RoleName)
| summarize Count=count() by RoleName, ActionType, OperationName
| sort by Count desc
```

## Key patterns

### Enumerate operations by resource type
```kql
CloudAuditEvents
| where Timestamp > ago(7d)
| extend ResourceType = tostring(split(OperationName, "/")[1])
| summarize Count=count() by ResourceType, ActionType
| sort by Count desc
```

### Detect VM creation/modification
```kql
CloudAuditEvents
| where Timestamp > ago(7d)
| where OperationName startswith "Microsoft.Compute/virtualMachines/write"
| extend Status = tostring(RawEventData.status)
| extend PrincipalOid = tostring(RawEventData.principalOid)
| project Timestamp, AzureResourceId, OperationName, Status, PrincipalOid, IPAddress
```

### Cross-platform summary
```kql
CloudAuditEvents
| where Timestamp > ago(7d)
| summarize Count=count() by AuditSource, DataSource, ActionType
| sort by Count desc
```

## Schema vs docs discrepancies

| Issue | Live schema | Docs |
|---|---|---|
| Resource ID column | `AzureResourceId` (+ `AwsResourceName`, `GcpFullResourceName`) | Listed as `ResourceId` (single column) |
| `ActionType` values | `CloudAuditEvent{Create,Read,Update,Delete,Other,Get}` | Listed without `CloudAuditEvent` prefix |
| `ISP` column name | `ISP` (uppercase) | `Isp` |
| `AdditionalFields` | Always null in Azure rows | Described as "additional information" |

## Gotchas

- `RawEventData.httpRequest`, `RawEventData.claims`, `RawEventData.authorization` are **JSON strings** inside the native dynamic bag — each requires `parse_json(tostring(...))` for sub-field access.
- `Account` is a subscription GUID (not a UPN) for Azure service principal actions. For true actor identity, use `RawEventData.principalOid`.
- `AdditionalFields` is null (not just empty) in observed Azure rows — do not parse it.
- `RawEventData.caller` is blank for Azure rows — do not use it as a fallback for `Account`.
- `ISP`, `UserAgent`, `City`, `CountryCode` are blank for machine/service-principal-initiated Azure operations (no user-facing HTTP client).
- Sentinel returns HTTP 400 — Defender-only; always use `run_hunting_query`.
- Table is empty without Microsoft Defender for Cloud deployed and integrated.
- `ReportId` for Azure rows equals `RawEventData.correlationId` (ARM correlation ID).
