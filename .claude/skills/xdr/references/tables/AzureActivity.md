# AzureActivity

Azure control-plane audit log. Records subscription-level and management-group-level operations (ARM API calls): resource creates/updates/deletes, RBAC changes, policy actions, etc. Available in both Defender Advanced Hunting and Sentinel (`run_sentinel_query`). Uses `TimeGenerated`, not `Timestamp`.

Source: Azure Activity Log, ingested via Azure Monitor diagnostic pipeline (`SourceSystem = "Azure"`).

## Key columns

| Column | Type | Notes |
|---|---|---|
| `TimeGenerated` | datetime | Use this for time filters — not `Timestamp` |
| `OperationNameValue` | string | Reliable. Canonical operation identifier e.g. `MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE`. Always uppercase. |
| `ActivityStatusValue` | string | Reliable. `Start`, `Success`, `Failed`, `Active`, `Resolved` |
| `ActivitySubstatusValue` | string | HTTP status phrase e.g. `OK`, `Created` |
| `Caller` | string | UPN or GUID of the initiating identity (user or service principal) |
| `CallerIpAddress` | string | IP of the caller |
| `ResourceGroup` | string | Reliable resource group name |
| `ResourceProviderValue` | string | Reliable. e.g. `MICROSOFT.STORAGE`, `MICROSOFT.SECURITY` |
| `SubscriptionId` | string | Subscription GUID |
| `CorrelationId` | string | Groups related Start/Success/Failed events for the same operation |
| `_ResourceId` | string | Full ARM resource path (lowercase). See gotcha below — use this for resource-specific filtering. |
| `Properties_d` | dynamic | Parsed form of `Properties`; use instead of `Properties` (string) |
| `Authorization_d` | dynamic | Parsed RBAC blob; use instead of `Authorization` (string) |
| `Claims_d` | dynamic | Parsed JWT claims; use instead of `Claims` (string) |

## GOTCHA: `Resource` column is always empty — use `_ResourceId`

`Resource` is always blank — every row, including `take 3` samples. The resource name is not surfaced as a top-level column; it lives inside the `Properties` JSON string and in `_ResourceId`.

**Use `_ResourceId` for all resource-specific filtering and grouping.** It is a Log Analytics system column (underscore prefix) that contains the full lowercase ARM resource path and is consistently populated:

```kql
// WRONG — Resource is always empty
AzureActivity
| where TimeGenerated > ago(7d)
| summarize Count=count() by Resource, ResourceGroup

// RIGHT — _ResourceId is reliable
AzureActivity
| where TimeGenerated > ago(7d)
| summarize Count=count() by _ResourceId
| sort by Count desc

// Filter to a specific storage account
AzureActivity
| where TimeGenerated > ago(7d)
| where _ResourceId has "/storageaccounts/my-storage-account"
| project TimeGenerated, OperationNameValue, Caller, ActivityStatusValue, _ResourceId
```

`_ResourceId` format: `/subscriptions/<guid>/resourcegroups/<rg>/providers/<namespace>/<type>/<name>` (always lowercase).

## Each operation emits paired events

Operations produce a `Start` row immediately and a `Success`/`Failed` row on completion. Both share the same `CorrelationId`. For deduplication or counting distinct operations (not events), filter on `ActivityStatusValue != "Start"` or use `CorrelationId` to pair them.

## Dynamic columns

`Properties_d`, `Authorization_d`, and `Claims_d` are the parsed dynamic equivalents of the string columns `Properties`, `Authorization`, `Claims`. Always prefer the `_d` variants:

```kql
| extend action = tostring(Authorization_d.action)
| extend role = tostring(Authorization_d.evidence.role)
| extend statusCode = tostring(Properties_d.statusCode)
```

## Relation to StorageBlobLogs (data-plane)

`AzureActivity` covers **control-plane** operations only (ARM API): creating/deleting/configuring storage accounts, listing keys/SAS tokens, changing access policies. It does **not** record blob read/write operations.

`StorageBlobLogs` covers **data-plane** access (blob reads, writes, deletes). It requires diagnostic settings to be explicitly enabled per storage account. Even if `StorageBlobLogs` appears in the workspace schema, it may be empty if diagnostic settings are not configured — the table schema exists but contains no data.

For full storage account visibility, both tables are needed.
