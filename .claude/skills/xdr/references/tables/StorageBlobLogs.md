# StorageBlobLogs

Azure Blob Storage data-plane audit log. Sentinel/Log Analytics only — not in Defender Advanced Hunting. Use `run_sentinel_query`.

## Population requirement (critical)

The table contains **zero rows** unless Azure Storage diagnostic settings have been explicitly configured to send logs to the workspace. 

To enable: Storage Account → Monitoring → Diagnostic settings → enable `StorageRead`, `StorageWrite`, `StorageDelete` categories targeting the Log Analytics workspace.

## Scope: data-plane only

Covers REST/SMB/NFS operations against blob objects. Does **not** cover ARM control-plane operations — those are in `AzureActivity`.

## Time column

`TimeGenerated` — not `Timestamp`.

## Key columns

| Column | Type | Notes |
|---|---|---|
| `AccountName` | string | Storage account name (not full resource ID) |
| `OperationName` | string | REST operation: `GetBlob`, `PutBlob`, `ListBlobs`, `DeleteBlob`, `CopyBlob`, etc. |
| `AuthenticationType` | string | `OAuth`, `SAS`, `AccountKey`, `Anonymous`, `Kerberos` |
| `RequesterUpn` | string | UPN of caller — populated only for OAuth auth; empty for SAS/AccountKey/Anonymous |
| `RequesterObjectId` | string | AAD object ID of caller (OAuth) |
| `RequesterAppId` | string | App ID if caller is a service principal (OAuth) |
| `CallerIpAddress` | string | Source IP including port, e.g. `1.2.3.4:54321` — strip port before IP comparison |
| `ObjectKey` | string | Blob path accessed, e.g. `storageaccount/container/path/blob.ext` |
| `StatusCode` | string | HTTP status code as string, e.g. `"200"`, `"404"` |
| `StatusText` | string | Human-readable status: `Success`, `SASSuccess`, `AuthorizationError`, etc. |
| `AuthorizationDetails` | dynamic | RBAC details: action, result (`Granted`/`Denied`), roleDefinitionId, roleAssignmentId |
| `Category` | string | Log category routed: `StorageRead`, `StorageWrite`, `StorageDelete` |
| `DurationMs` | real | End-to-end request duration in ms (includes network) |
| `ServerLatencyMs` | real | Server-only processing time in ms (excludes network round-trip) |
| `Uri` | string | Full request URI |
| `TlsVersion` | string | e.g. `TLS 1.2` |
| `SasExpiryStatus` | string | Populated when SAS token violates SAS policy (e.g. duration too long) |

## AuthorizationDetails structure

`AuthorizationDetails` is a native `dynamic` column (not double-serialized). Access sub-fields directly:

```kql
StorageBlobLogs
| where TimeGenerated > ago(7d)
| extend AuthResult = tostring(AuthorizationDetails[0].result)       // "Granted" or "Denied"
| extend AuthAction = tostring(AuthorizationDetails[0].action)       // ARM action string
| extend RoleDefId  = tostring(AuthorizationDetails[0].roleDefinitionId)
| extend AuthReason = tostring(AuthorizationDetails[0].reason)       // "Policy", "NoApplicablePolicy"
```

## AzureActivity vs StorageBlobLogs

| Dimension | AzureActivity | StorageBlobLogs |
|---|---|---|
| Plane | Control (ARM) | Data (REST/SMB/NFS) |
| Events | Create/delete account, RBAC changes, key rotation | GetBlob, PutBlob, ListBlobs, DeleteBlob |
| Caller identity | Requires subscription onboarded to Sentinel | Inline via `RequesterUpn`, `RequesterObjectId` |
| Always present | Yes (if subscription connected) | Only if diagnostic settings configured |

### AzureActivity storage account name extraction

`ResourceId` is often empty in AzureActivity rows for storage accounts. Extract the account name from `Properties_d.entity`:

```kql
AzureActivity
| where ResourceProviderValue =~ "Microsoft.Storage"
| extend StorageAccount = extract(@"storageAccounts/([^/]+)", 1, tostring(Properties_d.entity))
```

## Common query patterns

### Blob access by a specific identity (OAuth)
```kql
| where RequesterUpn =~ "user@example.com"
| project TimeGenerated, AccountName, OperationName, ObjectKey, StatusCode, CallerIpAddress
```

### Anonymous access audit
```kql
| where AuthenticationType == "Anonymous"
| summarize Count=count() by AccountName, OperationName, Uri
```

### Failed / denied operations
```kql
| where StatusText !contains "Success"
```

### SAS token policy violations
```kql
| where isnotempty(SasExpiryStatus)
| project TimeGenerated, AccountName, SasExpiryStatus, CallerIpAddress, ObjectKey
```

## Connector and ingestion

- Sentinel data connector: "Azure Storage Account" (DCR-based).
- Three diagnostic categories feed this table: `StorageRead`, `StorageWrite`, `StorageDelete` — each can be enabled independently.
- The table supports the Basic log plan (lower cost, limited query capabilities); confirm plan before running expensive joins.

## Sources

- [Azure Monitor reference: StorageBlobLogs columns](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/storagebloblogs)
- [Azure Blob Storage monitoring reference](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage-reference)
- [Sentinel data connectors reference: Azure Storage Account](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference#azure-storage-account)
