# CloudStorageAggregatedEvents

**Preview table** — Microsoft Defender for Cloud integration required. Defender-only (Sentinel returns 400). Query via `run_hunting_query`.

Each row is a one-hour aggregation of Azure Storage access activity per (storage account, IP address, user/app identity, authentication type). Not a per-request event log.

## Time columns

- `DataAggregationStartTime` / `DataAggregationEndTime` — the hour bucket boundaries (e.g. 22:00–23:00 UTC). These are the semantically correct time columns for filtering.
- `Timestamp` — when the record was ingested; lags behind `DataAggregationEndTime` by ~1 hour. Suitable for `| where Timestamp > ago(7d)` time-bounding queries.
- `TimeGenerated` — present in live schema (Log Analytics system column) but always equals `Timestamp`. No Sentinel rows.

**Important:** official docs list `FirstEventTimestamp` and `LastEventTimestamp` as top-level columns — they are **not** top-level in the live schema. They live inside `AdditionalFields` (see below).

## ActionType

Single value in practice: `"Data Aggregation"`. No need to filter by ActionType.

## ServiceType confirmed values (2026-04)

`Blob`, `Files.REST`, `Files.SMB`, `ADLS Gen2` (per docs; not confirmed in live data)

## AuthenticationType confirmed values (2026-04)

`OAuth`, `SAS`, `TrustedAccessSas`, `TrustedAccess`, `AccountKey`, `Anonymous`, `NTLMv2`, blank

- `OAuth` is the dominant type (~68% of rows in sample tenants).
- `TrustedAccessSas` / `TrustedAccess` = Azure-internal service-to-service access (Defender for Storage malware scanning, etc.).
- `Anonymous` rows warrant investigation — check `HasAnonymousResourceNotFoundFailures` and `SuccessfulOperationsCount`.

## AccountType confirmed values

`App`, `User`, blank. `App` is the dominant type; blank rows have no identity context.

## OperationNamesList

Native dynamic array of operation name strings — direct indexing and `mv-expand` work without `parse_json()`. Common values: `GetBlob`, `ListBlobs`, `GetBlobProperties`, `GetBlobTags`, `SetBlobTags`, `ListFiles`, `CreateContainer`, `DeleteContainer`, `PutBlob`, etc.

```kql
CloudStorageAggregatedEvents
| where Timestamp > ago(7d)
| mv-expand Op = OperationNamesList
| summarize Count=count() by tostring(Op)
| sort by Count desc
```

## Md5Hashes

Native dynamic array. Contains MD5 hash metadata for uploaded blobs — populated when Defender for Storage malware scanning processes files. Empty array `[]` when no files with recorded hashes. In practice, frequently empty even in active tenants with Defender for Storage.

When populated, elements have structure: `{md5Hash, resourcePath, operationType, etag}`. Access via:
```kql
| mv-expand HashReputation = Md5Hashes
| extend Md5 = tostring(HashReputation.md5Hash), Path = tostring(HashReputation.resourcePath)
```

## AdditionalFields — critical schema divergence from docs

Official docs list the following as **top-level columns**; they are actually **nested inside `AdditionalFields`** in the live schema:

| Key in AdditionalFields | Type | Notes |
|---|---|---|
| `FirstEventTimestamp` | datetime string | First operation time within the aggregation hour |
| `LastEventTimestamp` | datetime string | Last operation time within the aggregation hour |
| `ClientCloudPlatformName` | string | Azure cloud platform name (`"Azure"` / `"N/A"`) |
| `IsTorExitNode` | bool | IP is a known Tor exit node |
| `IsKnownSuspiciousIp` | bool | IP is in Defender threat intelligence |
| `IsPrivateIp` | bool | IP is RFC-1918 private |
| `CountryName` | string | Lowercase country name; absent when IsPrivateIp = true |
| `CityName` | string | Lowercase city name; absent when IsPrivateIp = true |
| `ProvinceName` | string | Lowercase region/state name; absent when IsPrivateIp = true |
| `ClientSystemServiceName` | string | Azure service name when originating from Azure datacenter (e.g. `"AzureConnectors"`) |

`AdditionalFields` `gettype()` = `"dictionary"` — native dynamic, direct property access works. `@odata.type` wrapper key present but harmless.

```kql
CloudStorageAggregatedEvents
| where Timestamp > ago(7d)
| where tobool(AdditionalFields.IsTorExitNode) == true or tobool(AdditionalFields.IsKnownSuspiciousIp) == true
| project DataAggregationStartTime, StorageAccount, IPAddress, AuthenticationType, OperationsCount, AdditionalFields
```

```kql
// Non-private access with geo context
CloudStorageAggregatedEvents
| where Timestamp > ago(7d)
| where tobool(AdditionalFields.IsPrivateIp) == false and isnotempty(AccountUpn)
| project DataAggregationStartTime, StorageAccount, IPAddress,
    Country = tostring(AdditionalFields.CountryName),
    City = tostring(AdditionalFields.CityName),
    AccountUpn, AuthenticationType, OperationsCount
```

Keys confirmed across live rows (2026-04): the base 6 keys are always present; `CountryName`/`CityName`/`ProvinceName` present for non-private IPs; `ClientSystemServiceName` present when traffic originates from Azure datacenter services.

`SuspiciousUserAgentName` and `HashReputationMd5List` — listed in official docs as top-level columns; **not observed** in live AdditionalFields keys or live schema (2026-04). May be future additions or require specific Defender for Storage configuration.

## ReportId

`string` (GUID) — globally unique per aggregation row. Single-column joins are safe.

## Key join paths

- `AccountObjectId` → `IdentityInfo.AccountObjectId` — resolve user/app display name and group membership.
- `AzureResourceId` → `AzureActivity._ResourceId` (ARM path) — correlate storage access with control-plane changes.
- `StorageAccount` / `AzureResourceId` → `StorageBlobLogs` (Sentinel) — for per-request detail behind the aggregated summary. Note: `StorageBlobLogs` is a Sentinel/Log Analytics table with raw individual requests.

## Hunting patterns

### Anonymous access with failures
```kql
CloudStorageAggregatedEvents
| where Timestamp > ago(7d)
| where AuthenticationType == "Anonymous"
| where FailedOperationsCount > 0 or AnonymousSuccessfulOperations > 0
| project DataAggregationStartTime, StorageAccount, StorageContainer, IPAddress,
    AnonymousSuccessfulOperations, FailedOperationsCount, OperationNamesList,
    HasAnonymousResourceNotFoundFailures
| sort by AnonymousSuccessfulOperations desc
```

### Unusual authentication types (non-standard for most environments)
```kql
let ExpectedAuthTypes = dynamic(["OAuth", "TrustedAccessSas", "TrustedAccess"]);
CloudStorageAggregatedEvents
| where Timestamp > ago(7d)
| where AuthenticationType !in (ExpectedAuthTypes)
| summarize TotalOps=sum(OperationsCount), FailedOps=sum(FailedOperationsCount)
    by StorageAccount, AuthenticationType, AccountUpn
| sort by TotalOps desc
```

### High failure rates by IP/identity
```kql
CloudStorageAggregatedEvents
| where Timestamp > ago(7d)
| where FailedOperationsCount > 10
| project DataAggregationStartTime, StorageAccount, IPAddress, AccountUpn, AccountType,
    AuthenticationType, OperationsCount, FailedOperationsCount,
    Country = tostring(AdditionalFields.CountryName),
    IsTor = tobool(AdditionalFields.IsTorExitNode),
    IsSuspiciousIp = tobool(AdditionalFields.IsKnownSuspiciousIp)
| sort by FailedOperationsCount desc
```

## Prerequisites

Requires Microsoft Defender for Cloud integrated with Defender XDR. If the integration is not configured, the table will be empty or absent. See: [Defender for Cloud integration with Defender XDR](https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-integration-365).
