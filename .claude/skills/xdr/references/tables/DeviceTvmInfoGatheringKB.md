# DeviceTvmInfoGatheringKB

**Source**: Defender-only. Not present in Sentinel.
**Docs**: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvminfogatheringkb-table

Metadata catalog for `DeviceTvmInfoGathering.AdditionalFields`. Static reference table — 90 rows (confirmed 2026-04), no `Timestamp` column, no time filter possible or needed.

## Schema

| Column | Type | Notes |
|---|---|---|
| `IgId` | string | Unique ID, e.g. `"igid-1"`. No Timestamp/DeviceId — static reference. |
| `FieldName` | string | Key name in `DeviceTvmInfoGathering.AdditionalFields` |
| `Description` | string | Human-readable description. May contain HTML `<a>` links. |
| `Categories` | dynamic | Native dynamic string array. `mv-expand` to query per category. |
| `DataStructure` | string | Description of values/format for the field |

## Available categories (confirmed 2026-04)

`.NET 3.5`, `.NET 4.0`, `asr`, `communication`, `crypto`, `defender antivirus`, `network protocol`, `os`, `ssl`, `tls`, `vulnerability`

```kql
// All distinct categories
DeviceTvmInfoGatheringKB
| mv-expand Categories to typeof(string)
| distinct Categories
| sort by Categories asc
```

## Usage pattern

This table is the discovery tool for `DeviceTvmInfoGathering`. Query it first to find the `FieldName` values relevant to your investigation, then use those field names in `AdditionalFields` access.

```kql
// Find all AV-related fields
DeviceTvmInfoGatheringKB
| where Categories contains "defender antivirus"
| project FieldName, DataStructure, Description

// Find all ASR fields
DeviceTvmInfoGatheringKB
| where Categories contains "asr"
| project FieldName, DataStructure

// Full catalog
DeviceTvmInfoGatheringKB
| project IgId, FieldName, Categories, DataStructure
| order by IgId asc
```

## Relationship to DeviceTvmInfoGathering

`FieldName` in this table maps 1:1 to keys in `DeviceTvmInfoGathering.AdditionalFields`. There is no direct join key between rows — the relationship is by field name convention.

```kql
// Workflow: discover → query
// Step 1: find TLS fields
DeviceTvmInfoGatheringKB
| where Categories contains "tls"
| project FieldName, DataStructure

// Step 2: use FieldName results in DeviceTvmInfoGathering
DeviceTvmInfoGathering
| where AdditionalFields.TlsClient10 == "Enabled"
    or AdditionalFields.TlsServer10 == "Enabled"
| project DeviceName, OSPlatform, Timestamp
```

## Notes

- `Categories` is a native dynamic array — direct indexing and `mv-expand` both work without `parse_json()`.
- `Description` may contain HTML markup — strip if needed for display.
- Table is static (no device or time columns). Run without time filter.
- 90 rows as of 2026-04. New assessment types are added by Microsoft over time.
