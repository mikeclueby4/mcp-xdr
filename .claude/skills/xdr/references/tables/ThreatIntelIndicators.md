# ThreatIntelIndicators

Sentinel table. Use `run_sentinel_query`. Time column: `TimeGenerated`. Supports Basic log plan.

## Table lineage

| Table | Status | Schema |
|---|---|---|
| `ThreatIntelIndicators` | **Current** — launched April 3, 2025; STIX 2.1 native | `ObservableKey` / `ObservableValue` |
| `ThreatIntelligenceIndicator` | **Legacy** — ingestion stopped July 31 2025, retiring May 31 2026 | `NetworkIP`, `NetworkSourceIP`, `NetworkDestinationIP` |

The `NetworkIP`/`NetworkSourceIP`/`NetworkDestinationIP` columns from the legacy table **do not exist** in `ThreatIntelIndicators` — using them causes `SEM0100`.

## Schema

| Column | Type | Notes |
|---|---|---|
| `ObservableKey` | string | Left-hand side of the STIX equality pattern — the indicator type path |
| `ObservableValue` | string | Right-hand side — the raw IOC value to match against |
| `Pattern` | string | Full STIX pattern string, e.g. `[network-traffic:src_ref.value = '1.2.3.4']` |
| `Data` | dynamic | Full STIX indicator object. Some fields (`description`, `pattern`) truncated at 1000 chars. Access via `parse_json(tostring(Data))` |
| `AdditionalFields` | dynamic | Sentinel-added metadata; confirmed key: `TLPLevel` (`"Green"`, `"White"`, `"Amber"`, `"Red"`) |
| `Confidence` | int | 0–100 |
| `IsActive` | bool | Whether the indicator is currently active |
| `Revoked` | bool | **Always blank in live data** (confirmed) — revocation state lives in `Data.revoked`, not this column |
| `IsDeleted` | bool | Whether the record was deleted from Sentinel |
| `ValidFrom` / `ValidUntil` | datetime | Indicator validity window |
| `Tags` | string | Comma-separated tags; populated for `network-traffic:` indicators, blank for file hash rows (confirmed) |
| `SourceSystem` | string | TI feed source, e.g. `"Microsoft Defender Threat Intelligence"` |
| `LastUpdateMethod` | string | `"BasicMDTIConnector"` for live feed; `"LogARepublisher"` for periodic republish (every 7–10 days) |
| `Id` | string | Unique indicator ID (base64-encoded source + STIX indicator ID); usable with Sentinel APIs |
| `Created` / `Modified` | datetime | STIX object lifecycle timestamps |

## ObservableKey values (confirmed live)

| ObservableKey | What it is |
|---|---|
| `network-traffic:src_ref.value` | Source IP (most common by volume) |
| `network-traffic:dst_ref.value` | Destination IP |
| `ipv4-addr:value` | Standalone IPv4 address |
| `domain-name:value` | Domain |
| `url:value` | URL |
| `file:hashes.'SHA-256'` | SHA-256 file hash |
| `file:hashes.'SHA-1'` | SHA-1 file hash |
| `file:hashes.MD5` | MD5 file hash |

Rows with blank `ObservableKey` exist when the STIX pattern cannot be parsed into key/value pairs — the raw `Pattern` is still present for custom analytics.

## indicator_types values (from `Data.indicator_types[0]`)

Confirmed live (MDTI feed): `"Botnet"`, `"WatchList"`, `"Malware"`, `"MaliciousUrl"`, `"Variant"`

## Data column structure

`Data` is a native `dynamic` column but benefits from `parse_json(tostring(Data))` for reliable access (double-serialization risk). Key paths:

```
Data.indicator_types       // array, e.g. ["Botnet"]
Data.description           // string, truncated at 1000 chars
Data.name                  // string, e.g. "Microsoft Identified IOC"
Data.labels                // array of strings (honeypot tags, p:default, MITRE TTPs as JSON objects)
Data.external_references   // array; contains MDTI article URLs
Data.extensions.IndicatorProvider.provider_name  // e.g. "Microsoft", "MDTI"
Data.id                    // STIX indicator ID (use for joins with ThreatIntelObjects)
```

`Data.labels` for MDTI/MSTIC indicators contains a mix of plain strings (`"honeypot"`, `"p:default"`) and serialized JSON objects (MITRE ATT&CK technique entries with `Id`, `Name`, `FullName`, `ExternalId`, `Alias`).

## Deduplication

The table receives periodic full republishes (`LastUpdateMethod == "LogARepublisher"`) every 7–10 days, so the same indicator appears multiple times. Deduplicate with:

```kql
| summarize arg_max(TimeGenerated, *) by Id
```

## Common patterns

### IP lookup
```kql
ThreatIntelIndicators
| where ObservableKey in ("network-traffic:src_ref.value", "network-traffic:dst_ref.value", "ipv4-addr:value")
    and ObservableValue == "1.2.3.4"
| summarize arg_max(TimeGenerated, *) by Id
| where IsActive == true
| project TimeGenerated, ObservableKey, ObservableValue, Confidence, ValidFrom, ValidUntil, SourceSystem
```

Use `Pattern contains "1.2.3.4"` as fallback when `ObservableKey` is blank (unparsed patterns).

### File hash lookup
```kql
ThreatIntelIndicators
| where ObservableKey has "file:hashes"
    and ObservableValue =~ "HASH_VALUE_HERE"
| summarize arg_max(TimeGenerated, *) by Id
```

### Active high-confidence indicators summary
```kql
ThreatIntelIndicators
| where IsActive == true and IsDeleted == false
| summarize arg_max(TimeGenerated, *) by Id
| where Confidence >= 75
| summarize Count=count() by ObservableKey, tostring(parse_json(tostring(Data)).indicator_types[0])
| sort by Count desc
```

### Join ThreatIntelIndicators with DeviceNetworkEvents
```kql
let TI = ThreatIntelIndicators
| where IsActive == true and IsDeleted == false
| where ObservableKey in ("network-traffic:src_ref.value", "ipv4-addr:value")
| summarize arg_max(TimeGenerated, *) by Id
| project ObservableValue, Confidence, ThreatType=tostring(parse_json(tostring(Data)).indicator_types[0]);
DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| join kind=inner TI on $left.RemoteIP == $right.ObservableValue
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, Confidence, ThreatType
```

Note: `ObservableValue` for IP indicators is a plain IPv4 string — string equality is safe here since this is a TI lookup table, not a network log. No IPv6-mapped form risk.

### Migrate legacy query pattern (recreate legacy column names)
```kql
ThreatIntelIndicators
| extend NetworkSourceIP = iff(ObservableKey == 'network-traffic:src_ref.value', ObservableValue, ''),
        NetworkDestinationIP = iff(ObservableKey == 'network-traffic:dst_ref.value', ObservableValue, ''),
        NetworkIP = iff(ObservableKey == 'ipv4-addr:value', ObservableValue, ''),
        DomainName = iff(ObservableKey == 'domain-name:value', ObservableValue, ''),
        Url = iff(ObservableKey == 'url:value', ObservableValue, ''),
        FileHashType = case(ObservableKey has 'MD5', 'MD5',
                            ObservableKey has 'SHA-1', 'SHA-1',
                            ObservableKey has 'SHA-256', 'SHA-256', ''),
        FileHashValue = iff(ObservableKey has 'file:hashes', ObservableValue, ''),
        ThreatType = tostring(parse_json(tostring(Data)).indicator_types[0])
```

## ThreatIntelObjects companion table

`ThreatIntelObjects` holds non-indicator STIX objects (`threat-actor`, `attack-pattern`, `relationship`, etc.). Join on `Data.id` to correlate indicators with threat actors:

```kql
// Get STIX id from indicator
ThreatIntelIndicators
| extend tlId = tostring(parse_json(tostring(Data)).id)
| summarize arg_max(TimeGenerated, *) by Id
| where IsDeleted == false
// then join to ThreatIntelObjects via AllRelationships (see official docs pattern)
```

## Retention note

Omit or widen the `TimeGenerated` filter when checking historical presence — TI indicators can be old/expired but still present in the table.

## Filter unparsed rows

When `ObservableKey` is blank, the STIX pattern could not be parsed into key/value form:
```kql
| where isnotempty(ObservableKey) and isnotempty(ObservableValue)
```
