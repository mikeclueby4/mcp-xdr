# ThreatIntelIndicators

Available in both Defender (`run_hunting_query`) and Sentinel (`run_sentinel_query`). Time column: `TimeGenerated`.

## Table family

Three tables make up the current TI table family (all launched 2025-04-03):

| Table | Purpose |
|---|---|
| `ThreatIntelIndicators` | STIX indicator objects — IOCs with `ObservableKey`/`ObservableValue` |
| `ThreatIntelObjects` | All other STIX objects: `threat-actor`, `attack-pattern`, `relationship`, `identity`, etc. |
| `ThreatIntelligenceIndicator` | **Legacy** — ingestion stopped 2025-07-31; retiring 2026-05-31. See `ThreatIntelligenceIndicator.md`. |

`ThreatIntelObjects` is the companion for contextual TI. Join key between `ThreatIntelIndicators` and `ThreatIntelObjects`: `tostring(Data.id)` (STIX indicator ID, format `indicator--<uuid>`).

## Schema

| Column | Type | Notes |
|---|---|---|
| `ObservableKey` | string | LHS of STIX equality pattern (indicator type path) |
| `ObservableValue` | string | RHS — raw IOC value |
| `Pattern` | string | Full STIX pattern string, e.g. `[network-traffic:src_ref.value = '1.2.3.4']` |
| `Data` | dynamic | Full STIX indicator object. **Native dynamic** — direct property access works. Fields `description` and `pattern` truncated at 1000 chars. |
| `AdditionalFields` | dynamic | Sentinel-added metadata. **Native dynamic**. Key: `TLPLevel` (`"Green"`, `"White"`, `"Amber"`, `"Red"`) |
| `Confidence` | int | 0–100 |
| `IsActive` | bool | Whether the indicator is currently active |
| `Revoked` | bool | **Always blank in live data** — revocation state lives in `Data.revoked` |
| `IsDeleted` | bool | Whether the record was deleted from Sentinel |
| `ValidFrom` / `ValidUntil` | datetime | Indicator validity window |
| `Tags` | string | Comma-separated tags; populated for `network-traffic:` indicators, blank for file hash rows |
| `SourceSystem` | string | TI feed source, e.g. `"Microsoft Defender Threat Intelligence"` |
| `LastUpdateMethod` | string | `"BasicMDTIConnector"` (live feed) or `"LogARepublisher"` (7–10 day republish cycle) |
| `Id` | string | `base64(SourceSystem) + "---" + stixId`; unique per indicator version |
| `Type` | string | Always `"ThreatIntelIndicators"` |
| `Created` / `Modified` | datetime | STIX object lifecycle timestamps |

## ObservableKey values (confirmed live, MDTI feed — descending volume)

| ObservableKey | What it is |
|---|---|
| `network-traffic:src_ref.value` | Source IP (dominant — ~80% of rows) |
| `file:hashes.'SHA-256'` | SHA-256 file hash |
| `domain-name:value` | Domain |
| `file:hashes.MD5` | MD5 file hash |
| `url:value` | URL |
| `file:hashes.'SHA-1'` | SHA-1 file hash |
| `ipv4-addr:value` | Standalone IPv4 address (rare from MDTI) |
| `email-addr:value` | Email address |
| `x509-certificate:hashes.*` | Certificate hash |
| `x509-certificate:issuer` / `x509-certificate:serial_number` | Certificate metadata |
| *(blank)* | STIX pattern couldn't be parsed into key/value pairs |

`network-traffic:dst_ref.value` has zero rows in tenants with only the MDTI feed — do not rely on it without verifying.

When joining `ObservableValue` against device IP columns, normalize both sides with `parse_ipv6()` — the device tables may contain IPv4-mapped IPv6 (`::ffff:x.x.x.x`). See kql-facts.md IP normalization section.

## Data column structure

`Data` is native dynamic — direct property access works. `bag_keys(Data)` works:

```kql
| extend indicatorType = tostring(Data.indicator_types[0])
| extend providerName  = tostring(Data.extensions.IndicatorProvider.provider_name)
| extend stixId        = tostring(Data.id)
```

Key paths:
```
Data.indicator_types       // array, e.g. ["Botnet"]
Data.description           // string, truncated at 1000 chars
Data.name                  // string
Data.labels                // mixed array: plain strings + JSON-encoded MITRE TTP objects
Data.external_references   // array; contains source article URLs
Data.extensions.IndicatorProvider.provider_name  // e.g. "Microsoft"
Data.id                    // STIX indicator ID (join key for ThreatIntelObjects)
Data.revoked               // bool — use this, not the top-level Revoked column
```

`Data.labels` for MDTI/MSTIC indicators is a mixed array: plain strings (e.g. `"honeypot"`, `"p:default"`) and JSON-encoded MITRE ATT&CK objects. To access MITRE fields: `parse_json(tostring(Data.labels[N]))`.

## indicator_types values (confirmed live, MDTI feed)

`"Botnet"`, `"WatchList"`, `"Malware"`, `"MaliciousUrl"`, `"Variant"`

## Deduplication

Full republish every 7–10 days (`LastUpdateMethod == "LogARepublisher"`). Always deduplicate:

```kql
| summarize arg_max(TimeGenerated, *) by Id
```

## Common patterns

### IP lookup
```kql
ThreatIntelIndicators
| where ObservableKey in ("network-traffic:src_ref.value", "ipv4-addr:value")
    and ObservableValue == "1.2.3.4"
| summarize arg_max(TimeGenerated, *) by Id
| where IsActive == true
| project TimeGenerated, ObservableKey, ObservableValue, Confidence, ValidFrom, ValidUntil, SourceSystem
```

Note: `ObservableValue` for IP indicators is a plain IPv4 string — string equality is safe here (no IPv6-mapped form risk in this lookup table).

Use `Pattern contains "1.2.3.4"` as fallback when `ObservableKey` is blank.

### File hash lookup
```kql
ThreatIntelIndicators
| where ObservableKey has "file:hashes"
    and ObservableValue =~ "HASH_VALUE_HERE"
| summarize arg_max(TimeGenerated, *) by Id
```

### Active high-confidence summary
```kql
ThreatIntelIndicators
| where IsActive == true and IsDeleted == false
| summarize arg_max(TimeGenerated, *) by Id
| where Confidence >= 75
| summarize Count=count() by ObservableKey, tostring(Data.indicator_types[0])
| sort by Count desc
```

### Join with DeviceNetworkEvents
```kql
let TI = ThreatIntelIndicators
    | where IsActive == true and IsDeleted == false
    | where ObservableKey in ("network-traffic:src_ref.value", "ipv4-addr:value")
    | summarize arg_max(TimeGenerated, *) by Id
    | project ObservableValue, Confidence, ThreatType=tostring(Data.indicator_types[0]);
DeviceNetworkEvents
| where Timestamp > ago(1d)
| join kind=inner TI on $left.RemoteIP == $right.ObservableValue
| project Timestamp, DeviceName, RemoteIP, RemotePort, Confidence, ThreatType
```

### Correlate indicators with threat actors (via ThreatIntelObjects)
```kql
let Indicators = ThreatIntelIndicators
    | extend tlId = tostring(Data.id)
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsDeleted == false;
let ThreatActors = ThreatIntelObjects
    | where StixType == 'threat-actor'
    | extend tlId = tostring(Data.id), ThreatActorName = tostring(Data.name)
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsDeleted == false;
let Relationships = ThreatIntelObjects
    | where StixType == 'relationship'
    | extend tlSourceRef = tostring(Data.source_ref), tlTargetRef = tostring(Data.target_ref)
    | extend tlId = tostring(Data.id)
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsDeleted == false;
Indicators
| join Relationships on $left.tlId == $right.tlSourceRef
| join ThreatActors on $left.tlTargetRef == $right.tlId
| union (
    Indicators
    | join Relationships on $left.tlId == $right.tlTargetRef
    | join ThreatActors on $left.tlSourceRef == $right.tlId
)
| project ObservableValue, ThreatActorName
```

### Migrate legacy query pattern (recreate legacy column names)
```kql
ThreatIntelIndicators
| extend NetworkSourceIP   = iff(ObservableKey == 'network-traffic:src_ref.value', ObservableValue, ''),
         NetworkDestIP     = iff(ObservableKey == 'network-traffic:dst_ref.value', ObservableValue, ''),
         NetworkIP         = iff(ObservableKey == 'ipv4-addr:value', ObservableValue, ''),
         DomainName        = iff(ObservableKey == 'domain-name:value', ObservableValue, ''),
         Url               = iff(ObservableKey == 'url:value', ObservableValue, ''),
         FileHashType      = case(ObservableKey has 'MD5', 'MD5',
                                  ObservableKey has 'SHA-1', 'SHA-1',
                                  ObservableKey has 'SHA-256', 'SHA-256', ''),
         FileHashValue     = iff(ObservableKey has 'file:hashes', ObservableValue, ''),
         ThreatType        = tostring(Data.indicator_types[0])
```

## Filter unparsed rows

```kql
| where isnotempty(ObservableKey) and isnotempty(ObservableValue)
```

## Retention / time filter note

Omit or widen `TimeGenerated` filter when checking historical presence — the 7–10 day republish cycle means recent `TimeGenerated` does not imply a recently-seen threat. Deduplicate by `Id`, not by `TimeGenerated`.
