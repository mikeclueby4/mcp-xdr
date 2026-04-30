# ThreatIntelligenceIndicator

**DEPRECATED — DO NOT USE FOR NEW QUERIES.**

- Ingestion stopped: **2025-07-31**
- Retiring: **2026-05-31** (TIP data connector that feeds it deprecates June 2026)

Use `ThreatIntelIndicators` instead. See `ThreatIntelIndicators.md` for the current schema and migration patterns.

## Why it still exists in get_schema

The table schema is still visible in some tenants (Defender+Sentinel) because Log Analytics retains the schema definition until the table is fully retired. Live data may be absent or stale.

## Key schema differences vs ThreatIntelIndicators

| Legacy column | New equivalent |
|---|---|
| `NetworkIP` | `ObservableKey == 'ipv4-addr:value'` → `ObservableValue` |
| `NetworkSourceIP` | `ObservableKey == 'network-traffic:src_ref.value'` → `ObservableValue` |
| `NetworkDestinationIP` | `ObservableKey == 'network-traffic:dst_ref.value'` → `ObservableValue` |
| `DomainName` | `ObservableKey == 'domain-name:value'` → `ObservableValue` |
| `Url` | `ObservableKey == 'url:value'` → `ObservableValue` |
| `FileHashValue` + `FileHashType` | `ObservableKey has 'file:hashes'` → `ObservableValue` |
| `IndicatorId` | `tostring(Data.id)` in `ThreatIntelIndicators` |
| `ConfidenceScore` (real) | `Confidence` (int) in `ThreatIntelIndicators` |
| `Active` (bool) | `IsActive` (bool) in `ThreatIntelIndicators` |
| `ThreatType` (string) | `tostring(Data.indicator_types[0])` |
| `TrafficLightProtocolLevel` | `tostring(AdditionalFields.TLPLevel)` |

## Notable legacy-only columns (no equivalent in new table)

`DiamondModel`, `KillChain*` (bool columns per phase), `PassiveOnly`, `ThreatSeverity`, `Email*`, `File*` (dedicated columns), `NetworkProtocol`, `NetworkPort`, `NetworkCidrBlock`, `UserAgent`

These fields either moved into `Data` (the full STIX object) or were dropped as the schema became STIX-native.
