# ThreatIntelIndicators

Sentinel table. Use `run_sentinel_query`. Time column: `TimeGenerated`.

## Table lineage — do not confuse with the legacy table

| Table | Status | Schema |
|---|---|---|
| `ThreatIntelIndicators` | **Current** — launched April 3, 2025; STIX-native | `ObservableKey` / `ObservableValue` |
| `ThreatIntelligenceIndicator` | **Legacy** — ingestion stopped Aug 31 2025, retiring May 31 2026 | `NetworkIP`, `NetworkSourceIP`, `NetworkDestinationIP` |

Many search results and older docs refer to the legacy table. The new table is the correct target. The `NetworkIP`/`NetworkSourceIP`/`NetworkDestinationIP` columns that appear in legacy docs **do not exist** in `ThreatIntelIndicators` — using them causes `SEM0100`.

## Schema shape (confirmed live)

This table uses a **normalized key/value model** — no dedicated `NetworkIP`, `NetworkSourceIP`, or `NetworkDestinationIP` columns despite what many docs imply. The lookup columns are:

| Column | Type | Notes |
|---|---|---|
| `ObservableKey` | string | Indicator type, e.g. `"ipv4-addr:value"`, `"url:value"`, `"domain-name:value"` |
| `ObservableValue` | string | The raw IOC value — match here for IP/URL/domain lookups |
| `Pattern` | string | Full STIX pattern string — use `contains` as a fallback |
| `Data` | dynamic | Full raw indicator object — `tostring(Data) contains "..."` as last resort |
| `Confidence` | int | 0–100 |
| `IsActive` | bool | Whether the indicator is currently active |
| `ValidFrom` / `ValidUntil` | datetime | Indicator validity window |
| `Tags` | string | Comma-separated tags |
| `SourceSystem` | string | TI feed source |

## IP lookup pattern

```kql
ThreatIntelIndicators
| where ObservableValue == "1.2.3.4"
    or Pattern contains "1.2.3.4"
    or tostring(Data) contains "1.2.3.4"
| project TimeGenerated, Type, ObservableKey, ObservableValue, Pattern, Confidence, IsActive, ValidFrom, ValidUntil, Tags, SourceSystem
| sort by TimeGenerated desc
```

Do NOT use `NetworkIP`, `NetworkSourceIP`, `NetworkDestinationIP` — those columns do not exist in this table and will cause a `SEM0100` semantic error.

## Retention note

Omit the `TimeGenerated > ago(30d)` filter when checking if an IP has ever appeared — TI indicators can be old/expired but still present in the table at deeper retention.
