# ThreatIntelObjects

Available in both Defender (`run_hunting_query`) and Sentinel (`run_sentinel_query`). Time column: `TimeGenerated`.

Companion table to `ThreatIntelIndicators`. Stores all non-indicator STIX 2.1 objects: `threat-actor`, `attack-pattern`, `relationship`, `identity`, `malware`, `tool`, `course-of-action`, `campaign`, etc.

Launched 2025-04-03. May be empty in tenants without STIX object feeds beyond basic MDTI indicator data.

## Schema

| Column | Type | Notes |
|---|---|---|
| `StixType` | string | STIX object type: `"threat-actor"`, `"attack-pattern"`, `"relationship"`, `"identity"`, etc. |
| `Data` | dynamic | Full STIX object. **Native dynamic** — direct property access works. |
| `AdditionalFields` | dynamic | **Native dynamic**. Sentinel-added metadata. |
| `IsDeleted` | bool | Whether record was deleted |
| `LastUpdateMethod` | string | `"BasicMDTIConnector"` or `"LogARepublisher"` |
| `Id` | string | `base64(SourceSystem) + "---" + stixId` |
| `SourceSystem` | string | Feed source |
| `Type` | string | Always `"ThreatIntelObjects"` |

## Key Data paths by StixType

```
// relationship
Data.source_ref     // STIX ID of the source object
Data.target_ref     // STIX ID of the target object
Data.relationship_type  // e.g. "uses", "attributed-to", "targets"

// threat-actor
Data.id
Data.name
Data.aliases        // array of known names

// attack-pattern (MITRE technique)
Data.name
Data.external_references  // contains MITRE ATT&CK technique IDs

// All types
Data.id             // join key — matches ThreatIntelIndicators.Data.id for indicator objects
```

## Deduplication

Same 7–10 day republish cycle as `ThreatIntelIndicators`. Always deduplicate:

```kql
| summarize arg_max(TimeGenerated, *) by Id
| where IsDeleted == false
```

## Join with ThreatIntelIndicators

Join key: `tostring(Data.id)` on both sides (STIX object ID).

```kql
// Find threat actors linked to specific indicators
let Indicators = ThreatIntelIndicators
    | where ObservableKey in ("network-traffic:src_ref.value", "ipv4-addr:value")
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsDeleted == false
    | extend tlId = tostring(Data.id);
let Relationships = ThreatIntelObjects
    | where StixType == 'relationship'
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsDeleted == false
    | extend tlSourceRef = tostring(Data.source_ref)
    | extend tlTargetRef = tostring(Data.target_ref);
let ThreatActors = ThreatIntelObjects
    | where StixType == 'threat-actor'
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsDeleted == false
    | extend tlId = tostring(Data.id);
Indicators
| join kind=inner Relationships on $left.tlId == $right.tlSourceRef
| join kind=inner ThreatActors on $left.tlTargetRef == $right.tlId
| project ObservableValue, ThreatActorName = tostring(ThreatActors.Data.name)
```

## Investigate a specific threat actor's TTPs

```kql
let ACTOR = 'Sangria Tempest';
let Actor = ThreatIntelObjects
    | where StixType == 'threat-actor' and Data.name == ACTOR
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsDeleted == false
    | extend tlId = tostring(Data.id);
let Relationships = ThreatIntelObjects
    | where StixType == 'relationship'
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsDeleted == false
    | extend tlSourceRef = tostring(Data.source_ref)
    | extend tlTargetRef = tostring(Data.target_ref);
let AllObjects = ThreatIntelObjects
    | union (ThreatIntelIndicators | extend StixType = 'indicator')
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsDeleted == false
    | extend tlId = tostring(Data.id);
Actor
| join Relationships on $left.tlId == $right.tlSourceRef
| join AllObjects on $left.tlTargetRef == $right.tlId
| project StixType, ObservableValue, Pattern = tostring(Data.pattern), Name = tostring(Data.name)
```
