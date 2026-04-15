# Eval 4 — ExposureGraphNodes Internet-Exposed Servers

## Tool call sequence (7 substantive calls)
1. `mcp__microsoft-learn__microsoft_docs_fetch` — fetched ExposureGraphNodes table reference doc
2. `mcp__defender__get_hunting_schema` — got column names/types for ExposureGraphNodes
3. `mcp__defender__run_hunting_query` — `take 3` to see live NodeProperties structure
4. `mcp__defender__run_hunting_query` — probed for internet-exposure key name variants
5. `mcp__defender__run_hunting_query` — `bag_keys()` to enumerate all rawData keys on device nodes
6. `mcp__defender__run_hunting_query` — validated server + isCustomerFacing filter with `take 5`
7. `mcp__defender__run_hunting_query` — ran final production query

## Final KQL Query

```kql
ExposureGraphNodes
| where NodeLabel == "device"
| extend props = parse_json(tostring(NodeProperties))
| extend rawData = props.rawData
| where tostring(rawData.deviceType) == "Server" or tostring(rawData.deviceSubtype) == "Server"
| extend isCustomerFacing = tobool(rawData.isCustomerFacing)
| where isCustomerFacing == true
| extend ExposureScore    = tostring(rawData.exposureScore)
| extend RiskScore        = tostring(rawData.riskScore)
| extend PublicIP         = tostring(rawData.publicIP)
| extend OsPlatform       = tostring(rawData.osPlatformFriendlyName)
| extend OnboardingStatus = tostring(rawData.onboardingStatus)
| project
    NodeName,
    NodeLabel,
    NodeType          = tostring(rawData.deviceType),
    NodeSubtype       = tostring(rawData.deviceSubtype),
    IsInternetExposed = isCustomerFacing,
    ExposureScore,
    RiskScore,
    PublicIP,
    OsPlatform,
    OnboardingStatus
| sort by ExposureScore asc
```

**Results: 12 internet-exposed servers found.**

## Notable observations
1. Internet-exposure property is `rawData.isCustomerFacing` — not guessable from docs; live-sampling was mandatory.
2. `NodeProperties` is double-serialized — `parse_json(tostring(NodeProperties))` required.
3. No `Timestamp` column — no time filter applicable (snapshot/inventory table).
4. 11 of 12 servers not onboarded to Defender for Endpoint; `publicIP` and `exposureScore` only populated for the 1 onboarded server.
5. Non-onboarded servers show `exposureScore: None` despite internet-facing flag — exposure scoring requires DfE sensor.
