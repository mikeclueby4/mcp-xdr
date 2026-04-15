# Eval 4 WITH skill: ExposureGraphNodes doc fetch

## Tool calls made

1. **ToolSearch** — loaded schemas for `get_hunting_schema`, `run_hunting_query`, `microsoft_docs_fetch`
2. **`mcp__defender__get_hunting_schema(table_name="ExposureGraphNodes")`** — columns: NodeId, NodeLabel, NodeName, Categories (dynamic), NodeProperties (dynamic), EntityIds, TenantId
3. **`mcp__defender__run_hunting_query("ExposureGraphNodes | take 3")`** — returned AI model nodes; NodeProperties.rawData has aiModelMetadata keys
4. **`mcp__microsoft-learn__microsoft_docs_fetch(url="https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-exposuregraphnodes-table")`** — confirmed NodeProperties is unstructured JSON with security insights
5. **`mcp__defender__run_hunting_query` (device filter + take 3)** — found real device node structure; key fields: exposureScore, publicIP, deviceType, deviceSubtype, remoteServicesInfo
6. **`mcp__defender__run_hunting_query` (internet keyword search + take 3)** — confirmed publicIP and exposureScore fields present
7. **`mcp__defender__run_hunting_query` (server type filter + take 3)** — found on-prem Windows Servers and Azure VMs; Azure VM had publicIP + exposureScore="High" but no `isInternetFacing` field
8. **`mcp__defender__run_hunting_query` (isInternetFacing keyword + take 3)** — found field exists on some nodes, set to `false`
9. **`mcp__defender__run_hunting_query` (isInternetFacing="True" string match)** — 0 rows (Python dict repr doesn't match exact string)
10. **`mcp__defender__run_hunting_query` (parse_json + tobool + summarize by isInternetFacing)** — result: false=6, true=1
11. **`mcp__defender__run_hunting_query` (filter isInternetFacing==true + project)** — 1 true node: Windows 11 Workstation with publicIP `155.4.163.184`, exposureScore="Medium"

---

## Final KQL query

```kql
// Internet-exposed servers in ExposureGraphNodes
// "Internet-exposed" = isInternetFacing:true OR (has a publicIP AND exposureScore != "None")
ExposureGraphNodes
| extend props = parse_json(tostring(NodeProperties))
| extend
    isInternetFacing = tobool(props.rawData.isInternetFacing),
    exposureScore    = tostring(props.rawData.exposureScore),
    publicIP         = tostring(props.rawData.publicIP),
    deviceType       = tostring(props.rawData.deviceType),
    deviceSubtype    = tostring(props.rawData.deviceSubtype),
    osPlatform       = tostring(props.rawData.osPlatform),
    riskScore        = tostring(props.rawData.riskScore),
    onboardingStatus = tostring(props.rawData.onboardingStatus),
    lastSeen         = todatetime(props.rawData.lastSeen),
    environmentName  = tostring(props.rawData.environmentName)
| where
    deviceSubtype == "Server"
    or deviceType == "Server"
    or Categories has "virtual_machine"
    or (Categories has "environmentCloud" and Categories has "compute")
| where
    isInternetFacing == true
    or (isnotempty(publicIP) and publicIP != "" and exposureScore in ("High", "Medium"))
| where lastSeen >= ago(30d) or isnull(lastSeen)
| project
    NodeName, NodeLabel, Categories,
    deviceType, deviceSubtype, osPlatform, environmentName,
    isInternetFacing, exposureScore, riskScore,
    publicIP, onboardingStatus, lastSeen, NodeId
| sort by isInternetFacing desc, exposureScore asc
```

---

## Notes

- `isInternetFacing` is sparsely populated — only 7 nodes had it, only 1 set to `true` (a workstation). Using only that flag would miss real servers.
- Combined signal (flag OR publicIP + exposureScore) is more reliable.
- `ExposureGraphNodes` is a current-state inventory table — no native time filter; `lastSeen` inside rawData used as a proxy.
- Server identification requires checking both `deviceSubtype`/`deviceType` (on-prem) and `Categories` (cloud VMs with `NodeLabel` = `microsoft.compute/virtualmachines`).
- MS Learn doc fetch confirmed NodeProperties is unstructured — live sampling was essential to discover actual key names (`isInternetFacing`, `publicIP` under `rawData`).
