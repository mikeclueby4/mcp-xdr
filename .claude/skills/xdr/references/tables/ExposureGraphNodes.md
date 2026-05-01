# ExposureGraphNodes + ExposureGraphEdges

Security Exposure Management attack-path graph. **Defender-only** (Sentinel returns 400). Query via `run_hunting_query`. No `Timestamp` column.

Source: Microsoft Defender XDR + Security Exposure Management. Populated by MDE, MDI, Defender for Cloud, Entra ID, and third-party data connectors. Richer data = more products deployed.

---

## ExposureGraphNodes

One row per entity node. Key columns:

| Column | Type | Notes |
|---|---|---|
| `NodeId` | string | Opaque hex hash — unique per entity |
| `NodeLabel` | string | Entity type classifier — see table below |
| `NodeName` | string | Display name of the entity |
| `Categories` | dynamic | Native dynamic string array — direct indexing works |
| `NodeProperties` | dynamic | **Native dynamic dict** — all payload under `.rawData` (see below) |
| `EntityIds` | dynamic | Native dynamic array; each element is a **native dynamic dict** (`type`, `id`) |

### NodeProperties structure — critical gotcha

`NodeProperties` is a genuine native dynamic (`gettype()` = `"dictionary"`, `bag_keys()` = `["rawData"]`), but **all meaningful data is nested one level deeper under `.rawData`**. Top-level access returns nothing useful.

```kql
// WRONG — returns null (no top-level "deviceName")
| extend name = NodeProperties.deviceName

// RIGHT — always go through .rawData
| extend name = tostring(NodeProperties.rawData.deviceName)
| extend score = tostring(NodeProperties.rawData.exposureScore)
```

`rawData` itself is also a native dynamic dict. Within it, some keys (e.g. `discoverySources-udi`, `highRiskVulnerabilityInsights`, `remoteServicesInfo`) are nested sub-objects. Array-valued keys use the `fieldName@odata.type: "#Collection(String)"` annotation pattern — ignore the `@odata.type` siblings; access the array key directly.

### EntityIds element access

Each element in `EntityIds` is a **native dynamic dict** (not a JSON string). Direct property access works:

```kql
| extend eid = EntityIds[0]
| extend eidType = tostring(eid.type)
| extend eidValue = tostring(eid.id)
```

Known `type` values: `AadObjectId`, `AzureResourceId`, `DeviceInventoryId`, `SenseDeviceId`, `SecurityIdentifier`, `ActiveDirectoryObjectGuid`, `CveId`, `MdcAssessmentId`, `AiModelNameAndVersion`, `HealthIssueTypeIdentifier`.

`AadObjectId` `id` format: `"tenantid=<guid>;objectid=<guid>"` — parse with `split(eid.id, ";")[1]` if you need just the object GUID.

### NodeLabel values (confirmed live 2026-05)

High-volume labels first:

| NodeLabel | Categories | rawData keys (representative) |
|---|---|---|
| `mdcSecurityRecommendation` | `["finding","security_finding"]` | `description`, `recommendationCategory`, `severity`, `securityIssue` |
| `Cve` | `["finding","vulnerability_finding"]` | `cvssVectorString` |
| `user` | `["environmentAzure","environmentCloud","identities","identity","user_account"]` | `accountDisplayName`, `accountUpn`, `accountObjectId`, `accountEnabled`, `aadSid`, `adSid`, `primaryProvider`, `identityType`, `assignedRoles`, `userAccountControl`, `hasLeakedCredentials`, `adminCount`, `passwordUpdateTime` |
| `group` | `["environmentAzure","environmentCloud","identities","identity","user_group"]` | `aadDisplayName`, `aadId`, `aadSid`, `adGroupType`, `primaryProvider` |
| `device` | `["compute","device","physical_device"]` | `deviceName`, `deviceType`, `deviceSubtype`, `deviceCategory`, `osPlatform`, `osVersion`, `onboardingStatus`, `sensorHealthState`, `exposureScore`, `riskScore`, `isCustomerFacing`, `isExcluded`, `machineGroup`, `lastSeen`, `firstSeenByInventory` |
| `serviceprincipal` | `["application_identity","environmentAzure","environmentCloud","identities","identity"]` | `accountDisplayName`, `appId`, `servicePrincipalType`, `accountEnabled`, `appOwnerOrganizationId` |
| `baseModel` | `["AI","ai_model"]` | `aiModelMetadata` (sub-object: `type`, `modelName`, `modelVersion`, `createdBy`, `collectionType`, `taskCapabilities`, `isExpired`, `depricationDate`) |
| `microsoft.compute/virtualmachines` | `["compute","device","environmentAzure","environmentCloud","virtual_machine"]` | All `device` keys plus `publicIP`, `aadDeviceId`, `isAzureADJoined`, `azureADJoinType`, `osArchitecture`, `senseClientVersion`, `highRiskVulnerabilityInsights`, `rdpStatus`, `remoteServicesInfo`, `tpmData`, `identifiedResourceUsers`, `hasGuardMisconfigurations`, `tags` |
| `managedidentity` | `["application_identity","environmentAzure","environmentCloud","identities","identity"]` | Similar to `serviceprincipal` |
| `mdcManagementRecommendation` | `["finding","security_finding"]` | Similar to `mdcSecurityRecommendation` |
| `mde-healthFinding` | `["finding","management_finding"]` | `description`, `remediationOptions` (array) |
| `entra-userCookie` | varies | Session/cookie entity |
| `copilot-studio-ai-agent` / `endpointAiAgent` | `["AI",…]` | AI workload agents |
| Azure resource types (`microsoft.network/…`, `microsoft.storage/…`, `microsoft.keyvault/vaults`, etc.) | `["compute","environmentAzure","environmentCloud",…]` | Resource-type-specific properties |

The full set of NodeLabel values is open-ended and tenant-dependent. Always live-sample with `take 3` when working with an unfamiliar NodeLabel.

### Querying NodeProperties efficiently

Since all data is under `rawData`, pre-filter with string `has` before parsing for performance:

```kql
// Find internet-exposed devices
ExposureGraphNodes
| where NodeLabel == "device"
| where NodeProperties has "isCustomerFacing"
| extend isExposed = tobool(NodeProperties.rawData.isCustomerFacing)
| where isExposed == true
| project NodeName, NodeId,
    onboardingStatus = tostring(NodeProperties.rawData.onboardingStatus),
    exposureScore    = tostring(NodeProperties.rawData.exposureScore),
    riskScore        = tostring(NodeProperties.rawData.riskScore)

// Find users with leaked credentials
ExposureGraphNodes
| where NodeLabel == "user"
| where NodeProperties has "hasLeakedCredentials"
| where tobool(NodeProperties.rawData.hasLeakedCredentials) == true
| project NodeName,
    upn = tostring(NodeProperties.rawData.accountUpn),
    lastPasswordChange = NodeProperties.rawData.passwordUpdateTime

// Find CVEs affecting any node (via ExposureGraphEdges join)
ExposureGraphEdges
| where EdgeLabel == "affecting"
| join kind=inner (
    ExposureGraphNodes
    | where NodeLabel == "Cve"
    | project CveNodeId=NodeId, CveName=NodeName,
              cvss=tostring(NodeProperties.rawData.cvssVectorString)
) on $left.SourceNodeId == $right.CveNodeId
| project CveName, cvss, TargetNodeName, TargetNodeLabel
```

---

## ExposureGraphEdges

One row per directional relationship (edge) between two nodes. Key columns:

| Column | Type | Notes |
|---|---|---|
| `EdgeId` | string | Unique edge identifier |
| `EdgeLabel` | string | Relationship type — see below |
| `SourceNodeId` | string | FK into `ExposureGraphNodes.NodeId` |
| `SourceNodeName` | string | Denormalized display name |
| `SourceNodeLabel` | string | Denormalized NodeLabel of source |
| `SourceNodeCategories` | dynamic | Native dynamic array |
| `TargetNodeId` | string | FK into `ExposureGraphNodes.NodeId` |
| `TargetNodeName` | string | Denormalized display name |
| `TargetNodeLabel` | string | Denormalized NodeLabel of target |
| `TargetNodeCategories` | dynamic | Native dynamic array |
| `EdgeProperties` | dynamic | Native dynamic dict — optional, under `.rawData`. May be empty (`rawData` present but no keys) |

`SourceNodeName`, `SourceNodeLabel`, `SourceNodeCategories` are denormalized copies of the source node's data — use them to avoid joining back to `ExposureGraphNodes` for simple queries.

### EdgeLabel values (confirmed live 2026-05, sorted by volume)

| EdgeLabel | Typical SourceNodeLabel → TargetNodeLabel | Notes |
|---|---|---|
| `affecting` | `Cve` → any asset | CVE-to-asset vulnerability link. EdgeProperties usually empty rawData |
| `member of` | `user`/`device` → `group` | Group membership |
| `has role on` | `managedidentity`/`serviceprincipal` → subscription/resource | RBAC role assignment; EdgeProperties `.rawData.permissions.roles` = array of JSON strings (each needs `parse_json(tostring(role))` to access `id`, `name`, `actions`, etc.) |
| `has permissions to` | identity → resource | Access permission edge |
| `can authenticate to` | `group`/`user` → `device` | Lateral movement risk; EdgeProperties `.rawData.userRightsOnDevice` = sub-object with `userRights` array and `logonMethods` array, `isLocalAdmin` bool |
| `can authenticate as` | identity → identity | Impersonation/delegation |
| `contains` | resource group/subscription → resource | Containment hierarchy |
| `can impersonate as` | identity → identity | Service account impersonation |
| `has credentials of` | identity → identity | Credential relationship |
| `frequently logged in by` | `device` → `user` | Usage pattern link |
| `routes traffic to` | network → resource | Network path |
| `runs on` / `is running` | agent/workload → infrastructure | AI/workload hosting |

`EdgeProperties` structure follows the same `.rawData` wrapper pattern as `NodeProperties`. Roles within `has role on` edges store individual role objects as JSON strings inside the `roles` array — two levels of parsing required:

```kql
ExposureGraphEdges
| where EdgeLabel == "has role on"
| mv-expand Role = EdgeProperties.rawData.permissions.roles
| extend r = parse_json(tostring(Role))
| project SourceNodeName, TargetNodeName,
    RoleName = tostring(r.name),
    RoleId   = tostring(r.id)
```

### Cross-table join patterns

Join `ExposureGraphNodes` to `ExposureGraphEdges` on `NodeId`:

```kql
// Attack path query: find users who can authenticate to internet-exposed devices
let ExposedDevices =
    ExposureGraphNodes
    | where NodeLabel in ("device", "microsoft.compute/virtualmachines")
    | where tobool(NodeProperties.rawData.isCustomerFacing) == true
    | project DeviceNodeId=NodeId, DeviceName=NodeName;
ExposureGraphEdges
| where EdgeLabel == "can authenticate to"
| join kind=inner ExposedDevices on $left.TargetNodeId == $right.DeviceNodeId
| project SourceNodeName, SourceNodeLabel, DeviceName,
    isLocalAdmin = tobool(EdgeProperties.rawData.userRightsOnDevice.isLocalAdmin)
```

Join to `DeviceInfo` for MDE-enrolled devices — link via `EntityIds`:

```kql
// Resolve ExposureGraphNodes device → DeviceInfo
ExposureGraphNodes
| where NodeLabel in ("device", "microsoft.compute/virtualmachines")
| extend eid0 = EntityIds[0]
| extend inventoryId = iff(tostring(eid0.type) == "DeviceInventoryId", tostring(eid0.id), "")
| where isnotempty(inventoryId)
| join kind=inner (
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceId, MachineGroup, OSPlatform
) on $left.inventoryId == $right.DeviceId
```

`EntityIds[0]` may not always be `DeviceInventoryId` — filter by `type` explicitly when the label can have multiple entity ID types.

---

## Common gotchas

- **No time filter available** — no `Timestamp` column. These are snapshot tables.
- **`@odata.type` annotation keys** — `fieldName@odata.type` sibling keys appear throughout `NodeProperties.rawData` and `EdgeProperties.rawData`. They are type annotations, not data. Ignore when iterating `bag_keys()`.
- **`NodeLabel` casing is inconsistent** — some are lowercase (`device`, `user`, `group`), some are PascalCase (`Cve`), some are kebab-case (`mde-healthFinding`), some are Azure resource type paths (`microsoft.compute/virtualmachines`). Use case-insensitive `=~` or `in~` if uncertain.
- **EdgeProperties may be empty** — the `rawData` key is always present but may have no child keys (e.g. `affecting` edges). Check `bag_keys(EdgeProperties.rawData)` before accessing sub-fields.
- **`Categories` is a native dynamic array** — direct indexing and `mv-expand` work; no `parse_json()` needed.
- **Table population depends on deployed products** — missing MDI → no identity edges; missing Defender for Cloud → no `mdcSecurityRecommendation` nodes, no Azure resource edges.
