# AIAgentsInfo

Copilot Studio / AI agent inventory table. Populated by Microsoft Defender for Cloud Apps connectors for **Power Platform** and **Microsoft Agent 365 (A365)**. If neither service is deployed, the table will be empty.

Official docs: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aiagentsinfo-table  
Status: Preview (as of 2026-04)

---

## Ingestion model

`Timestamp` = "last date and time recorded for the agent info" (per docs). Rows are written on **agent creation, modification, or deletion events**, not on a daily heartbeat. This means:

- The table is **sparse** — most days produce no new rows for a given agent.
- Multiple rows per `AIAgentId` accumulate over time as the agent is updated.
- **Always deduplicate with `arg_max(Timestamp, *) by AIAgentId`** to get current state. This is the canonical pattern used in all official sample queries.

**Time filter guidance:** A narrow window like `ago(7d)` will miss most agents — use `ago(90d)` or omit the time filter entirely, then rely on `arg_max` to select the latest row per agent.

```kql
// Current state of all agents — correct pattern
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
```

---

## RegistrySource segmentation

Rows are tagged with `RegistrySource` indicating their data source:

| Value | Source |
|---|---|
| `"PowerPlatform"` | Defender for Cloud Apps — Power Platform connector |
| `"A365"` | Microsoft Agent 365 |
| `""` (empty) | Observed in some tenants; source unclear |

Many columns are populated by only one source. Filter `RegistrySource` before accessing source-specific columns.

---

## Schema

Live schema as of 2026-04 (from `getschema`):

| Column | Type | Notes |
|---|---|---|
| `Timestamp` | datetime | Last event time for this agent record |
| `AIAgentId` | guid | Unique agent identifier |
| `AIAgentName` | string | Display name |
| `AgentCreationTime` | datetime | |
| `AgentStatus` | string | `Created`, `Published`, `Deleted` |
| `AgentDescription` | string | |
| `Instructions` | string | System prompt / persona definition |
| `Version` | string | |
| `Platform` | string | Currently `Copilot Studio` |
| `RegistrySource` | string | See above |
| `EnvironmentId` | string | Power Platform environment |
| `AgentAppId` | string | Entra app registration ID |
| `EntraObjectId` | guid | Enterprise app object ID |
| `EntraBlueprintId` | guid | Agent identity blueprint principal (Entra Agent ID) |
| `SourceAgentId` | string | Platform-native ID (ARM ID for Foundry agents; env-scoped ID for Copilot Studio) |
| `AIModel` | string | |
| `IsBlocked` | bool | Blocked by admin |
| `IsGenerativeOrchestrationEnabled` | bool | Agent uses dynamic tool/knowledge selection |
| `CreatorAccountUpn` | string | PowerPlatform only |
| `OwnerAccountUpns` | string | PowerPlatform only; semicolon-delimited UPNs |
| `LastModifiedByUpn` | string | |
| `LastModifiedTime` | datetime | |
| `LastPublishedTime` | datetime | |
| `UserAuthenticationType` | string | `None`, `Microsoft`, `Custom` |
| `AuthenticationTrigger` | string | `As Needed`, `Always` |
| `AccessControlPolicy` | string | `Any`, `Copilot readers`, `Group membership`, `Any (multitenant)` |
| `AgentActionTriggers` | string | JSON string — triggers for autonomous action |
| `RawAgentInfo` | string | Full raw JSON from provider; parse with `parse_json(RawAgentInfo)` |
| `KnowledgeDetails` | dynamic | Knowledge sources added to the agent |
| `AgentToolsDetails` | dynamic | Tools the agent can access |
| `AgentTopicsDetails` | dynamic | Topic/dialog specs (PowerPlatform) |
| `AuthorizedSecurityGroupIds` | dynamic | AAD group IDs allowed to interact |
| `ConnectedAgentsSchemaNames` | dynamic | Schema names of linked agents |
| `ChildAgentsSchemaNames` | dynamic | Schema names of child agents |
| `AccessCapabilities` | dynamic | Data access capabilities granted |
| `ElementTypes` | dynamic | Technical component types |
| `TenantId` | string | Log Analytics system column |
| `TimeGenerated` | datetime | Log Analytics ingest time (use `Timestamp` for event time) |
| `SourceSystem` | string | Log Analytics system column |
| `Type` | string | Log Analytics system column |

**Schema discrepancy:** Official docs list `LastPublishedByUpn` as a column, but it is absent from the live `getschema` output (2026-04). May be source-specific or not yet rolled out.

**Type discrepancy:** Docs list `KnowledgeDetails` as `string`; live schema shows `dynamic`.

---

## Dynamic columns

`AgentToolsDetails`, `AgentTopicsDetails`, `KnowledgeDetails`, `ConnectedAgentsSchemaNames`, `AccessCapabilities`, `ElementTypes` are `dynamic` — sample live rows to understand their structure before querying.

`AgentActionTriggers` and `RawAgentInfo` are `string` type (not `dynamic`), but contain JSON. Use `parse_json()` explicitly:

```kql
| extend RawAgentInfoJson = parse_json(RawAgentInfo)
| extend DeveloperName = RawAgentInfoJson.developerName
```

---

## Common patterns

**Get current state of all active agents:**
```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| project AIAgentId, AIAgentName, RegistrySource, AgentStatus, CreatorAccountUpn, LastModifiedTime, IsBlocked
```

**Agents with no authentication (PowerPlatform):**
```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where RegistrySource == "PowerPlatform"
| where AgentStatus != "Deleted"
| where UserAuthenticationType == "None"
```

**Agents with MCP tools configured (PowerPlatform):**
```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where RegistrySource == "PowerPlatform"
| where AgentStatus != "Deleted"
| mvexpand Action = AgentToolsDetails
| where Action.action.operationDetails["$kind"] == "ModelContextProtocolMetadata"
```

**Agents with MCP tools (A365):**
```kql
AIAgentsInfo
| where RegistrySource == "A365"
| summarize arg_max(Timestamp, *) by AIAgentId
| extend AgentActionTriggersJson = parse_json(AgentActionTriggers)
| mv-expand Trigger = AgentActionTriggersJson
| where Trigger.type == "RemoteMCPServer"
```

**Join owner UPN via IdentityInfo (A365 — owner stored in RawAgentInfo):**
```kql
let UPNMap = materialize(IdentityInfo | distinct AccountObjectId, AccountUpn | extend AccountObjectId = tostring(AccountObjectId));
AIAgentsInfo
| where RegistrySource == "A365"
| summarize arg_max(Timestamp, *) by AIAgentId
| extend OwnerId = tostring(parse_json(RawAgentInfo).owners[0].entityId)
| join kind=leftouter UPNMap on $left.OwnerId == $right.AccountObjectId
```

---

## Security hunting use cases

- Agents with `UserAuthenticationType == "None"` (publicly accessible)
- Agents with `IsGenerativeOrchestrationEnabled == true` and empty `Instructions` (prompt injection risk)
- HTTP (non-HTTPS) action endpoints in `AgentActionTriggers`
- Hard-coded credentials pattern-matched in `AgentToolsDetails` or `AgentTopicsDetails`
- MCP tools added to agents (new attack surface)
- `IsBlocked == false` agents with broad `AccessControlPolicy == "Any"`
