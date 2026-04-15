# Eval 5 WITH skill: AIAgentsInfo doc fetch

## Tool calls made

1. **`mcp__defender__get_hunting_schema(table_name="AIAgentsInfo")`** — 40 columns; confirmed `AgentToolsDetails`, `AgentTopicsDetails`, `ConnectedAgentsSchemaNames` are dynamic; `IsGenerativeOrchestrationEnabled` is bool
2. **`mcp__defender__run_hunting_query("AIAgentsInfo | take 3")`** — result too large (1.4M chars); accessed via Grep to understand shape
3. **`mcp__defender__run_hunting_query` (focused sample: non-empty AgentToolsDetails, take 2)** — revealed `AgentToolsDetails` is a JSON array with `action.$kind` values: `InvokeConnectorTaskAction` and `InvokeAIPluginTaskAction`
4. **`mcp__microsoft-learn__microsoft_docs_fetch(url="https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aiagentsinfo-table")`** — full column reference fetched plus 5 official sample security queries including HTTP exfiltration patterns
5. **`mcp__defender__run_hunting_query` (distinct action.$kind counts)** — only 2 kinds: `InvokeAIPluginTaskAction` (12), `InvokeConnectorTaskAction` (6)
6. **`mcp__defender__run_hunting_query` (InvokeConnectorTaskAction connection reference analysis)** — all 6 rows use Microsoft first-party Dataverse connector (`shared_commondataserviceforapps`)
7. **`mcp__defender__run_hunting_query` (InvokeAIPluginTaskAction entity key details)** — all 12 rows belong to `CustomerServiceKnowledgeHarvest` with 4 AI plugin operations
8. **`mcp__defender__run_hunting_query` (HttpRequestAction in AgentTopicsDetails with external host filtering)** — 13 rows, all hosts Microsoft-internal; zero external hosts
9. **`mcp__defender__run_hunting_query` (method field extraction syntax test)** — confirmed `todynamic(tostring(action.method)).literalValue` returns `Post`/`Get`
10. **Multiple syntax-validation runs** — identified Defender KQL limitations: ternary `? :` not supported (must use `iff()`); `let` subqueries with `union` cause parse errors
11. **`mcp__defender__run_hunting_query` (final query)** — executed successfully; 1 agent returned: `CustomerServiceKnowledgeHarvest` (RiskScore=4, 4 AIPlugin connectors)

---

## Final KQL query

### Primary: Agent tools with external HTTP connectors

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| where isnotempty(AgentToolsDetails)
| mvexpand Action = AgentToolsDetails
| extend ActionKind    = tostring(Action.action["$kind"])
| extend ConnectionRef = tostring(Action.action.connectionReference)
| extend EntityKey     = tostring(Action.action.entityKey)
| extend DisplayName   = tostring(Action.modelDisplayName)
| extend OperationId   = tostring(Action.action.operationId)
| extend IsExternalConnector = (
    ActionKind == "InvokeConnectorTaskAction"
    and not(ConnectionRef has_any(
        "commondataserviceforapps", "office365", "sharepointonline",
        "shared_teams", "azureblob", "microsoftforms", "onedriveforbusiness",
        "shared_outlook", "shared_powerbi", "shared_planner", "microsoftgraph"
    ))
)
| extend IsAIPlugin = (ActionKind == "InvokeAIPluginTaskAction")
| where IsExternalConnector or IsAIPlugin
| extend ConnectorType = iff(IsAIPlugin,
    "AIPlugin (custom OpenAPI/REST)",
    "CustomConnector (3rd-party Power Platform)"
)
| extend ExternalHost = iff(IsAIPlugin, EntityKey, ConnectionRef)
| extend ConnDetail = iff(IsAIPlugin,
    strcat(DisplayName, " | entityKey=", EntityKey),
    strcat(DisplayName, " | op=", OperationId, " | ref=", ConnectionRef)
)
| summarize
    ConnectorTypes   = make_set(ConnectorType),
    ConnectorDetails = make_set(ConnDetail),
    ExternalHosts    = make_set(ExternalHost),
    LastModifiedTime = max(LastModifiedTime)
    by AIAgentId, AIAgentName, AgentStatus, CreatorAccountUpn,
       OwnerAccountUpns, IsGenerativeOrchestrationEnabled
| extend ExternalConnectorCount = array_length(ExternalHosts)
| extend RiskScore = ExternalConnectorCount + iff(IsGenerativeOrchestrationEnabled == true, 2, 0)
| order by RiskScore desc, LastModifiedTime desc
| project
    AIAgentName, AgentStatus, RiskScore, IsGenerativeOrchestrationEnabled,
    ExternalConnectorCount, ConnectorTypes, ExternalHosts, ConnectorDetails,
    CreatorAccountUpn, OwnerAccountUpns, LastModifiedTime, AIAgentId
```

### Supplementary: Direct outbound HTTP in Topics to external hosts

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| where AgentTopicsDetails has "HttpRequestAction"
| mvexpand Topic = AgentTopicsDetails
| where Topic has "HttpRequestAction"
| extend TopicActions = Topic.beginDialog.actions
| mvexpand action = TopicActions
| where action["$kind"] == "HttpRequestAction"
| extend Url        = tostring(action.url.literalValue)
| extend HttpMethod = tostring(todynamic(tostring(action.method)).literalValue)
| extend Host       = tostring(parse_url(Url)["Host"])
| where isnotempty(Host)
| where not(Host has_any(
    "microsoft.com", "microsoftonline.com", "azure.com", "azureedge.net",
    "sharepointonline.com", "dynamics.com", "office.com", "dataverse", "ppapi.env"
))
| summarize
    ExternalUrls     = make_set(strcat(HttpMethod, " ", Url)),
    ExternalHosts    = make_set(Host),
    LastModifiedTime = max(LastModifiedTime)
    by AIAgentId, AIAgentName, AgentStatus, CreatorAccountUpn,
       OwnerAccountUpns, IsGenerativeOrchestrationEnabled
| extend RiskScore = array_length(ExternalHosts) + iff(IsGenerativeOrchestrationEnabled == true, 2, 0)
| order by RiskScore desc
| project
    AIAgentName, AgentStatus, RiskScore, IsGenerativeOrchestrationEnabled,
    ExternalHosts, ExternalUrls, CreatorAccountUpn, OwnerAccountUpns,
    LastModifiedTime, AIAgentId
```

---

## Notes

- Two queries required: Defender KQL doesn't support `let` subqueries with `union`; ternary `? :` not supported (use `iff()`).
- `arg_max(Timestamp, *) by AIAgentId` gets current state — no time filter; correct for snapshot-style table.
- Correct column is `AgentToolsDetails` (not `Tools`); `action.$kind` values discovered by live sampling.
- `IsGenerativeOrchestrationEnabled=true` adds +2 risk: autonomous tool selection enables XPIA attacks.
- Tenant finding: 1 agent flagged (`CustomerServiceKnowledgeHarvest`, 4 AI plugin tools). All `InvokeConnectorTaskAction` tools are first-party Dataverse — not external.
- MS Learn doc fetch returned official sample queries, directly informing the `HttpRequestAction` supplementary query.
