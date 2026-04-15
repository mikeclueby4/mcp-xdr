# Eval 5 — AIAgentsInfo: Copilot Studio Agents with External HTTP Connectors

## Tool call sequence (7 substantive calls)
| # | Tool | Purpose | Result |
|---|------|---------|--------|
| 1 | `mcp__microsoft-learn__microsoft_docs_fetch` | Fetch AIAgentsInfo docs | Full schema + 5 official sample queries; revealed exact `Topic.beginDialog.actions` → `HttpRequestAction` path |
| 2 | `mcp__defender__get_hunting_schema` | Get column types | Confirmed `AgentTopicsDetails` and `AgentToolsDetails` are `dynamic` |
| 3 | `mcp__defender__run_hunting_query` | `AIAgentsInfo \| take 3` | Too large (1M chars) — `RawAgentInfo` blobs dominate |
| 4 | `mcp__defender__run_hunting_query` | Sample with `mvexpand AgentToolsDetails` | Too large; grepped for connector patterns |
| 5 | `mcp__defender__run_hunting_query` | Full HTTP connector query (all hosts) | 13 rows — all internal Microsoft endpoints |
| 6 | `mcp__defender__run_hunting_query` | Same query with external-host filter | 0 rows — no external HTTP connectors |
| 7 | `mcp__defender__run_hunting_query` | Companion query on `AgentToolsDetails` | 0 rows — no non-Microsoft connector tools |

## Final KQL Query

```kql
// Security review: Copilot Studio agents with external HTTP connectors (exfiltration risk)
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| mvexpand Topic = AgentTopicsDetails
| where Topic has "HttpRequestAction"
| extend TopicActions = Topic.beginDialog.actions
| mvexpand action = TopicActions
| where action['$kind'] == "HttpRequestAction"
| extend HttpUrl = tostring(action.url.literalValue)
| extend ParsedUrl = parse_url(HttpUrl)
| extend HttpHost = tostring(ParsedUrl["Host"])
| extend HttpPort = tostring(ParsedUrl["Port"])
| extend HttpMethod = tostring(action.method)
| where isnotempty(HttpHost)
| where not (HttpHost has_any(
    "dataverse", "microsoft.com", "microsoftonline.com", "azure.com",
    "office.com", "sharepoint.com", "graph.microsoft.com",
    "management.azure.com", "ppapi.env", "dynamics.com"
))
| project
    Timestamp, AIAgentId, AIAgentName, AgentStatus,
    CreatorAccountUpn, OwnerAccountUpns,
    UserAuthenticationType, IsGenerativeOrchestrationEnabled,
    ExternalHost = HttpHost, FullUrl = HttpUrl,
    Port = HttpPort, Method = HttpMethod,
    EnvironmentId, ConnectorType = "DirectHttpRequest"
| sort by AIAgentName asc
```

**Result on this tenant: 0 agents.** All observed HTTP actions call internal Microsoft platform endpoints.

## Notable observations
1. MS Learn doc fetch was highly productive — official page included exact property path (`Topic.beginDialog.actions` → `$kind == "HttpRequestAction"`), saving significant trial-and-error.
2. `AIAgentsInfo | take 3` produces 1M+ characters because `RawAgentInfo` contains huge JSON blobs. Always `project`-away `RawAgentInfo` in exploratory queries.
3. Skill's note about omitting time filters on `AIAgentsInfo` confirmed correct — snapshot-style table.
4. Two exfiltration paths to check: (1) `HttpRequestAction` in `AgentTopicsDetails` (direct HTTP, bypasses connector governance) and (2) non-Microsoft connectors in `AgentToolsDetails`.
