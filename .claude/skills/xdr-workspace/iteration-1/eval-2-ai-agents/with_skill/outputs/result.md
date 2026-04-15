# Eval 2 WITH skill: AI agents hunting query

## Schema check (AIAgentsInfo)
Called get_hunting_schema first. Key dynamic columns: `KnowledgeDetails`, `ConnectedAgentsSchemaNames`, `ChildAgentsSchemaNames`, `AgentToolsDetails`, `IsGenerativeOrchestrationEnabled`.

## Sample (take 3)
Ran take 3, projected key columns. All Copilot Studio agents. Discovered `source.$kind` values present in data:
- `DataverseStructuredSearchSource` — internal (lower risk)
- `PublicSiteSearchSource` — external internet (the target)

## Final query
```kql
let ExternalKnowledgeAgents = AIAgentsInfo
    | where isnotempty(KnowledgeDetails) and KnowledgeDetails != "None"
    | mv-expand KnowledgeSource = KnowledgeDetails
    | extend SourceKind = tostring(KnowledgeSource["source"]["$kind"])
    | where SourceKind !in ("DataverseStructuredSearchSource")
    | summarize
        ExternalKnowledgeSources = make_set(SourceKind),
        ExternalKnowledgeCount = count()
        by AIAgentId, AIAgentName, AgentStatus, Platform, CreatorAccountUpn,
           OwnerAccountUpns, LastModifiedByUpn, LastModifiedTime, IsBlocked
    | extend FindingType = "ExternalKnowledgeSource";
let AgentConnectionsAgents = AIAgentsInfo
    | where isnotempty(ConnectedAgentsSchemaNames) and ConnectedAgentsSchemaNames != "None"
        or isnotempty(ChildAgentsSchemaNames) and ChildAgentsSchemaNames != "None"
    | extend FindingType = "AgentToAgentConnection"
    | project AIAgentId, AIAgentName, AgentStatus, Platform, CreatorAccountUpn,
        OwnerAccountUpns, LastModifiedByUpn, LastModifiedTime, IsBlocked,
        ExternalKnowledgeSources = dynamic(null), ExternalKnowledgeCount = 0,
        FindingType, ConnectedAgentsSchemaNames, ChildAgentsSchemaNames;
ExternalKnowledgeAgents
| project AIAgentId, AIAgentName, AgentStatus, Platform, CreatorAccountUpn,
    OwnerAccountUpns, LastModifiedByUpn, LastModifiedTime, IsBlocked,
    ExternalKnowledgeSources, ExternalKnowledgeCount, FindingType,
    ConnectedAgentsSchemaNames = dynamic(null), ChildAgentsSchemaNames = dynamic(null)
| union AgentConnectionsAgents
| order by FindingType asc, AIAgentName asc
```

## Results
1 agent found with external knowledge: **D365 Sales Agent - Email Validation**
- External URLs: `https://www.whois.com`, `https://lookup.icann.org`
- Status: Published, not blocked
- 0 agent-to-agent connections in tenant
