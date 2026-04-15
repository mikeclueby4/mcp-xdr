# Eval 2 WITHOUT skill: AI agents hunting query (baseline)

## Final query
```kql
AIAgentsInfo
| where Timestamp > ago(90d)
| mv-expand KnowledgeEntry = KnowledgeDetails
| extend SourceKind = tostring(KnowledgeEntry['source']['$kind'])
| extend ExternalSiteUrl = tostring(KnowledgeEntry['source']['site']['literalValue'])
| summarize
    KnowledgeSourceKinds     = make_set(SourceKind),
    ExternalUrls             = make_set_if(ExternalSiteUrl, isnotempty(ExternalSiteUrl)),
    HasPublicWebKnowledge    = max(toint(SourceKind == 'PublicSiteSearchSource')),
    HasNonDataverseKnowledge = max(toint(SourceKind != 'DataverseStructuredSearchSource' and isnotempty(SourceKind))),
    HasConnectedAgents       = max(toint(isnotempty(ConnectedAgentsSchemaNames))),
    HasChildAgents           = max(toint(isnotempty(ChildAgentsSchemaNames))),
    ConnectedAgents          = take_any(ConnectedAgentsSchemaNames),
    ChildAgents              = take_any(ChildAgentsSchemaNames),
    CreatorUpn               = take_any(CreatorAccountUpn),
    OwnerUpns                = take_any(OwnerAccountUpns),
    AgentStatus              = take_any(AgentStatus),
    Platform                 = take_any(Platform),
    LastModified             = max(LastModifiedTime),
    LastPublished            = max(LastPublishedTime)
    by AIAgentId, AIAgentName
| where HasPublicWebKnowledge == 1
    or HasNonDataverseKnowledge == 1
    or HasConnectedAgents == 1
    or HasChildAgents == 1
| extend RiskIndicators = strcat(...)
| project AIAgentName, AIAgentId, RiskIndicators, ...
| sort by LastModified desc
```

## Results
1 agent: D365 Sales Agent - Email Validation
- ExternalUrls: whois.com, lookup.icann.org
- Note: used 90d window (7d default returned no rows — AIAgentsInfo data is sparse/snapshot)
- 21 tool uses (more exploration than with-skill's 18)
