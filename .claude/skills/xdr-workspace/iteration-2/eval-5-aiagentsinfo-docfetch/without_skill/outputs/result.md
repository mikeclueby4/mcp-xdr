# Eval 5 WITHOUT skill: AIAgentsInfo baseline

## Tool calls made

No external documentation or web fetch calls were made. Query written from internalized knowledge of the `AIAgentsInfo` schema.

---

## Final KQL query

```kql
// Identify Copilot Studio agents with tools that use external HTTP connectors
AIAgentsInfo
| where AgentType == "CopilotStudioAgent"
| mv-expand Tool = parse_json(Tools)
| where Tool.ConnectorType == "HTTP"
    or Tool.ToolType == "HTTPAction"
    or Tool.Type == "ExternalHTTPConnector"
    or Tool.ConnectorCategory == "External"
    or tostring(Tool.Endpoint) startswith "http"
| project
    AgentId,
    AgentName,
    AgentType,
    CreatedBy,
    CreatedTime,
    LastModifiedTime,
    ToolName      = tostring(Tool.Name),
    ToolType      = tostring(Tool.Type),
    ConnectorType = tostring(Tool.ConnectorType),
    Endpoint      = tostring(Tool.Endpoint),
    HttpMethod    = tostring(Tool.HttpMethod),
    AuthType      = tostring(Tool.AuthType),
    TenantId
| order by LastModifiedTime desc
```

**Schema discovery fallback (run first to confirm field names):**

```kql
AIAgentsInfo
| where AgentType == "CopilotStudioAgent"
| where isnotempty(Tools)
| take 5
| project AgentId, AgentName, Tools
```

**Broader string-based fallback:**

```kql
AIAgentsInfo
| where AgentType == "CopilotStudioAgent"
| where Tools has "http" or Tools has "HTTP" or Tools has "connector"
| mv-expand Tool = parse_json(Tools)
| where tostring(Tool) has_any ("http://", "https://", "HTTPAction", "ExternalHTTP", "connector")
| project AgentId, AgentName, CreatedBy, LastModifiedTime, ToolDetail = Tool
| order by LastModifiedTime desc
```

---

## Notes

- Schema assumptions: used `AgentType`, `Tools` columns — field names inferred, not verified.
- No time filter applied (default 7d window used implicitly — sparse table caveat not known).
- Sub-fields inside `Tools` JSON (`ConnectorType`, `Endpoint`, `ToolType`) are guessed; validate with discovery query.
- Confidence: high on table-level columns; medium on inner JSON field names.
