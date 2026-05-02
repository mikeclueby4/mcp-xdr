# Dynamic Column Serialization in Defender Advanced Hunting
**Date:** 2026-04-28  
**Status:** Complete — all major questions resolved via live testing

---

## The Question

When querying Defender Advanced Hunting via the Graph Security API (`runHuntingQuery`), why do some `dynamic` columns come back wrapped with `@odata.type: "#microsoft.graph.security.dynamicColumnValue"` while others don't? Is there a systematic rule?

**Short answer:** Yes. The rule is `getschema` ColumnType. `string` columns never get the wrapper; `dynamic` columns always do (when queried via the Graph API). `getschema` is honest — it predicts runtime behaviour exactly, confirmed across all tested tables with no exceptions.

```kql
TableName | getschema | where ColumnName == "TheColumn"
// ColumnType "string"  → stores JSON as text; parse_json(tostring(col)) required; no @odata.type wrapper
// ColumnType "dynamic" → native Kusto dynamic; direct col.Field access works; @odata.type wrapper appears via Graph API
```

---

## The Master Table

`| getschema` and `get_schema()` DefenderType agree perfectly on all tested columns — they both run `| getschema` against the same Defender API. SentinelType comes from a separate Log Analytics schema registry and **can differ** from DefenderType; when it does, DefenderType is ground truth for runtime behaviour.

| Column | Table | DefenderType | SentinelType | `@odata.type` wrapper | Direct access |
|---|---|---|---|---|---|
| `AdditionalFields` | `DeviceProcessEvents` | `string` | `dynamic` ⚠️ | No | `parse_json(tostring(col))` |
| `AdditionalFields` | `AlertEvidence` | `string` | `string` | No | `parse_json(tostring(col))` |
| `AdditionalFields` | `EmailEvents` | `string` | `string` | No | `parse_json(tostring(col))` |
| `AdditionalFields` | `CloudAppEvents` | `dynamic` | `dynamic` | **Yes** | `col.Field` |
| `AdditionalFields` | `IdentityLogonEvents` | `dynamic` | `dynamic` | **Yes** | `col.Field` |
| `ActivityObjects` | `CloudAppEvents` | `dynamic` | `dynamic` | **Yes** | `mv-expand` then `elem.Field` |
| `RawEventData` | `CloudAppEvents` | `dynamic` | `dynamic` | **Yes** | `col.Field` |
| `LastSeenForUser` | `CloudAppEvents` | `dynamic` | `dynamic` | **Yes** | `col.Field` |
| `NodeProperties` | `ExposureGraphNodes` | `dynamic` | N/A (Defender-only) | **Yes** | `col.rawData.Field` (single-key wrapper — see below) |
| `ConditionalAccessPolicies` | `EntraIdSignInEvents` | `string` | N/A (Defender-only) | No | `parse_json(tostring(col))` |
| `AuthenticationProcessingDetails` | `EntraIdSignInEvents` | `string` | N/A (Defender-only) | No | `parse_json(tostring(col))` |
| `LogonType` | `EntraIdSignInEvents` | `string` | N/A (Defender-only) | No | `tostring(col)` then `contains`/`parse_json` |

**⚠️ `DeviceProcessEvents.AdditionalFields` SentinelType mismatch:** In some tenants, an older Log Analytics connector registered this column as `dynamic` in its schema — predating the unified portal and set up independently of the Defender pipeline. The physical data is still a JSON-encoded string (`gettype()` = `"string"`, column blank in Sentinel sample rows). The two schema registries are independent; a legacy connector's schema declaration can outlive the actual data shape. DefenderType is always the authoritative signal for how data actually behaves — SentinelType reflects how the Log Analytics schema was originally declared, not necessarily the current physical storage type.

---

## Three Behaviours to Know

### 1. `string` ColumnType — parse before access

The column stores JSON as a plain string. `getschema` says `string`. Direct property access (`col.Field`) silently returns null. `bag_keys(col)` fails at compile time with "argument must be a dynamic."

```kql
// WRONG — silently null
| extend policy = ConditionalAccessPolicies[0].id

// RIGHT
| extend parsed = parse_json(tostring(ConditionalAccessPolicies))
| extend policy = parsed[0].id
```

`LogonType` stores a JSON array string (e.g. `["nonInteractiveUser"]`). Use `contains` or `parse_json(tostring(LogonType))` — not `==`.

**Why some `AdditionalFields` are `string`:** MDE-sourced tables (`Device*`, `Alert*`) ingest `AdditionalFields` as a JSON-encoded string. MDI-sourced (`Identity*`) and MDCA-sourced (`CloudApp*`) tables ingest it as a native Kusto dynamic. Product-team-level ingestion decision, not controllable at query time.

---

### 2. `dynamic` ColumnType — direct access works, expect `@odata.type` noise from Graph API

The column is a native Kusto dynamic. `getschema` says `dynamic`. Direct `col.Field` access works. `bag_keys(col)` compiles and returns the key list.

When queried via `run_hunting_query` (Graph Security API), the serializer annotates dictionary-typed columns with `@odata.type: "#microsoft.graph.security.dynamicColumnValue"`. This is cosmetic — it does not break property access. It does not appear when querying via `run_sentinel_query` (Log Analytics API).

Additional serializer behaviour:
- Nested dynamic objects get the wrapper recursively (e.g. `RawEventData.AppAccessContext`)
- Int64 fields get a sibling annotation key: `FieldName@odata.type: "#Int64"` alongside the actual value under `FieldName`

---

### 3. `dynamic` ColumnType with a single-key wrapper — `NodeProperties.rawData`

`ExposureGraphNodes.NodeProperties` is a genuine native dynamic (`getschema` = `dynamic`, `bag_keys()` works) but all payload is nested one level deeper under a single key — `rawData`. Direct access to named fields returns null not because of encoding but because they don't exist at the top level.

```kql
// bag_keys shows the structure
ExposureGraphNodes | sample 1 | extend keys = bag_keys(NodeProperties)
// → ["rawData"]

// WRONG — no top-level field named "deviceName"
| extend name = NodeProperties.deviceName

// RIGHT
| extend name = NodeProperties.rawData.deviceName       // device nodes
| extend upn  = NodeProperties.rawData.accountUpn       // identity nodes
| extend desc = NodeProperties.rawData.description      // vulnerability nodes
```

The schema of `rawData` varies by `NodeLabel`. Run `bag_keys(NodeProperties.rawData)` or `tostring(NodeProperties)` on a sample to discover available fields for a given node type. Gets `@odata.type` wrapper from Graph API (behaviour 2 — it's a native dictionary).

---

## Columns Worth Calling Out

### `CloudAppEvents.ActivityObjects`

`getschema` ColumnType = `dynamic`, `gettype(ActivityObjects)` = `"array"`. After `mv-expand`, elements are `"dictionary"` and direct `elem.Field` access works on both `run_hunting_query` and `run_sentinel_query`.

**Note:** An earlier test session (before 2026-04-28) found elements were JSON-encoded strings on the Defender backend. A 2026-04-28 retest across 14 `ActionType` values showed `"dictionary"` on both backends. Best explanation: Microsoft fixed the pipeline. Defensive `parse_json(tostring(elem))` still works but is no longer required.

### `CloudAppEvents.LastSeenForUser`

Despite the name, values are **integer counts** per attribute — e.g. `{"ActionType":0,"ISP":13,"IPAddress":13}` — not a timestamp. The integers appear to represent how many times each attribute appeared in recent activity for that user. `getschema` = `dynamic`, direct access works on both backends.

### `AIAgentsInfo.AgentToolsDetails`

`getschema` = `dynamic`, `gettype()` = `"array"` on populated rows (column is very sparse — mostly null). Elements are native dictionaries; `[0].toolEnabled` and `[0]["$kind"]` work directly. Check `isnotempty()` before accessing.

### `ExposureGraphNodes.EntityIds`

`getschema` = `dynamic`, `gettype()` = `"array"`. Elements are **JSON-encoded strings** — the same array-of-encoded-strings pattern. Sample: `["{\"type\":\"AiModelNameAndVersion\",\"id\":\"name=gpt-5;version=2025-08-07\"}"]`. Use `mv-expand` then `parse_json(tostring(elem))` to access fields.

```kql
ExposureGraphNodes
| mv-expand EntityId = EntityIds
| extend parsed = parse_json(tostring(EntityId))
| extend entityType = tostring(parsed.type)
| extend entityId   = tostring(parsed.id)
```

---

## Decision Flow

```
Look up the column with: TableName | getschema | where ColumnName == "TheColumn"
  OR: get_schema(table_name="TableName") → use DefenderType column, not SentinelType
  (SentinelType can misreport — e.g. DeviceProcessEvents.AdditionalFields shows dynamic
   in Sentinel schema but is physically string at rest)

  ColumnType "string"
    → parse_json(tostring(col)) before any property access
    → no @odata.type wrapper in output

  ColumnType "dynamic"
    → direct col.Field access works
    → @odata.type wrapper will appear via Graph API (cosmetic — ignore)
    → if col.Field returns null despite correct field name:
        run bag_keys(col) — if only key is "rawData", use col.rawData.Field
    → if col is an array: mv-expand then elem.Field
        → run gettype(elem) on a sample to check element type
        → "dictionary" → direct elem.Field access
        → "string"     → parse_json(tostring(elem)).Field
```

---

## What Microsoft Documents

- `dynamicColumnValue` resource type has an empty schema (`{}`). No properties, no relationships documented — official position is pass-through with no guarantees.
- No Microsoft docs describe per-table or per-column serialization differences, or the `getschema` ↔ wrapper correlation.
- The `FieldName@odata.type: "#Int64"` sibling key pattern is standard OData behaviour for numeric type annotation.

---

## Querying Safely

```kql
// Step 1: check the schema before writing a query against an unfamiliar column
TableName | getschema | where ColumnName == "TheColumn"

// Step 2 (optional): verify at runtime and discover top-level keys
TableName
| where Timestamp > ago(1d)
| sample 10
| extend col_type = gettype(TheColumn)
| extend col_keys = iff(col_type == "dictionary", tostring(bag_keys(TheColumn)), "n/a")
| summarize by col_type, col_keys
```

**mcp-xdr `get_schema(table_name=...)` is equivalent to `getschema`** and returns ColumnType directly — use it instead of a separate query when already working via the MCP tools.

**Sentinel vs Defender:** `@odata.type` wrappers appear only via `run_hunting_query` (Graph API). `run_sentinel_query` (Log Analytics API) returns clean JSON with no wrapper and no int64 sibling keys. The ColumnType rule still holds for access patterns — only the wrapper noise differs.

**mcp-xdr TSV note:** TSV output cannot reliably distinguish a native JSON object from a JSON-encoded string — both appear as JSON text. The only visual hint is escaped inner quotes (`\"`) in the encoded-string case. Ground truth is `getschema` ColumnType.

---

## Why the ARM Data Connectors API Is Not Used Here

The ARM `GET .../dataConnectors` endpoint (`api-version=2024-03-01` or later) can identify which connector type is registered in a tenant via the `kind` field. This is mechanistically relevant — a tenant with a legacy standalone connector is the exact configuration that produces SentinelType mismatches like the `DeviceProcessEvents.AdditionalFields` case above.

**Relevant `kind` values (verified against ARM schema, Apr 2026):**

| `kind` | API version | Meaning | Schema drift risk |
|---|---|---|---|
| `MicrosoftThreatProtection` | preview only (≥ 2023-04-01-preview) | Modern unified Defender XDR connector | Low |
| `MicrosoftDefenderAdvancedThreatProtection` | GA 2024-03-01+ | Legacy standalone MDE (Defender for Endpoint) | **High** |
| `MicrosoftCloudAppSecurity` | GA 2024-03-01+ | Legacy standalone MDCA (Defender for Cloud Apps) | **High** |
| `AzureAdvancedThreatProtection` | GA 2024-03-01+ | Legacy standalone MDI (Defender for Identity) | **High** |

**Naming footgun:** The ARM `kind` values were never updated when Microsoft rebranded from "Microsoft Threat Protection" → "Microsoft 365 Defender" → "Defender XDR". `MicrosoftThreatProtection` is the API name for what the UI calls the unified Defender XDR connector. `Microsoft365Defender` does not exist anywhere in the ARM schema.

**Why this API is (currently) not implemented in mcp-xdr:** The ARM path requires `SENTINEL_SUBSCRIPTION_ID`, `SENTINEL_RESOURCE_GROUP`, and `SENTINEL_WORKSPACE_NAME` — three values with no current config home. Also, `MicrosoftThreatProtection` only appears when calling a preview API version; the GA `2024-03-01` schema would never return it, making positive identification of modern-connector tenants impossible without a preview call.

**Why `DefenderType` remains sufficient:** The connectors API answers *why* a mismatch exists in a given tenant, not *what the correct access pattern is*. `DefenderType` from `get_schema()` already gives the ground truth column type directly — use that for query decisions regardless of connector age.
