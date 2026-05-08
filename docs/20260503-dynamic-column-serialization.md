# Dynamic Column Serialization in Defender Advanced Hunting
**Date:** 2026-05-03 (supersedes [20260428-dynamic-column-serialization.md](20260428-dynamic-column-serialization.md))
**Status:** Complete — extended with `parse_json()` semantics and array-element-type ambiguity findings from 2026-05-03

---

## The Question

When querying Defender Advanced Hunting via the Graph Security API (`runHuntingQuery`), why do some `dynamic` columns come back wrapped with `@odata.type: "#microsoft.graph.security.dynamicColumnValue"` while others don't? Is there a systematic rule? And — added 2026-05-03 — when is the `tostring()` wrap inside `parse_json(tostring(col))` actually required versus redundant?

**Short answers:**

1. **Wrapper rule:** `getschema` ColumnType decides. `string` columns never get the wrapper; `dynamic` columns always do (when queried via the Graph API). `getschema` is honest — it predicts runtime behaviour exactly, confirmed across all tested tables with no exceptions.

2. **`tostring()` rule:** `tostring()` inside `parse_json(tostring(col))` is required only when the argument's *declared KQL type* is `dynamic`. For a `string`-typed column, `parse_json(col)` works directly. The defensive form `parse_json(tostring(col))` is always correct (no-ops harmlessly on dynamic, parses on string) and is the recommended idiom for KQL-authoring LLMs that may not have read `getschema` first.

```kql
TableName | getschema | where ColumnName == "TheColumn"
// ColumnType "string"  → stores JSON as text; parse_json(col) works; parse_json(tostring(col)) also works (redundant tostring)
// ColumnType "dynamic" → native Kusto dynamic; direct col.Field access works; @odata.type wrapper appears via Graph API
```

---

## The Master Table

`| getschema` and `get_schema()` DefenderType agree perfectly on all tested columns — they both run `| getschema` against the same Defender API. SentinelType comes from a separate Log Analytics schema registry and **can differ** from DefenderType — this can occur in any tenant, since Sentinel schemas are user-controlled.

| Column | Table | DefenderType | SentinelType | `@odata.type` wrapper | Direct access |
|---|---|---|---|---|---|
| `AdditionalFields` | `DeviceProcessEvents` | `string` | `dynamic` ⚠️ | No | `parse_json(tostring(col))` |
| `AdditionalFields` | `AlertEvidence` | `string` | `string` | No | `parse_json(tostring(col))` |
| `AdditionalFields` | `EmailEvents` | `string` | `string` | No | `parse_json(tostring(col))` |
| `AdditionalFields` | `CloudAppEvents` | `dynamic` | `dynamic` | **Yes** | `col.Field` |
| `AdditionalFields` | `IdentityLogonEvents` | `dynamic` | `dynamic` | **Yes** | `col.Field` |
| `ActivityObjects` | `CloudAppEvents` | `dynamic` | `dynamic` | **Yes** | `mv-expand` then `elem.Field` |
| `RawEventData` | `CloudAppEvents` | `dynamic` | `dynamic` | **Yes** | `col.Field` (some sub-fields nested-as-string — see Behaviour 4) |
| `Data` | `ThreatIntelIndicators` | `dynamic` | `dynamic` | **Yes** | `col.Field` (incl. `Data.indicator_types[0]`); some array elements are JSON strings — see Behaviour 4 |
| `AdditionalFields` | `ThreatIntelIndicators` | `dynamic` | `dynamic` | **Yes** | `col.TLPLevel` directly |
| `LastSeenForUser` | `CloudAppEvents` | `dynamic` | `dynamic` | **Yes** | `col.Field` |
| `NodeProperties` | `ExposureGraphNodes` | `dynamic` | N/A (Defender-only) | **Yes** | `col.rawData.Field` (single-key wrapper — see below) |
| `EntityIds` | `ExposureGraphNodes` | `dynamic` | N/A (Defender-only) | **Yes** | `mv-expand` then `elem.Field` (elements are `dictionary` as of 2026-04-28) |
| `Categories` | `ExposureGraphNodes` | `dynamic` | N/A (Defender-only) | **Yes** | `mv-expand` then `tostring(elem)` (elements are plain string scalars) |
| `ConditionalAccessPolicies` | `EntraIdSignInEvents` | `string` | N/A (Defender-only) | No | `parse_json(tostring(col))` |
| `AuthenticationProcessingDetails` | `EntraIdSignInEvents` | `string` | N/A (Defender-only) | No | `parse_json(tostring(col))` |
| `LogonType` | `EntraIdSignInEvents` | `string` | N/A (Defender-only) | No | `tostring(col)` then `contains`/`parse_json` |

**⚠️ `DeviceProcessEvents.AdditionalFields` SentinelType mismatch:** In some tenants, an older Log Analytics connector registered this column as `dynamic` in its schema — predating the unified portal and set up independently of the Defender pipeline. The physical data is still a JSON-encoded string (`gettype()` = `"string"`, column blank in Sentinel sample rows). The two schema registries are independent; a legacy connector's schema declaration can outlive the actual data shape. DefenderType is always the authoritative signal for how data actually behaves — SentinelType reflects how the Log Analytics schema was originally declared, not necessarily the current physical storage type.

---

## Four Behaviours to Know

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

### 4. `dynamic` ColumnType with nested string-encoded JSON sub-fields

A column may be a genuine native dynamic at the top level (`getschema` = `dynamic`, `gettype()` = `"dictionary"`, direct `col.Field` works) yet contain **selected sub-fields whose values are JSON-encoded strings** rather than nested dictionaries. These sub-fields parse as `string` at the KQL layer; direct property access into them silently returns null. Confirmed cases (this tenant, 2026-05-03):

**`CloudAppEvents.RawEventData`** — top-level access works (`RawEventData.Workload` → `"Exchange"`), but these sub-fields are stored as JSON strings:
- `RawEventData.AppAccessContext`
- `RawEventData.PolicyMatchInfo`
- `RawEventData.SensitiveInfoTypeData`

```kql
// WRONG — silently null even though RawEventData.Workload works
| extend tenant = RawEventData.AppAccessContext.AADTenantId

// RIGHT — re-parse the nested string
| extend ctx    = parse_json(tostring(RawEventData.AppAccessContext))
| extend tenant = tostring(ctx.AADTenantId)
```

**`ThreatIntelIndicators.Data.labels`** — `Data` is dictionary, `Data.indicator_types[0]` works directly, but elements of `Data.labels` (MITRE TTP objects) are JSON-encoded strings inside the array.

```kql
ThreatIntelIndicators
| mv-expand label = Data.labels
| extend parsed = parse_json(tostring(label))
| extend tactic = tostring(parsed.tactic)
```

**`DeviceNetworkEvents.AdditionalFields` for `ActionType == "DnsConnectionInspected"`** — `AdditionalFields` is `string`-typed at the column level (so `parse_json(tostring(AdditionalFields))` is the entry point per Behaviour 1), but the inner `answers` field is itself a JSON-encoded array string requiring a second `parse_json()`:

```kql
DeviceNetworkEvents
| where ActionType == "DnsConnectionInspected"
| extend af = parse_json(tostring(AdditionalFields))
| extend query   = tostring(af.query)
| extend rcode   = tostring(af.rcode_name)
| extend answers = parse_json(tostring(af.answers))   // second parse for the inner string-encoded array
| mv-expand ans = answers
| project Timestamp, DeviceName, query, rcode, ans
```

Full `DnsConnectionInspected` payload (Zeek DNS): `query`, `answers` (JSON-encoded array string), `rcode_name`, `qtype_name`, `TTLs`, `rtt`. This is the primary Defender table for DNS-based hunting.

**Why this matters:** there is no signal at the column level that says "some sub-fields are nested-encoded." `getschema` ColumnType describes the column, not its leaves. The shape probe in `mcp-xdr get_schema` only inspects the top level. The only ways to find these are:
1. Read a per-table reference doc that has documented the case
2. `bag_keys()` on a sample, then `gettype()` on each value
3. Try direct access; if it returns null but the field name looks right, suspect nested-string

**Diagnostic:**
```kql
TableName | take 1 | extend keys_and_types = bag_pack_columns(...)
// Better:
TableName
| take 1
| project SubField = tostring(SomeDynamicCol.SuspectedField),
          SubType  = tostring(gettype(SomeDynamicCol.SuspectedField))
// SubType == "string" → it's nested-encoded, needs parse_json(tostring(...))
// SubType == "dictionary" or "array" → direct access works
```

This is also the canonical case where the official `parse_json()` doc's "use `tostring()` on the second call" rule is mandatory rather than defensive — see the next section.

---

## TSV-rendering trap: get_schema sample rows can mislead

Native dynamic columns get serialized to JSON text in the TSV `Sample rows` output. Visually identical to a JSON-encoded string column. Confirmed examples:

- `ThreatIntelIndicators.Data` and `AdditionalFields` — native dynamic in both Defender and Sentinel (`gettype()` = `"dictionary"`, `bag_keys()` works), but the TSV sample renders the value as `{"indicator_types":[...],...}` exactly the same way it would render a string-encoded JSON column.

Conclusion: **never infer column type from sample-row appearance.** Use `DefenderType` from the `get_schema` schema header, or run `gettype()` directly. The only visual hint that *might* indicate string-encoding is escaped inner quotes (`\"`) — but this is unreliable since the TSV layer escapes for delimiter safety regardless.

---

## When is `tostring()` actually required inside `parse_json()`?

Added 2026-05-03 after a live audit of `parse_json()` semantics across both APIs.

**The rule from the official `parse_json()` documentation:**

> *"If `json` is of type `dynamic`, its value is used as-is."*
>
> *"In such cases, it isn't only necessary to invoke `parse_json` twice, but also to make sure that in the second call, `tostring` is used. Otherwise, the second call to `parse_json` just passes on the input to the output as-is, because its declared type is `dynamic`."*
>
> — [parse_json() reference](https://learn.microsoft.com/kusto/query/parse-json-function)

So `parse_json()` only parses a value whose **declared KQL type** is `string`. On a value whose declared type is `dynamic`, it's a no-op — even if the actual content is a JSON-encoded string.

### Decision matrix

| Situation | Required form | Why |
|---|---|---|
| Column is `getschema`-typed `string` | `parse_json(col)` — `tostring()` redundant | Column is already string-typed at the KQL layer; `parse_json` parses strings directly. |
| Column is `getschema`-typed `dynamic` | None — direct `col.Field` works | Column is already a dynamic; nothing to parse. `parse_json(col)` would be a no-op anyway. |
| Defensive (written without consulting `getschema`) | `parse_json(tostring(col))` | Works in both string and dynamic cases. Safe-but-redundant style. The mcp-xdr `get_schema` Notes column uses this form intentionally. |
| Re-parsing a JSON-encoded-string nested inside an already-parsed dictionary | `parse_json(tostring(parsed.field))` — **`tostring()` is mandatory** | After the first parse, `parsed.field` has declared type `dynamic`. Without `tostring()`, the second `parse_json` no-ops and you get the encoded string back. |
| `mv-expand`-ed array element that is itself a JSON-encoded string | `parse_json(tostring(elem))` — **`tostring()` is mandatory** | After `mv-expand`, `elem` has declared type `dynamic` even though its actual value may be a string. Same no-op trap as nested JSON. |

### Live verification on this tenant (2026-05-03)

**At the top column level:** probed 16 columns across `Device*`, `Email*`, `Alert*`, `Identity*`, `CloudApp*`, `AI*`, and `ExposureGraph*` tables for the case "DefenderType=`dynamic` but actual cell `gettype()`=`string`". **Zero matches.** The historic `EntityIds`-as-array-of-encoded-strings pattern has been fixed by Microsoft (`gettype(EntityIds[0])` now returns `dictionary`).

**At the sub-field level (Behaviour 4):** the case is alive and well — `CloudAppEvents.RawEventData.{AppAccessContext, PolicyMatchInfo, SensitiveInfoTypeData}`, `ThreatIntelIndicators.Data.labels[*]`, and `DeviceNetworkEvents.AdditionalFields → answers` all require a second `parse_json(tostring(...))` to unpack a JSON-encoded sub-value. There is no top-level signal for this — only per-table reference docs or runtime `gettype()` probing on the specific sub-field reveals it.

This means in current data:
- `parse_json(col)` (no `tostring()`) works on every top-level `string`-typed column we tested
- `parse_json(tostring(col))` works the same on top-level `string`-typed columns (the wrap is redundant but harmless)
- Both forms behave identically on top-level `dynamic`-typed columns (both no-op)
- For **second-pass parses** of nested-encoded JSON inside a parsed dictionary, `tostring()` is mandatory — without it the second `parse_json` no-ops because its argument has declared type `dynamic`

The mcp-xdr `get_schema` tool emits the defensive `parse_json(tostring())` form intentionally: an LLM authoring a query may not always reconcile column-type at compose time, and the redundant `tostring()` is cheaper than a wrong-but-silent parse. The same form is also genuinely required for sub-field re-parsing, so emitting it consistently teaches the right idiom.

---

## Array element-type ambiguity (added 2026-05-03)

`gettype(elem) == "string"` after `mv-expand` is ambiguous. Two distinct cases produce the same probe signal but require different access patterns:

### Case A: array of plain string scalars

The column holds an array of bare string values. Each element is a string at every level — there's no JSON to parse.

**Example: `ExposureGraphNodes.Categories`**
```kql
ExposureGraphNodes | take 1 | project Categories
// Output (Graph API):
// ["AI", "ai_model", "environmentAzure"]
```
- `gettype(Categories)` → `"array"`
- `gettype(Categories[0])` → `"string"`
- The string `"AI"` is **not** JSON.

Right access:
```kql
| mv-expand cat = Categories
| extend cat_name = tostring(cat)     // RIGHT
| extend wrong    = parse_json(tostring(cat))   // WRONG — returns dynamic-wrapped "AI"
```

Per the `parse_json()` doc: *"if it isn't a properly formatted JSON string, then the returned value is an object of type `dynamic` that holds the original `string` value."* So `parse_json("AI")` doesn't error — it returns dynamic-wrapped `"AI"`. Pointless and confusing in a query, but not broken.

### Case B: array of JSON-encoded objects (the historic `EntityIds` pattern)

The column holds an array where each element is a JSON-encoded string representation of a dictionary. Per the design-doc note from 2026-04-28, this was previously the `EntityIds` shape, which has since been fixed to elements being dictionaries.

If found, the right access is:
```kql
| mv-expand elem = SomeArrayCol
| extend parsed = parse_json(tostring(elem))     // tostring required after mv-expand
| extend val    = tostring(parsed.someField)
```

### Why probes can't distinguish A from B with `gettype()` alone

Both cases report `gettype(elem) == "string"`. The only signal that works is content inspection:
- Element starts with `{` or `[` → likely Case B (JSON-encoded)
- Otherwise → Case A (plain string scalar)

The current mcp-xdr `get_schema` shape probe doesn't do content inspection, so it emits `mv-expand → parse_json(tostring())` for both cases. For `Categories`-shaped columns this advice is misleading — but harmless thanks to `parse_json`'s no-error behaviour on non-JSON input.

**Live findings (2026-05-03):** Across the array-typed dynamic columns probed, only Case A was found in this tenant (`ExposureGraphNodes.Categories`). Case B (array of JSON-encoded strings) appears extinct under the current Graph Security API serializer. The design doc preserves the pattern in case it resurfaces.

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

`getschema` = `dynamic`, `gettype()` = `"array"`. As of 2026-04-28 the elements are **`dictionary`** (Microsoft fixed the pipeline; previously they were JSON-encoded strings). Direct property access on the expanded element works:

```kql
ExposureGraphNodes
| mv-expand EntityId = EntityIds
| extend entityType = tostring(EntityId.type)
| extend entityId   = tostring(EntityId.id)
```

The Graph API JSON serialization may *render* elements as escaped JSON strings (`["{\"type\":\"...\"}"]`) but at the KQL layer they are first-class dictionaries. The probe's `gettype()` reflects the KQL layer, which is the layer that matters for query authoring.

### `ExposureGraphNodes.Categories`

`getschema` = `dynamic`, `gettype()` = `"array"`. Elements are **plain string scalars** (e.g. `"AI"`, `"ai_model"`, `"environmentAzure"`) — not JSON. Use `tostring(elem)` after `mv-expand`, not `parse_json(tostring(elem))`.

### `ThreatIntelIndicators.Data` and `AdditionalFields`

Both are **native dynamic** in both Defender and Sentinel sources. `gettype()` = `"dictionary"`, `bag_keys()` works. Direct property access:
- `Data.indicator_types[0]`
- `Data.pattern`
- `AdditionalFields.TLPLevel`

No `parse_json(tostring())` needed at the top level. **Exception:** elements of `Data.labels` (MITRE TTP descriptors) are stored as JSON-encoded strings inside the array — see Behaviour 4.

The TSV sample-rows view in `get_schema` renders `Data` as a JSON string, which can mislead into assuming double-serialization. It's not encoded — `getschema` says `dynamic`; trust that.

### `CloudAppEvents.RawEventData`

Top-level dictionary, direct access works for most fields. **Exception:** these sub-fields are nested JSON strings and need a second `parse_json(tostring(...))` — see Behaviour 4:
- `RawEventData.AppAccessContext`
- `RawEventData.PolicyMatchInfo`
- `RawEventData.SensitiveInfoTypeData`

### `DeviceNetworkEvents.AdditionalFields` for `DnsConnectionInspected`

Full Zeek DNS payload: `query`, `answers`, `rcode_name`, `qtype_name`, `TTLs`, `rtt`. The column is `string`-typed (Behaviour 1), and `answers` inside it is itself a JSON-encoded array requiring a second `parse_json()`. Primary table for DNS-based hunting in Defender. See Behaviour 4 for the full pattern.

### `ExposureGraphNodes.NodeProperties`

`getschema` = `dynamic`. Single-key wrapper pattern (see Behaviour 3) — all data is nested under `.rawData`. Use `bag_keys(NodeProperties.rawData)` to discover the per-`NodeLabel` schema.

---

## Decision Flow

```
Look up the column with: TableName | getschema | where ColumnName == "TheColumn"
  OR: get_schema(table_name="TableName") → use DefenderType column, not SentinelType
  (SentinelType can misreport — e.g. DeviceProcessEvents.AdditionalFields shows dynamic
   in Sentinel schema but is physically string at rest)

  ColumnType "string"
    → parse_json(col) works (or parse_json(tostring(col)) defensively — both are correct)
    → no @odata.type wrapper in output

  ColumnType "dynamic"
    → direct col.Field access works at the top level
    → @odata.type wrapper will appear via Graph API (cosmetic — ignore)
    → if col.Field returns null despite correct field name:
        (a) run bag_keys(col) — if only key is "rawData", use col.rawData.Field
        (b) run gettype(col.Field) — if "string", it's nested-encoded JSON
            → re-parse: parse_json(tostring(col.Field)).InnerField
              (CloudAppEvents.RawEventData.AppAccessContext is the canonical example)
    → if col is an array: mv-expand then elem.Field
        → run gettype(elem) on a sample to check element type:
            "dictionary"  → direct elem.Field access
            "string"      → either:
                              (a) plain string scalar  → tostring(elem)
                              (b) JSON-encoded object → parse_json(tostring(elem)).Field
                            Disambiguate by inspecting whether elem starts with `{` or `[`.
                            On this tenant as of 2026-05-03 only case (a) was found in live data
                            for top-level array columns; case (b) DOES occur for nested arrays
                            like ThreatIntelIndicators.Data.labels.
```

---

## What Microsoft Documents

- `dynamicColumnValue` resource type has an empty schema (`{}`). No properties, no relationships documented — official position is pass-through with no guarantees.
- No Microsoft docs describe per-table or per-column serialization differences, or the `getschema` ↔ wrapper correlation.
- The `FieldName@odata.type: "#Int64"` sibling key pattern is standard OData behaviour for numeric type annotation.
- The `parse_json()` reference [documents](https://learn.microsoft.com/kusto/query/parse-json-function) the dynamic-passthrough rule explicitly: a `dynamic` argument is returned as-is, which is why `tostring()` is needed for a second-pass parse on a nested-encoded-JSON value.

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

// Step 3 (for array columns): probe element type before mv-expanding into property access
TableName
| where isnotnull(SomeArrayCol) and gettype(SomeArrayCol) == "array"
| take 50
| mv-expand elem = SomeArrayCol
| extend elem_type = tostring(gettype(elem))
| extend elem_starts_with = substring(tostring(elem), 0, 1)  // disambiguates plain-vs-JSON
| summarize by elem_type, elem_starts_with
```

**mcp-xdr `get_schema(table_name=...)` is equivalent to `getschema`** and returns ColumnType directly, plus a `Notes` column with cell-shape and enum-cardinality probes — use it instead of a separate query when already working via the MCP tools.

**Sentinel vs Defender:** `@odata.type` wrappers appear only via `run_hunting_query` (Graph API). `run_sentinel_query` (Log Analytics API) returns clean JSON with no wrapper and no int64 sibling keys. The ColumnType rule still holds for access patterns — only the wrapper noise differs.

**mcp-xdr TSV note:** TSV output cannot reliably distinguish a native JSON object from a JSON-encoded string — both appear as JSON text. The only visual hint is escaped inner quotes (`\"`) in the encoded-string case. Ground truth is `getschema` ColumnType plus `gettype()` probing.

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

---

## Changelog

- **2026-04-28** — Initial doc: `getschema` ↔ `@odata.type` wrapper correlation, three behaviours (`string`, `dynamic`, single-key wrapper), `DeviceProcessEvents.AdditionalFields` mismatch case, ARM connectors API analysis.
- **2026-05-03 (initial)** — Added: `parse_json()` `tostring()` semantics (when required vs redundant, sourced from official KQL doc); array element-type ambiguity (`Categories` plain-string vs historic `EntityIds` JSON-encoded-string disambiguation); live tenant audit confirming Case B (top-level array of JSON-encoded strings) is currently absent across 16 probed columns; updated decision flow with element-type disambiguation step; updated master table to include `EntityIds` and `Categories`.
- **2026-05-03 (revision, from xdr-refine memory)** — Added Behaviour 4: nested-string-inside-dynamic. Documents `CloudAppEvents.RawEventData.{AppAccessContext, PolicyMatchInfo, SensitiveInfoTypeData}` as JSON-encoded sub-fields requiring second `parse_json(tostring())`; `ThreatIntelIndicators.Data` and `AdditionalFields` as native dynamic (the TSV sample-row trap); `Data.labels[*]` as JSON-encoded MITRE TTP elements; `DeviceNetworkEvents.AdditionalFields` for `DnsConnectionInspected` exposing full Zeek DNS data with nested `answers` array. Added "TSV-rendering trap" section. Refined live-verification claim to distinguish top-level vs sub-field cases. Updated decision flow to include `gettype(col.Field) == "string"` detection step.
