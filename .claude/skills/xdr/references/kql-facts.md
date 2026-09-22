## KQL facts for Defender Advanced Hunting and Sentinel Log Analytics
transclusion-sentinel: KQLFACTS-7F3A


### CRITICAL: IP address comparisons

**Never use string equality (`==`) or string-based joins on IP address columns.**

IPv4 addresses are increasingly logged in IPv6-mapped form: `::ffff:1.2.3.4`. A plain `IPAddress == "1.2.3.4"` will silently miss these rows — no error, just wrong (incomplete) results.

**Always use `IPV6_MATCH()`** (injected automatically by the MCP server into every query):

```kql
// Single IP — exact match, two-arg form (prefix_mask defaults to 128)
| where IPV6_MATCH(IPAddress, "1.2.3.4")

// CIDR range — the prefix arg is ALWAYS an IPv6 prefix (0–128), even when both
// operands are IPv4 strings. IPv4 strings are first canonicalized to ::ffff:a.b.c.d,
// so the IPv4 octets live in IPv6 bits 96–127. To express an IPv4 /N range, pass 96+N:
//   IPv4 /8  → prefix 104,  /16 → 112,  /24 → 120,  /32 → 128
// Example: 10.0.0.0/8 → IPV6_MATCH(IP, "10.0.0.0", 104)
| where IPV6_MATCH(IPAddress, "10.0.0.0", 104)

// Joining two tables on IP — normalize both sides with parse_ipv6() first,
// then join on the canonical string. Works in both Defender and Sentinel.
TableA
| extend SrcKey = parse_ipv6(SrcIP)
| join kind=inner (
    TableB
    | extend DstKey = parse_ipv6(DstIP)
) on $left.SrcKey == $right.DstKey

// parse_ipv6() expands any IPv4 or IPv6 input to a fully canonical form:
//   "1.2.3.4"        → "0000:0000:0000:0000:0000:ffff:0102:0304"
//   "::ffff:1.2.3.4" → "0000:0000:0000:0000:0000:ffff:0102:0304"  (same!)
// So both representations of the same address produce the same key — safe to join on.

// For equality checks in where clauses, IPV6_MATCH() remains cleaner:
| where IPV6_MATCH(IPAddress, "1.2.3.4")
```

When joining two tables on IPs, always normalize both sides with `parse_ipv6()` first — it handles IPv4, IPv6, and IPv6-mapped IPv4 (`::ffff:x.x.x.x`) and collapses them to the same canonical string. `ipv6_compare(a, b) == 0` is an alternative equality test. For `where` filters, `IPV6_MATCH()` is the most readable option.

---

### Azure Monitor / Log Analytics: underscore-prefixed system columns

In Log Analytics (Sentinel) tables, columns prefixed with `_` (e.g. `_ResourceId`, `_SubscriptionId`, `_ResourceGroup`) are **system-generated** and reliably populated. Named schema columns that appear to carry the same data can be permanently blank — not just sparse at scale.

**`AzureActivity`: `Resource` is always blank.** The resource name is not surfaced as a top-level column — it lives inside the `Properties` JSON string and in `_ResourceId`. Always use `_ResourceId` for resource-specific filtering:

```kql
// WRONG — Resource is always empty in AzureActivity
AzureActivity
| where Resource == "mystorageaccount"

// RIGHT — _ResourceId is the full ARM path (lowercase), reliably populated
AzureActivity
| where _ResourceId has "/storageaccounts/mystorageaccount"
```

If you need the short resource name as a display column, extract it from `_ResourceId`:
```kql
| extend ResourceName = tostring(split(_ResourceId, "/")[-1])
```

---

### Defender KQL syntax gotchas

These diverge from standard ADX/KQL and will silently produce parse errors or wrong results:

#### **No ternary operator** — `condition ? a : b` is not supported. Use `iff()`:
```kql
// WRONG — parse error
| extend Label = IsBlocked ? "Blocked" : "Active"
// RIGHT
| extend Label = iff(IsBlocked, "Blocked", "Active")
```

#### **`let` + `union`/`join` — works in both Defender and Sentinel** 

`let` subqueries piped into `union` or `join` are fully supported (verified 2026-04 against both the Graph Security API and Log Analytics):
```kql
// Works fine in Defender
let Baseline = TableA | where Timestamp between (ago(30d) .. ago(3d));
let Recent   = TableA | where Timestamp > ago(3d);
Baseline | union Recent
Baseline | join kind=inner Recent on AppId

// Works fine in Sentinel
let Baseline = TableA | where TimeGenerated between (ago(30d) .. ago(3d));
let Recent   = TableA | where TimeGenerated > ago(3d);
Baseline | union Recent
```

For before/after comparisons the `evaluate pivot()` pattern is often *cleaner* than a join, but it is not required:
```kql
// Alternative pivot approach (cleaner for ratio analysis):
TableA
| where Timestamp > ago(30d)
| extend Period = iff(Timestamp > ago(3d), "Recent", "Baseline")
| summarize Events=count() by AppId, Period
| evaluate pivot(Period, sum(Events))
| extend SpikeRatio = iff(todouble(Baseline) > 0, round(todouble(Recent) / todouble(Baseline), 2), todouble(999))
```

#### **Dynamic column access — check `getschema` ColumnType first**

`get_schema(table_name=...)` (or `TableName | getschema`) is the ground truth. ColumnType predicts top-level access pattern exactly:

| ColumnType | Access pattern | Symptom if wrong |
|---|---|---|
| `string` | `parse_json(tostring(col))` before any property access | direct `col.Field` silently returns null; `bag_keys(col)` compile error |
| `dynamic` | direct `col.Field` access | `parse_json(col)` is a no-op (returns dynamic as-is); use `parse_json(tostring(col))` if you really mean to re-parse |

**`get_schema` Notes vocabulary** — the Notes column surfaces *shape facts* from a sample probe, not access recipes. Translate to your access pattern based on intent:

| Notes value | What it means | Implied access |
|---|---|---|
| `dict` | top-level dictionary | direct `col.Field` (dynamic) or `parse_json` first (string) |
| `dict, bag_keys=["X"]` | single-key wrapper — payload nested under one key | `col.X.Field` (e.g. `NodeProperties.rawData.Field`) |
| `array<dict>` | array of dictionaries | `mv-apply ... on (...)` if you'll fold back to source row; `mv-expand` if you want per-element rows |
| `array<string>` | array of typed-string elements (could be plain scalars OR JSON-encoded objects — probe can't tell) | inspect first char with `substring(tostring(elem),0,1)`: `{`/`[` → `parse_json(tostring(elem))`, otherwise `tostring(elem)` |
| `array<long>` / `array<bool>` etc. | array of typed scalars | `tostring(elem)` or arithmetic directly after `mv-expand` |
| `array<X mixed>` | heterogeneous element types | probe `gettype(elem)` before assuming a uniform pattern |
| `string-encoded <shape>` | DefenderType=string, contents parse to that shape | `parse_json(tostring(col))` first, then access per `<shape>` row above |
| `string-encoded JSON` | DefenderType=string with JSON content but no specific shape detected | `parse_json(tostring(col))` first |

```kql
// string-typed column — must parse first
| extend parsed = parse_json(tostring(col))
| extend val = parsed[0].id

// dynamic-typed column — direct access works
| extend val = col.Field
```

**SentinelType can misreport** — use DefenderType (from `get_schema`) as the authoritative signal. A legacy Log Analytics connector can declare a column `dynamic` in its schema even when the physical data is a JSON-encoded string.

**`@odata.type` wrapper (Graph API only):** native `dynamic` columns get annotated with `@odata.type: "#microsoft.graph.security.dynamicColumnValue"` via `run_hunting_query`. This is cosmetic — ignore it, direct access still works. Does not appear via `run_sentinel_query`.

**`col.Field` returns null on a `dynamic` column?** Two diagnostic steps:
1. `bag_keys(col)` — if the only key is `"rawData"`, payload is nested one level deeper, use `col.rawData.Field`
2. `gettype(col.Field)` — if `"string"`, the sub-field itself is a JSON-encoded string and needs a second parse: `parse_json(tostring(col.Field)).InnerField`. This is the **nested-string-inside-dynamic** pattern. Real cases: `CloudAppEvents.RawEventData.{AppAccessContext, PolicyMatchInfo, SensitiveInfoTypeData}`; `ThreatIntelIndicators.Data.labels[*]` (MITRE TTPs); the `answers` field inside `DeviceNetworkEvents.AdditionalFields` for `DnsConnectionInspected`.

#### **`mv-apply` vs `mv-expand` for array columns**

Both unroll a dynamic array, but with very different cost models:

| Operator | Effect on row count | When to use |
|---|---|---|
| `mv-expand T = arr` | **Multiplies** — one output row per array element | You actually want one row per element (e.g. listing every member of every group, every tag of every entity). |
| `mv-apply T = arr on (...)` | **Preserves** — one output row in, one out; sub-pipeline aggregates the array into scalar columns | You want to extract specific values *from* the array but keep one row per source event. |

**Rule of thumb:** if your next step after `mv-expand` is `summarize ... by SomeRowKey` to fold the rows back together, you're paying for the unroll twice — switch to `mv-apply`. The summarize moves *inside* the `on (...)` clause and runs per-row.

The sub-pipeline inside `on (...)` accepts most KQL operators (`where`, `extend`, `project`, `summarize`, `take`). `take_anyif(value, predicate)` inside a summarize is the canonical pattern for "extract one specific element from a heterogeneous typed array":

```kql
// Pattern: extract Role name + User UPN from AuditLogs.TargetResources (typed-object array)
| extend TargetArr = parse_json(tostring(TargetResources))
| mv-apply T = TargetArr on (
    summarize
        RoleName  = take_anyif(tostring(T.displayName),       tostring(T.type) == "Role"),
        TargetUPN = take_anyif(tostring(T.userPrincipalName), tostring(T.type) == "User")
)
```

The mv-expand-then-pivot equivalent would be ~3× the rows, then `summarize ... by CorrelationId` to collapse — same result, more I/O.

**Use `mv-expand` when** you genuinely want per-element rows: enumerating every member of every group, listing every URL clicked per email, exploding `AdditionalFields` arrays for full-detail forensic review.

**Array-typed dynamic columns (mv-expand path):** check `gettype(elem)` on a sample:

| `gettype(elem)` | Element shape | Access pattern |
|---|---|---|
| `"dictionary"` | Native dict (most common) | direct `elem.Field` |
| `"string"` starting with `{` or `[` | JSON-encoded object/array (rare) | `parse_json(tostring(elem)).Field` |
| `"string"` plain text | Plain string scalar (e.g. tag list) | just `tostring(elem)` — `parse_json` would no-op since the string isn't JSON |

The two `"string"` cases share the same `gettype()` signal — disambiguate by inspecting whether the element starts with `{`/`[`. Calling `parse_json(tostring(elem))` on a plain string scalar isn't an error (it returns dynamic-wrapped scalar) but is misleading and wasteful.

**Why `tostring()` inside `parse_json()`?** Per the official `parse_json()` doc: *"If `json` is of type `dynamic`, its value is used as-is."* So `parse_json()` only parses values whose declared KQL type is `string`. After `mv-expand`, after a first `parse_json()`, or on any pre-typed `dynamic` column, the argument's declared type is `dynamic` — without `tostring()` the parse silently no-ops. The defensive form `parse_json(tostring(col))` is always correct: redundant on a top-level `string` column, mandatory for second-pass parses of nested-encoded values.

**TSV sample-row trap:** the `Sample rows` view in `get_schema` renders native dynamic dictionaries as JSON text — visually identical to a string-encoded JSON column. **Never infer column type from sample appearance.** Trust `DefenderType` from the schema header, or run `gettype()` directly. (Notable case: `ThreatIntelIndicators.Data` and `AdditionalFields` are native dynamic in both Defender and Sentinel despite looking like JSON strings in the TSV.)


#### **Verdict columns can be mutable (rewritten) or immutable (frozen) — and this varies per table, even for same-named columns**

Threat/security verdicts often arrive asynchronously (detonation, campaign correlation, manual reclassification) — long after the event row was written. How a table handles that update is **not consistent across tables**, and the two known instances are opposite behaviors:

- `EmailEvents.ThreatTypes`/`DetectionMethods`/`ConfidenceLevel` — **mutable**, rewritten in place on reclassification. The table also exposes an immutable delivery-time snapshot via `OriginalThreatTypes`/`OriginalDetectionMethods`/`OriginalConfidenceLevel`.
- `UrlClickEvents.ThreatTypes` — **never backfilled**. A retroactive verdict lands only in `AlertInfo`/`AlertEvidence`, never touching the original click row.

**Lesson:** never assume a verdict/threat column's mutability from its name or from another table's behavior. Before trusting a "final" read: (1) check whether the table has a frozen/`Original*` counterpart column, (2) if not, check whether retroactive verdicts surface in a different table entirely (`AlertInfo`/`AlertEvidence` is the common fallback), (3) verify empirically — pick a row with an empty verdict and see if it acquires one over time, or find a case where `AlertInfo` shows a threat classification with no matching row-level verdict.

---

#### **`ReportId` uniqueness differs by table family** 

Two completely different semantics, same column name:

| Table family | Type | Unique? | Join key |
|---|---|---|---|
| All `Device*` tables (MDE-sourced) | `long` | **No** — local counter | `ReportId` + `DeviceName` + `Timestamp` |
| `Email*`, `Identity*`, `CloudAppEvents`, `UrlClickEvents` (MDO/MDI/MDCA) | `string` (GUID) | Yes — globally unique per event | `ReportId` alone is safe |

Device tables with `ReportId: long` (all require the three-column composite for safe joins):
`DeviceEvents`, `DeviceFileEvents`, `DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceNetworkEvents`, `DeviceNetworkInfo`, `DeviceInfo`, `DeviceFileCertificateInfo`

Tables with **no** `ReportId`: `AlertInfo`, `AlertEvidence`, `DeviceTvmSoftwareInventory`, `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSecureConfigurationAssessment` — these use `AlertId`, `DeviceId+CveId`, etc.

```kql
// RIGHT for Device tables
DeviceNetworkEvents
| join kind=inner AlertEvidence on ReportId, DeviceName, Timestamp

// OK for email/identity tables — ReportId is a GUID and globally unique
EmailEvents
| join kind=inner EmailAttachmentInfo on ReportId
```

---

### General KQL hygiene

**Time filter** — always include one; default to last 7 days. Sentinel/Log Analytics tables use `TimeGenerated`; Defender XDR tables use `Timestamp`. `get_schema()` shows which source a table comes from — if it has `Sentinel=yes`, use `TimeGenerated`.
```kql
| where Timestamp > ago(7d)      -- Defender XDR tables
| where TimeGenerated > ago(7d)  -- Sentinel / Log Analytics tables
```

**Limit columns** — use `project` to return only what's needed; Defender tables are wide and raw rows waste context:
```kql
| project Timestamp, DeviceName, AccountUpn, ActionType, AdditionalFields
```

**Summarize over raw rows** — for large tables (`DeviceEvents`, `DeviceNetworkEvents`, `EmailEvents`), prefer aggregation unless we actually need individual events:
```kql
| summarize Count=count() by DeviceName, ActionType
| sort by Count desc
```

**Dynamic column access** — use `tostring()`, `toint()`, `parse_json()`, and `bag_keys()` to work with dynamic columns safely:
```kql
| extend parsed = parse_json(AdditionalFields)
| extend ProcessName = tostring(parsed.ProcessName)
```

---

### Query economy — protect your context budget

**1. Summarize on-server first**

Never pull raw rows for exploratory work — always end with e.g. `summarize … by <key> | sort by Count desc`. If you need individual events, add a `where` filter to narrow first, *then* remove the summarize.

**2. Use `| sample N` for big-picture exploration ... but not inventory**

`| sample N` draws a quasi-random subset — useful for checking whether a pattern is worth pursuing, and avoids temporal/sorting clustering bias that "| take N" gives.

**3. Overflow files — default to Bash tooling, not context**

When a query hits the `[MCP-XDR:OVERFLOW]` sentinel, the full result is in a tmpfile at the path shown. Do **not** default to reading the whole file into main agent context window. Instead, grep/extract what you need:

```bash
# Count distinct values in column 1 from an overflow file
cut -f1 /tmp/baz.tsv | sort | uniq -c | sort -rn | head -30

# Search for a specific value in an overflow result
rg -i "keyword" C/Users/foo/AppData/Local/Temp/bar.tsv | head -20

# Extract specific columns (e.g. 1 and 3) with optional filter
awk -F'\t' 'NR==1 || $1 ~ /pattern/ {print $1, $3}' foobar.tsv
```

Remember that Bash is Bash, even on Windows. If you are given a Windows path with backslashes, convert to e.g. "/C/Path/to/file.ext" with forward slashes, or Bash errors.

**4. Delegate exploratory tool calling and/or large resultset ingestion to a Haiku subagent**

When you can reasonably infer that something may take many tool calls, delegate to a general-purpose `model="haiku"` with `effort=medium` to investigate the chain / relationship you're looking for. 

**5. Prefer one wide summarize over multiple narrow queries**

Run one broad query that captures all variants ranked by volume, then drill into specific findings with `where` filters. Resist the urge to issue a separate query per hypothesis — each query costs context and round-trip time.

```kql
// Wide first — all variants, ranked
TableName
| where Timestamp > ago(30d)
| summarize Count=count(), Devices=dcount(DeviceName) by Kind
| sort by Count desc

// Then narrow — only after identifying a finding worth drilling
TableName
| where Timestamp > ago(30d)
| where Kind == "specific-value-from-above"
| project Timestamp, DeviceName, AccountName, AdditionalFields
| sort by Timestamp desc
```

---

### Cross-platformness: Windows, Mac, Linux

When formulating KQL for, and reading query results from, endpoint-sourced tables and columns: **keep in mind that MDE runs on Windows+Mac+Linux**! 
  - Looking for executables with ".exe" is Windows-only. Find the correct **non-.exe** binary name for Mac/Linux!
  - Network metadata can be populated differently, e.g. only numeric IPs vs also domain names. Importantly, Defender on MacOS likes ipv4-as-v6 notation!

Example query ideas: 
  - Get samples of file paths with forward slashes vs backslashes.
