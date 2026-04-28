## KQL facts for Defender Advanced Hunting
transclusion-sentinel: KQLFACTS-7F3A


### CRITICAL: IP address comparisons

**Never use string equality (`==`) or string-based joins on IP address columns.**

IPv4 addresses are increasingly logged in IPv6-mapped form: `::ffff:1.2.3.4`. A plain `IPAddress == "1.2.3.4"` will silently miss these rows — no error, just wrong (incomplete) results.

**Always use `ipv6_is_match()`:**

```kql
// Single IP
| where ipv6_is_match(IPAddress, "1.2.3.4")

// CIDR range — netmask is IPv6 prefix length, NOT the IPv4 prefix length
// Convert: IPv6 prefix = IPv4 prefix + 96
//   /8  → 104,  /16 → 112,  /24 → 120,  /32 → 128
// Example: 10.0.0.0/8 in IPv4 → ipv6_is_match(IP, "10.0.0.0", 104)
| where ipv6_is_match(IPAddress, "10.0.0.0", 104)

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

// For equality checks in where clauses, ipv6_is_match() remains cleaner:
| where ipv6_is_match(IPAddress, "1.2.3.4")
```

When joining two tables on IPs, always normalize both sides with `parse_ipv6()` first — it handles IPv4, IPv6, and IPv6-mapped IPv4 (`::ffff:x.x.x.x`) and collapses them to the same canonical string. `ipv6_compare(a, b) == 0` is an alternative equality test. For `where` filters, `ipv6_is_match()` is the most readable option.

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

**No ternary operator** — `condition ? a : b` is not supported. Use `iff()`:
```kql
// WRONG — parse error
| extend Label = IsBlocked ? "Blocked" : "Active"
// RIGHT
| extend Label = iff(IsBlocked, "Blocked", "Active")
```

**`let` + `union`/`join` — works in both Defender and Sentinel** — `let` subqueries piped into `union` or `join` are fully supported (verified 2026-04 against both the Graph Security API and Log Analytics):
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

**Double-serialized dynamic columns** — some dynamic columns (e.g. `NodeProperties`, `AgentToolsDetails`) are stored as JSON-encoded strings, not native dynamic objects. Direct property access returns null; wrap with `tostring()` first:
```kql
// WRONG — returns null
| extend val = NodeProperties.rawData.exposureScore
// RIGHT
| extend props = parse_json(tostring(NodeProperties))
| extend val = tostring(props.rawData.exposureScore)
```

**`ReportId` uniqueness differs by table family** — two completely different semantics, same column name:

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
cut -f1 <path>.tsv | sort | uniq -c | sort -rn | head -30

# Search for a specific value in an overflow result
rg -i "keyword" <path>.tsv | head -20

# Extract specific columns (e.g. 1 and 3) with optional filter
awk -F'\t' 'NR==1 || $1 ~ /pattern/ {print $1, $3}' <path>.tsv
```

Remember that Bash is Bash, even on Windows. If you are given a Windows path with backslashes, convert to e.g. "/C/Path/to/file.ext" with forward slashes, or Bash errors.

For more complex analysis, write a reusable named Python script in `.claude/skills/xdr/references/scripts/`.

**4. Delegate exploratory tool calling to a Haiku subagent**

When you can reasonably infer that something may take many tool calls, delegate to a general-purpose `model="haiku"` with `effort=medium` to investigate the chain / relationship you're looking for. The agent starts with tiny context, making the turns cheap. "See this Defender XDR query result file <resultfile|tmpfile>. I need to understand <...> so that I can <...>" is a good starting pattern.

**5. Delegate large result set non-deterministic summarization to a Haiku subagent**

For large result sets where deterministic Bash won't do the job, spawn a subagent to ingest and summarize the output. Always use `model="haiku"` for these — the task is pure reading/summarization, not reasoning, and Haiku is faster and cheaper for it. Choose `effort="low|medium"` appropriate for the task, don't let it inherit yours.
```
Agent(model="haiku", prompt="Read the TSV at <path>. Summarize: distinct values in
col A (entity names), top 10 by count in col B, flag any values that look unusual
or non-standard.")
```

**6. Prefer one wide summarize over multiple narrow queries**

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
