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

// Joining two tables on IP
| join kind=inner (
    OtherTable
    | extend IPKey = IPAddress
) on $left.SrcIP == $right.IPKey   // WRONG — use mv-expand + ipv6_is_match instead

// Better join pattern:
TableA
| join kind=inner TableB on $left.SrcIP == $right.DstIP  // only safe if both came from same source
// If unsure, normalize first:
| extend NormalizedIP = iff(IPAddress startswith "::ffff:", substring(IPAddress, 7), IPAddress)
```

When joining two tables on IPs where you can't guarantee format consistency, normalize both sides first or use `ipv6_is_match` in a post-join `where`.

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

**`let` + `union`/`join` causes parse errors** — Defender KQL does not support `union` or `join` downstream of a `let` subquery. This catches people writing before/after comparisons with two `let` windows joined together:
```kql
// WRONG — parse error
let Baseline = TableA | where Timestamp between (ago(30d) .. ago(3d));
let Recent   = TableA | where Timestamp > ago(3d);
Baseline | join kind=inner Recent on AppId  // fails
// also fails with: Baseline | union Recent

// RIGHT for before/after comparisons — use evaluate pivot() on a Period column:
TableA
| where Timestamp > ago(30d)
| extend Period = iff(Timestamp > ago(3d), "Recent", "Baseline")
| summarize Events=count() by AppId, Period
| evaluate pivot(Period, sum(Events))
| extend SpikeRatio = iff(todouble(Baseline) > 0, round(todouble(Recent) / todouble(Baseline), 2), todouble(999))

// RIGHT for multi-table queries — run as separate queries
TableA | where …
// -- and separately --
TableB | where …
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

**Time filter** — always include one; default to last 3 days unless the user specifies otherwise:
```kql
| where Timestamp > ago(3d)
```

**Limit columns** — use `project` to return only what's needed; Defender tables are wide and raw rows waste context:
```kql
| project Timestamp, DeviceName, AccountUpn, ActionType, AdditionalFields
```

**Summarize over raw rows** — for large tables (`DeviceEvents`, `DeviceNetworkEvents`, `EmailEvents`), prefer aggregation unless the user needs individual events:
```kql
| summarize Count=count() by DeviceName, ActionType
| sort by Count desc
```

**Large result sets** — if a query returns more rows than fit comfortably in context, spawn a subagent to ingest and summarize the output. Always use `model: "haiku"` for these — the task is pure reading/summarization, not reasoning, and Haiku is faster and cheaper for it. Choose `effort:` appropriate for the task, don't let it inherit yours.

**Dynamic column access** — use `tostring()`, `toint()`, `parse_json()`, and `bag_keys()` to work with dynamic columns safely:
```kql
| extend parsed = parse_json(AdditionalFields)
| extend ProcessName = tostring(parsed.ProcessName)
```
