"""MCP tool: get_schema — unified schema discovery for Defender and Sentinel."""

import asyncio
import json
import re
from typing import Any

import httpx
from mcp.types import TextContent, Tool

import mcp_xdr._cache as _cache
import mcp_xdr._client as _client
from mcp_xdr._output import _append_query_log, _cell_str, _format_colsrows_for_toolreturn, _sanitise
import mcp_xdr._config as _config


_ENUM_NAME_RE = re.compile(
    r"(Type|Status|Kind|Category|Severity|Result|Outcome|State|Action|Direction|Protocol|Platform)$"
)


def _type_stub(obj: Any) -> Any:
    """Return a type-accurate placeholder for obj: {…} for dict, […] for list, scalar as-is."""
    if isinstance(obj, dict):
        return "{…}"
    if isinstance(obj, list):
        return "[…]"
    return obj


def _depth_reduce(obj: Any, depth: int, str_limit: int = 0) -> Any:
    """Recursively reduce obj to the given depth, preserving type hints at leaves.

    If str_limit > 0, string values longer than str_limit are truncated to
    str_limit chars + "…". Applied at every level, enabling compression of
    lists-of-long-strings that survive structural depth reduction.
    """
    if str_limit and isinstance(obj, str) and len(obj) > str_limit:
        return obj[:str_limit] + "…"
    if depth == 0:
        return _type_stub(obj)
    if isinstance(obj, dict):
        if depth == 1:
            return {k: _type_stub(v) for k, v in obj.items()}
        return {k: _depth_reduce(v, depth - 1, str_limit) for k, v in obj.items()}
    if isinstance(obj, list):
        if not obj:
            return []
        first = _depth_reduce(obj[0], depth - 1, str_limit)
        if len(obj) == 1:
            return [first]
        return [first, f"…+{len(obj) - 1} more"]
    return obj


def _truncate_cell(value: str, limit: int = 1024) -> str:
    if len(value) <= limit:
        return value
    try:
        parsed = json.loads(value)
        for depth in (3, 2, 1):
            reduced = json.dumps(_depth_reduce(parsed, depth), separators=(",", ":"), ensure_ascii=False)
            if len(reduced) <= limit:
                return reduced + "…"
        # Structural depth alone didn't fit — also truncate long string leaves
        reduced = json.dumps(_depth_reduce(parsed, 1, str_limit=200), separators=(",", ":"), ensure_ascii=False)
        if len(reduced) <= limit:
            return reduced + "…"
        return reduced[:limit] + "…"
    except (json.JSONDecodeError, ValueError):
        return value[:200] + "…"


TOOL_DEFINITION = Tool(
    name="get_schema",
    description=(
        "Discover available tables and columns before writing KQL queries."
        "\n\n"
        "No arguments: lists all tables across Defender and (when configured) Sentinel as TSV. "
        "SentinelLastSeen (hourly granularity) and SentinelSolution (e.g. SecurityInsights, LogManagement) come from the Log Analytics `Usage` table. "
        "SentinelSolution indicates the product origin of a table: SecurityInsights = Defender stream; LogManagement = Azure/AAD native."
        "\n\n"
        "With table_name: returns the full column schema (ColumnName, DefenderType, SentinelType, Notes) "
        "plus up to 3 sample rows from that table."
        "\n\n"
        "The Notes column surfaces deterministic per-tenant shape facts from a bounded sample probe — "
        "use the skill's kql-facts.md (or `getschema` rules you already know) to pick operators. "
        "Vocabulary: "
        "`dict`, `array<dict>`, `array<string>`, `array<scalar>` describe runtime shape; "
        "`string-encoded <shape>` flags a DefenderType=string column whose cells parse to that shape "
        "(needs `parse_json(tostring(col))` before access); "
        "`bag_keys=[\"X\"]` flags a single-key wrapper dict (e.g. NodeProperties.rawData); "
        "`enum: a, b, c` lists low-cardinality values; "
        "`high-cardinality (N distinct)` flags columns above the enum cap. "
        "DefenderType is authoritative when the two sources disagree on type."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "table_name": {
                "type": "string",
                "description": "Table to inspect. Omit to list all tables.",
            }
        },
        "required": [],
    },
)


def _parse_getschema_hunting(result: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (ColumnName, ColumnType) pairs from a Defender getschema query result."""
    return [
        (row.get("ColumnName", ""), row.get("ColumnType", ""))
        for row in result.get("results", [])
        if row.get("ColumnName")
    ]


def _parse_getschema_sentinel(result: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (ColumnName, ColumnType) pairs from a Sentinel getschema query result."""
    table = result["tables"][0]
    col_idx = {c["name"]: i for i, c in enumerate(table["columns"])}
    cn_i = col_idx.get("ColumnName", -1)
    ct_i = col_idx.get("ColumnType", -1)
    return [
        (str(row[cn_i]), str(row[ct_i]))
        for row in table["rows"]
        if cn_i >= 0 and row[cn_i]
    ]


# ── Deterministic per-tenant fact probes ─────────────────────────────────────
#
# Two probes run alongside the existing schema/sample queries so the agent can
# see in-tenant truths inline (no need to read or trigger a per-table reference
# doc):
#   1. _build_shape_probe_kql  — gettype() + bag_keys() per candidate column,
#      classifies dynamic/string columns into {string, dictionary, array<dict>,
#      array<string>, array<scalar>, mixed, null-only} + single-key wrapper.
#   2. _build_enum_probe_kql   — bounded enum-value probe for *Type / *Status /
#      etc. columns. Returns up to ENUM_PROBE_LIMIT distinct values; above that
#      cap a single "high-cardinality" marker is emitted.
#
# Both are batched into one KQL union per source so total round-trip is one extra
# query per source. Failures are silent — Notes for the affected source fall back
# to empty.


def _is_enum_candidate(col_name: str, def_type: str, sen_type: str) -> bool:
    """Column matches *Type/Status/etc. AND is a string/int in at least one source."""
    if not _ENUM_NAME_RE.search(col_name):
        return False
    types = {def_type, sen_type}
    return bool(types & {"string", "int", "long"})


def _is_shape_candidate(def_type: str, sen_type: str) -> bool:
    """Worth probing the cell shape for — string or dynamic in at least one source."""
    types = {def_type, sen_type}
    return bool(types & {"string", "dynamic"})


def _build_shape_probe_kql(
    table_name: str, dynamic_cols: list[str], string_cols: list[str]
) -> str:
    """KQL union that emits per-column (ColumnName, OuterType, ElemType, FirstKeys, IsParsed).

    Two probe shapes by source declared type, to avoid hiding facts the agent
    needs when writing real queries:

    * dynamic_cols — probed DIRECTLY (no tostring/todynamic wrap). What we observe
      is what the agent's `mv-expand`/property access will see. `bag_keys()` and
      array indexing compile fine because the parser already knows the column is
      dynamic. IsParsed=false.
    * string_cols  — probed via `todynamic(tostring(col))`. The agent MUST run
      `parse_json(tostring(col))` before any property access — that's the headline
      note for these columns. The probe additionally reports what shape the JSON
      parses to ("after parse: array of dict", etc.) as bonus information. The
      parser-level `bag_keys argument must be dynamic` error forces this wrap
      for string-typed columns. IsParsed=true.

    Returns OuterType, ElemType (for arrays), and FirstKeys (for dicts).
    Empty-string entries are filtered from the make_set so we don't get
    leading-`;` artifacts when some sample rows are empty arrays.
    """
    if not dynamic_cols and not string_cols:
        return ""
    sample_size = _config.PROBE_SAMPLE_ROWS
    parts: list[str] = []

    # Branch 1: dynamic-typed columns — no wrap.
    for col in dynamic_cols:
        parts.append(
            f"""(
{table_name}
| take {sample_size}
| where isnotnull({col}) and tostring({col}) != ""
| extend _outer = gettype({col})
| extend _keys = case(_outer == "dictionary", tostring(bag_keys({col})), "")
| extend _elem = case(_outer == "array" and array_length({col}) > 0, gettype({col}[0]), "")
| summarize OuterTypes = strcat_array(make_set_if(_outer, isnotempty(_outer), 8), ";"),
            ElemTypes  = strcat_array(make_set_if(_elem, isnotempty(_elem), 8), ";"),
            FirstKeys  = take_anyif(_keys, isnotempty(_keys))
| extend ColumnName = "{col}", IsParsed = false
| project ColumnName, OuterTypes, ElemTypes, FirstKeys, IsParsed
)"""
        )

    # Branch 2: string-typed columns — wrapped (compile-required + tells us what's
    # inside the JSON; the headline `parse_json(tostring())` note still applies).
    for col in string_cols:
        parts.append(
            f"""(
{table_name}
| take {sample_size}
| where isnotnull({col}) and tostring({col}) != ""
| extend _v = todynamic(tostring({col}))
| extend _outer = gettype(_v)
| extend _keys = case(_outer == "dictionary", tostring(bag_keys(_v)), "")
| extend _elem = case(_outer == "array" and array_length(_v) > 0, gettype(_v[0]), "")
| summarize OuterTypes = strcat_array(make_set_if(_outer, isnotempty(_outer), 8), ";"),
            ElemTypes  = strcat_array(make_set_if(_elem, isnotempty(_elem), 8), ";"),
            FirstKeys  = take_anyif(_keys, isnotempty(_keys))
| extend ColumnName = "{col}", IsParsed = true
| project ColumnName, OuterTypes, ElemTypes, FirstKeys, IsParsed
)"""
        )

    return "union " + ",\n".join(parts)


def _build_dcount_probe_kql(table_name: str, columns: list[str]) -> str:
    """KQL union that emits (ColumnName, Distinct) — distinct-value cardinality
    per enum candidate. Acts as a gate before the more expensive value-enum probe:
    columns with Distinct > ENUM_PROBE_LIMIT are flagged high-cardinality directly
    from the dcount, no enumeration needed.

    Uses a larger sample size than the shape probe — high-volume tables
    (DeviceEvents has 80+ ActionTypes globally) get false-low cardinality
    when sampled at 200 rows. dcount() uses HLL so cost stays bounded.
    """
    if not columns:
        return ""
    sample_size = _config.ENUM_PROBE_SAMPLE_ROWS
    parts: list[str] = []
    for col in columns:
        parts.append(
            f"""(
{table_name}
| take {sample_size}
| where isnotnull({col}) and tostring({col}) != ""
| summarize Distinct = dcount(tostring({col}))
| extend ColumnName = "{col}"
| project ColumnName, Distinct
)"""
        )
    return "union " + ",\n".join(parts)


def _build_enum_probe_kql(table_name: str, columns: list[str]) -> str:
    """KQL union that emits (ColumnName, Value, Count) for enum candidates.

    Only run for columns that passed the dcount gate (Distinct ≤ ENUM_PROBE_LIMIT).
    Sample size matches the dcount probe so the value list is consistent with
    the cardinality estimate.
    """
    if not columns:
        return ""
    sample_size = _config.ENUM_PROBE_SAMPLE_ROWS
    cap = _config.ENUM_PROBE_LIMIT + 1
    parts: list[str] = []
    for col in columns:
        parts.append(
            f"""(
{table_name}
| take {sample_size}
| where isnotnull({col}) and tostring({col}) != ""
| summarize Count = count() by Value = tostring({col})
| top {cap} by Count desc
| extend ColumnName = "{col}"
| project ColumnName, Value, Count
)"""
        )
    return "union " + ",\n".join(parts)


def _parse_shape_hunting(result: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Defender shape-probe → {col: {OuterTypes, ElemTypes, FirstKeys, IsParsed}}.

    IsParsed is "true" / "false" — captures whether the probe wrapped the column
    in todynamic(tostring()) (string-typed source column) or accessed it directly
    (dynamic-typed source column). Consumers use it to decide whether to emit a
    `parse_json(tostring())` headline or trust the shape directly.
    """
    out: dict[str, dict[str, str]] = {}
    for row in result.get("results", []):
        col = row.get("ColumnName")
        if not col:
            continue
        out[col] = {
            "OuterTypes": str(row.get("OuterTypes") or ""),
            "ElemTypes": str(row.get("ElemTypes") or ""),
            "FirstKeys": str(row.get("FirstKeys") or ""),
            "IsParsed": "true" if row.get("IsParsed") else "false",
        }
    return out


def _parse_shape_sentinel(result: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Sentinel shape-probe → same shape as _parse_shape_hunting."""
    table = result["tables"][0]
    col_idx = {c["name"]: i for i, c in enumerate(table["columns"])}
    cn_i = col_idx.get("ColumnName", -1)
    ot_i = col_idx.get("OuterTypes", -1)
    et_i = col_idx.get("ElemTypes", -1)
    fk_i = col_idx.get("FirstKeys", -1)
    ip_i = col_idx.get("IsParsed", -1)
    out: dict[str, dict[str, str]] = {}
    for row in table["rows"]:
        if cn_i < 0:
            continue
        col = str(row[cn_i]) if row[cn_i] else ""
        if not col:
            continue
        out[col] = {
            "OuterTypes": str(row[ot_i] or "") if ot_i >= 0 else "",
            "ElemTypes": str(row[et_i] or "") if et_i >= 0 else "",
            "FirstKeys": str(row[fk_i] or "") if fk_i >= 0 else "",
            "IsParsed": "true" if (ip_i >= 0 and row[ip_i]) else "false",
        }
    return out


def _parse_dcount_hunting(result: dict[str, Any]) -> dict[str, int]:
    """Defender dcount-probe → {col: distinct_count}."""
    out: dict[str, int] = {}
    for row in result.get("results", []):
        col = row.get("ColumnName")
        d = row.get("Distinct")
        if not col or d is None:
            continue
        try:
            out[col] = int(d)
        except (TypeError, ValueError):
            continue
    return out


def _parse_dcount_sentinel(result: dict[str, Any]) -> dict[str, int]:
    """Sentinel dcount-probe → {col: distinct_count}."""
    table = result["tables"][0]
    col_idx = {c["name"]: i for i, c in enumerate(table["columns"])}
    cn_i = col_idx.get("ColumnName", -1)
    d_i = col_idx.get("Distinct", -1)
    out: dict[str, int] = {}
    for row in table["rows"]:
        if cn_i < 0 or d_i < 0:
            continue
        col = str(row[cn_i]) if row[cn_i] else ""
        if not col:
            continue
        try:
            out[col] = int(row[d_i] or 0)
        except (TypeError, ValueError):
            continue
    return out


def _parse_enum_hunting(result: dict[str, Any]) -> dict[str, list[str]]:
    """Defender enum-probe → {col: [value, value, ...] sorted by descending count}."""
    by_col: dict[str, list[tuple[str, int]]] = {}
    for row in result.get("results", []):
        col = row.get("ColumnName")
        val = row.get("Value")
        cnt = row.get("Count", 0)
        if not col:
            continue
        by_col.setdefault(col, []).append((str(val) if val is not None else "", int(cnt or 0)))
    return {c: [v for v, _ in sorted(rows, key=lambda x: -x[1])] for c, rows in by_col.items()}


def _parse_enum_sentinel(result: dict[str, Any]) -> dict[str, list[str]]:
    """Sentinel enum-probe → same shape as _parse_enum_hunting."""
    table = result["tables"][0]
    col_idx = {c["name"]: i for i, c in enumerate(table["columns"])}
    cn_i = col_idx.get("ColumnName", -1)
    val_i = col_idx.get("Value", -1)
    cnt_i = col_idx.get("Count", -1)
    by_col: dict[str, list[tuple[str, int]]] = {}
    for row in table["rows"]:
        if cn_i < 0:
            continue
        col = str(row[cn_i]) if row[cn_i] else ""
        if not col:
            continue
        val = str(row[val_i]) if val_i >= 0 and row[val_i] is not None else ""
        cnt = int(row[cnt_i] or 0) if cnt_i >= 0 else 0
        by_col.setdefault(col, []).append((val, cnt))
    return {c: [v for v, _ in sorted(rows, key=lambda x: -x[1])] for c, rows in by_col.items()}


def _shape_to_note(def_type: str, shape: dict[str, str] | None) -> str | None:
    """Translate a per-column shape probe result into one shape-fact note, or None.

    Emits declarative shape vocabulary, not access recipes. The skill-loaded
    kql-facts.md guides the LLM on operator choice (mv-apply vs mv-expand,
    parse_json(tostring()) for string-typed columns, etc.) — duplicating that
    advice here as imperatives can override the nuance and steer toward the
    wrong operator. Facts surfaced:

    * shape: `dict`, `array<dict>`, `array<string>`, `array<scalar>`, mixed
    * encoding: `string-encoded ` prefix when DefenderType=string but cells
      hold JSON (the agent still needs parse_json — kql-facts.md covers this)
    * structural fact: `bag_keys=[...]` when a dict has a single wrapper key
      (the NodeProperties.rawData pattern — non-obvious from type alone)

    Returns None when the probe found nothing useful (plain string column,
    null cells only, etc.).
    """
    if not shape:
        return None
    outer = shape.get("OuterTypes", "")
    elem = shape.get("ElemTypes", "")
    keys = shape.get("FirstKeys", "")
    outer_set = {s for s in outer.split(";") if s}
    elem_set = {s for s in elem.split(";") if s}

    def _shape_phrase() -> str | None:
        # Build the noun-phrase shape description from probe data.
        if outer_set <= {"dictionary"} and outer_set:
            single_key = None
            if keys:
                try:
                    parsed = json.loads(keys)
                    if isinstance(parsed, list) and len(parsed) == 1:
                        single_key = parsed[0]
                except (json.JSONDecodeError, ValueError):
                    pass
            if single_key is not None:
                return f'dict, bag_keys=["{single_key}"]'
            return "dict"
        if "array" in outer_set:
            if not elem_set:
                return "array"
            if elem_set <= {"dictionary"}:
                return "array<dict>"
            if elem_set <= {"string"}:
                # Probe can't distinguish plain-string from JSON-encoded-string
                # elements (gettype returns "string" for both). Emit the typed
                # fact; kql-facts.md tells the LLM how to disambiguate at query
                # time if it matters (inspect first char for `{`/`[`).
                return "array<string>"
            if elem_set <= {"long", "int", "real", "datetime", "bool", "guid"}:
                return f"array<{','.join(sorted(elem_set))}>"
            return f"array<{','.join(sorted(elem_set))} mixed>"
        return None

    if def_type == "string":
        # Plain-string columns (e.g. DeviceName) probe as OuterTypes={"string"}
        # via the todynamic(tostring()) wrap and need no shape note.
        if not (outer_set & {"dictionary", "array"}):
            return None
        phrase = _shape_phrase()
        if phrase:
            return f"string-encoded {phrase}"
        return "string-encoded JSON"

    if def_type == "dynamic":
        phrase = _shape_phrase()
        if phrase:
            return phrase
        if outer_set == {"string"}:
            # Rare: DefenderType=dynamic but cells are strings. Direct probe of
            # a genuinely-dynamic column shouldn't hit this (gettype would say
            # dictionary/array), but legacy edge cases exist.
            return "string-encoded (legacy dynamic)"
        return None

    return None


def _enum_to_note(values: list[str], distinct_count: int | None = None) -> str | None:
    """Translate a per-column enum probe result into a note fragment, or None.

    distinct_count comes from the dcount gate. When provided and above the
    limit, emit the high-cardinality marker with the actual count — this
    catches cases where the value list itself is short (e.g. dcount probe
    skipped the enum probe, so values is empty) but cardinality is high.
    """
    if distinct_count is not None and distinct_count > _config.ENUM_PROBE_LIMIT:
        return f"high-cardinality ({distinct_count} distinct values)"
    if not values:
        return None
    if len(values) > _config.ENUM_PROBE_LIMIT:
        return f"high-cardinality (>{_config.ENUM_PROBE_LIMIT} distinct values)"
    return "enum: " + ", ".join(values)


def _format_notes(
    col_name: str,
    def_type: str,
    sen_type: str,
    def_shape: dict[str, dict[str, str]],
    sen_shape: dict[str, dict[str, str]],
    def_enum: dict[str, list[str]],
    sen_enum: dict[str, list[str]],
    def_dcount: dict[str, int] | None = None,
    sen_dcount: dict[str, int] | None = None,
) -> str:
    """Merge Defender + Sentinel probe results into a single Notes cell.

    Defender-authoritative: when both sources have an opinion, prefer Defender's.
    Sentinel notes only appear when Defender has nothing useful for that fragment.
    Enum values: prefer the source with the larger known set.
    Distinct count (from dcount gate): used to flag high-cardinality even when
    the value list is empty (because we skipped the enum probe).
    """
    fragments: list[str] = []

    # Shape note — Defender wins. Use Defender's type as the rule basis even
    # when the probe data came from Sentinel (DefenderType is the truth signal).
    shape_note = _shape_to_note(def_type if def_type != "N/A" else sen_type, def_shape.get(col_name))
    if not shape_note:
        # Defender had no usable signal — try Sentinel data, but still apply
        # Defender's type to decide the rule when it exists.
        shape_note = _shape_to_note(def_type if def_type != "N/A" else sen_type, sen_shape.get(col_name))
    if shape_note:
        fragments.append(shape_note)

    # Enum note — prefer the larger set when both probed.
    def_vals = def_enum.get(col_name) or []
    sen_vals = sen_enum.get(col_name) or []
    chosen = def_vals if len(def_vals) >= len(sen_vals) else sen_vals
    # Use the larger distinct count too (HLL undercounts more often than overcounts).
    distinct_def = (def_dcount or {}).get(col_name)
    distinct_sen = (sen_dcount or {}).get(col_name)
    distinct = max((d for d in (distinct_def, distinct_sen) if d is not None), default=None)
    enum_note = _enum_to_note(chosen, distinct)
    if enum_note:
        fragments.append(enum_note)

    note = "; ".join(fragments)
    if len(note) > _config.NOTES_CELL_MAX_CHARS:
        note = note[: _config.NOTES_CELL_MAX_CHARS - 1] + "…"
    return _sanitise(note)


async def _run_shape_probe(
    table_name: str, dynamic_cols: list[str], string_cols: list[str], *, is_sentinel: bool
) -> dict[str, dict[str, str]]:
    """Run the shape probe; return empty dict on any failure."""
    if not dynamic_cols and not string_cols:
        return {}
    kql = _build_shape_probe_kql(table_name, dynamic_cols, string_cols)
    try:
        if is_sentinel:
            raw = await _client.run_sentinel_query_raw(kql)
            return _parse_shape_sentinel(raw)
        raw = await _client.run_hunting_query_raw(kql)
        return _parse_shape_hunting(raw)
    except Exception:
        return {}


async def _run_dcount_probe(
    table_name: str, columns: list[str], *, is_sentinel: bool
) -> dict[str, int]:
    """Run the dcount gate probe; return empty dict on any failure."""
    if not columns:
        return {}
    kql = _build_dcount_probe_kql(table_name, columns)
    try:
        if is_sentinel:
            raw = await _client.run_sentinel_query_raw(kql)
            return _parse_dcount_sentinel(raw)
        raw = await _client.run_hunting_query_raw(kql)
        return _parse_dcount_hunting(raw)
    except Exception:
        return {}


async def _run_enum_probe(
    table_name: str, columns: list[str], *, is_sentinel: bool
) -> dict[str, list[str]]:
    """Run the enum probe; return empty dict on any failure."""
    if not columns:
        return {}
    kql = _build_enum_probe_kql(table_name, columns)
    try:
        if is_sentinel:
            raw = await _client.run_sentinel_query_raw(kql)
            return _parse_enum_sentinel(raw)
        raw = await _client.run_hunting_query_raw(kql)
        return _parse_enum_hunting(raw)
    except Exception:
        return {}


async def get_schema(table_name: str | None) -> list[TextContent]:
    """MCP TOOL get_schema: Unified schema discovery for Defender Advanced Hunting and Sentinel."""
    use_sentinel = bool(_config._sentinel_workspace_id)
    source_key = "def" + ("sen" if use_sentinel else "")
    try:
        if table_name:
            text = await _cache.cache_get(
                f"schema-{table_name}-{source_key}.txt",
                lambda: _get_schema_for_table(table_name),
                ttl=_config.SCHEMA_TABLE_CACHE_TTL
            )
            out = [TextContent(type="text", text=text)]
        else:
            text = await _cache.cache_get(
                f"alltables-{source_key}.tsv",
                lambda: _get_schema_tablelist(),
                ttl=_config.SCHEMA_LIST_CACHE_TTL
            )
            out = [TextContent(type="text", text=text)]
    except httpx.HTTPStatusError as e:
        error_detail = e.response.text if e.response else str(e)
        out = [TextContent(type="text", text=f"Schema error: {error_detail}")]
    except Exception as e:
        out = [TextContent(type="text", text=f"Schema error: {e}")]
    args_label = f"table_name={table_name!r}" if table_name else "(listing all tables)"
    _append_query_log("get_schema", args_label, out[0].text if out else "", lang="text")
    return out


async def _get_schema_tablelist() -> str:
    """Fetch raw table listing data from APIs; return as TSV text (header + rows, no overflow limiter)."""
    use_sentinel = bool(_config._sentinel_workspace_id)
    coros: list[tuple[str, Any]] = []
    coros.append(("def_tables", _client.run_hunting_query_raw(
        # TODO: this is a stupid expensive way to get the table list but until we implement pure API calls, it is what it is. 
        # Getschema on the entire union forces Defender to enumerate all tables, then we distinct on $table.
        "union withsource=$table * | distinct $table | sort by $table asc"
    )))
    if use_sentinel:
        coros.append(("sen_usage", _client.run_sentinel_query_raw(
            # This excludes tables that haven't received data in the last 30 days; seems reasonable 
            # for a "what can I query?" listing and much cheaper than the above Defender hack.
            "Usage | where TimeGenerated > ago(30d) | summarize LastSeen=max(TimeGenerated), SentinelSolution=any(Solution) by DataType"
        )))

    # TODO: yikes rewrite all of the below to not assume that a result can go missing. Also don't hide exceptions! Let the caller catch them!
    labels = [label for label, _ in coros]
    raw_results = await asyncio.gather(*[coro for _, coro in coros], return_exceptions=True)
    results_by_label: dict[str, Any] = dict(zip(labels, raw_results))

    def_tables: set[str] = set()
    if "def_tables" in results_by_label:
        r = results_by_label["def_tables"]
        if not isinstance(r, Exception):
            def_tables = {row.get("$table", "") for row in r.get("results", []) if row.get("$table")}

    sen_tables: set[str] = set()
    sen_lastseen: dict[str, str] = {}
    sen_solution: dict[str, str] = {}
    if "sen_usage" in results_by_label:
        r = results_by_label["sen_usage"]
        if not isinstance(r, Exception):
            table = r["tables"][0]
            col_idx = {c["name"]: i for i, c in enumerate(table["columns"])}
            dt_i = col_idx.get("DataType", -1)
            ls_i = col_idx.get("LastSeen", -1)
            sol_i = col_idx.get("SentinelSolution", -1)
            for row in table["rows"]:
                dt = str(row[dt_i]) if dt_i >= 0 and row[dt_i] else ""
                ls = str(row[ls_i]) if ls_i >= 0 and row[ls_i] else ""
                sol = str(row[sol_i]) if sol_i >= 0 and row[sol_i] else ""
                if dt:
                    sen_tables.add(dt)
                    sen_lastseen[dt] = ls
                    sen_solution[dt] = sol

    all_tables = sorted(def_tables | sen_tables)
    col_names = ["Table", "Defender", "Sentinel", "SentinelLastSeen", "SentinelSolution"]
    data_rows = []
    for t in all_tables:
        in_def = "yes" if t in def_tables else "-"
        in_sen = "yes" if t in sen_tables else "-"
        ls = sen_lastseen.get(t, "")
        sol = sen_solution.get(t, "")
        data_rows.append("\t".join([_sanitise(t), in_def, in_sen, ls, sol]))

    return "\n".join(["\t".join(col_names)] + data_rows)




async def _get_schema_for_table( table_name: str ) -> str:
    """Return merged schema + sample rows for a specific table from all sources."""
    use_sentinel = bool(_config._sentinel_workspace_id)
    coros: list[tuple[str, Any]] = []
    coros.append(("def_schema", _client.run_hunting_query_raw(f"{table_name} | getschema")))
    coros.append(("def_sample", _client.run_hunting_query_raw(f"{table_name} | take 3")))
    if use_sentinel:
        coros.append(("sen_schema", _client.run_sentinel_query_raw(f"{table_name} | getschema")))
        coros.append(("sen_sample", _client.run_sentinel_query_raw(f"{table_name} | take 3")))

    labels = [label for label, _ in coros]
    raw_results = await asyncio.gather(*[coro for _, coro in coros], return_exceptions=True)
    results_by_label: dict[str, Any] = dict(zip(labels, raw_results))

    # ── Collect per-source schema columns ────────────────────────────────────
    def_cols: list[tuple[str, str]] = []
    sen_cols: list[tuple[str, str]] = []
    error_parts: list[str] = []

    if "def_schema" in results_by_label:
        r = results_by_label["def_schema"]
        if isinstance(r, Exception):
            if isinstance(r, httpx.HTTPStatusError) and r.response.status_code == 400:  # TODO: move this to client and return empty
                error_parts.append("Defender: table not found in this source.")
            else:
                error_parts.append(f"Defender: ERROR — {r}")
        else:
            def_cols = _parse_getschema_hunting(r)

    if "sen_schema" in results_by_label:
        r = results_by_label["sen_schema"]
        if isinstance(r, Exception):
            if isinstance(r, httpx.HTTPStatusError) and r.response.status_code == 400:  # TODO: move this to client and return empty
                error_parts.append("Sentinel: table not found in this source.")
            else:
                error_parts.append(f"Sentinel: ERROR — {r}")
        else:
            sen_cols = _parse_getschema_sentinel(r)

    # ── Merge into unified column dict (full outer join) ─────────────────────
    # ColumnName -> (DefenderType, SentinelType)
    merged: dict[str, tuple[str, str]] = {}
    for col_name, col_type in def_cols:
        merged[col_name] = (col_type, "N/A")
    for col_name, col_type in sen_cols:
        if col_name in merged:
            merged[col_name] = (merged[col_name][0], col_type)
        else:
            merged[col_name] = ("N/A", col_type)

    if not merged:
        if error_parts:
            return "\n".join(error_parts)
        return f"Table '{table_name}' not found in any configured source."

    # ── Probe deterministic per-tenant facts (shape + enum cardinality) ───────
    # Run after schema is known (we need the column type lists to pick candidates),
    # but in parallel across both sources. Failures are silent — Notes fall back
    # to empty for the affected source.
    #
    # Shape probe candidates split by source-declared type because the KQL parser
    # rejects bag_keys()/array indexing on a string column. Defender's probe
    # passes its dynamic columns directly and wraps its string columns in
    # todynamic(tostring()); Sentinel's probe does the same against ITS schema.
    enum_cols = [c for c, (dt, st) in merged.items() if _is_enum_candidate(c, dt, st)]
    def_dyn_cols = [c for c, (dt, _) in merged.items() if dt == "dynamic"]
    def_str_cols = [c for c, (dt, _) in merged.items() if dt == "string"]
    sen_dyn_cols = [c for c, (_, st) in merged.items() if st == "dynamic"]
    sen_str_cols = [c for c, (_, st) in merged.items() if st == "string"]

    # Stage A: shape probe + dcount gate (parallel across sources).
    # The dcount gate runs first so we can skip enumerating high-cardinality
    # columns entirely — saves a chunk of result data on tables like DeviceEvents
    # where ActionType has 80+ distinct values.
    stage_a_coros: list[tuple[str, Any]] = []
    if def_cols:
        stage_a_coros.append((
            "def_shape",
            _run_shape_probe(table_name, def_dyn_cols, def_str_cols, is_sentinel=False),
        ))
        stage_a_coros.append(("def_dcount", _run_dcount_probe(table_name, enum_cols, is_sentinel=False)))
    if sen_cols:
        stage_a_coros.append((
            "sen_shape",
            _run_shape_probe(table_name, sen_dyn_cols, sen_str_cols, is_sentinel=True),
        ))
        stage_a_coros.append(("sen_dcount", _run_dcount_probe(table_name, enum_cols, is_sentinel=True)))

    probe_results: dict[str, Any] = {}
    if stage_a_coros:
        labels_a = [label for label, _ in stage_a_coros]
        raw_a = await asyncio.gather(*[coro for _, coro in stage_a_coros], return_exceptions=True)
        for label, res in zip(labels_a, raw_a):
            probe_results[label] = res if not isinstance(res, Exception) else {}

    def_dcount: dict[str, int] = probe_results.get("def_dcount") or {}
    sen_dcount: dict[str, int] = probe_results.get("sen_dcount") or {}

    # Stage B: enum value probe — ONLY for columns confirmed low-cardinality by
    # the dcount gate. Per source: take the columns whose dcount(this-source) is
    # ≤ ENUM_PROBE_LIMIT. If dcount didn't run or returned nothing for a column,
    # we still enumerate (preserves existing behavior when dcount fails silently).
    def _enum_keep(cols: list[str], dcount: dict[str, int]) -> list[str]:
        kept: list[str] = []
        for c in cols:
            d = dcount.get(c)
            if d is None or d <= _config.ENUM_PROBE_LIMIT:
                kept.append(c)
        return kept

    def_enum_cols = _enum_keep(enum_cols, def_dcount) if def_cols else []
    sen_enum_cols = _enum_keep(enum_cols, sen_dcount) if sen_cols else []

    stage_b_coros: list[tuple[str, Any]] = []
    if def_enum_cols:
        stage_b_coros.append(("def_enum", _run_enum_probe(table_name, def_enum_cols, is_sentinel=False)))
    if sen_enum_cols:
        stage_b_coros.append(("sen_enum", _run_enum_probe(table_name, sen_enum_cols, is_sentinel=True)))

    if stage_b_coros:
        labels_b = [label for label, _ in stage_b_coros]
        raw_b = await asyncio.gather(*[coro for _, coro in stage_b_coros], return_exceptions=True)
        for label, res in zip(labels_b, raw_b):
            probe_results[label] = res if not isinstance(res, Exception) else {}

    def_shape = probe_results.get("def_shape") or {}
    sen_shape = probe_results.get("sen_shape") or {}
    def_enum = probe_results.get("def_enum") or {}
    sen_enum = probe_results.get("sen_enum") or {}

    # ── Render merged schema as TSV with Notes column ─────────────────────────
    # Plain TSV (no fixed-width alignment): the consumer is an LLM, not a
    # spreadsheet. Notes can be long (full enum lists up to NOTES_CELL_MAX_CHARS).
    lines = [
        f"Schema for {table_name}:",
        "",
        "ColumnName\tDefenderType\tSentinelType\tNotes",
    ]
    for col_name, (def_type, sen_type) in merged.items():
        notes = _format_notes(
            col_name, def_type, sen_type,
            def_shape, sen_shape, def_enum, sen_enum,
            def_dcount, sen_dcount,
        )
        lines.append("\t".join([_sanitise(col_name), def_type, sen_type, notes]))
    output_parts: list[str] = ["\n".join(lines)]

    if error_parts:
        output_parts.append("\n".join(error_parts))

    # ── Sample rows (per-source, intelligently summarize huge cells) ──────────────────────────────────
    for source_label, sample_key, is_sentinel in [
        ("Defender", "def_sample", False),
        ("Sentinel", "sen_sample", True),
    ]:
        if sample_key not in results_by_label:
            continue
        sample_result = results_by_label[sample_key]
        if isinstance(sample_result, Exception):
            output_parts.append(f"Sample rows from {table_name} ({source_label}): ERROR — {sample_result}")
            continue
        if is_sentinel:
            s_col_names, s_data_rows = _client._sentinel_result_to_tsv(sample_result)
            s_data_rows = [
                "\t".join(_truncate_cell(cell) for cell in row.split("\t"))
                for row in s_data_rows
            ]
        else:
            s_schema = sample_result.get("schema", [])
            s_col_names = [col.get("name", "") for col in s_schema]
            s_data_rows = [
                "\t".join(_sanitise(_truncate_cell(_cell_str(row.get(n)))) for n in s_col_names)
                for row in sample_result.get("results", [])
            ]
        if s_data_rows:
            header = "\t".join(_sanitise(n) for n in s_col_names)
            output_parts.append(
                "\n".join([f"Sample rows from {table_name} ({source_label}):", "", header] + s_data_rows)
            )
        else:
            output_parts.append(f"Sample rows from {table_name} ({source_label}): (no rows — table may be empty)")

    return "\n\n---\n\n".join(output_parts)


async def warm_schema_cache() -> None:
    """Warm the schema listing cache in the background. Swallows all exceptions."""
    try:
        await get_schema(None)
    except Exception:
        pass
