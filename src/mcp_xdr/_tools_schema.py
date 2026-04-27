"""MCP tool: get_schema — unified schema discovery for Defender and Sentinel."""

import asyncio
import json
from typing import Any

import httpx
from mcp.types import TextContent, Tool

import mcp_xdr._cache as _cache
import mcp_xdr._client as _client
from mcp_xdr._output import _append_query_log, _cell_str, _run_query, _sanitise
import mcp_xdr._config as _config


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
        "SentinelLastSeen (hourly granularity) comes from the Log Analytics `Usage` table."
        "\n\n"
        "With table_name: returns the full column schema (ColumnName, ColumnType) plus "
        "up to 3 sample rows from that table."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "table_name": {
                "type": "string",
                "description": "Optional. Table to inspect. Omit to list all tables.",
            },
            "source": {
                "type": "string",
                "enum": ["defender", "sentinel"],
                "description": "Optional. Restrict to one source. Omit for both.",
            },
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


async def get_schema(table_name: str | None, source: str | None) -> list[TextContent]:
    """Unified schema discovery for Defender Advanced Hunting and Sentinel."""
    try:
        if source is not None:
            source = source.lower()
            if source not in ("defender", "sentinel"):
                out = [TextContent(type="text", text=f"Invalid source '{source}'. Use 'defender', 'sentinel', or omit.")]
                _append_query_log("get_schema", f"table_name={table_name!r} source={source!r}", out[0].text, lang="text")
                return out
        use_defender = source in (None, "defender")
        use_sentinel = (source in (None, "sentinel")) and bool(_config._sentinel_workspace_id)
        if source == "sentinel" and not _config._sentinel_workspace_id:
            out = [TextContent(type="text", text="Error: source='sentinel' but SENTINEL_WORKSPACE_ID is not configured.")]
            _append_query_log("get_schema", f"table_name={table_name!r} source={source!r}", out[0].text, lang="text")
            return out
        if table_name:
            out = await _get_schema_for_table(table_name, use_defender, use_sentinel)
        else:
            out = await _get_schema_listing(use_defender, use_sentinel)
    except httpx.HTTPStatusError as e:
        error_detail = e.response.text if e.response else str(e)
        out = [TextContent(type="text", text=f"Schema error: {error_detail}")]
    except Exception as e:
        out = [TextContent(type="text", text=f"Schema error: {e}")]
    args_label = f"table_name={table_name!r} source={source!r}" if table_name else "(listing all tables)"
    _append_query_log("get_schema", args_label, out[0].text if out else "", lang="text")
    return out


async def _get_schema_listing(use_defender: bool, use_sentinel: bool) -> list[TextContent]:
    """List all tables across sources as a TSV with activity columns."""
    coros: list[tuple[str, Any]] = []
    if use_defender:
        coros.append(("def_tables", _cache.get_defender_tables()))
    if use_sentinel:
        coros.append(("sen_usage", _client.run_sentinel_query_raw(
            "Usage | where TimeGenerated > ago(30d) | summarize LastSeen=max(TimeGenerated) by DataType"
        )))

    if not coros:
        return [TextContent(type="text", text="No sources available.")]

    labels = [label for label, _ in coros]
    raw_results = await asyncio.gather(*[coro for _, coro in coros], return_exceptions=True)
    results_by_label: dict[str, Any] = dict(zip(labels, raw_results))

    def_tables: set[str] = set()
    if "def_tables" in results_by_label:
        r = results_by_label["def_tables"]
        if not isinstance(r, Exception):
            def_tables = r  # already a set[str] from _cache.get_defender_tables()

    sen_tables: set[str] = set()
    sen_lastseen: dict[str, str] = {}
    if "sen_usage" in results_by_label:
        r = results_by_label["sen_usage"]
        if not isinstance(r, Exception):
            table = r["tables"][0]
            col_idx = {c["name"]: i for i, c in enumerate(table["columns"])}
            dt_i = col_idx.get("DataType", -1)
            ls_i = col_idx.get("LastSeen", -1)
            for row in table["rows"]:
                dt = str(row[dt_i]) if dt_i >= 0 and row[dt_i] else ""
                ls = str(row[ls_i]) if ls_i >= 0 and row[ls_i] else ""
                if dt:
                    sen_tables.add(dt)
                    sen_lastseen[dt] = ls

    all_tables = sorted(def_tables | sen_tables)
    if not all_tables:
        return [TextContent(type="text", text="No tables found.")]

    col_names = ["Table", "Defender", "Sentinel", "SentinelLastSeen"]
    data_rows = []
    for t in all_tables:
        in_def = "yes" if t in def_tables else "-"
        in_sen = "yes" if t in sen_tables else "-"
        ls = sen_lastseen.get(t, "")
        data_rows.append("\t".join([_sanitise(t), in_def, in_sen, ls]))

    return await _run_query(col_names, data_rows, "mcp-xdr-schema-")


async def _get_schema_for_table(
    table_name: str, use_defender: bool, use_sentinel: bool
) -> list[TextContent]:
    """Return merged schema + sample rows for a specific table from the requested source(s)."""
    coros: list[tuple[str, Any]] = []
    if use_defender:
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
    fallback_notes: list[str] = []
    error_parts: list[str] = []

    if "def_schema" in results_by_label:
        r = results_by_label["def_schema"]
        s = results_by_label.get("def_sample")
        if isinstance(r, Exception):
            if isinstance(r, httpx.HTTPStatusError) and r.response.status_code == 400:
                error_parts.append("Defender: table not found in this source.")
            else:
                error_parts.append(f"Defender: ERROR — {r}")
        else:
            def_cols = _parse_getschema_hunting(r)
            if not def_cols and s is not None and not isinstance(s, Exception):
                api_schema = s.get("schema", [])
                if api_schema:
                    def_cols = [(c.get("name", ""), c.get("type", "")) for c in api_schema if c.get("name")]
                    fallback_notes.append("Defender schema from API metadata — table has no rows")

    if "sen_schema" in results_by_label:
        r = results_by_label["sen_schema"]
        if isinstance(r, Exception):
            if isinstance(r, httpx.HTTPStatusError) and r.response.status_code == 400:
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
            return [TextContent(type="text", text="\n".join(error_parts))]
        return [TextContent(type="text", text=f"Table '{table_name}' not found in any configured source.")]

    # ── Render merged schema table ────────────────────────────────────────────
    note = f" ({'; '.join(fallback_notes)})" if fallback_notes else ""
    lines = [f"Schema for {table_name}:{note}", ""]
    lines.append(f"{'ColumnName':<45} {'DefenderType':<15} SentinelType")
    lines.append("-" * 75)
    for col_name, (def_type, sen_type) in merged.items():
        lines.append(f"{col_name:<45} {def_type:<15} {sen_type}")
    output_parts: list[str] = ["\n".join(lines)]

    if error_parts:
        output_parts.append("\n".join(error_parts))

    # ── Sample rows (per-source, unchanged) ──────────────────────────────────
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

    return [TextContent(type="text", text="\n\n---\n\n".join(output_parts))]
