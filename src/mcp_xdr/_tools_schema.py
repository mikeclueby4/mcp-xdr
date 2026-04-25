"""MCP tool: get_schema — unified schema discovery for Defender and Sentinel."""

import asyncio
from typing import Any

import httpx
from mcp.types import TextContent, Tool

import mcp_xdr._client as _client
from mcp_xdr._output import _append_query_log, _run_query, _sanitise
import mcp_xdr._config as _config

TOOL_DEFINITION = Tool(
    name="get_schema",
    description=(
        "Discover available tables and columns before writing KQL queries."
        "\n\n"
        "No arguments: lists all tables across Defender and (when configured) Sentinel as TSV. "
        "SentinelLastSeen (hourly granularity) and SentinelMB come from the Log Analytics `Usage` table."
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
        coros.append(("def_tables", _client.run_hunting_query_raw(
            "search * | distinct $table | sort by $table asc"
        )))
    if use_sentinel:
        coros.append(("sen_tables", _client.run_sentinel_query_raw(
            "search * | distinct $table | sort by $table asc"
        )))
        coros.append(("sen_usage", _client.run_sentinel_query_raw(
            "Usage | summarize LastSeen=max(TimeGenerated), TotalMB=sum(Quantity) by DataType"
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
            for row in r.get("results", []):
                t = row.get("$table", "")
                if t:
                    def_tables.add(t)

    sen_tables: set[str] = set()
    if "sen_tables" in results_by_label:
        r = results_by_label["sen_tables"]
        if not isinstance(r, Exception):
            for row in r["tables"][0]["rows"]:
                t = str(row[0]) if row else ""
                if t:
                    sen_tables.add(t)

    sen_lastseen: dict[str, str] = {}
    sen_mb: dict[str, str] = {}
    if "sen_usage" in results_by_label:
        r = results_by_label["sen_usage"]
        if not isinstance(r, Exception):
            table = r["tables"][0]
            col_idx = {c["name"]: i for i, c in enumerate(table["columns"])}
            dt_i = col_idx.get("DataType", -1)
            ls_i = col_idx.get("LastSeen", -1)
            mb_i = col_idx.get("TotalMB", -1)
            for row in table["rows"]:
                dt = str(row[dt_i]) if dt_i >= 0 and row[dt_i] else ""
                ls = str(row[ls_i]) if ls_i >= 0 and row[ls_i] else ""
                mb = f"{row[mb_i]:.2f}" if mb_i >= 0 and row[mb_i] is not None else ""
                if dt:
                    sen_lastseen[dt] = ls
                    sen_mb[dt] = mb

    all_tables = sorted(def_tables | sen_tables)
    if not all_tables:
        return [TextContent(type="text", text="No tables found.")]

    col_names = ["Table", "Defender", "Sentinel", "SentinelLastSeen", "SentinelMB"]
    data_rows = []
    for t in all_tables:
        in_def = "yes" if t in def_tables else "-"
        in_sen = "yes" if t in sen_tables else "-"
        ls = sen_lastseen.get(t, "")
        mb = sen_mb.get(t, "")
        data_rows.append("\t".join([_sanitise(t), in_def, in_sen, ls, mb]))

    return await _run_query(col_names, data_rows, "mcp-xdr-schema-")


async def _get_schema_for_table(
    table_name: str, use_defender: bool, use_sentinel: bool
) -> list[TextContent]:
    """Return schema + sample rows for a specific table from the requested source(s)."""
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

    output_parts: list[str] = []

    for source_label, schema_key, sample_key, is_sentinel in [
        ("Defender", "def_schema", "def_sample", False),
        ("Sentinel", "sen_schema", "sen_sample", True),
    ]:
        if schema_key not in results_by_label:
            continue

        schema_result = results_by_label[schema_key]
        sample_result = results_by_label[sample_key]

        if isinstance(schema_result, Exception):
            output_parts.append(f"Schema for {table_name} ({source_label}): ERROR — {schema_result}")
            continue

        if is_sentinel:
            schema_cols = _parse_getschema_sentinel(schema_result)
        else:
            schema_cols = _parse_getschema_hunting(schema_result)

        # Fallback: if getschema returned nothing (table has no rows), use the API schema field
        # from the take-3 response, which always carries column metadata.
        fallback_note = ""
        if not schema_cols and not isinstance(sample_result, Exception):
            api_schema = sample_result.get("schema", []) if not is_sentinel else []
            if api_schema:
                schema_cols = [(c.get("name", ""), c.get("type", "")) for c in api_schema if c.get("name")]
                fallback_note = " (schema from API metadata — table has no rows)"

        if not schema_cols:
            output_parts.append(f"Schema for {table_name} ({source_label}): table not found or no schema available.")
            continue

        lines = [f"Schema for {table_name} ({source_label}):{fallback_note}", ""]
        lines.append(f"{'ColumnName':<45} ColumnType")
        lines.append("-" * 65)
        for col_name, col_type in schema_cols:
            lines.append(f"{col_name:<45} {col_type}")
        output_parts.append("\n".join(lines))

        if isinstance(sample_result, Exception):
            output_parts.append(f"Sample rows from {table_name} ({source_label}): ERROR — {sample_result}")
        else:
            if is_sentinel:
                s_col_names, s_data_rows = _client._sentinel_result_to_tsv(sample_result)
            else:
                s_schema = sample_result.get("schema", [])
                s_col_names = [col.get("name", "") for col in s_schema]
                s_data_rows = [
                    "\t".join(_sanitise(str(row.get(n, ""))) for n in s_col_names)
                    for row in sample_result.get("results", [])
                ]
            if s_data_rows:
                header = "\t".join(_sanitise(n) for n in s_col_names)
                output_parts.append(
                    "\n".join([f"Sample rows from {table_name} ({source_label}):", "", header] + s_data_rows)
                )
            else:
                output_parts.append(f"Sample rows from {table_name} ({source_label}): (no rows — table may be empty)")

    if not output_parts:
        return [TextContent(type="text", text=f"Table '{table_name}' not found in any configured source.")]

    return [TextContent(type="text", text="\n\n---\n\n".join(output_parts))]
