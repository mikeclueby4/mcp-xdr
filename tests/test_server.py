"""Tests for the MCP Defender Advanced Hunting server."""

import os
import re
from unittest.mock import AsyncMock, patch

import pytest

import mcp_xdr._config as cfg
from mcp_xdr.server import INLINE_BYTE_LIMIT, list_tools, run_hunting_query, run_sentinel_query, get_schema

async def _cache_passthrough(filename, fetcher, **kw):
    """Test helper: makes cache_get transparent by calling the fetcher directly."""
    return await fetcher()


# Synthetic lorem text (~60 chars) used to bulk up rows for overflow tests
_LOREM = "Lorem ipsum dolor sit amet, consectetur adipiscing elit pad"

SCHEMA = [{"name": "LineNum"}, {"name": "LoremIpsum"}]


def _make_api_result(num_rows: int) -> dict:
    # Graph Security API uses lowercase keys: schema / results
    return {
        "schema": SCHEMA,
        "results": [{"LineNum": str(i), "LoremIpsum": _LOREM} for i in range(num_rows)],
        "stats": {},
    }


def _make_sentinel_api_result(num_rows: int) -> dict:
    # Log Analytics API returns parallel arrays
    return {
        "tables": [{
            "name": "PrimaryResult",
            "columns": [{"name": "LineNum", "type": "int"}, {"name": "LoremIpsum", "type": "string"}],
            "rows": [[i, _LOREM] for i in range(num_rows)],
        }],
    }



def _make_defender_tables_result(*table_names: str) -> dict:
    """Defender response for the union withsource=$table listing query."""
    return {
        "schema": [{"name": "$table", "type": "string"}],
        "results": [{"$table": t} for t in table_names],
        "stats": {},
    }


def _make_sentinel_usage_result(*entries: tuple[str, str]) -> dict:
    """Sentinel Usage query response. entries = (DataType, LastSeen)."""
    return {
        "tables": [{
            "name": "PrimaryResult",
            "columns": [
                {"name": "DataType", "type": "string"},
                {"name": "LastSeen", "type": "datetime"},
           ],
            "rows": [[dt, ls] for dt, ls in entries],
        }],
    }


def _make_getschema_hunting_result(*cols: tuple[str, str]) -> dict:
    """Defender response for `TableName | getschema`. cols = (ColumnName, ColumnType)."""
    return {
        "schema": [
            {"name": "ColumnName", "type": "string"},
            {"name": "ColumnOrdinal", "type": "int"},
            {"name": "DataType", "type": "string"},
            {"name": "ColumnType", "type": "string"},
        ],
        "results": [
            {"ColumnName": cn, "ColumnOrdinal": i, "DataType": "System.Object", "ColumnType": ct}
            for i, (cn, ct) in enumerate(cols)
        ],
        "stats": {},
    }


def _make_getschema_sentinel_result(*cols: tuple[str, str]) -> dict:
    """Sentinel response for `TableName | getschema`. cols = (ColumnName, ColumnType)."""
    return {
        "tables": [{
            "name": "PrimaryResult",
            "columns": [
                {"name": "ColumnName", "type": "string"},
                {"name": "ColumnOrdinal", "type": "int"},
                {"name": "DataType", "type": "string"},
                {"name": "ColumnType", "type": "string"},
            ],
            "rows": [
                [cn, i, "System.Object", ct]
                for i, (cn, ct) in enumerate(cols)
            ],
        }],
    }


def _make_sample_hunting_result(*cols: tuple[str, str]) -> dict:
    """Defender take-3 response with empty rows (no data)."""
    return {
        "schema": [{"name": cn, "type": ct} for cn, ct in cols],
        "results": [],
        "stats": {},
    }


# ── Tool listing tests ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_tools_without_sentinel_workspace():
    """Without SENTINEL_WORKSPACE_ID, 2 tools are exposed: run_hunting_query + get_schema."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        tools = await list_tools()
        tool_names = [t.name for t in tools]
        assert "run_hunting_query" in tool_names
        assert "get_schema" in tool_names
        assert "run_sentinel_query" not in tool_names
        assert "get_sentinel_tables" not in tool_names
        assert "get_hunting_schema" not in tool_names
        assert len(tools) == 2
    finally:
        cfg._sentinel_workspace_id = original


@pytest.mark.asyncio
async def test_list_tools_with_sentinel_workspace():
    """With SENTINEL_WORKSPACE_ID set, 3 tools are exposed."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = "fake-workspace-id"
    try:
        tools = await list_tools()
        tool_names = [t.name for t in tools]
        assert "run_hunting_query" in tool_names
        assert "get_schema" in tool_names
        assert "run_sentinel_query" in tool_names
        assert "get_sentinel_tables" not in tool_names
        assert "get_hunting_schema" not in tool_names
        assert len(tools) == 3
        assert "list_incidents" not in tool_names
        assert "list_alerts" not in tool_names
    finally:
        cfg._sentinel_workspace_id = original


@pytest.mark.asyncio
async def test_run_hunting_query_tool_schema():
    """Test that run_hunting_query has correct input schema."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        tools = await list_tools()
        query_tool = next(t for t in tools if t.name == "run_hunting_query")
        assert query_tool.inputSchema["required"] == ["query"]
        assert "query" in query_tool.inputSchema["properties"]
    finally:
        cfg._sentinel_workspace_id = original


@pytest.mark.asyncio
async def test_get_schema_tool_schema():
    """Test that get_schema has correct input schema with optional table_name."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        tools = await list_tools()
        schema_tool = next(t for t in tools if t.name == "get_schema")
        assert schema_tool.inputSchema["required"] == []
        assert "table_name" in schema_tool.inputSchema["properties"]
    finally:
        cfg._sentinel_workspace_id = original


# ── run_hunting_query overflow tests ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_hunting_query_small_result_no_overflow():
    """Small result set (<INLINE_BYTE_LIMIT) returns pure TSV with no sentinel."""
    with patch("mcp_xdr._client.run_hunting_query_raw", new=AsyncMock(return_value=_make_api_result(5))):
        contents = await run_hunting_query("DeviceEvents | take 5")

    text = contents[0].text
    lines = text.splitlines()

    assert lines[0] == "LineNum\tLoremIpsum"
    data_lines = [l for l in lines[1:] if l]
    for line in data_lines:
        assert line.count("\t") == 1, f"Expected 1 tab in: {line!r}"
    assert not any("[MCP-XDR:OVERFLOW]" in l for l in lines)
    assert len(data_lines) == 5


@pytest.mark.asyncio
async def test_run_hunting_query_large_result_overflow():
    """Large result set (>INLINE_BYTE_LIMIT) emits inline rows, sentinel, and last row; writes full_results_file."""
    num_rows = 300
    with patch("mcp_xdr._client.run_hunting_query_raw", new=AsyncMock(return_value=_make_api_result(num_rows))):
        contents = await run_hunting_query("DeviceEvents | take 300")

    text = contents[0].text
    lines = text.splitlines()

    assert lines[0] == "LineNum\tLoremIpsum"

    sentinel_lines = [l for l in lines if l.startswith("[MCP-XDR:OVERFLOW]")]
    assert len(sentinel_lines) == 1
    sentinel = sentinel_lines[0]

    rows_shown = int(re.search(r"rows_shown=(\d+)", sentinel).group(1))  # type: ignore[union-attr]
    rows_omitted = int(re.search(r"rows_omitted=(\d+)", sentinel).group(1))  # type: ignore[union-attr]
    rows_total = int(re.search(r"rows_total=(\d+)", sentinel).group(1))  # type: ignore[union-attr]
    tmp_path = re.search(r"full_results_file=(\S+)", sentinel).group(1)  # type: ignore[union-attr]

    assert rows_total == num_rows
    assert rows_shown + rows_omitted + 1 == rows_total
    assert rows_shown >= 1

    last_line = lines[-1]
    assert last_line.count("\t") == 1

    inline_lines = lines[: lines.index(sentinel)]
    inline_bytes = sum(len((l + "\n").encode()) for l in inline_lines)
    assert inline_bytes <= INLINE_BYTE_LIMIT

    try:
        assert os.path.exists(tmp_path), f"full_results_file not found: {tmp_path}"
        with open(tmp_path, encoding="utf-8") as f:
            file_lines = f.read().splitlines()
        assert len(file_lines) == num_rows + 1  # header + data rows
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ── run_sentinel_query overflow tests ────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_sentinel_query_small_result_no_overflow():
    """Sentinel small result set (<INLINE_BYTE_LIMIT) returns pure TSV with no overflow sentinel."""
    with patch("mcp_xdr._client.run_sentinel_query_raw", new=AsyncMock(return_value=_make_sentinel_api_result(5))):
        contents = await run_sentinel_query("SecurityAlert | take 5")

    text = contents[0].text
    lines = text.splitlines()

    assert lines[0] == "LineNum\tLoremIpsum"
    data_lines = [l for l in lines[1:] if l]
    for line in data_lines:
        assert line.count("\t") == 1, f"Expected 1 tab in: {line!r}"
    assert not any("[MCP-XDR:OVERFLOW]" in l for l in lines)
    assert len(data_lines) == 5


@pytest.mark.asyncio
async def test_run_sentinel_query_large_result_overflow():
    """Sentinel large result set (>INLINE_BYTE_LIMIT) emits overflow sentinel + full_results_file."""
    num_rows = 300
    with patch("mcp_xdr._client.run_sentinel_query_raw", new=AsyncMock(return_value=_make_sentinel_api_result(num_rows))):
        contents = await run_sentinel_query("SecurityAlert | take 300")

    text = contents[0].text
    lines = text.splitlines()

    assert lines[0] == "LineNum\tLoremIpsum"

    sentinel_lines = [l for l in lines if l.startswith("[MCP-XDR:OVERFLOW]")]
    assert len(sentinel_lines) == 1
    sentinel = sentinel_lines[0]

    rows_shown = int(re.search(r"rows_shown=(\d+)", sentinel).group(1))  # type: ignore[union-attr]
    rows_omitted = int(re.search(r"rows_omitted=(\d+)", sentinel).group(1))  # type: ignore[union-attr]
    rows_total = int(re.search(r"rows_total=(\d+)", sentinel).group(1))  # type: ignore[union-attr]
    tmp_path = re.search(r"full_results_file=(\S+)", sentinel).group(1)  # type: ignore[union-attr]

    assert rows_total == num_rows
    assert rows_shown + rows_omitted + 1 == rows_total
    assert rows_shown >= 1

    inline_lines = lines[: lines.index(sentinel)]
    inline_bytes = sum(len((l + "\n").encode()) for l in inline_lines)
    assert inline_bytes <= INLINE_BYTE_LIMIT

    try:
        assert os.path.exists(tmp_path), f"full_results_file not found: {tmp_path}"
        with open(tmp_path, encoding="utf-8") as f:
            file_lines = f.read().splitlines()
        assert len(file_lines) == num_rows + 1
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ── get_schema listing mode tests ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_alltables_defender_only():
    """Listing mode with no Sentinel: TSV shows Defender=yes, Sentinel=-, empty activity cols."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        def_result = _make_defender_tables_result("AlertInfo", "DeviceEvents")
        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=AsyncMock(return_value=def_result)):
                contents = await get_schema(None)
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    lines = text.splitlines()
    assert lines[0] == "Table\tDefender\tSentinel\tSentinelLastSeen\tSentinelSolution"
    rows = {l.split("\t")[0]: l.split("\t") for l in lines[1:] if l}
    assert rows["AlertInfo"][1] == "yes"
    assert rows["AlertInfo"][2] == "-"
    assert rows["AlertInfo"][3] == ""
    assert rows["DeviceEvents"][1] == "yes"


@pytest.mark.asyncio
async def test_get_alltables_both_sources():
    """Listing mode with Sentinel: merged table list with yes/- and LastSeen from Usage."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = "fake-ws"
    try:
        sen_usage = _make_sentinel_usage_result(
            ("AlertInfo", "2026-04-15T21:00:00Z"),
            ("SentinelOnly", "2026-04-16T01:00:00Z"),
        )

        def_result = _make_defender_tables_result("AlertInfo", "DefenderOnly")
        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=AsyncMock(return_value=def_result)):
                with patch("mcp_xdr._client.run_sentinel_query_raw", new=AsyncMock(return_value=sen_usage)):
                    contents = await get_schema(None)
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    lines = text.splitlines()
    assert lines[0] == "Table\tDefender\tSentinel\tSentinelLastSeen\tSentinelSolution"
    rows = {l.split("\t")[0]: l.split("\t") for l in lines[1:] if l}

    assert rows["AlertInfo"][1] == "yes"
    assert rows["AlertInfo"][2] == "yes"
    assert rows["AlertInfo"][3] == "2026-04-15T21:00:00Z"

    assert rows["DefenderOnly"][1] == "yes"
    assert rows["DefenderOnly"][2] == "-"
    assert rows["DefenderOnly"][3] == ""

    assert rows["SentinelOnly"][1] == "-"
    assert rows["SentinelOnly"][2] == "yes"
    assert rows["SentinelOnly"][3] == "2026-04-16T01:00:00Z"


@pytest.mark.asyncio
async def test_get_alltables_usage_failure_graceful():
    """If Usage query fails, Sentinel tables are absent; Defender tables still show."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = "fake-ws"
    try:
        def_result = _make_defender_tables_result("AlertInfo")
        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=AsyncMock(return_value=def_result)):
                with patch("mcp_xdr._client.run_sentinel_query_raw", side_effect=Exception("Usage table unavailable")):
                    contents = await get_schema(None)
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    lines = text.splitlines()
    assert lines[0] == "Table\tDefender\tSentinel\tSentinelLastSeen\tSentinelSolution"
    rows = {l.split("\t")[0]: l.split("\t") for l in lines[1:] if l and not l.startswith("[")}
    assert rows["AlertInfo"][1] == "yes"
    assert rows["AlertInfo"][2] == "-"   # Sentinel failed → not in sen_tables
    assert rows["AlertInfo"][3] == ""    # no LastSeen


# ── get_schema per-table mode tests ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_schema_table_defender():
    """Per-table mode: Defender schema + sample rows returned and formatted correctly."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        getschema_result = _make_getschema_hunting_result(
            ("Timestamp", "datetime"), ("DeviceId", "string")
        )
        sample_result = {
            "schema": [{"name": "Timestamp", "type": "datetime"}, {"name": "DeviceId", "type": "string"}],
            "results": [{"Timestamp": "2026-04-16T10:00:00Z", "DeviceId": "abc123"}],
            "stats": {},
        }

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return getschema_result
            return sample_result

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                contents = await get_schema("DeviceEvents")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    assert "Schema for DeviceEvents" in text
    assert "DefenderType" in text
    assert "SentinelType" in text
    assert "Timestamp" in text
    assert "datetime" in text
    assert "Sample rows from DeviceEvents (Defender)" in text
    assert "abc123" in text


@pytest.mark.asyncio
async def test_get_schema_table_not_found():
    """Per-table mode: empty getschema + empty take3 → 'not found' message."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        empty = {"schema": [], "results": [], "stats": {}}
        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=AsyncMock(return_value=empty)):
                contents = await get_schema("NonExistentTable")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    assert "not found" in text.lower() or "no schema" in text.lower()



@pytest.mark.asyncio
async def test_get_schema_table_both_sources_merged():
    """Per-table mode with both sources: merged single table, N/A for source-exclusive columns."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = "fake-ws"
    try:
        def_schema = _make_getschema_hunting_result(
            ("Timestamp", "datetime"), ("DeviceId", "string"), ("DefenderOnly", "int")
        )
        sen_schema = _make_getschema_sentinel_result(
            ("Timestamp", "datetime"), ("DeviceId", "string"), ("SentinelOnly", "dynamic")
        )
        empty_sample = {"schema": [], "results": [], "stats": {}}
        empty_sen_sample = {"tables": [{"name": "PrimaryResult", "columns": [], "rows": []}]}

        async def mock_hunting(query: str) -> dict:
            return def_schema if "getschema" in query else empty_sample

        async def mock_sentinel(query: str) -> dict:
            return sen_schema if "getschema" in query else empty_sen_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                with patch("mcp_xdr._client.run_sentinel_query_raw", new=mock_sentinel):
                    contents = await get_schema("DeviceEvents")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    assert "DefenderType" in text
    assert "SentinelType" in text
    # Columns present in both show actual types
    assert "datetime" in text
    # Defender-only column: SentinelType should be N/A
    lines = {l.split()[0]: l for l in text.splitlines() if l.startswith("DefenderOnly")}
    assert lines, "DefenderOnly column missing from schema table"
    assert "N/A" in lines["DefenderOnly"]
    # Sentinel-only column: DefenderType should be N/A
    lines2 = {l.split()[0]: l for l in text.splitlines() if l.startswith("SentinelOnly")}
    assert lines2, "SentinelOnly column missing from schema table"
    assert "N/A" in lines2["SentinelOnly"]




# ── get_schema probe (Notes column) tests ────────────────────────────────────


def _make_shape_probe_hunting_result(*rows: tuple) -> dict:
    """Defender shape-probe response.

    Each row is either a 4-tuple (ColumnName, OuterTypes, ElemTypes, FirstKeys) — IsParsed
    defaults to False — or a 5-tuple (ColumnName, OuterTypes, ElemTypes, FirstKeys, IsParsed).
    """
    return {
        "schema": [
            {"name": "ColumnName", "type": "string"},
            {"name": "OuterTypes", "type": "string"},
            {"name": "ElemTypes", "type": "string"},
            {"name": "FirstKeys", "type": "string"},
            {"name": "IsParsed", "type": "bool"},
        ],
        "results": [
            {
                "ColumnName": r[0],
                "OuterTypes": r[1],
                "ElemTypes": r[2],
                "FirstKeys": r[3],
                "IsParsed": r[4] if len(r) >= 5 else False,
            }
            for r in rows
        ],
        "stats": {},
    }


def _make_enum_probe_hunting_result(*rows: tuple[str, str, int]) -> dict:
    """Defender enum-probe response. rows = (ColumnName, Value, Count)."""
    return {
        "schema": [
            {"name": "ColumnName", "type": "string"},
            {"name": "Value", "type": "string"},
            {"name": "Count", "type": "long"},
        ],
        "results": [{"ColumnName": cn, "Value": v, "Count": c} for cn, v, c in rows],
        "stats": {},
    }


def _make_dcount_probe_hunting_result(*rows: tuple[str, int]) -> dict:
    """Defender dcount-probe response. rows = (ColumnName, Distinct)."""
    return {
        "schema": [
            {"name": "ColumnName", "type": "string"},
            {"name": "Distinct", "type": "long"},
        ],
        "results": [{"ColumnName": cn, "Distinct": d} for cn, d in rows],
        "stats": {},
    }


def _make_dcount_probe_sentinel_result(*rows: tuple[str, int]) -> dict:
    """Sentinel dcount-probe response. rows = (ColumnName, Distinct)."""
    return {
        "tables": [{
            "name": "PrimaryResult",
            "columns": [
                {"name": "ColumnName", "type": "string"},
                {"name": "Distinct", "type": "long"},
            ],
            "rows": [[cn, d] for cn, d in rows],
        }],
    }


def _make_shape_probe_sentinel_result(*rows: tuple) -> dict:
    """Sentinel shape-probe response.

    Each row is either 4-tuple (no IsParsed → False) or 5-tuple (with IsParsed).
    """
    return {
        "tables": [{
            "name": "PrimaryResult",
            "columns": [
                {"name": "ColumnName", "type": "string"},
                {"name": "OuterTypes", "type": "string"},
                {"name": "ElemTypes", "type": "string"},
                {"name": "FirstKeys", "type": "string"},
                {"name": "IsParsed", "type": "bool"},
            ],
            "rows": [
                [r[0], r[1], r[2], r[3], r[4] if len(r) >= 5 else False]
                for r in rows
            ],
        }],
    }


def _parse_schema_row(text: str, col_name: str) -> list[str]:
    """Find the schema row for col_name in TSV output and return its tab-split fields."""
    for line in text.splitlines():
        parts = line.split("\t")
        if parts and parts[0] == col_name:
            return parts
    raise AssertionError(f"Column {col_name!r} not found in schema output:\n{text}")


@pytest.mark.asyncio
async def test_get_schema_table_emits_notes_column():
    """Schema TSV has a Notes column with enum lists for matching candidates."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        getschema_result = _make_getschema_hunting_result(
            ("Timestamp", "datetime"),
            ("JoinType", "string"),
        )
        empty_sample = {"schema": [], "results": [], "stats": {}}
        # JoinType has 3 distinct values, well under the 30-cap.
        dcount_result = _make_dcount_probe_hunting_result(("JoinType", 3))
        enum_result = _make_enum_probe_hunting_result(
            ("JoinType", "AAD Joined", 100),
            ("JoinType", "Hybrid Azure AD Join", 50),
            ("JoinType", "AAD Registered", 10),
        )
        # Shape probe has nothing useful for a string column with no JSON content.
        empty_shape = _make_shape_probe_hunting_result(("JoinType", "string", "", ""))

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return getschema_result
            if "summarize Distinct = dcount" in query:
                return dcount_result
            if "summarize Count = count() by Value" in query:
                return enum_result
            if "OuterTypes" in query:
                return empty_shape
            return empty_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                contents = await get_schema("DeviceInfo")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    # Header asserts new TSV format with Notes column.
    assert "ColumnName\tDefenderType\tSentinelType\tNotes" in text
    join_row = _parse_schema_row(text, "JoinType")
    assert join_row[1] == "string"
    notes = join_row[3]
    assert "enum:" in notes
    assert "AAD Joined" in notes
    assert "Hybrid Azure AD Join" in notes
    assert "AAD Registered" in notes


@pytest.mark.asyncio
async def test_get_schema_high_cardinality_enum_redacted():
    """Columns with > ENUM_PROBE_LIMIT distinct values yield a high-cardinality marker, not the value list."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        getschema_result = _make_getschema_hunting_result(("ActionType", "string"))
        empty_sample = {"schema": [], "results": [], "stats": {}}
        # dcount gate fires: 80 distinct → high-cardinality, no enum probe runs.
        dcount_result = _make_dcount_probe_hunting_result(("ActionType", 80))
        empty_shape = _make_shape_probe_hunting_result(("ActionType", "string", "", ""))
        enum_called = []

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return getschema_result
            if "summarize Distinct = dcount" in query:
                return dcount_result
            if "summarize Count = count() by Value" in query:
                # The dcount gate should have short-circuited this — record the call.
                enum_called.append(query)
                return _make_enum_probe_hunting_result()
            if "OuterTypes" in query:
                return empty_shape
            return empty_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                contents = await get_schema("DeviceEvents")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    action_row = _parse_schema_row(text, "ActionType")
    notes = action_row[3]
    assert "high-cardinality" in notes
    # Note now reports the actual distinct count (from dcount, not the value list).
    assert "80" in notes
    # Enum probe must not have run — dcount gate short-circuited it.
    assert enum_called == [], f"Enum probe ran despite high-cardinality dcount: {enum_called}"


@pytest.mark.asyncio
async def test_get_schema_string_dynamic_mismatch_uses_defender():
    """When DefenderType=string and SentinelType=dynamic, Notes recommend parse_json (Defender authoritative)."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = "fake-ws"
    try:
        # Same column, different types per source — the design-doc mismatch case.
        def_schema = _make_getschema_hunting_result(("AdditionalFields", "string"))
        sen_schema = _make_getschema_sentinel_result(("AdditionalFields", "dynamic"))
        empty_sample = {"schema": [], "results": [], "stats": {}}
        empty_sen_sample = {"tables": [{"name": "PrimaryResult", "columns": [], "rows": []}]}
        # Defender probe (string column wrapped in todynamic(tostring())) parses to a dict.
        def_shape = _make_shape_probe_hunting_result(("AdditionalFields", "dictionary", "", "", True))
        # Sentinel probe sees a dictionary cell directly. Should be ignored — Defender wins.
        sen_shape = _make_shape_probe_sentinel_result(("AdditionalFields", "dictionary", "", "", False))
        empty_enum = _make_enum_probe_hunting_result()

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return def_schema
            if "summarize Count = count() by Value" in query:
                return empty_enum
            if "OuterTypes" in query:
                return def_shape
            return empty_sample

        async def mock_sentinel(query: str) -> dict:
            if "getschema" in query:
                return sen_schema
            if "OuterTypes" in query:
                return sen_shape
            return empty_sen_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                with patch("mcp_xdr._client.run_sentinel_query_raw", new=mock_sentinel):
                    contents = await get_schema("DeviceProcessEvents")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    af_row = _parse_schema_row(text, "AdditionalFields")
    assert af_row[1] == "string"   # DefenderType
    assert af_row[2] == "dynamic"  # SentinelType
    notes = af_row[3]
    # Defender-authoritative rule: string-encoded JSON, agent applies parse_json
    # per kql-facts.md guidance.
    assert "string-encoded" in notes


@pytest.mark.asyncio
async def test_get_schema_probe_failure_falls_back_silently():
    """If the probe queries raise, schema still renders cleanly with empty Notes."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        getschema_result = _make_getschema_hunting_result(
            ("Timestamp", "datetime"),
            ("JoinType", "string"),
        )
        empty_sample = {"schema": [], "results": [], "stats": {}}

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return getschema_result
            if (
                "summarize Count = count() by Value" in query
                or "summarize Distinct = dcount" in query
                or "OuterTypes" in query
            ):
                raise RuntimeError("probe failed")
            return empty_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                contents = await get_schema("DeviceInfo")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    assert "ColumnName\tDefenderType\tSentinelType\tNotes" in text
    join_row = _parse_schema_row(text, "JoinType")
    assert join_row[1] == "string"
    # No notes — probe failures swallowed.
    assert join_row[3] == ""


@pytest.mark.asyncio
async def test_get_schema_dynamic_array_of_dict_emits_shape_note():
    """A dynamic column whose cells are arrays of dicts gets the array<dict> note."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        getschema_result = _make_getschema_hunting_result(("ActivityObjects", "dynamic"))
        empty_sample = {"schema": [], "results": [], "stats": {}}
        # OuterTypes=array, ElemTypes=dictionary  →  array<dict>
        shape_result = _make_shape_probe_hunting_result(("ActivityObjects", "array", "dictionary", ""))
        empty_enum = _make_enum_probe_hunting_result()

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return getschema_result
            if "summarize Count = count() by Value" in query:
                return empty_enum
            if "OuterTypes" in query:
                return shape_result
            return empty_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                contents = await get_schema("CloudAppEvents")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    row = _parse_schema_row(text, "ActivityObjects")
    assert row[1] == "dynamic"
    assert "array<dict>" in row[3]


@pytest.mark.asyncio
async def test_get_schema_dynamic_single_key_wrapper_note():
    """A dynamic column whose dictionary cells have a single bag_key emits the wrapper note."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        getschema_result = _make_getschema_hunting_result(("NodeProperties", "dynamic"))
        empty_sample = {"schema": [], "results": [], "stats": {}}
        shape_result = _make_shape_probe_hunting_result(
            ("NodeProperties", "dictionary", "", '["rawData"]')
        )
        empty_enum = _make_enum_probe_hunting_result()

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return getschema_result
            if "summarize Count = count() by Value" in query:
                return empty_enum
            if "OuterTypes" in query:
                return shape_result
            return empty_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                contents = await get_schema("ExposureGraphNodes")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    row = _parse_schema_row(text, "NodeProperties")
    assert row[1] == "dynamic"
    assert 'dict, bag_keys=["rawData"]' in row[3]


@pytest.mark.asyncio
async def test_get_schema_string_column_with_post_parse_shape_detail():
    """A string-typed column whose JSON parses to an array of dicts emits
    `string-encoded array<dict>` so the agent learns both the serialization
    rule AND what's inside without an extra round-trip.
    """
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        getschema_result = _make_getschema_hunting_result(("LoggedOnUsers", "string"))
        empty_sample = {"schema": [], "results": [], "stats": {}}
        # Probe ran via todynamic(tostring(col)); shape after parse is array<dict>.
        shape_result = _make_shape_probe_hunting_result(
            ("LoggedOnUsers", "array", "dictionary", "", True)
        )
        empty_enum = _make_enum_probe_hunting_result()

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return getschema_result
            if "summarize Count = count() by Value" in query:
                return empty_enum
            if "OuterTypes" in query:
                return shape_result
            return empty_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                contents = await get_schema("DeviceInfo")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    row = _parse_schema_row(text, "LoggedOnUsers")
    assert row[1] == "string"
    notes = row[3]
    # Shape fact: string-encoded array of dicts.
    assert "string-encoded array<dict>" in notes


@pytest.mark.asyncio
async def test_get_schema_string_column_with_single_key_wrapper_detail():
    """String-typed JSON dict with a single bag-key emits
    `string-encoded dict, bag_keys=["…"]`. Useful when a string column
    wraps its real payload behind one key (rare but possible).
    """
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        getschema_result = _make_getschema_hunting_result(("WrappedField", "string"))
        empty_sample = {"schema": [], "results": [], "stats": {}}
        shape_result = _make_shape_probe_hunting_result(
            ("WrappedField", "dictionary", "", '["rawData"]', True)
        )
        empty_enum = _make_enum_probe_hunting_result()

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return getschema_result
            if "summarize Count = count() by Value" in query:
                return empty_enum
            if "OuterTypes" in query:
                return shape_result
            return empty_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                contents = await get_schema("AnyTable")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    row = _parse_schema_row(text, "WrappedField")
    assert row[1] == "string"
    notes = row[3]
    assert 'string-encoded dict, bag_keys=["rawData"]' in notes


@pytest.mark.asyncio
async def test_get_schema_dynamic_column_no_parse_json_headline():
    """Dynamic-typed columns must NEVER emit parse_json(tostring()) — direct access works."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        getschema_result = _make_getschema_hunting_result(("RawEventData", "dynamic"))
        empty_sample = {"schema": [], "results": [], "stats": {}}
        # Probed directly (not wrapped) — IsParsed=False.
        shape_result = _make_shape_probe_hunting_result(
            ("RawEventData", "dictionary", "", "", False)
        )
        empty_enum = _make_enum_probe_hunting_result()

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return getschema_result
            if "summarize Count = count() by Value" in query:
                return empty_enum
            if "OuterTypes" in query:
                return shape_result
            return empty_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                contents = await get_schema("CloudAppEvents")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    row = _parse_schema_row(text, "RawEventData")
    assert row[1] == "dynamic"
    # Dynamic columns never get a parse_json/string-encoded note — direct
    # .Field access works. Multi-key dict surfaces as the bare `dict` fact.
    assert "parse_json" not in row[3]
    assert "string-encoded" not in row[3]
    assert row[3] == "dict"


@pytest.mark.asyncio
async def test_get_schema_plain_string_column_emits_no_parse_json_note():
    """A string column whose cells are plain strings (not JSON) gets NO note —
    todynamic(tostring("DEVICE-001")) parses to a string scalar, which is a
    false-positive trigger we must filter out.
    """
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        getschema_result = _make_getschema_hunting_result(("DeviceName", "string"))
        empty_sample = {"schema": [], "results": [], "stats": {}}
        # Probe via todynamic(tostring()) on a plain-string column → OuterTypes="string".
        # No parse advice should be emitted.
        shape_result = _make_shape_probe_hunting_result(
            ("DeviceName", "string", "", "", True)
        )
        empty_enum = _make_enum_probe_hunting_result()

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return getschema_result
            if "summarize Count = count() by Value" in query:
                return empty_enum
            if "OuterTypes" in query:
                return shape_result
            return empty_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                contents = await get_schema("DeviceInfo")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    row = _parse_schema_row(text, "DeviceName")
    assert row[1] == "string"
    # No note — the column doesn't contain JSON.
    assert row[3] == ""


@pytest.mark.asyncio
async def test_get_schema_dcount_gate_filters_per_column():
    """Two enum candidates: one low-cardinality (enumerated), one high (skipped).

    The enum probe should run for the low-cardinality column ONLY. The high-
    cardinality column gets its note from the dcount alone with the actual
    distinct count.
    """
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        getschema_result = _make_getschema_hunting_result(
            ("JoinType", "string"),
            ("ActionType", "string"),
        )
        empty_sample = {"schema": [], "results": [], "stats": {}}
        # JoinType = 3 distinct (enumerate), ActionType = 80 distinct (skip enum).
        dcount_result = _make_dcount_probe_hunting_result(
            ("JoinType", 3),
            ("ActionType", 80),
        )
        # Enum probe should run for JoinType only — the mock asserts that.
        enum_result = _make_enum_probe_hunting_result(
            ("JoinType", "AAD Joined", 100),
            ("JoinType", "Hybrid", 50),
            ("JoinType", "AAD Registered", 10),
        )
        empty_shape = _make_shape_probe_hunting_result(
            ("JoinType", "string", "", ""),
            ("ActionType", "string", "", ""),
        )
        enum_queries: list[str] = []

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return getschema_result
            if "summarize Distinct = dcount" in query:
                return dcount_result
            if "summarize Count = count() by Value" in query:
                enum_queries.append(query)
                return enum_result
            if "OuterTypes" in query:
                return empty_shape
            return empty_sample

        with patch("mcp_xdr._cache.cache_get", side_effect=_cache_passthrough):
            with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
                contents = await get_schema("DeviceInfo")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    join_row = _parse_schema_row(text, "JoinType")
    action_row = _parse_schema_row(text, "ActionType")
    # Low-cardinality column: full enum.
    assert "AAD Joined" in join_row[3]
    assert "high-cardinality" not in join_row[3]
    # High-cardinality column: dcount-derived note with the actual count.
    assert "high-cardinality" in action_row[3]
    assert "80" in action_row[3]
    assert "AAD Joined" not in action_row[3]
    # Enum probe ran exactly once and only for JoinType.
    assert len(enum_queries) == 1
    assert "JoinType" in enum_queries[0]
    assert "ActionType" not in enum_queries[0]


def test_build_dcount_probe_kql():
    """dcount probe builder emits one summarize per column, all unioned."""
    from mcp_xdr._tools_schema import _build_dcount_probe_kql
    kql = _build_dcount_probe_kql("DeviceInfo", ["JoinType", "OnboardingStatus"])
    assert "union " in kql
    assert "summarize Distinct = dcount(tostring(JoinType))" in kql
    assert "summarize Distinct = dcount(tostring(OnboardingStatus))" in kql
    # Sample size = ENUM_PROBE_SAMPLE_ROWS (the larger budget).
    assert f"take {cfg.ENUM_PROBE_SAMPLE_ROWS}" in kql
    # No columns → empty.
    assert _build_dcount_probe_kql("AnyTable", []) == ""


def test_build_shape_probe_kql_splits_by_type():
    """Builder produces todynamic(tostring()) wrap for string cols, no wrap for dynamic cols."""
    from mcp_xdr._tools_schema import _build_shape_probe_kql
    kql = _build_shape_probe_kql("DeviceInfo", ["RawDyn"], ["RawStr"])
    # Dynamic column accessed directly — bag_keys(RawDyn), not bag_keys(_v).
    assert "bag_keys(RawDyn)" in kql
    assert "todynamic(tostring(RawDyn))" not in kql
    # String column wrapped — bag_keys(_v) with a prior `_v = todynamic(tostring(RawStr))`.
    assert "todynamic(tostring(RawStr))" in kql
    assert "bag_keys(_v)" in kql
    # Both branches mark IsParsed correctly.
    assert "IsParsed = false" in kql
    assert "IsParsed = true" in kql


def test_build_shape_probe_kql_no_columns_returns_empty():
    """No candidates → empty KQL (caller will skip the round-trip)."""
    from mcp_xdr._tools_schema import _build_shape_probe_kql
    assert _build_shape_probe_kql("AnyTable", [], []) == ""


# ── Probe candidate filter tests ──────────────────────────────────────────────


def test_enum_candidate_regex():
    """*Type/Status/etc. names match; data-id-style names don't."""
    from mcp_xdr._tools_schema import _is_enum_candidate
    assert _is_enum_candidate("JoinType", "string", "string")
    assert _is_enum_candidate("OnboardingStatus", "string", "N/A")
    assert _is_enum_candidate("ActionType", "string", "string")
    assert _is_enum_candidate("Severity", "string", "N/A")
    assert _is_enum_candidate("ConnectivityType", "string", "N/A")
    # Not a name match
    assert not _is_enum_candidate("DeviceId", "string", "string")
    assert not _is_enum_candidate("Timestamp", "datetime", "datetime")
    assert not _is_enum_candidate("AccountUpn", "string", "string")
    # Name matches but type isn't string/int/long
    assert not _is_enum_candidate("JoinType", "datetime", "datetime")
    assert not _is_enum_candidate("JoinType", "dynamic", "dynamic")


def test_shape_candidate_filter():
    """Only string and dynamic columns are worth probing for cell shape."""
    from mcp_xdr._tools_schema import _is_shape_candidate
    assert _is_shape_candidate("string", "string")
    assert _is_shape_candidate("dynamic", "N/A")
    assert _is_shape_candidate("string", "dynamic")
    assert not _is_shape_candidate("datetime", "datetime")
    assert not _is_shape_candidate("int", "long")
    assert not _is_shape_candidate("real", "decimal")


def test_cell_str_dynamic_column():
    """_cell_str serializes dict/list as JSON, not Python repr."""
    from mcp_xdr._output import _cell_str
    assert _cell_str(None) == ""
    assert _cell_str("plain") == "plain"
    assert _cell_str(42) == "42"
    assert _cell_str({"a": 1}) == '{"a": 1}'
    assert _cell_str([{"$kind": "foo"}]) == '[{"$kind": "foo"}]'
    # Ensure no Python repr artifacts
    assert "'" not in _cell_str({"key": "value"})
    assert "True" not in _cell_str({"flag": True})
    assert '"flag": true' in _cell_str({"flag": True})


def test_truncate_cell_type_hints():
    """_truncate_cell depth-reduces JSON with type-accurate placeholders."""
    from mcp_xdr._tools_schema import _truncate_cell
    import json

    # Small value: pass through unchanged
    assert _truncate_cell("hello") == "hello"

    # Dict: depth-1 shows keys with type-accurate stubs
    # full=48 chars, depth-1=41 chars — limit=45 triggers reduction without hard-cutting
    big_dict = json.dumps({"a": {"nested": 1}, "b": [1, 2], "c": "scalar", "d": 42})
    result = json.loads(_truncate_cell(big_dict, limit=45).rstrip("…"))
    assert result["a"] == "{…}"
    assert result["b"] == "[…]"
    assert result["c"] == "scalar"
    assert result["d"] == 42

    # List: shows first element + count hint, not ["…"]
    # full=25 chars, depth-1=20 chars — limit=22 triggers reduction
    big_list = json.dumps(["item1", "item2", "item3"])
    result = _truncate_cell(big_list, limit=22)
    assert "…+2 more" in result

    # Non-JSON: plain truncation
    result = _truncate_cell("x" * 2000)
    assert len(result) <= 204  # 200 + ellipsis
    assert result.endswith("…")
