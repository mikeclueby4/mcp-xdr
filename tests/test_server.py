"""Tests for the MCP Defender Advanced Hunting server."""

import os
import re
from unittest.mock import AsyncMock, patch

import pytest

import mcp_xdr._config as cfg
from mcp_xdr.server import INLINE_BYTE_LIMIT, list_tools, run_hunting_query, run_sentinel_query, get_schema

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


def _make_tables_hunting_result(*table_names: str) -> dict:
    """Defender response for `search * | distinct $table`."""
    return {
        "schema": [{"name": "$table", "type": "string"}],
        "results": [{"$table": t} for t in sorted(table_names)],
        "stats": {},
    }


def _make_tables_sentinel_result(*table_names: str) -> dict:
    """Sentinel response for `search * | distinct $table`."""
    return {
        "tables": [{
            "name": "PrimaryResult",
            "columns": [{"name": "$table", "type": "string"}],
            "rows": [[t] for t in sorted(table_names)],
        }],
    }


def _make_sentinel_usage_result(*entries: tuple[str, str, float]) -> dict:
    """Sentinel Usage query response. entries = (DataType, LastSeen, TotalMB)."""
    return {
        "tables": [{
            "name": "PrimaryResult",
            "columns": [
                {"name": "DataType", "type": "string"},
                {"name": "LastSeen", "type": "datetime"},
                {"name": "TotalMB", "type": "real"},
            ],
            "rows": [[dt, ls, mb] for dt, ls, mb in entries],
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
    """Test that get_schema has correct input schema with table_name and source."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        tools = await list_tools()
        schema_tool = next(t for t in tools if t.name == "get_schema")
        assert schema_tool.inputSchema["required"] == []
        assert "table_name" in schema_tool.inputSchema["properties"]
        assert "source" in schema_tool.inputSchema["properties"]
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
async def test_get_schema_listing_defender_only():
    """Listing mode with no Sentinel: TSV shows Defender=yes, Sentinel=-, empty activity cols."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        mock_tables = _make_tables_hunting_result("AlertInfo", "DeviceEvents")
        with patch("mcp_xdr._client.run_hunting_query_raw", new=AsyncMock(return_value=mock_tables)):
            contents = await get_schema(None, None)
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    lines = text.splitlines()
    assert lines[0] == "Table\tDefender\tSentinel\tSentinelLastSeen\tSentinelMB"
    rows = {l.split("\t")[0]: l.split("\t") for l in lines[1:] if l}
    assert rows["AlertInfo"][1] == "yes"
    assert rows["AlertInfo"][2] == "-"
    assert rows["AlertInfo"][3] == ""
    assert rows["AlertInfo"][4] == ""
    assert rows["DeviceEvents"][1] == "yes"


@pytest.mark.asyncio
async def test_get_schema_listing_both_sources():
    """Listing mode with Sentinel: merged table list with yes/- and LastSeen/MB from Usage."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = "fake-ws"
    try:
        def_tables = _make_tables_hunting_result("AlertInfo", "DefenderOnly")
        sen_tables = _make_tables_sentinel_result("AlertInfo", "SentinelOnly")
        sen_usage = _make_sentinel_usage_result(
            ("AlertInfo", "2026-04-15T21:00:00Z", 40.32),
            ("SentinelOnly", "2026-04-16T01:00:00Z", 1234.5),
        )

        sentinel_call_count = 0

        async def mock_hunting(query: str) -> dict:
            return def_tables

        async def mock_sentinel(query: str) -> dict:
            nonlocal sentinel_call_count
            sentinel_call_count += 1
            if "Usage" in query:
                return sen_usage
            return sen_tables

        with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
            with patch("mcp_xdr._client.run_sentinel_query_raw", new=mock_sentinel):
                contents = await get_schema(None, None)
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    lines = text.splitlines()
    assert lines[0] == "Table\tDefender\tSentinel\tSentinelLastSeen\tSentinelMB"
    rows = {l.split("\t")[0]: l.split("\t") for l in lines[1:] if l}

    assert rows["AlertInfo"][1] == "yes"
    assert rows["AlertInfo"][2] == "yes"
    assert rows["AlertInfo"][3] == "2026-04-15T21:00:00Z"
    assert rows["AlertInfo"][4] == "40.32"

    assert rows["DefenderOnly"][1] == "yes"
    assert rows["DefenderOnly"][2] == "-"
    assert rows["DefenderOnly"][3] == ""

    assert rows["SentinelOnly"][1] == "-"
    assert rows["SentinelOnly"][2] == "yes"
    assert rows["SentinelOnly"][3] == "2026-04-16T01:00:00Z"
    assert rows["SentinelOnly"][4] == "1234.50"


@pytest.mark.asyncio
async def test_get_schema_listing_usage_failure_graceful():
    """If Usage query fails, table list still returns with empty activity columns."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = "fake-ws"
    try:
        def_tables = _make_tables_hunting_result("AlertInfo")
        sen_tables = _make_tables_sentinel_result("AlertInfo")

        async def mock_hunting(query: str) -> dict:
            return def_tables

        async def mock_sentinel(query: str) -> dict:
            if "Usage" in query:
                raise Exception("Usage table unavailable")
            return sen_tables

        with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
            with patch("mcp_xdr._client.run_sentinel_query_raw", new=mock_sentinel):
                contents = await get_schema(None, None)
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    lines = text.splitlines()
    assert lines[0] == "Table\tDefender\tSentinel\tSentinelLastSeen\tSentinelMB"
    assert lines[1] == "[MCP-XDR:BLANK-COLS] always_empty=SentinelLastSeen, SentinelMB"
    row = lines[2].split("\t")
    assert row[0] == "AlertInfo"
    assert row[3] == ""   # SentinelLastSeen empty due to failure
    assert row[4] == ""   # SentinelMB empty due to failure


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

        with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
            contents = await get_schema("DeviceEvents", None)
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    assert "Schema for DeviceEvents (Defender)" in text
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
        with patch("mcp_xdr._client.run_hunting_query_raw", new=AsyncMock(return_value=empty)):
            contents = await get_schema("NonExistentTable", None)
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    assert "not found" in text.lower() or "no schema" in text.lower()


@pytest.mark.asyncio
async def test_get_schema_table_defender_api_schema_fallback():
    """Per-table mode: getschema empty but take3 has schema field → fallback to API schema."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        empty_getschema = {"schema": [], "results": [], "stats": {}}
        sample_with_schema = {
            "schema": [{"name": "Timestamp", "type": "datetime"}, {"name": "DeviceId", "type": "string"}],
            "results": [],
            "stats": {},
        }

        async def mock_hunting(query: str) -> dict:
            if "getschema" in query:
                return empty_getschema
            return sample_with_schema

        with patch("mcp_xdr._client.run_hunting_query_raw", new=mock_hunting):
            contents = await get_schema("DeviceEvents", "defender")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    assert "Timestamp" in text
    assert "datetime" in text
    assert "API metadata" in text  # fallback note


@pytest.mark.asyncio
async def test_get_schema_source_sentinel_not_configured():
    """source='sentinel' with no workspace ID returns an error."""
    original = cfg._sentinel_workspace_id
    cfg._sentinel_workspace_id = None
    try:
        contents = await get_schema(None, "sentinel")
    finally:
        cfg._sentinel_workspace_id = original

    text = contents[0].text
    assert "SENTINEL_WORKSPACE_ID" in text
    assert "Error" in text


@pytest.mark.asyncio
async def test_get_schema_invalid_source():
    """Invalid source value returns a clear error message."""
    contents = await get_schema(None, "invalid_source")
    text = contents[0].text
    assert "Invalid source" in text
    assert "defender" in text
    assert "sentinel" in text
