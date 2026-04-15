"""Tests for the MCP Defender Advanced Hunting server."""

import os
import re
from unittest.mock import AsyncMock, patch

import pytest

from mcp_xdr.server import INLINE_BYTE_LIMIT, list_tools, run_hunting_query, run_sentinel_query

# Synthetic lorem text (~60 chars) used to bulk up rows for overflow tests
_LOREM = "Lorem ipsum dolor sit amet, consectetur adipiscing elit pad"

SCHEMA = [{"Name": "LineNum"}, {"Name": "LoremIpsum"}]


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


@pytest.mark.asyncio
async def test_list_tools_without_sentinel_workspace():
    """Without SENTINEL_WORKSPACE_ID, only 2 tools are exposed."""
    with patch.dict(os.environ, {}, clear=False):
        # Ensure the module-level variable sees no workspace ID by reloading
        import mcp_xdr.server as srv
        original = srv._sentinel_workspace_id
        srv._sentinel_workspace_id = None
        try:
            tools = await list_tools()
            tool_names = [t.name for t in tools]
            assert "run_hunting_query" in tool_names
            assert "get_hunting_schema" in tool_names
            assert "run_sentinel_query" not in tool_names
            assert "get_sentinel_tables" not in tool_names
            assert len(tools) == 2
        finally:
            srv._sentinel_workspace_id = original


@pytest.mark.asyncio
async def test_list_tools_with_sentinel_workspace():
    """With SENTINEL_WORKSPACE_ID set, 4 tools are exposed."""
    import mcp_xdr.server as srv
    original = srv._sentinel_workspace_id
    srv._sentinel_workspace_id = "fake-workspace-id"
    try:
        tools = await list_tools()
        tool_names = [t.name for t in tools]
        assert "run_hunting_query" in tool_names
        assert "get_hunting_schema" in tool_names
        assert "run_sentinel_query" in tool_names
        assert "get_sentinel_tables" in tool_names
        assert len(tools) == 4
        # Should NOT have alerts/incidents tools
        assert "list_incidents" not in tool_names
        assert "list_alerts" not in tool_names
    finally:
        srv._sentinel_workspace_id = original


@pytest.mark.asyncio
async def test_run_hunting_query_tool_schema():
    """Test that run_hunting_query has correct input schema."""
    import mcp_xdr.server as srv
    original = srv._sentinel_workspace_id
    srv._sentinel_workspace_id = None
    try:
        tools = await list_tools()
        query_tool = next(t for t in tools if t.name == "run_hunting_query")
        assert query_tool.inputSchema["required"] == ["query"]
        assert "query" in query_tool.inputSchema["properties"]
    finally:
        srv._sentinel_workspace_id = original


@pytest.mark.asyncio
async def test_get_hunting_schema_tool_schema():
    """Test that get_hunting_schema has correct input schema."""
    import mcp_xdr.server as srv
    original = srv._sentinel_workspace_id
    srv._sentinel_workspace_id = None
    try:
        tools = await list_tools()
        schema_tool = next(t for t in tools if t.name == "get_hunting_schema")
        assert schema_tool.inputSchema["required"] == []
        assert "table_name" in schema_tool.inputSchema["properties"]
    finally:
        srv._sentinel_workspace_id = original


@pytest.mark.asyncio
async def test_run_hunting_query_small_result_no_overflow():
    """Small result set (<INLINE_BYTE_LIMIT) returns pure TSV with no sentinel."""
    with patch("mcp_xdr.server.run_hunting_query_raw", new=AsyncMock(return_value=_make_api_result(5))):
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
    with patch("mcp_xdr.server.run_hunting_query_raw", new=AsyncMock(return_value=_make_api_result(num_rows))):
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


@pytest.mark.asyncio
async def test_run_sentinel_query_small_result_no_overflow():
    """Sentinel small result set (<INLINE_BYTE_LIMIT) returns pure TSV with no overflow sentinel."""
    with patch("mcp_xdr.server.run_sentinel_query_raw", new=AsyncMock(return_value=_make_sentinel_api_result(5))):
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
    with patch("mcp_xdr.server.run_sentinel_query_raw", new=AsyncMock(return_value=_make_sentinel_api_result(num_rows))):
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
