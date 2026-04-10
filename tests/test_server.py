"""Tests for the MCP Defender Advanced Hunting server."""

import os
import re
from unittest.mock import AsyncMock, patch

import pytest

from mcp_defender.server import INLINE_BYTE_LIMIT, list_tools, run_hunting_query

# Synthetic lorem text (~60 chars) used to bulk up rows for overflow tests
_LOREM = "Lorem ipsum dolor sit amet, consectetur adipiscing elit pad"

SCHEMA = [{"Name": "LineNum"}, {"Name": "LoremIpsum"}]


def _make_api_result(num_rows: int) -> dict:
    return {
        "Schema": SCHEMA,
        "Results": [{"LineNum": str(i), "LoremIpsum": _LOREM} for i in range(num_rows)],
        "Stats": {},
    }


@pytest.mark.asyncio
async def test_list_tools():
    """Test that only hunting tools are exposed."""
    tools = await list_tools()
    tool_names = [t.name for t in tools]

    # Should only have hunting-focused tools
    assert "run_hunting_query" in tool_names
    assert "get_hunting_schema" in tool_names

    # Should NOT have alerts/incidents (moved to streaming pipeline)
    assert "list_incidents" not in tool_names
    assert "get_incident" not in tool_names
    assert "list_alerts" not in tool_names

    # Should only be 2 tools
    assert len(tools) == 2


@pytest.mark.asyncio
async def test_run_hunting_query_tool_schema():
    """Test that run_hunting_query has correct input schema."""
    tools = await list_tools()
    query_tool = next(t for t in tools if t.name == "run_hunting_query")

    assert query_tool.inputSchema["required"] == ["query"]
    assert "query" in query_tool.inputSchema["properties"]


@pytest.mark.asyncio
async def test_get_hunting_schema_tool_schema():
    """Test that get_hunting_schema has correct input schema."""
    tools = await list_tools()
    schema_tool = next(t for t in tools if t.name == "get_hunting_schema")

    # table_name is optional
    assert schema_tool.inputSchema["required"] == []
    assert "table_name" in schema_tool.inputSchema["properties"]


@pytest.mark.asyncio
async def test_run_hunting_query_small_result_no_overflow():
    """Small result set (<10 KB) returns pure TSV with no sentinel."""
    with patch("mcp_defender.server.run_defender_query", new=AsyncMock(return_value=_make_api_result(5))):
        contents = await run_hunting_query("DeviceEvents | take 5")

    text = contents[0].text
    lines = text.splitlines()

    # Header is TSV
    assert lines[0] == "LineNum\tLoremIpsum"
    # All data lines are TSV (exactly one tab each)
    data_lines = [l for l in lines[1:] if l and not l.startswith("execution_time=")]
    for line in data_lines:
        assert line.count("\t") == 1, f"Expected 1 tab in: {line!r}"
    # No overflow sentinel
    assert not any("[MCP-DEFENDER:OVERFLOW]" in l for l in lines)
    # 5 data rows present
    assert len(data_lines) == 5


@pytest.mark.asyncio
async def test_run_hunting_query_large_result_overflow():
    """Large result set (>10 KB) emits inline rows, sentinel, and last row; writes tmpfile."""
    num_rows = 300  # ~300 * ~75 bytes ≈ 22 KB — well over the 10 KB limit
    with patch("mcp_defender.server.run_defender_query", new=AsyncMock(return_value=_make_api_result(num_rows))):
        contents = await run_hunting_query("DeviceEvents | take 300")

    text = contents[0].text
    lines = text.splitlines()

    # Header must be first line
    assert lines[0] == "LineNum\tLoremIpsum"

    # Find sentinel line
    sentinel_lines = [l for l in lines if l.startswith("[MCP-DEFENDER:OVERFLOW]")]
    assert len(sentinel_lines) == 1, "Expected exactly one sentinel line"
    sentinel = sentinel_lines[0]

    # Parse sentinel fields
    rows_shown = int(re.search(r"rows_shown=(\d+)", sentinel).group(1))  # type: ignore[union-attr]
    rows_omitted = int(re.search(r"rows_omitted=(\d+)", sentinel).group(1))  # type: ignore[union-attr]
    rows_total = int(re.search(r"rows_total=(\d+)", sentinel).group(1))  # type: ignore[union-attr]
    tmp_path = re.search(r"tmpfile=(\S+)", sentinel).group(1)  # type: ignore[union-attr]

    assert rows_total == num_rows
    assert rows_shown + rows_omitted + 1 == rows_total  # +1 for the last row shown after sentinel
    assert rows_shown >= 1

    # Last line (after sentinel) is a TSV data row
    last_line = lines[-1] if not lines[-1].startswith("execution_time=") else lines[-2]
    assert last_line.count("\t") == 1

    # Inline byte size of the shown rows must be ≤ INLINE_BYTE_LIMIT
    inline_lines = lines[: lines.index(sentinel)]
    inline_bytes = sum(len((l + "\n").encode()) for l in inline_lines)
    assert inline_bytes <= INLINE_BYTE_LIMIT

    # tmpfile must exist and contain the full result
    try:
        assert os.path.exists(tmp_path), f"tmpfile not found: {tmp_path}"
        with open(tmp_path, encoding="utf-8") as f:
            file_lines = f.read().splitlines()
        assert len(file_lines) == num_rows + 1  # header + data rows
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
