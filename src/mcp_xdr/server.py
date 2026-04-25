"""MCP server for Microsoft Defender Advanced Hunting and Microsoft Sentinel.

This module is wire-up only: it owns the MCP Server object, the tool registry,
and the entry point. All business logic lives in the _tools_* modules.

See CLAUDE.md for architecture overview and auth details.
"""

import asyncio
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

import mcp_xdr._config as _config
from mcp_xdr._tools_hunting import TOOL_DEFINITION as _D_HUNTING, run_hunting_query
from mcp_xdr._tools_sentinel import TOOL_DEFINITION as _D_SENTINEL, run_sentinel_query
from mcp_xdr._tools_schema import TOOL_DEFINITION as _D_SCHEMA, get_schema

# Re-export for backward-compat with tests and external callers
from mcp_xdr._config import INLINE_BYTE_LIMIT  # noqa: F401
from mcp_xdr._client import run_hunting_query_raw, run_sentinel_query_raw  # noqa: F401

server = Server("mcp-xdr")

# Tool registry: (Tool descriptor, async handler).
# Always-on tools:
_ALWAYS_TOOLS: list[tuple[Tool, Any]] = [
    (_D_HUNTING, lambda args: run_hunting_query(args["query"])),
    (_D_SCHEMA,  lambda args: get_schema(args.get("table_name"), args.get("source"))),
]
# Sentinel tool — only registered when workspace ID is configured:
_SENTINEL_TOOLS: list[tuple[Tool, Any]] = [
    (_D_SENTINEL, lambda args: run_sentinel_query(args["query"])),
]


@server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
async def list_tools() -> list[Tool]:
    tools = [tool_def for tool_def, _ in _ALWAYS_TOOLS]
    if _config._sentinel_workspace_id:
        tools += [tool_def for tool_def, _ in _SENTINEL_TOOLS]
    return tools


@server.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    active = _ALWAYS_TOOLS + (_SENTINEL_TOOLS if _config._sentinel_workspace_id else [])
    for tool_def, handler in active:
        if tool_def.name == name:
            return await handler(arguments)
    return [TextContent(type="text", text=f"Unknown tool: {name}")]


def main() -> None:
    asyncio.run(run_server())


async def run_server() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    main()
