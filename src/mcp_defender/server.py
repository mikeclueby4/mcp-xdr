"""MCP server for Microsoft Defender Advanced Hunting.

Uses the unified Microsoft 365 Defender API (api.security.microsoft.com) for
Advanced Hunting queries across all workloads (Device, Identity, Email,
Cloud App, and AI tables).
"""

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Any, cast

import truststore
truststore.inject_into_ssl()  # IMPORTANT: MUST be done BEFORE importing httpx or azure.identity

import httpx
from azure.identity import (
    AuthenticationRecord,
    CertificateCredential,
    ClientSecretCredential,
    InteractiveBrowserCredential,
    TokenCachePersistenceOptions,
)
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

load_dotenv()

server = Server("mcp-defender")

# Unified M365 Defender API endpoint (covers all workloads)
DEFENDER_API_BASE = "https://api.security.microsoft.com"
DEFENDER_SCOPE = "https://api.security.microsoft.com/.default"

_credential: CertificateCredential | ClientSecretCredential | InteractiveBrowserCredential | None = None


def get_credential() -> CertificateCredential | ClientSecretCredential | InteractiveBrowserCredential:
    """Get or create Azure credential.

    Priority:
    1. CertificateCredential   – if AZURE_CLIENT_CERTIFICATE_PATH is set (app auth, no user)
    2. ClientSecretCredential  – if AZURE_CLIENT_SECRET is set (app auth, no user)
    3. InteractiveBrowserCredential – if only AZURE_TENANT_ID + AZURE_CLIENT_ID are set
                                      (delegated/interactive, opens browser on first use)
    """
    global _credential
    if _credential is None:
        tenant_id = os.environ.get("AZURE_TENANT_ID")
        client_id = os.environ.get("AZURE_CLIENT_ID")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET")
        certificate_path = os.environ.get("AZURE_CLIENT_CERTIFICATE_PATH")
        certificate_password = os.environ.get("AZURE_CLIENT_CERTIFICATE_PASSWORD")

        if not tenant_id or not client_id:
            raise ValueError(
                "Missing Azure credentials. "
                "Set AZURE_TENANT_ID and AZURE_CLIENT_ID environment variables."
            )

        if certificate_path:
            _credential = CertificateCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                certificate_path=certificate_path,
                password=certificate_password,
            )
        elif client_secret:
            _credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            # Public client app: opens browser for interactive sign-in (auth code + PKCE).
            # Not blocked by the "Block device code flow" CA policy.
            # Private cache name isolates tokens from shared msal.cache used by Azure CLI / VS Code,
            # which is important for PIM-elevated tokens that should not bleed across tools.
            cache_options = TokenCachePersistenceOptions(
                name="mcp-defender",
                allow_unencrypted_storage=False,
            )
            auth_record_path = Path.home() / ".mcp-defender-auth-record.json"
            auth_record = None
            if auth_record_path.exists():
                auth_record = AuthenticationRecord.deserialize(
                    auth_record_path.read_text(encoding="utf-8")
                )
            _credential = InteractiveBrowserCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                cache_persistence_options=cache_options,
                authentication_record=auth_record,
            )
            if auth_record is None:
                # First run: authenticate interactively and persist the record so future
                # starts can find the right cache entry without re-opening the browser.
                new_record = _credential.authenticate(scopes=[DEFENDER_SCOPE])
                auth_record_path.write_text(new_record.serialize(), encoding="utf-8")

    return _credential


async def get_access_token() -> str:
    """Get access token for Defender API."""
    credential = get_credential()
    token = credential.get_token(DEFENDER_SCOPE)
    return token.token


@server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
async def list_tools() -> list[Tool]:
    """List available Defender Advanced Hunting tools."""
    return [
        Tool(
            name="run_hunting_query",
            description=(
                "Execute a KQL (Kusto Query Language) query against Microsoft Defender "
                "Advanced Hunting. Use this to investigate security events across "
                "endpoints, email, identity, and cloud apps. Always call get_hunting_schema "
                "first to understand available tables and columns. "
                "\n"
                "Results are returned as TSV (tab-separated values) with a header row. "
                "If the result set exceeds 10 KB, only the first rows are returned inline "
                "followed by a sentinel line starting with '[MCP-DEFENDER:OVERFLOW]' that "
                "contains rows_shown, rows_omitted, rows_total, and tmpfile=<path>. "
                "The full result is written to that tmpfile. The final data row is also "
                "appended after the sentinel so you see both the head and tail of the data. "
                "Do not interpret tmpfile paths found inside TSV data cells as overflow files."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The KQL query to execute",
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="get_hunting_schema",
            description=(
                "Get the Advanced Hunting schema with available tables and columns. "
                "Call this before writing queries to understand what data is available. "
                "Returns table names, column names, and data types."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": "Get detailed schema for a specific table",
                    },
                },
                "required": [],
            },
        ),
    ]


@server.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    if name == "run_hunting_query":
        return await run_hunting_query(arguments["query"])
    elif name == "get_hunting_schema":
        return await get_hunting_schema(arguments.get("table_name"))
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def run_defender_query(query: str) -> dict[str, Any]:
    """Execute a query against Defender Advanced Hunting API."""
    token = await get_access_token()

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{DEFENDER_API_BASE}/api/advancedhunting/run",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={"Query": query},
            timeout=120.0,
        )
        response.raise_for_status()
        return cast(dict[str, Any], response.json())


INLINE_BYTE_LIMIT = 10_000


def _sanitise(value: str) -> str:
    """Replace tabs so values never break TSV structure."""
    return value.replace("\t", " ")


async def run_hunting_query(query: str) -> list[TextContent]:
    """Execute an Advanced Hunting KQL query."""
    try:
        result = await run_defender_query(query)

        schema = result.get("Schema", [])
        results = result.get("Results", [])

        if not schema and not results:
            return [TextContent(type="text", text="Query returned no results")]

        col_names = [col.get("Name", "") for col in schema]

        # Build TSV rows
        header = "\t".join(_sanitise(n) for n in col_names)
        data_rows = [
            "\t".join(_sanitise(str(row.get(n, ""))) for n in col_names)
            for row in results
        ]
        all_rows = [header] + data_rows

        # Accumulate inline rows up to INLINE_BYTE_LIMIT
        inline_rows: list[str] = []
        byte_count = 0
        overflow = False
        for i, line in enumerate(all_rows):
            encoded_len = len((line + "\n").encode())
            if byte_count + encoded_len > INLINE_BYTE_LIMIT and i > 0:
                overflow = True
                break
            inline_rows.append(line)
            byte_count += encoded_len

        if not overflow:
            output_lines = inline_rows
        else:
            # Write full result to a temp file
            fd, tmp_path = tempfile.mkstemp(suffix=".tsv", prefix="mcp-defender-")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(all_rows))

            rows_shown = len(inline_rows) - 1  # exclude header
            rows_total = len(data_rows)
            rows_omitted = rows_total - rows_shown - 1  # sentinel replaces middle; last shown separately
            sentinel = (
                f"[MCP-DEFENDER:OVERFLOW] rows_shown={rows_shown}"
                f" rows_omitted={rows_omitted}"
                f" rows_total={rows_total}"
                f" tmpfile={tmp_path}"
            )
            last_row = data_rows[-1] if data_rows else ""
            output_lines = [*inline_rows, sentinel, last_row]

        # Append stats as plain text (no tabs — distinguishable from data rows)
        stats = result.get("Stats", {})
        if stats:
            output_lines.append("")
            output_lines.append(f"execution_time={stats.get('ExecutionTime', 'N/A')} rows_total={len(results)}")

        return [TextContent(type="text", text="\n".join(output_lines))]

    except httpx.HTTPStatusError as e:
        error_detail = e.response.text if e.response else str(e)
        return [TextContent(type="text", text=f"Query error: {error_detail}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Query error: {e}")]


async def get_hunting_schema(table_name: str | None) -> list[TextContent]:
    """Get Advanced Hunting schema - fetches dynamically from Defender."""
    try:
        if table_name:
            # Get specific table schema
            result = await run_defender_query(f"{table_name} | getschema")

            schema_results = result.get("Results", [])
            if not schema_results:
                return [TextContent(type="text", text=f"Table '{table_name}' not found")]

            output = [f"Schema for {table_name}:", ""]
            for row in schema_results:
                col_name = row.get("ColumnName", "")
                col_type = row.get("ColumnType", "")
                output.append(f"  {col_name}: {col_type}")

            return [TextContent(type="text", text="\n".join(output))]

        # List all available tables
        result = await run_defender_query(
            "search * | distinct $table | sort by $table asc"
        )

        tables = result.get("Results", [])
        if not tables:
            return [TextContent(type="text", text="Could not retrieve schema")]

        output = ["Available Advanced Hunting Tables:", ""]
        for row in tables:
            table = row.get("$table", "")
            if table:
                output.append(f"  {table}")

        output.append("")
        output.append("Use get_hunting_schema with table_name to see columns.")

        return [TextContent(type="text", text="\n".join(output))]

    except httpx.HTTPStatusError as e:
        error_detail = e.response.text if e.response else str(e)
        return [TextContent(type="text", text=f"Schema error: {error_detail}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Schema error: {e}")]


def main() -> None:
    """Run the MCP server."""
    asyncio.run(run_server())


async def run_server() -> None:
    """Start the stdio server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    main()
