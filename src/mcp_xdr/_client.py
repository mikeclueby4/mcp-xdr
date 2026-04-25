"""Raw HTTP callers for the Graph Security and Log Analytics APIs.

Each function here is a thin httpx wrapper that returns the raw API response dict.
Result-to-TSV conversion helpers live here too since they are format-specific to
each API's response schema.
"""

from typing import Any, cast

import httpx

import mcp_xdr._config as _config
import mcp_xdr._auth as _auth
from mcp_xdr._output import _normalize_query, _sanitise


async def run_hunting_query_raw(query: str) -> dict[str, Any]:
    """Execute a KQL query against the Microsoft Graph Security Advanced Hunting API.

    Returns the raw API response: {"schema": [...], "results": [...], "stats": {...}}
    """
    token = _auth.get_access_token()
    query = _normalize_query(query)

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{_config.GRAPH_API_BASE}/v1.0/security/runHuntingQuery",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={"Query": query},
            timeout=120.0,
        )
        response.raise_for_status()
        return cast(dict[str, Any], response.json())


async def run_sentinel_query_raw(query: str) -> dict[str, Any]:
    """Execute a KQL query against the Log Analytics workspace API.

    Returns the raw API response: {"tables": [{"columns": [...], "rows": [...]}]}
    """
    if not _config._sentinel_workspace_id:
        raise ValueError("SENTINEL_WORKSPACE_ID is not set")
    token = _auth.get_sentinel_access_token()
    query = _normalize_query(query)

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{_config.SENTINEL_API_BASE}/v1/workspaces/{_config._sentinel_workspace_id}/query",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={"query": query},  # lowercase "query" — Log Analytics API convention
            timeout=120.0,
        )
        response.raise_for_status()
        return cast(dict[str, Any], response.json())


def _sentinel_result_to_tsv(result: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Convert a Log Analytics API response to (col_names, data_rows) for TSV output.

    Log Analytics returns parallel arrays:
      {"tables": [{"columns": [{"name": "col", "type": "..."}], "rows": [[val, ...]]}]}
    """
    table = result["tables"][0]
    col_names = [c["name"] for c in table["columns"]]
    data_rows = [
        "\t".join(_sanitise(str(v) if v is not None else "") for v in row)
        for row in table["rows"]
    ]
    return col_names, data_rows
