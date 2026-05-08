"""Shared constants and mutable runtime state.

No imports from within this package — stdlib only.
All other modules read _sentinel_workspace_id through the module reference
(import mcp_xdr._config as _config; _config._sentinel_workspace_id) so that
test mutations are visible at call time rather than being snapshot at import time.
"""

import os
from datetime import timedelta
from pathlib import Path

GRAPH_API_BASE = "https://graph.microsoft.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Pre-existing Log Analytics SP's _may_ only list api.loganalytics.io in its
# servicePrincipalNames — we request tokens by well-known SP app ID instead.
SENTINEL_API_BASE = "https://api.loganalytics.azure.com"
SENTINEL_SCOPE = "ca7f3f0b-7d91-482c-8e09-c5d840d0eac5/.default"

# Set a byte limit for inline results to prevent overwhelming the client.
# Results above this limit will be written to a temp file with a sentinel line pointing to it.
INLINE_BYTE_LIMIT = 10_000  # ~10 KB

xdr_dir = Path.home() / ".mcp-xdr"
xdr_dir.mkdir(parents=True, exist_ok=True)

_logs_queries_dir = xdr_dir / "logs" / "queries"

SCHEMA_LIST_CACHE_TTL = timedelta(hours=24)
SCHEMA_TABLE_CACHE_TTL = timedelta(hours=24)

# get_schema(table_name) deterministic-fact probes:
# Sample size for the cell-shape probe — small is fine, shapes converge quickly.
PROBE_SAMPLE_ROWS = 200
# Sample size for the enum-cardinality + value probes. Larger than PROBE_SAMPLE_ROWS
# so high-volume tables (DeviceEvents has 80+ distinct ActionTypes) don't get
# undersampled and falsely classified as low-cardinality. dcount() uses HLL
# under the hood, so the cost stays bounded.
ENUM_PROBE_SAMPLE_ROWS = 5000
# Max distinct values for enum-style columns; above this we redact to "high-cardinality".
ENUM_PROBE_LIMIT = 30
# Max chars per Notes cell (LLM-readable; not for visual alignment).
NOTES_CELL_MAX_CHARS = 1000

# Mutable at runtime: set from env at startup, overridable by tests.
_sentinel_workspace_id: str | None = os.environ.get("SENTINEL_WORKSPACE_ID") or None
_tenant_id: str | None = os.environ.get("AZURE_TENANT_ID") or None
