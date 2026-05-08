"""TSV formatting, overflow handling, and query logging.

Pure data-transformation utilities — no knowledge of which API is being called.
"""

import datetime
import json
import os
import re
import tempfile
from typing import Any, TYPE_CHECKING

import mcp_xdr._config as _config

from mcp.types import TextContent


def _cell_str(v: Any) -> str:
    """Serialize a cell value to string for TSV output.

    dict/list values (KQL dynamic columns) are JSON-serialized so the output
    is valid JSON rather than Python repr (single-quoted, True/False, None).
    """
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def _sanitise(value: str) -> str:
    """Replace tabs so values never break TSV structure."""
    return value.replace("\t", " ")


# Precede the query with a guard against LLM-footgun IPv4 CIDR masks in ipv6_is_match() calls. 
# All documentation + get_schema examples use IPV6_MATCH instead of ipv6_is_match for this reason.
_IPV6_MATCH_PREAMBLE = (
    "let IPV6_MATCH = (addr: string, prefix: string, prefix_mask: int = 128) {\n"
    "    assert(prefix_mask > 32,"
    ' "IPV6_MATCH: prefix_mask in 0-32 is IPv4 range — did you mean ipv4_is_match()? For IPv4 CIDRs use prefix_mask+96 (e.g. /24 → 120).")\n'
    "    and ipv6_is_match(addr, prefix, prefix_mask)\n"
    "};\n"
)


def _normalize_query(query: str) -> str:
    """Prepend IPV6_MATCH guard and replace blank/whitespace-only lines with a comment.

    IPV6_MATCH wraps ipv6_is_match() with an assert that fires if prefix_mask is
    in 0-32 (the IPv4 footgun range — those masks wildcard the entire IPv4 portion).

    The Defender portal web UI rejects blank lines; a '//' comment is
    syntactically valid for both the Graph and Log Analytics APIs.
    """
    normalized = re.sub(r"^[ \t]*$", "//", query, flags=re.MULTILINE)
    return _IPV6_MATCH_PREAMBLE + normalized


def _blank_column_notice(col_names: list[str], data_rows: list[str]) -> str:
    """Return a notice line listing columns that are blank in every data row.

    Critical for LLM comprehension: prevents misreading a JSON value inside
    a populated column as evidence that the column itself is populated.
    """
    if not data_rows:
        return ""
    split_rows = [row.split("\t") for row in data_rows]
    blank = [
        name
        for i, name in enumerate(col_names)
        if all(i >= len(parts) or parts[i] == "" for parts in split_rows)
    ]
    if not blank:
        return ""
    return f"[MCP-XDR:BLANK-COLS] always_empty={', '.join(blank)}"


async def _format_colsrows_for_toolreturn(
    col_names: list[str],
    data_rows: list[str],
    tmpfile_prefix: str,
) -> list[TextContent]:
    """Shared overflow/output logic for all query results.

    Returns TSV with a header row. When the result exceeds INLINE_BYTE_LIMIT,
    writes full results to a temp file and emits an [MCP-XDR:OVERFLOW] notice line.
    """
    if not col_names and not data_rows:
        return [TextContent(type="text", text="Query returned no results")]

    header = "\t".join(_sanitise(n) for n in col_names)
    notice = _blank_column_notice(col_names, data_rows)
    all_rows = [header] + ([notice] if notice else []) + data_rows

    inline_rows: list[str] = []
    byte_count = 0
    overflow = False
    for i, line in enumerate(all_rows):
        encoded_len = len((line + "\n").encode())
        if byte_count + encoded_len > _config.INLINE_BYTE_LIMIT and i > 0:
            overflow = True
            break
        inline_rows.append(line)
        byte_count += encoded_len

    if not overflow:
        return [TextContent(type="text", text="\n".join(inline_rows))]

    fd, tmp_path = tempfile.mkstemp(suffix=".tsv", prefix=tmpfile_prefix)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(all_rows))

    prefix_lines = 1 + (1 if notice else 0)
    rows_shown = len(inline_rows) - prefix_lines
    rows_total = len(data_rows)
    rows_omitted = rows_total - rows_shown - 1
    overflow_line = (
        f"[MCP-XDR:OVERFLOW] rows_shown={rows_shown}"
        f" rows_omitted={rows_omitted}"
        f" rows_total={rows_total}"
        f" full_results_file={tmp_path}"
    )
    last_row = data_rows[-1]
    return [TextContent(type="text", text="\n".join([*inline_rows, overflow_line, last_row]))]


def _append_query_log(tool_name: str, query_or_args: str, result_text: str, lang: str = "kql") -> None:
    """Append one entry to today's daily query log at ~/.mcp-xdr/logs/queries/YYYY-MM-DD.md.

    Best-effort: exceptions are swallowed so a log failure never breaks a query.
    """
    try:
        _config._logs_queries_dir.mkdir(parents=True, exist_ok=True)
        today = datetime.date.today().isoformat()
        log_file = _config._logs_queries_dir / f"{today}.md"
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        indented = "\n".join("    " + line for line in result_text.splitlines())
        entry = f"## {ts} {tool_name}\n\n```{lang}\n{query_or_args}\n```\n\n{indented}\n\n---\n"
        with log_file.open("a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass
