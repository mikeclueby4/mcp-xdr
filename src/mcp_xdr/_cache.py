"""Disk-backed TTL cache for expensive Defender metadata queries."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import mcp_xdr._client as _client
import mcp_xdr._config as _config

# Created lazily so it's always bound to the running event loop.
_refresh_lock: asyncio.Lock | None = None


def _lock() -> asyncio.Lock:
    global _refresh_lock
    if _refresh_lock is None:
        _refresh_lock = asyncio.Lock()
    return _refresh_lock


def _cache_path() -> Path:
    tenant = _config._tenant_id or "unknown"
    return _config._cache_dir / f"defender-tables.{tenant}.tsv"


def _is_fresh() -> bool:
    p = _cache_path()
    if not p.exists():
        return False
    age = datetime.now(timezone.utc) - datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
    return age < _config.DEFENDER_TABLE_CACHE_TTL


def _read() -> set[str]:
    return {line.strip() for line in _cache_path().read_text(encoding="utf-8").splitlines() if line.strip()}


def _write(tables: set[str]) -> None:
    _cache_path().write_text("\n".join(sorted(tables)), encoding="utf-8")


async def get_defender_tables() -> set[str]:
    """Return cached Defender table list, refreshing from API when stale.

    Concurrent callers during a cache miss all wait on the same lock and share
    one refresh (double-checked locking pattern).
    """
    if _is_fresh():
        return _read()
    async with _lock():
        if _is_fresh():
            return _read()
        result = await _client.run_hunting_query_raw(
            "union withsource=$table * | distinct $table | sort by $table asc"
        )
        tables = {row.get("$table", "") for row in result.get("results", []) if row.get("$table")}
        _write(tables)
        return tables


async def warm_cache() -> None:
    """Warm the Defender table cache in the background. Swallows all exceptions."""
    try:
        await get_defender_tables()
    except Exception:
        pass
