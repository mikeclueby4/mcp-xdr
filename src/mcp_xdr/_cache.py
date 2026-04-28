"""Generic disk-backed TTL cache."""

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import mcp_xdr._config as _config

# One lock per (cache_dir_str, filename) — unrelated entries never block each other.
_locks: dict[tuple[str, str], asyncio.Lock] = {}


def _get_lock(cache_dir: Path, filename: str) -> asyncio.Lock:
    key = (str(cache_dir), filename)
    if key not in _locks:
        _locks[key] = asyncio.Lock()
    return _locks[key]


def _resolve_dir(unique: str | None) -> Path:
    resolved = (_config._tenant_id or "unknown") if unique is None else unique
    dirname = f"{resolved}.cache" if resolved else ".cache"
    return _config.xdr_dir / dirname


def _is_fresh(path: Path, ttl: timedelta) -> bool:
    if not path.exists():
        return False
    age = datetime.now(timezone.utc) - datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return age < ttl


async def cache_get(
    filename: str,
    fetcher: Callable[[], Awaitable[str]],
    unique: str | None = None,
    ttl: timedelta | None = None,
) -> str:
    """Return cached text for filename, calling fetcher to refresh when stale.

    unique=None  → tenant GUID from AZURE_TENANT_ID (or "unknown")
    unique=""    → global cache at ~/.mcp-xdr/.cache/
    unique="x"   → ~/.mcp-xdr/x.cache/

    Concurrent callers on the same entry share one refresh (double-checked locking).
    """
    if ttl is None:
        ttl = timedelta(minutes=5)
    cache_dir = _resolve_dir(unique)
    path = cache_dir / filename
    if _is_fresh(path, ttl):
        return path.read_text(encoding="utf-8")
    lock = _get_lock(cache_dir, filename)
    async with lock:
        if _is_fresh(path, ttl):
            return path.read_text(encoding="utf-8")
        content = await fetcher()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return content
