---
paths:
  - pyproject.toml
  - server.json
  - src/mcp_xdr/__init__.py
---

When `pyproject.toml`, `server.json`, or `src/mcp_xdr/__init__.py` is edited, check that the version number is consistent across **all** files:

- `pyproject.toml` → `[project] version`
- `server.json` → top-level `"version"` and `"packages"[0]."version"`
- `src/mcp_xdr/__init__.py` → `__version__`

All values must match. Also check that `server.json` `"name"` uses the correct GitHub owner (`io.github.mikeclueby4/mcp-xdr`) and that the `"description"` stays in sync with the `pyproject.toml` description.
