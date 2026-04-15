---
paths:
  - pyproject.toml
  - server.json
---

When `pyproject.toml` or `server.json` is edited, check that the version number is consistent across **both** files:

- `pyproject.toml` → `[project] version`
- `server.json` → top-level `"version"` and `"packages"[0]."version"`

All three values must match. Also check that `server.json` `"name"` uses the correct GitHub owner (`io.github.mikeclueby4/mcp-xdr`) and that the `"description"` stays in sync with the `pyproject.toml` description.
