#!/usr/bin/env bash
# PostToolUse hook for run_hunting_query / run_sentinel_query
# Injects a gentle reminder to document surprising findings when a query
# returns an overflow result or a KQL error — silent on clean small results.
set -euo pipefail

# Extract tool result text — flatten both string and list-of-content-blocks forms
result=$(jq -r '
  .tool_response
  | if type == "array" then map(.text // "") | join(" ")
    else tostring
    end
' 2>/dev/null || true)

# Fire reminder only on overflow (large result) or a KQL/API error
if grep -qE '(\[MCP-XDR:OVERFLOW\]|BadRequest|SyntaxError|"error"|error at line)' <<< "$result"; then
  printf '%s\n' '{
    "hookSpecificOutput": {
      "hookEventName": "PostToolUse",
      "additionalContext": "Reminder (`xdr` skill): if this result revealed anything surprising — unexpected column types, silent empty results, IP format quirks, schema discrepancies, error patterns — document it in references/tables/<TableName>.md while the detail is fresh. See SKILL.md for content guidelines (no tenant-specific data)."
    }
  }'
fi
# Silent exit when no match — no additionalContext injected
