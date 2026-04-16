---
name: xdr-report-writing
description: >
  When the user ask you to write up a report based on `xdr` investigations (defender/sentinel results), write it in the repo `reports/` folder (which is .gitignored)
model: sonnet
effort: medium
allowed-tools:
  - mcp__*__get_schema
  - mcp__*__run_hunting_query
  - mcp__*__run_sentinel_query
  - mcp__*__microsoft_docs_fetch
  - mcp__*__microsoft_docs_search
  - WebSearch
  - WebFetch
  - mcp__*__web_read
  - mcp__*__web_grounded_answer
  - Read({baseDir}/../xdr/references/**)
  - Write(reports/**)
---

# Report writing

Name the report file like `YYYYMMDD-slug-name.md`.

Include frontmatter with `status: report`, `author: mcp-xdr (YourModel)`, a `date` and `description` field. 

Generally follow what you can infer from the user's request, but good tips are:
- Start with a brief summary that states the investigation purpose and highlights key findings
- Itemize which tables were consulted, and which time periods were covered
- If you need to confirm high-value up-to-date facts or best practice: use available web tooling to research and cite!
- End with a next steps / open loops-ish section - _if_ any are actually worth mentioning. (So don't treat this as an ask to always invent something to say!)

When you have finalized:
1. Check that you didn't assume something about things starting/ending based on the query window (oops)
2. CLEARLY state in the your response which time periods are covered, to give the user a chance to catch an "oops, we should have looked at a different period"
3. You may suggest that the user edit `${CLAUDE_SKILL_DIR}/../xdr/tenant.local.md` to clarify open questions about the tenant/environment (hostnames, apps, nets, etc) for future reports and investigations. 

## Existing reference documentation in the `xdr` skill that you may consult

```!set -x;ls -1R ${CLAUDE_SKILL_DIR}/../xdr/references/```

## Local context

This is a transclusion of the `xql` skill's "tenant.local.md" if it exists:

!`set -x;cat ${CLAUDE_SKILL_DIR}/../xdr/tenant.local.md`

