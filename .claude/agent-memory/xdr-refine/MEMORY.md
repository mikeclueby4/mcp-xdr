# XDR Refine Agent Memory

## Research workflow learnings

### Parallelise the first four calls
Always fire these four in one block (no deps between them):
1. `Read` existing reference file
2. `Read` kql-facts.md
3. `get_schema(table_name=...)` — gives both Defender and Sentinel schemas + 3 sample rows from each source
4. `microsoft_docs_fetch` for the table's official docs page

The schema sample rows are the most valuable source for serialization/encoding gotchas — they show actual values, not just column types.

### Source-divergence pattern (Defender vs Sentinel)
`get_schema` returns separate sample rows for Defender and Sentinel sources when both exist. This is the primary mechanism for detecting source-specific serialization differences. Always compare both sample sets side-by-side before writing encoding guidance.

- For each `dynamic` column, run a targeted live query to confirm whether `col[0]` indexing auto-parses nested JSON strings (returns dictionary) or requires explicit `parse_json()`. This varies by source, table and column.
- Run `summarize count() by ActionType` and `summarize count() by Application, ApplicationId` early — cheap, defines the table's hunting surface.

Known source-specific divergence pattern in tables that appear in both Defender and Sentinel:
- `@odata.type` wrapper keys appear in Defender rows for dynamic columns (`RawEventData`, `AdditionalFields`, `LastSeenForUser`) — absent in Sentinel rows. The wrapper does not affect direct property access on native dynamic columns.
- Array-element serialization can differ: Defender may double-serialize array elements as JSON strings; Sentinel may keep them as native objects. Always verify per-table with live samples.

### Cross-source portability pattern
For dynamic columns with source-specific serialization, `parse_json(tostring(col))` or `parse_json(tostring(element))` is safe in both Defender and Sentinel. Recommend this pattern for portability when source is unknown or when writing for `union`-style queries. Keep in mind that it is _expensive_; do cheap filters first.

## Cross-reference meta-knowledge

- Any table with `OAuthAppId` should cross-reference `OAuthAppInfo.md` join note. Check that file exists and has the note.
- `IdentityInfo` is a standard enrichment join for any table with `AccountObjectId`.


### ActivityType known values for CloudAppEvents
Basic, Download, Edit, Synctolocal, Run, Read, Create, Delete, Failed, View.

### RawEventData nested-string fields in CloudAppEvents
Some fields in `RawEventData` are stored as nested JSON strings (not dicts): `AppAccessContext`, `PolicyMatchInfo`, `SensitiveInfoTypeData`. Access via `parse_json(tostring(RawEventData.FieldName))`.
