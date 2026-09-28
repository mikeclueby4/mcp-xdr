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
- Email* table family (`EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `EmailPostDeliveryEvents`) all join on `NetworkMessageId`. When working on any of these tables, note that `EmailEvents` is the root/anchor table.
- When updating `EmailEvents.md`: `AuthenticationDetails`, `DetectionMethods`, and `AdditionalFields` are string-encoded JSON in Defender source despite `AdditionalFields` being typed `dynamic` in Sentinel. Always note `parse_json()` required.

### CampaignInfo: one row per recipient message, join via NetworkMessageId
`CampaignInfo` has one row per campaign × recipient message. `CampaignId` is NOT a column in `EmailEvents` — the only join path is `NetworkMessageId`. `ReportId` in CampaignInfo is a composite non-GUID string (`<CampaignId>:0:<NetworkMessageId>-<long>-<long>`) — do not join to AlertEvidence or other tables via ReportId. Defender-only (Sentinel empty). Confirmed CampaignType values: `Phish`, `Malware`. CampaignSubType = brand/family or blank. CampaignId = dot-separated hex string, not a GUID.

### EmailEvents fanout trap
`EmailEvents` produces one row per recipient. Count distinct messages with `dcount(NetworkMessageId)` or `summarize by NetworkMessageId`, not `count()`. Mention this when writing queries for email-volume analyses.

### TVM table family: always write both reference files together
`DeviceTvmSoftwareVulnerabilities.md` and `DeviceTvmSoftwareVulnerabilitiesKB.md` are tightly coupled — write/update both in the same pass. Similarly, `DeviceTvmSoftwareInventory.md` is the anchor table for software-level context. Same applies to `DeviceTvmSecureConfigurationAssessment.md` + `DeviceTvmSecureConfigurationAssessmentKB.md`. Same applies to `DeviceTvmInfoGathering.md` + `DeviceTvmInfoGatheringKB.md`. Same applies to `DeviceBaselineComplianceAssessment.md` + `DeviceBaselineComplianceAssessmentKB.md`.

## Investigation playbook learnings

### Verdict-column mutability: always check for a frozen/`Original*` counterpart before writing "current verdict" guidance
When a table has both a live verdict column (e.g. `ThreatTypes`) and an `Original*`/frozen counterpart, prioritize documenting BOTH and their divergence — this is a recurring, high-value trap shape (confirmed in `EmailEvents` vs `UrlClickEvents`, which have opposite mutability behavior for the same-named `ThreatTypes` column). Cross-reference the two tables' reference files so readers of one see the contrast, and check `kql-facts.md` for a general "verdict mutability" entry before adding a third table-specific instance — extend the general entry instead of duplicating narrative.

### Live schema samples can contain real tenant data — sanitize before quoting
`get_schema()` sample rows pull from the live tenant and can include real domains/UPNs/org names even when researching a public repo. Never copy sample-row values verbatim into a reference file — always genericize to placeholders (`user@example.com`, `example.com`) before writing, even when the underlying pattern (e.g. an enum value or JSON shape) is worth preserving.

### Existing reference docs can assert "no time column" incorrectly — verify with get_schema even for facts that look settled
Found a reference file confidently stating a table has no time column (recommending join-only time filtering) when live schema + official docs both show a `Timestamp` column present all along. Always run `get_schema(table_name=...)` fresh even when updating a file that already documents the "shape" of a table — don't assume prior "no such column" claims are still (or were ever) fully correct without a quick live check.

### IOC substring-hunt false positives against serialized blobs — now a kql-facts.md general entry
Generalized fact added: `contains` searches for short IOC fragments (domain minus TLD, etc.) against stringified blob columns (`RawEventData`, `AdditionalFields`) can match schema field *names* (e.g. `TargetFileUrl` matching a `getfileurl` search). Don't re-derive this per-table — reference the kql-facts.md entry and only add a table-specific pointer/example if evidence is table-specific.

### Boot time / uptime from DeviceProcessEvents — use grandparent filter
`InitiatingProcessFileName =~ "wininit.exe"` returns near-zero rows (early-boot child events filtered by MDE). Use `InitiatingProcessParentFileName =~ "wininit.exe"` to match grandchildren of wininit (service-spawned processes) — `InitiatingProcessParentCreationTime` on those rows is the boot timestamp of `services.exe` = host boot time. `max()` = last boot, `dcount()` = number of distinct boots in window. Playbook written at `investigations/uptime-as-patch-proxy.md`.
