# XDR Refine Agent Memory

## Research workflow learnings

### EntraIdSpnSignInEvents: Defender-only, flat schema, Entra P2 required
`EntraIdSpnSignInEvents` is Defender-only (Sentinel 400). No dynamic columns — entirely flat. Entra ID P2 license required. `SessionId` blank when `IsConfidentialClient == false`. `UniqueTokenId` is base64url (not GUID). Sentinel equivalents: `AADServicePrincipalSignInLogs` (SP) + `AADManagedIdentitySignInLogs` (MI); `UniqueTokenId` maps to `UniqueTokenIdentifier` there. `ReportId` is GUID (safe single-column join). No user-identity columns (`AccountUpn` etc.) — SP identity is `ServicePrincipalName`/`ServicePrincipalId`. When working on EntraIdSpnSignInEvents, also note `EntraIdSignInEvents.md` for the parallel user sign-in table.

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

### ThreatIntelIndicators/ThreatIntelObjects/ThreatIntelligenceIndicator: three-table family
`ThreatIntelIndicators` and `ThreatIntelObjects` launched 2025-04-03 (Preview). `ThreatIntelligenceIndicator` (legacy) stopped ingestion 2025-07-31, retiring 2026-05-31. When writing any TI-related query, always default to the new tables.
- `ThreatIntelIndicators` = STIX indicator objects (IOCs) with `ObservableKey`/`ObservableValue`
- `ThreatIntelObjects` = all other STIX types: `threat-actor`, `attack-pattern`, `relationship`, `identity`, etc.
- Join key between the two: `tostring(Data.id)` on both sides (STIX object ID, format `indicator--<uuid>`)
- `ThreatIntelObjects` may be empty in tenants with only basic MDTI indicator feeds
- When a task involves ThreatIntelligenceIndicator, redirect to ThreatIntelIndicators and add migration pattern
- The `Revoked` top-level column is always blank — use `Data.revoked` instead
- `ConfidenceScore` (real) in legacy table → `Confidence` (int) in new table

### ThreatIntelIndicators: Data and AdditionalFields are native dynamic

`ThreatIntelIndicators.Data` and `AdditionalFields` are **native dynamic** in both Defender and Sentinel sources (confirmed via `gettype()` = `"dictionary"` and `bag_keys()` working). Direct property access works — `Data.indicator_types[0]`, `AdditionalFields.TLPLevel`. **No `parse_json(tostring())` needed.** Exception: `Data.labels` array elements that are MITRE TTP objects ARE stored as JSON strings inside the array — those sub-elements need `parse_json(tostring(Data.labels[N]))`.

This is notable because the get_schema sample rows show `Data` as a JSON string in the output (due to TSV rendering), which can mislead into thinking double-serialization is needed.

### ThreatIntelObjects is the companion STIX object table

Join `ThreatIntelIndicators` to `ThreatIntelObjects` via `tostring(Data.id)` (STIX indicator ID). Mention this when working on TI-related queries. Both have reference files; update both when doing any TI work.

## Cross-reference meta-knowledge

- Any table with `OAuthAppId` should cross-reference `OAuthAppInfo.md` join note. Check that file exists and has the note.
- `IdentityInfo` is a standard enrichment join for any table with `AccountObjectId`.
- Email* table family (`EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `EmailPostDeliveryEvents`) all join on `NetworkMessageId`. When working on any of these tables, note that `EmailEvents` is the root/anchor table.
- When updating `EmailEvents.md`: `AuthenticationDetails`, `DetectionMethods`, and `AdditionalFields` are string-encoded JSON in Defender source despite `AdditionalFields` being typed `dynamic` in Sentinel. Always note `parse_json()` required.

### CampaignInfo: one row per recipient message, join via NetworkMessageId
`CampaignInfo` has one row per campaign × recipient message. `CampaignId` is NOT a column in `EmailEvents` — the only join path is `NetworkMessageId`. `ReportId` in CampaignInfo is a composite non-GUID string (`<CampaignId>:0:<NetworkMessageId>-<long>-<long>`) — do not join to AlertEvidence or other tables via ReportId. Defender-only (Sentinel empty). Confirmed CampaignType values: `Phish`, `Malware`. CampaignSubType = brand/family or blank. CampaignId = dot-separated hex string, not a GUID.

### EmailEvents fanout trap
`EmailEvents` produces one row per recipient. Count distinct messages with `dcount(NetworkMessageId)` or `summarize by NetworkMessageId`, not `count()`. Mention this when writing queries for email-volume analyses.


### ActivityType known values for CloudAppEvents
Basic, Download, Edit, Synctolocal, Run, Read, Create, Delete, Failed, View.

### RawEventData nested-string fields in CloudAppEvents
Some fields in `RawEventData` are stored as nested JSON strings (not dicts): `AppAccessContext`, `PolicyMatchInfo`, `SensitiveInfoTypeData`. Access via `parse_json(tostring(RawEventData.FieldName))`.

### SecurityEvent: %%-prefixed message codes
Windows Security Event columns contain `%%NNNN` message insertion string codes left un-decoded at ingestion (e.g. `TokenElevationType == "%%1937"` = elevated; `FailureReason == "%%2313"` = wrong password). These are raw Windows message table references — Sentinel does not render them. Filter/compare on the literal code string, not on the English text. The `SecurityEvent.md` reference has a known-codes table.

### SecurityEvent: No dynamic columns
`SecurityEvent` has no `dynamic`-typed columns — all ~200 columns are `string` or `int`. No `parse_json()` needed anywhere. The high column count is because every possible Windows Security event field has a dedicated column; most are blank for any given EventID.

### SecurityEvent: IpAddress is not IPv6-mapped
Unlike Defender XDR tables, `SecurityEvent.IpAddress` uses plain IPv4/IPv6 strings or the literal `"-"` for local/unavailable. Standard `==` comparison is safe; no need for `ipv6_is_match()`.

### SecurityEvent vs DeviceLogonEvents / DeviceProcessEvents
For MDE-enrolled endpoints, prefer `DeviceLogonEvents` (logons) and `DeviceProcessEvents` (4688 analogue) — better enrichment and `ProcessCommandLine` always populated. Use `SecurityEvent` for non-MDE machines: Arc-connected servers, domain controllers.

### SecurityEvent: CommandLine requires explicit audit policy
`CommandLine` column (EventID 4688) is empty unless "Include command line in process creation events" is enabled via GPO or Security Center. Always check `isnotempty(CommandLine)` before relying on it.

### DeviceProcessEvents: AdditionalFields is string in Defender, dynamic in Sentinel
`AdditionalFields` is `string`-typed in Defender (confirmed `gettype()` = `"string"`) but `dynamic` in Sentinel. Use `parse_json(AdditionalFields)` in both — it parses the string in Defender and is a no-op on a dynamic in Sentinel. Do NOT add `tostring()` wrapper: `parse_json(tostring(AdditionalFields))` is wasteful in Sentinel (dynamic→string→parse round-trip).

### DeviceProcessEvents: AdditionalFields POSIX enrichment on macOS/Linux
On macOS/Linux events, `AdditionalFields` contains nested objects for POSIX identity and working directory:
- `ProcessPosixEffectiveUser` — object with `{Sid, Name, DomainName, LogonId, AadUserUpn, PosixUserId, PrimaryPosixGroup:{Name, PosixGroupId}}`
- `ProcessPosixEffectiveGroup`, `ProcessPosixRealUser`, `ProcessPosixProcessGroupId`, `ProcessPosixSessionId`, `ProcessPosixFilePermissions`, `ProcessCurrentWorkingDirectory`
- Initiating process equivalents with `InitiatingProcess` prefix
- Windows events only have `DesktopName` in `AdditionalFields`
Use `toint(af.ProcessPosixEffectiveUser.PosixUserId) == 0` to detect root processes on macOS/Linux.

### DeviceProcessEvents: ProcessUniqueId for process trees
`ProcessUniqueId` and `InitiatingProcessUniqueId` are Windows Process Start Keys (long integer strings) — use for reliable process-chain linking that survives PID reuse. More stable than `ProcessId + ProcessCreationTime` joins.

### DeviceProcessEvents: Only one ActionType
`ProcessCreated` is the only ActionType in this table. No need to filter by ActionType.

### DeviceLogonEvents: AdditionalFields parse pattern
`AdditionalFields` is `string` in Defender, `dynamic` in Sentinel. `parse_json(AdditionalFields)` works in both without `tostring()` wrapper (Defender auto-parses the JSON string). Confirmed keys: `IsLocalLogon` (bool, always present), `Upn` (string, present on CachedInteractive and some others). Same `@odata.type` wrapper key appears in Defender but doesn't block property access.

### DeviceLogonEvents: ProcessUniqueId docs/schema mismatch
Official docs list `ProcessUniqueId` as a column; it is **absent from the live schema** as of 2026-04. Querying it fails with a semantic error. `InitiatingProcessUniqueId` is present and populated.

### DeviceLogonEvents: LogonId for session correlation
`LogonId` (long) = Windows logon session ID. Unique per device per boot only. Can be used to join `DeviceLogonEvents` to `DeviceProcessEvents` on `DeviceId + LogonId` to find all processes in a session.

### DeviceLogonEvents: LogonType "Unknown" on LogonAttempted rows
`Unknown` LogonType is normal on `LogonAttempted` rows — Windows hasn't resolved the type before the attempt is logged. Don't treat as suspicious on its own.

### DeviceLogonEvents: FailureReason blank on LogonFailed
Significant fraction of `LogonFailed` rows have blank `FailureReason`. Always include `isnotempty(FailureReason)` filter when grouping by reason, or handle blank as a separate bucket.

### DeviceFileEvents: ProcessUniqueId docs/schema mismatch (same pattern as DeviceLogonEvents)
Official docs list `ProcessUniqueId` as a column; it is **absent from the live schema** as of 2026-04 — same pattern as `DeviceLogonEvents`. `InitiatingProcessUniqueId` IS present. This pattern (docs ahead of live schema) may apply to other Device* tables too — always verify with `get_schema` before using `ProcessUniqueId`.

### DeviceFileEvents: AdditionalFields schema divergence
`string` in Defender, `dynamic` in Sentinel. `parse_json(AdditionalFields)` works in both without `tostring()` wrapper. Windows events contain only `FileType` key; macOS/Linux events are much richer with POSIX identity + `FilePosixPermissions` + `FileType`. Pre-filter with `AdditionalFields has "PosixUserId"` before parsing on macOS/Linux queries.

### DeviceFileEvents: ActionType values (confirmed 2026-04)
Four values: `FileCreated`, `FileRenamed`, `FileDeleted`, `FileModified`. `FileCreated` is highest volume by far. No other values observed.

### DeviceFileEvents reference file already written
`DeviceFileEvents.md` was already complete when the "initial documentation pass" request came in. The file documents: ActionType enum, ReportId composite key, ProcessUniqueId mismatch, AdditionalFields Windows vs macOS/Linux divergence, RequestProtocol values, file origin tracking, sensitivity labels, remote session context, cross-table joins, and hunting patterns. No rewrite needed — check the file before writing.

### DeviceNetworkEvents: ProcessUniqueId docs/schema mismatch
Same pattern as `DeviceLogonEvents` and `DeviceFileEvents`: official docs list `ProcessUniqueId` as a column but it is **absent from the live schema** as of 2026-04. `InitiatingProcessUniqueId` IS present. This pattern now confirmed in at least 3 Device* tables — safe to assume it applies to all Device* tables. Always verify with `get_schema`.

### DeviceNetworkEvents: DnsConnectionInspected contains full DNS query/response
The existing reference file incorrectly stated "does not reveal the query name or answer". The `AdditionalFields` for `DnsConnectionInspected` contains full Zeek DNS data: `query`, `answers` (JSON-encoded array string — needs a second `parse_json()`), `rcode_name`, `qtype_name`, `TTLs`, `rtt`. This is the primary table for DNS-based hunting.

### DeviceNetworkEvents: Zeek ActionTypes — AdditionalFields schemas
Multiple Zeek-derived ActionTypes each have distinct `AdditionalFields` schemas. See `DeviceNetworkEvents.md` for per-ActionType schemas. Key types: `SslConnectionInspected` (JA3/JA4, cert, SNI), `HttpConnectionInspected` (method, URI, status), `NtlmAuthenticationInspected`, `KerberosConnectionInspected`, `SshConnectionInspected`, `NetworkSignatureInspected`, `InboundInternetScanInspected` (`PublicScannedPort`/`PublicScannedIp`).

### DeviceNetworkEvents: macOS/Linux ConnectionRequest/InboundConnectionAccepted have POSIX context in AdditionalFields
On macOS/Linux, `ConnectionRequest` and `InboundConnectionAccepted` rows carry POSIX identity (`InitiatingProcessPosixEffectiveUser` etc.) in `AdditionalFields` — same structure as `DeviceProcessEvents` and `DeviceFileEvents` POSIX enrichment.

### DeviceRegistryEvents: No AdditionalFields, no dynamic columns
`DeviceRegistryEvents` has no `AdditionalFields` column and no dynamic-typed columns at all. All columns are `string`, `long`, `datetime`, or `bool`. No `parse_json()` needed anywhere. Windows-only table.

### DeviceRegistryEvents: ProcessUniqueId absent (same pattern as other Device* tables)
`ProcessUniqueId` absent from live schema despite docs listing it — confirmed 2026-04. `InitiatingProcessUniqueId` IS present and well-populated.

### DeviceRegistryEvents: ActionType (exactly 4 values, confirmed 2026-04)
`RegistryValueSet`, `RegistryKeyCreated`, `RegistryKeyDeleted`, `RegistryValueDeleted`. No rename ActionType — renames appear as delete+create pairs.

### DeviceRegistryEvents: RegistryValueType negative integer values
`RegistryValueType` can be a negative integer string (e.g. `-65520`, `-65518`) for internal Windows device property store keys (paths like `HKLM\SYSTEM\...\Properties\{GUID}\NNNN`). Use `toint(RegistryValueType) >= 0` to exclude them when only named types are relevant. Named types: `None`, `Dword`, `String`, `Binary`, `ExpandString`, `Qword`, `MultiString`.

### DeviceRegistryEvents: Previous* columns — when populated
`PreviousRegistryKey` populated on `RegistryKeyDeleted` (holds deleted path; `RegistryKey` is blank for this ActionType). `PreviousRegistryValueName`/`PreviousRegistryValueData` populated on `RegistryValueDeleted` and partially on `RegistryValueSet` (prior value). `RegistryKeyCreated` never populates any Previous* column.

### DeviceImageLoadEvents: Single ActionType, no AdditionalFields, no dynamic columns
`ImageLoaded` is the only ActionType — no ActionType filter ever needed. Table has **no `AdditionalFields` column** and no dynamic-typed columns at all. Schema is identical between Defender and Sentinel. No `parse_json()` needed.

### DeviceImageLoadEvents: Primary join — DeviceFileCertificateInfo via SHA1
The key enrichment join for this table is `DeviceFileCertificateInfo` (on `SHA1`) to check `IsTrusted`, `Signer`, `IsRootSignerMicrosoft`. This enables unsigned/untrusted DLL detection. When working on `DeviceImageLoadEvents` queries, suggest this join proactively.

### DeviceImageLoadEvents: ProcessUniqueId absent (same pattern)
`ProcessUniqueId` absent from live schema despite docs listing it — confirmed 2026-04. Same pattern as all other Device* tables. `InitiatingProcessUniqueId` IS present.

### DeviceEvents: AdditionalFields string/dynamic divergence (same pattern as other Device* tables)
`AdditionalFields` is `string` in Defender, `dynamic` in Sentinel. `parse_json(AdditionalFields)` works in both without `tostring()` wrapper.

### DeviceEvents: `sample` is a reserved word in KQL
`summarize sample=any(col)` fails with "Missing expression: If the keyword 'sample' is intended to be part of an expression it needs to be bracketted as ['sample']". Use a different column alias (e.g. `AF`, `Val`, `Ex`).

### DeviceEvents: Some AdditionalFields values contain nested JSON strings
A few ActionTypes embed a *second* JSON object as a string inside an AdditionalFields key:
- `ScheduledTaskCreated`/`ScheduledTaskUpdated`.`TaskContent`
- `ProcessPrimaryTokenModified`.`TokenModificationProperties`
- `DnsQueryResponse`.`DnsQueryResult` — array of JSON strings (each element needs a second `parse_json(tostring(element))`)
Pattern: `parse_json(tostring(af.FieldName))`.

### DeviceEvents: `%%NNNN` message codes in account-change ActionTypes
`UserAccountModified` and `AuditPolicyModification` AdditionalFields contain `%%NNNN` Windows message codes (e.g. `%%1793` = "value not changed", `%%8450` = audit policy change description). Compare on literal code strings — Sentinel does not decode them.

### DeviceEvents: 85 ActionTypes confirmed (2026-04)
Full list and AdditionalFields schemas per ActionType are in `DeviceEvents.md`. Key high-volume types: `NamedPipeEvent`, `DpapiAccessed`, `NtProtectVirtualMemoryApiCall`, `AppControlCodeIntegrityOriginAudited`, `CreateRemoteThreadApiCall`. Many ActionTypes have blank `AdditionalFields` in practice — check before parsing.

### DeviceFileCertificateInfo: lookup table, not event stream
Not a primary event stream — one row per (DeviceId, SHA1) from certificate verification cycles. **Primary join key is `SHA1`**, not `ReportId`. No `AdditionalFields`, no dynamic columns, schema identical across Defender and Sentinel. Two `SignatureType` values: `Embedded` and `Catalog`.

### DeviceFileCertificateInfo: CrlDistributionPointUrls is string not dynamic
Typed `string` in both Defender and Sentinel despite containing a JSON array. Use `parse_json(CrlDistributionPointUrls)` to access individual URLs — no `tostring()` needed since it's already a string.

### DeviceFileCertificateInfo: primary join targets
`DeviceFileEvents` and `DeviceImageLoadEvents` both join to `DeviceFileCertificateInfo` via `SHA1`. Multiple rows per SHA1 can exist across devices; use `summarize arg_max(Timestamp, *) by SHA1` for one-cert-per-hash deduplication.

### DeviceFileCertificateInfo: IsTrusted vs IsSigned distinction
`IsSigned == true` + `IsTrusted == false` = signature present but broken/revoked/untrusted. High-value hunting signal. `IsRootSignerMicrosoft == true` means file is part of Windows OS, not just Microsoft-signed.

### DeviceInfo: snapshot table, not event stream
One row per device per heartbeat — each write is a full snapshot. Use `arg_max(ingestion_time(), *)` (not `Timestamp`) for latest state. `AdditionalFields` only populated when `IsInternetFacing == true`; contains `InternetFacingLastSeen`, `InternetFacingReason` (`"PublicScan"`/`"ExternalNetworkConnection"`), local/remote IP+port, protocol. `DlpInfo`, `ConnectivityType`, `DiscoverySources`, `FirmwareVersions` are Defender-only string columns (absent from Sentinel). `LoggedOnUsers` is string/dynamic (Defender/Sentinel divergence) — JSON array with `UserName`, `DomainName`, `Sid`. `JoinType` values confirmed: `"AAD Joined"`, `"Hybrid Azure AD Join"`, `"AAD Registered"`, blank. `OnboardingStatus` values: `"Onboarded"`, `"Can be onboarded"`, `"Unsupported"`, `"Insufficient info"`. `ConnectivityType` values: `"Standard"`, `"Streamlined"`, blank. `AadDeviceId` → `EntraIdSignInEvents.EntraIdDeviceId` for cross-table device-identity correlation. `MergedToDeviceId` tracks device renames/reimages.

### DeviceInfo is canonical enrichment join for Device* tables
When querying Device* event tables and needing device metadata (OS, join type, machine group, public IP), join to `DeviceInfo` on `DeviceId` with `summarize arg_max(Timestamp, ...) by DeviceId` on the DeviceInfo side first.

### DeviceNetworkInfo: string/dynamic divergence for all array columns
`IPAddresses`, `ConnectedNetworks`, `DnsAddresses`, `DefaultGateways` are all `string` in Defender, `dynamic` in Sentinel. `parse_json(col)` works in both without `tostring()` wrapper.

### DeviceNetworkInfo: IPAddresses SubnetPrefix can be null
`SubnetPrefix` in `IPAddresses` array elements can be `null` — confirmed in live data. Use `toint()` which returns `int(null)` gracefully; don't assume it's always populated.

### DeviceNetworkInfo: ConnectedNetworks Category confirmed values
`"Public"`, `"Private"`, `"Domain"`, blank/null. On non-domain-joined devices NLA can't detect a DC so corp networks appear as `"Public"` or `"Private"` — don't use Category as a security discriminator without understanding fleet join type.

### DeviceNetworkInfo: OnboardingStatus and NetworkAdapterDnsSuffix absent from live schema (2026-04)
Both columns appear in official docs but are absent from live schema in both Defender and Sentinel. Pattern: docs list columns before they ship. Do not reference them in queries until confirmed present.

### DeviceNetworkInfo: snapshot table — deduplicate with arg_max by DeviceId + MacAddress
Unlike event tables, deduplicate with `summarize arg_max(Timestamp, *) by DeviceId, MacAddress` for current adapter state. Primary use: IP-to-device resolution and location fingerprinting.

### DeviceTvmSoftwareInventory: ProductCodeCpe sentinel value is title-case
The literal sentinel for unknown CPE is `"Not Available"` (title-case) despite official docs saying `'not available'` (lowercase). Use `!= "Not Available"` or case-insensitive `!~ "not available"` to filter it out.

### DeviceTvmSoftwareEvidenceBeta: DiskPaths platform behaviour
`DiskPaths` content is OS-dependent — not always file system paths. Windows: backslash paths. macOS: `.app` bundle paths (e.g. `/System/Applications/TV.app`), not individual binaries. Linux (RPM): RPM query command strings, not paths. Filter to Windows paths with `has ":\\"` before path analysis.

### DeviceTvmSoftwareInventory: rows accumulate (no timestamp, no deletion)
TVM rows are never deleted on version update — every historically observed version persists. `dcount(DeviceName)` per version overcounts current exposure. Join `DeviceTvmSoftwareEvidenceBeta` on `DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion` + filter `todatetime(LastSeenTime) > ago(14d)` to approximate current install state.

### DeviceTvmSoftwareInventory: EOS metadata not Windows-only
`EndOfSupportStatus` is populated for Windows, macOS, and Android rows (confirmed 2026-04). Docs claim Windows-only — inaccurate.

### DeviceTvmSoftwareInventory: no dynamic columns
No `AdditionalFields`, no dynamic-typed columns anywhere. No `parse_json()` needed.

### DeviceTvmSoftwareInventory: primary join to DeviceTvmSoftwareVulnerabilities
Join key: `DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion`. The vulnerability table carries `CveId`, `VulnerabilitySeverityLevel`, etc.

### DeviceTvmSoftwareVulnerabilities: no Timestamp in Defender
No `Timestamp` column — using it causes a semantic error. Sentinel variant adds `TimeGenerated`; neither is an event log. Omit time filters entirely for most snapshot queries. `CveMitigationStatus` is Defender-only and blank in practice. `RecommendedSecurityUpdate`/`RecommendedSecurityUpdateId` are often blank even when patches exist.

### DeviceTvmSoftwareVulnerabilitiesKB: companion CVE knowledge base
Join `DeviceTvmSoftwareVulnerabilities` to `DeviceTvmSoftwareVulnerabilitiesKB` on `CveId` for CVSS score, EPSS score (`EpssScore` real, Defender-only), `IsExploitAvailable` (bool), description. `AffectedSoftware` is a native dynamic array of CPE strings. Both tables are Defender-primary; Sentinel rows often absent. When working on TVM vulnerability queries, always check both reference files.

### TVM table family: always write both reference files together
`DeviceTvmSoftwareVulnerabilities.md` and `DeviceTvmSoftwareVulnerabilitiesKB.md` are tightly coupled — write/update both in the same pass. Similarly, `DeviceTvmSoftwareInventory.md` is the anchor table for software-level context. Same applies to `DeviceTvmSecureConfigurationAssessment.md` + `DeviceTvmSecureConfigurationAssessmentKB.md`. Same applies to `DeviceTvmInfoGathering.md` + `DeviceTvmInfoGatheringKB.md`. Same applies to `DeviceBaselineComplianceAssessment.md` + `DeviceBaselineComplianceAssessmentKB.md`.

### DeviceTvmInfoGathering: AdditionalFields is native dynamic, but AvScanResults is nested string
`AdditionalFields` `gettype()` = `"dictionary"` — direct property access works without `parse_json()`. Exception: `AdditionalFields.AvScanResults` is `"string"` (nested JSON within the bag) — access inner fields with `parse_json(tostring(AdditionalFields.AvScanResults))`. Confirmed 2026-04.

### DeviceTvmInfoGathering: AvMode values
`AvMode` string values: `"0"` = Active, `"1"` = Passive, `"4"` = EDR Blocked.

### DeviceTvmInfoGathering: Defender-only table
Not in Sentinel (table not found). Defender-only, query via `run_hunting_query`. Has `Timestamp` column (assessment cycle time) and `LastSeenTime`.

### DeviceTvmInfoGatheringKB: static reference table, 90 rows
No `Timestamp`, no `DeviceId` — pure metadata catalog. Categories (confirmed 2026-04): `.NET 3.5`, `.NET 4.0`, `asr`, `communication`, `crypto`, `defender antivirus`, `network protocol`, `os`, `ssl`, `tls`, `vulnerability`. `Categories` is native dynamic array — `mv-expand` works without `parse_json()`. `Description` may contain HTML markup.

### DeviceTvmSecureConfigurationAssessment: has Timestamp (despite "snapshot" label)
The table HAS a `Timestamp` column (unlike `DeviceTvmSoftwareVulnerabilities`). It reflects the assessment time per device/config row. Still snapshot semantics — one row per (DeviceId, ConfigurationId). Do not narrow time windows; omit or use broad window.

### DeviceTvmSecureConfigurationAssessment: Context column is nested array
`Context` is `gettype()` = `"array"`. Outer array always has one element; `Context[0]` is itself an array of string values specific to the configuration. Access via `Context[0][N]`. The KB table does not document these per-ConfigurationId schemas; must sample live rows.

### DeviceTvmSecureConfigurationAssessment: always filter IsApplicable == 1
Many configurations are Windows-specific. macOS devices show ~87% not-applicable, iOS ~99%. Omitting `IsApplicable == 1` will massively overcount non-compliant rows.

### DeviceTvmSecureConfigurationAssessmentKB: Sentinel-only MITRE columns
`RelatedMitreTechniques` and `RelatedMitreTactics` are absent from Defender schema — Sentinel-only. Querying them via `run_hunting_query` causes semantic error.

### DeviceTvmSecureConfigurationAssessmentKB: RemediationOptions is HTML
`RemediationOptions` contains `<b>`, `<ol>`, `<li>`, `<a>` markup — not plain text. Strip tags if needed for non-HTML rendering.

### DeviceTvmSecureConfigurationAssessmentKB: ConfigurationBenchmarks and Tags confirmed values
`ConfigurationBenchmarks`: `CIS`, `STIG`, `MS`, `NIST`. Native dynamic string array, direct indexing works.
`Tags`: `UserImpactAssessment`, `HumanOperatedRansomware`, `covid19`. Sparse — most rows have empty array.

### DeviceTvmSecureConfigurationAssessmentKB: no Timestamp in Defender
`Timestamp` / `TimeGenerated` absent from Defender schema. Static reference table — no time filter possible or needed via `run_hunting_query`.

### DeviceTvmHardwareFirmware: snapshot, Defender-only, no Timestamp
Pure snapshot — one row per `(DeviceId, ComponentType)`. No `Timestamp` column (semantic error if used). Defender-only (Sentinel 400 error). Three ComponentTypes: `Hardware`, `Bios`, `Processor`. `ComponentVersion` is blank for `Processor` rows. `AdditionalFields` is native dynamic — `bag_keys()` and direct property access work without `parse_json()`. Keys vary by ComponentType: Bios → `BIOSReleaseDate`/`BIOSLastDetected`; Hardware → `SystemSKU`/`BaseBoardManufacturer`/`BaseBoardProduct`/`BaseBoardVersion`/`DeviceFamily`/`SystemFamily`; Processor → `ThreadsCount`/`Family`. `Manufacturer` is stored lowercase. No `ReportId` column.

### DeviceTvmHardwareFirmware: odata type annotation sibling keys in AdditionalFields
`ThreadsCount@odata.type` sibling keys appear in raw AdditionalFields output (e.g. `"ThreadsCount@odata.type": "#Int64"`) as type annotations. `bag_keys()` omits the `@odata.type` root key but DOES return these typed-field annotation siblings. Ignore them when iterating keys. Use `toint(AdditionalFields.ThreadsCount)` to access the actual value.

### DeviceTvmCertificateInfo: snapshot, Defender-only, no Timestamp
Covers device-level TLS/SSL and system certificates in Windows certificate store (NOT file-signing certs — that's `DeviceFileCertificateInfo`). No `Timestamp` column (semantic error if used). Sentinel 400 error. Primary key: `(DeviceId, Thumbprint)`. `IssuedTo` and `IssuedBy` are native dynamic dicts — direct property access works (keys: `CommonName`, `Organization`, `OrganizationalUnit`, `Locality`, `StateOrProvinceName`, `CountryName`). `KeyUsage` and `ExtendedKeyUsage` are native dynamic **arrays** (not dicts) — `bag_keys()` returns empty but array indexing and `mv-expand` work. Official docs list `KeySize`, `ExpirationDate`, `IssueDate` as `string` — they are `int`/`datetime` in live schema. `Path` format: `Microsoft.PowerShell.Security\Certificate::LocalMachine\<Store>\<Thumbprint>` — extract store with `split(Path,"\\")[2]`. No `ReportId` column.

### DeviceTvmCertificateInfo: official docs type errors
Docs say `KeySize: string`, `ExpirationDate: string`, `IssueDate: string`. Actual live schema: `KeySize: int`, `ExpirationDate: datetime`, `IssueDate: datetime`. This is another case where official docs are stale — always verify with `get_schema()`. Pattern applies to all Preview tables.

### DeviceBaselineComplianceAssessmentKB: static KB, 1146 rows, Defender-only
Pure catalog — no `Timestamp`, no `DeviceId`. Defender-only (Sentinel 400). Three `ConfigurationBenchmark` values: `"CIS"` (616), `"Microsoft"` (326), `"STIG"` (204). `BenchmarkProfileLevels`, `Source`, `RecommendedValue` are all native dynamic arrays (`gettype()` = `"array"`) — direct indexing and `mv-expand` work without `parse_json()`. `RemediationOptions` is HTML markup. `AssessmentMethod` values: `"Automatic"` (1077) or `"NotSupported"` (69). `Source` can have 1–13 registry paths per config. `ConfigurationDescription` and `ConfigurationRationale` also contain HTML.

### DeviceBaselineComplianceAssessment: per-device compliance snapshot, Defender-only
No `Timestamp` column. Snapshot — one row per (`DeviceId`, `ConfigurationId`). Always filter `IsApplicable == true` for gap analysis. `IsCompliant` and `IsExempt` are `bool` — use `== false`, not `== "0"` (web sources get this wrong). `Source`, `RecommendedValue`, `CurrentValue` are all native dynamic arrays. `MachineGroup` is Defender-only (not in docs). Table may be empty if no baseline profiles assigned.

### DeviceBaselineCompliance*: web source used IsCompliant == "0" (incorrect)
Online example queries (including those surfaced by web_grounded_answer) filter `IsCompliant == "0"` and `IsExempt == "0"`. Live schema confirms both are `bool` type — the correct filter is `== false`. Always verify bool vs string column type with `get_schema()` before trusting web samples.

### SecurityAlert: Sentinel-only table, all JSON columns are string-typed
Always query via `run_sentinel_query`. `run_hunting_query` returns empty even when workspace is onboarded to Defender portal.
- `Entities`, `ExtendedProperties`, `ExtendedLinks`, `RemediationSteps`, `Techniques`, `SubTechniques` are ALL `string` typed (not `dynamic`) in both Defender and Sentinel schema — use `parse_json(col)` directly (no `tostring()` wrapper needed).
- `Tactics` is a plain comma-separated string (NOT a JSON array) — split with `split(Tactics, ", ")` if needed.
- `Techniques`/`SubTechniques` ARE JSON string arrays — use `parse_json(Techniques)` + `mv-expand`.
- Primary key: `SystemAlertId` (GUID). `VendorOriginalId` is not globally unique.
- Join to `SecurityIncident`: `SecurityIncident.AlertIds` is a native dynamic array (not a string) — `mv-expand AlertIds` directly, then join on `SystemAlertId`. Note the SecurityAlert.md example used `mv-expand parse_json(AlertIds)` — redundant but harmless since parse_json on an array is a no-op.
- `ExtendedProperties` for `ASI *` alerts contains the firing KQL query in the `"Query"` field.
- `RemediationSteps` is a JSON string array of prose blocks (MDATP alerts only, blank for ASI/OATP).
- `SubTechniques` observed blank in practice — not reliably populated.

### SecurityAlert + SecurityIncident: companion table pair
When working on either table, update/check both reference files. SecurityIncident.md now exists (created 2026-05).

### SecurityIncident: update-append pattern (not upsert)
SecurityIncident writes a **new row** on every state change — same `IncidentNumber` produces many rows. Always deduplicate with `summarize arg_max(LastModifiedTime, *) by IncidentNumber` before any analysis. `TimeGenerated` = modification event time, not incident creation time.

### SecurityIncident: AlertIds is native dynamic array
`AlertIds` `gettype()` = `"array"` — direct `mv-expand AlertIds` works without `parse_json()`. Confirmed 2026-05. This is unlike `SecurityAlert.Entities` etc. which are string-typed. The SecurityAlert.md join example uses `mv-expand parse_json(AlertIds)` — that's redundant but harmless.

### SecurityIncident: Status enum
Confirmed values: `"New"`, `"Active"`, `"Closed"`. Note: this differs from SecurityAlert.Status which uses `"New"`, `"InProgress"`, `"Resolved"`.

### SecurityIncident: Classification only populated when Closed
`Classification` and `ClassificationReason` are blank on all non-closed incidents. Confirmed values: `TruePositive/SuspiciousActivity`, `BenignPositive/SuspiciousButExpected`, `FalsePositive/InaccurateData`, `Undetermined/(blank reason)`.

### SecurityIncident: AdditionalData.tactics is a native dynamic array
Unlike SecurityAlert.Tactics (comma-separated string), `AdditionalData.tactics` in SecurityIncident is a real dynamic array — direct indexing and `mv-expand` work without parsing.

### SecurityIncident: IncidentName is GUID, IncidentNumber is the human-facing ID
`IncidentName` = ARM resource GUID (appears in `IncidentUrl`). `IncidentNumber` = sequential int shown in portal. `ProviderIncidentId` = provider's own numeric ID (e.g. Defender's incident number) — distinct from `IncidentNumber`.

### SecurityIncident: ProviderName confirmed value
In tenants using Defender XDR as the primary SOC platform with Sentinel workspace onboarded: `ProviderName = "Microsoft XDR"` (not "Azure Sentinel" or similar). Verify in other configurations.

### UrlClickEvents: UrlChain and DetectionMethods are string-typed JSON, ThreatTypes is plain string
- `UrlChain`: `string`-typed JSON array — use `parse_json(UrlChain)` before indexing.
- `DetectionMethods`: `string`-typed JSON dict `{ThreatType: [methods]}` — use `parse_json(DetectionMethods)`.
- `ThreatTypes`: plain `string` — direct `has "Phish"` is correct, no parsing needed.
- `NetworkMessageId` is blank for Teams and Office clicks; also unreliable for Drafts/Sent items — cannot join to Email* tables in those cases.
- `Workload` confirmed values: `Email`, `Teams`, `Office`, `Copilot`.
- `ActionType` confirmed values (2026-04): `ClickAllowed`, `ClickBlocked`, `UrlErrorPage`, `ClickBlockedByTenantPolicy`.
- `ReportId` is a GUID string (like Email* tables) — globally unique, single-column join is safe.
- Requires MDO deployment; table empty without it.

### AlertInfo + AlertEvidence: combined reference file at AlertInfo.md
These tables are always documented together (reference file: `AlertInfo.md`).

### AlertInfo/AlertEvidence: AlertId prefix encodes source product
`sn` = Sentinel analytics, `fa` = MDO, `ca` = MDCA, `da` = MDE, `aa` = MDI. Confirmed live 2026-05. Useful for fast product-scoped filtering without needing `ServiceSource` column.

### AlertInfo: Category is a plain string, not JSON array
`AlertInfo.Category` = single tactic string (e.g. `"Persistence"`). By contrast, `AlertEvidence.Categories` is a JSON array string. Don't confuse the two — they differ in both name (singular vs plural) AND format (string vs JSON array).

### AlertInfo/AlertEvidence: AttackTechniques is a JSON array string in both tables
`gettype()` = `"string"`. Format: `'["Valid Accounts (T1078)","Cloud Accounts (T1078.004)"]'` — each element has name + T-number together. Use `parse_json(AttackTechniques)` + `mv-expand` to expand. Use `has "T1078"` for T-number pre-filtering (cheap bloom filter before parse).

### AlertEvidence: AdditionalFields is string in Defender, dynamic in Sentinel
Same divergence pattern as Device* tables. `parse_json(AdditionalFields)` works in both without `tostring()` wrapper. Contains full entity JSON — structure varies by EntityType.

### AlertEvidence: EntityType confirmed values (2026-05)
`User`, `Machine`, `File`, `Process`, `Ip`, `Url`, `MailMessage`, `MailCluster`, `Mailbox`, `CloudApplication`, `SecurityGroup`, `ActiveDirectoryDomain`, `RegistryValue`

### AlertEvidence: no join to Device* tables via ReportId
`AlertEvidence` has no `ReportId`. To correlate with `DeviceProcessEvents` etc., join on `DeviceId` extracted from `EntityType == "Machine"` rows. Do NOT attempt a `ReportId` join.

### AlertInfo + AlertEvidence: alert fanout trap
One alert = 1 AlertInfo row + N AlertEvidence rows. After joining, always `dcount(AlertId)` to count distinct alerts — `count()` counts entity rows, not alerts.

### IdentityDirectoryEvents: AdditionalFields is native dynamic in Defender
`gettype()` = `"dictionary"` in Defender — direct property access works. `@odata.type` wrapper key present but harmless. No `parse_json()` needed. Sentinel rows also native dynamic. Schema identical (no Defender/Sentinel divergence for AdditionalFields type).

### IdentityDirectoryEvents: ADCS Certificate issuance — Attributes is double-nested
`AdditionalFields.Attributes` is a **JSON-encoded string** (not a nested object) containing `CertificateTemplate`, `ccm` etc. Requires second `parse_json(tostring(af.Attributes))`. Disposition value `"3"` = issued. This is an exception to the "native dynamic" rule above — other AdditionalFields keys on this ActionType are direct-access.

### IdentityDirectoryEvents: actor vs target column semantics
`AccountName/Upn/Sid/ObjectId` = actor. `TargetAccountUpn/DisplayName` = subject account acted upon. `DestinationDeviceName/IP/Port` = DC that processed the action. `DeviceName/IPAddress/Port` = source client. For some ActionTypes (e.g. Directory Services replication) actor columns blank — use `AdditionalFields.SourceAccountId/SourceAccountSid` instead.

### IdentityDirectoryEvents: Category/AttackTechniques only when MDI flags event
`Category` and `AttackTechniques` in AdditionalFields are absent from routine benign events — only populated when MDI has a threat signal. `AttackTechniques` is a plain comma-separated string (not JSON array).

### IdentityDirectoryEvents: DestinationPort type diverges
`int` in Defender, `string` in Sentinel. Use `toint(DestinationPort)` for cross-platform numeric comparisons. Same for `Port`.

### IdentityDirectoryEvents: Sentinel rows have ARG.*/ACTOR.* extra keys
Sentinel-ingested rows include `ARG.TASK`, `ACTOR.ACCOUNT`, `ACTOR.ENT*` enrichment keys absent from Defender rows. Not reliable in cross-source queries.

### IdentityDirectoryEvents: requires MDI deployment
Table returns no results if Defender for Identity is not deployed. Note this when writing queries for environments where MDI status is unknown.

### IdentityLogonEvents: dual-source table — MDI (AD) and MDCA (cloud)
Two completely distinct row populations sharing the same schema:
- **MDI rows**: `Application = "Active Directory"`, `Protocol = Kerberos/Ntlm`, `Location = "INTERNAL_NETWORK"`. `LogonType` uses Windows descriptions (`Resource access`, `Failed logon`, `Credentials validation`, `Interactive`, `Remote desktop`).
- **MDCA rows**: `Application = Microsoft 365/Azure/Exchange/SharePoint/Teams`, `Protocol` = blank. `LogonType` uses OAuth/protocol method strings (`OAuth2:Authorize`, `SAS:EndAuth`, etc.). Non-interactive sign-ins NOT captured — those go to `AADNonInteractiveUserSignInLogs`/`EntraIdSignInEvents`.

### IdentityLogonEvents: AdditionalFields is native dynamic in both sources
`gettype()` = `"dictionary"` in both Defender and Sentinel. Direct property access works. `@odata.type` wrapper present in Defender rows but harmless. Key MDI fields: `ActionTypeInner`, `KerberosType`, `KdcOptions`, `Spns`, `EncryptionType`, `RequestTicketHash`, `Count` (string), `Category`, `AttackTechniques` (comma-separated string, NOT JSON array). Sentinel cloud rows add `ARG.*`/`ACTOR.*` enrichment keys absent from Defender.

### IdentityLogonEvents: UncommonForUser is native dynamic array, LastSeenForUser is native dynamic dict
`UncommonForUser`: `gettype()` = `"array"`, contains feature-name strings for dimensions that are unusual for this user. Filter `array_length(UncommonForUser) > 0` for anomaly hunting.
`LastSeenForUser`: `gettype()` = `"dictionary"`, int values (days since last seen = 0 means first-time). Defender rows include `FieldName@odata.type: "#Int64"` annotation siblings — ignore them. Access directly: `toint(LastSeenForUser.IPAddress)`.

### IdentityLogonEvents: Port and DestinationPort diverge by source
`int` in Defender, `string` in Sentinel — same pattern as `IdentityDirectoryEvents`. Use `toint()` for cross-platform comparisons.

### IdentityLogonEvents: ActionType is binary (only 2 values)
`LogonSuccess` and `LogonFailed` only. `FailureReason` blank on success; mix of short codes (MDI: `Generic`, `WrongPassword`, `AccountLocked`) and long human-readable strings (MDCA cloud) on failure.

### IdentityLogonEvents: Category/AttackTechniques same MDI pattern as IdentityDirectoryEvents
Only populated on MDI-flagged events. `AttackTechniques` is a comma-separated plain string. Confirmed techniques: Kerberoasting (T1558.003), Valid Accounts (T1078.002), RDP (T1021.001).

### IdentityLogonEvents: ReportId is GUID string (safe single-column join)
Unlike Device* tables, `ReportId` is a GUID string — globally unique. No composite key needed.

### IdentityLogonEvents: distinct from DeviceLogonEvents
MDI covers the identity/DC plane; MDE (`DeviceLogonEvents`) covers the endpoint plane for the same logon. Correlate on `AccountSid` + `Timestamp` window, not `ReportId`.

### IdentityLogonEvents: requires MDI for AD rows, MDCA for cloud rows
Table may be empty or partial if neither is deployed. Cloud rows only cover interactive + legacy protocol sign-ins (not all sign-ins).

### IdentityQueryEvents: MDI-only, three ActionTypes
`DNS query`, `LDAP query`, `SAMR query` — all `Application = "Active Directory"`. No MDCA rows (unlike IdentityLogonEvents). Requires MDI deployment. DNS query is highest-volume by far (~15x LDAP volume).

### IdentityQueryEvents: AdditionalFields is native dynamic in both sources
`gettype()` = `"dictionary"` in both Defender and Sentinel. Direct property access works — no `parse_json()` needed. `@odata.type` wrapper present in Defender rows, harmless. Sentinel rows add `ARG.TASK`, `FROM.DEVICE`, `TO.DEVICE`, `ACTOR.DEVICE` enrichment keys absent from Defender — same pattern as `IdentityDirectoryEvents` and `IdentityLogonEvents`.

### IdentityQueryEvents: LDAP-specific AdditionalFields keys
`BaseObject` (base DN), `LdapSearchScope` (`"WholeSubtree"`, `"SingleLevel"`, `"BaseObject"`), `SearchFilter` (full LDAP filter string). SAMR-specific: `QueriedUniqueEntityId`. Common to all: `ActionTypeInner` (`ldapquery`/`samrquery`/`dnsquery`), `Count` (string), `SourceComputerId`/`SourceComputerObjectGuid`/`SourceComputerSid`, `DestinationComputerObjectGuid`.

### IdentityQueryEvents: Category/AttackTechniques same MDI pattern as IdentityDirectoryEvents + IdentityLogonEvents
Only populated when MDI flags the event. `AttackTechniques` is comma-separated plain string (NOT JSON array). Common categories: `"Discovery"`. Common techniques: `"Domain Trust Discovery (T1482)"`, `"Permission Groups Discovery (T1069), Account Discovery (T1087)"`.

### IdentityQueryEvents: Query column blank for SAMR
`Query` is always blank for `SAMR query` ActionType. The target group/user name is in `QueryTarget` instead. LDAP `Query` contains a human-readable description of the search.

### IdentityQueryEvents: Port/DestinationPort int/string divergence
`int` in Defender, `string` in Sentinel — same pattern as `IdentityDirectoryEvents` and `IdentityLogonEvents`. Use `toint()` for cross-platform comparisons.

### Identity* table family: Port/DestinationPort int/string divergence is universal
Confirmed across `IdentityLogonEvents`, `IdentityDirectoryEvents`, `IdentityQueryEvents` — always `int` in Defender, `string` in Sentinel. Treat this as a rule for any Identity* table not yet verified.

### IdentityAccountInfo: Defender-only snapshot, Sentinel returns 400
`IdentityAccountInfo` returns HTTP 400 from Sentinel Log Analytics API — Defender-only. No `SentinelType` columns. Live schema includes `TimeGenerated` and `SourceSystem` Log Analytics system columns even though it's Defender-only; use `Timestamp` for time filtering.

### IdentityAccountInfo: GroupMembership contains display name strings, not IDs
`GroupMembership` is a native dynamic array of group **display name strings**. Not usable for programmatic group membership checks requiring GUIDs. All dynamic columns (`GroupMembership`, `AssignedRoles`, `EligibleRoles`, `EnrolledMfas`, `Tags`) are native dynamic — no `parse_json()` needed.

### IdentityAccountInfo: DefenderRiskLevel/DefenderRiskUpdateTime absent from live schema
Official docs list these two columns; they do not appear in the live schema. Same "docs ahead of schema" pattern seen in other tables.

### IdentityAccountInfo vs IdentityInfo
These overlap but differ. `IdentityInfo` is the standard enrichment join (Defender+Sentinel, key=`AccountObjectId`). `IdentityAccountInfo` is Defender-only, key=`AccountId`/`SourceProviderAccountId`, adds `EligibleRoles` (PIM), `EnrolledMfas`, identity-link metadata (`IdentityId`, `IsPrimary`, `IdentityLinkType`), and multi-source account federation. When working on privilege-escalation or MFA-gap queries, suggest `IdentityAccountInfo` over `IdentityInfo`.

### BehaviorAnalytics: all three dynamic columns are native dynamic
`UsersInsights`, `DevicesInsights`, `ActivityInsights` are all `gettype()` = `"dictionary"` — direct property access and `bag_keys()` work without `parse_json()` in both Defender and Sentinel. ActivityInsights boolean-flag values are **strings** (`"True"`/`"False"`), not booleans.

### BehaviorAnalytics: join key to UserPeerAnalytics
`UsersInsights.AccountObjectID` (from BehaviorAnalytics) == `UserPeerAnalytics.UserId`. There is NO top-level `UserId` column in BehaviorAnalytics — must extract from the dynamic field. When working on BehaviorAnalytics queries, always note the UserPeerAnalytics companion and the IdentityInfo enrichment join.

### UserPeerAnalytics: UPN/UserName columns always blank
`UserPrincipalName`, `UserName`, `PeerUserPrincipalName`, `PeerUserName` are always blank in live data. Only `UserId`/`PeerUserId` (Entra GUIDs) are populated. Rank range is 1–20. Join to `IdentityInfo` on `AccountObjectId` to resolve names.

### UserPeerAnalytics: update-append table, deduplicate needed
Same (UserId, PeerUserId, Rank) combination appears across multiple `TimeGenerated` rows. Always deduplicate with `summarize arg_max(TimeGenerated, *) by UserId, PeerUserId` before analysis.

### BehaviorAnalytics: ActivityType casing inconsistency
`Logon` and `LogOn` both appear as ActivityType values in live data — they coexist. Do not assume one canonical casing. Use case-insensitive `=~` or `in~` if filtering by ActivityType.

### BehaviorAnalytics: ActivityInsights context keys vary by ActivityType
Beyond the boolean anomaly flags, `ActivityInsights` also contains scalar context keys like `Resource`, `App`, `LogonMethod`, `EventResult`, `EventCount`, `LastTimeUserPerformedAction`, `NewProcessName`, `ParentProcessName` etc. These vary based on source event type — always live-sample before relying on a specific key.

### ExposureGraphNodes + ExposureGraphEdges: combined reference file at ExposureGraphNodes.md
Both tables documented together. Defender-only (Sentinel returns 400). No Timestamp column.

### ExposureGraphNodes: NodeProperties rawData wrapper (not double-serialized)
`NodeProperties` is native dynamic (`gettype()` = `"dictionary"`), `bag_keys()` = `["rawData"]`. All payload is under `.rawData`. Do NOT attempt `parse_json(tostring())` — not needed. BUT do NOT access `.fieldName` directly at top level — always go via `.rawData.fieldName`. Already documented in kql-facts.md.

### ExposureGraphNodes: EntityIds elements are native dynamic dicts
`EntityIds[0]` is a native dynamic dict (not a JSON string). `gettype()` = `"dictionary"`. Access `.type` and `.id` directly. `AadObjectId` `.id` format: `"tenantid=<guid>;objectid=<guid>"`.

### ExposureGraphNodes: NodeLabel casing is inconsistent
Mix of lowercase (`device`, `user`, `group`), PascalCase (`Cve`), kebab-case (`mde-healthFinding`), Azure resource paths (`microsoft.compute/virtualmachines`). Use `=~` or `in~` when uncertain.

### ExposureGraphEdges: EdgeProperties roles are double-nested JSON strings
`EdgeProperties.rawData.permissions.roles` is a dynamic array, but each element is a **JSON string** (not a native dict) — requires `parse_json(tostring(role))` to access `id`, `name`, `actions`. Confirmed on `has role on` edges.

### ExposureGraphEdges: EdgeProperties may be empty rawData
`affecting` edges have `rawData` present but no child keys. Always check before accessing sub-fields.

### ExposureGraphNodes/ExposureGraphEdges: table population depends on deployed products
MDI required for identity edges; Defender for Cloud for `mdcSecurityRecommendation` nodes and Azure resource edges. Warn when querying in unknown-product-deployment contexts.

### ExposureGraphNodes: @odata.type annotation sibling keys everywhere
Same `fieldName@odata.type: "#Collection(String)"` / `"#Int64"` annotation pattern as other tables. Appears throughout `rawData` for array and typed scalar fields. Ignore when iterating bag_keys.

### MessageEvents + MessageUrlInfo: combined reference at MessageEvents.md
Defender-only (Sentinel 400). Both tables. Join key is `TeamsMessageId`. Requires MDO deployment.

### MessageEvents: column names differ from official docs
Official docs use `MessageFormatType`, `MessageFormatSubtype`, `MessageSubject`. Live schema names: `MessageType`, `MessageSubtype`, `Subject`. `ThreadName` is in live schema but not in docs. `LastEditedTime` is `datetime` in live schema, docs say `string`. Always use live schema names.

### MessageEvents: RecipientDetails is native dynamic array
`gettype()` = `"array"`, elements are native dynamic dicts. Direct `mv-expand` and property access work — no `parse_json()` needed. `@odata.type` wrapper key present in elements but harmless.

### MessageEvents: ThreatTypes/DetectionMethods/ConfidenceLevel blank in benign tenants
In practice >99% of rows have all three blank. ThreatTypes is plain string; DetectionMethods and ConfidenceLevel are dynamic. Do not use these columns for volume/counting queries.

### MessageUrlInfo: ThreatTypes absent from live schema despite docs listing it
Querying `ThreatTypes` on MessageUrlInfo causes semantic error (column does not exist). Only `MessageEvents` carries the threat verdict.

### MessageUrlInfo: ReportId is composite string, not a simple GUID
Format: `<guid>_<long-integer>`. Multiple URLs from the same message produce distinct ReportId values. Join across tables via `TeamsMessageId`, not `ReportId`.

### UrlClickEvents: TeamsMessageId join path
`UrlClickEvents` with `Workload == "Teams"` can be joined to `MessageEvents`/`MessageUrlInfo` via `TeamsMessageId`. Note: in UrlClickEvents the equivalent column may need extraction from the `Url` column — check UrlClickEvents.md for current confirmed join keys.

### CloudAuditEvents: Defender for Cloud control-plane table (not SaaS app events)
Covers Azure ARM, AWS, GCP, Kubernetes control-plane audit. Requires Defender for Cloud integration. Sentinel returns 400.
- `ActionType` values in live data are `CloudAuditEvent{Create,Read,Update,Delete,Other,Get}` — docs omit the `CloudAuditEvent` prefix entirely (wrong).
- Live schema has `AzureResourceId`, `AwsResourceName`, `GcpFullResourceName` — docs incorrectly show a single `ResourceId` column.
- `ISP` is uppercase in live schema; docs show `Isp`.
- `AdditionalFields` is always null in Azure rows — do not parse it.
- `Account` = subscription GUID for Azure service-principal actions (not a UPN). Actor identity in `RawEventData.principalOid`.
- `RawEventData` is native dynamic. But `RawEventData.httpRequest`, `RawEventData.claims`, `RawEventData.authorization` are **JSON strings** inside the bag — each needs `parse_json(tostring(RawEventData.fieldName))`.
- `RawEventData.caller` is blank for Azure rows.
- `ReportId` for Azure rows equals `RawEventData.correlationId`.

### CloudAuditEvents vs CloudAppEvents: completely different tables
`CloudAuditEvents` = Defender for Cloud infrastructure control-plane (Azure/AWS/GCP/K8s).
`CloudAppEvents` = MDCA SaaS app connector (M365, Exchange, SharePoint, Teams, 3rd-party SaaS).
Do not confuse them. Both are Defender-only in practice (Sentinel 400 for CloudAuditEvents; CloudAppEvents present in Sentinel but empty).

### MicrosoftPurviewInformationProtection: Basic log — pre-filter aggressively
Table is classified as **Basic log** in Azure Monitor. Queryable via both `run_hunting_query` and `run_sentinel_query` with identical row counts. Uses `TimeGenerated` (not `Timestamp`). No `ReportId` column.

### MicrosoftPurviewInformationProtection: dominant event type is NOT a label change
`SensitivityLabeledFileOpened` (RecordTypeName: `SensitivityLabeledFileAction`) is the highest-volume Operation by far — it tracks that a labelled file was opened, not that a label changed. Exclude `Operation in ("SensitivityLabeledFileOpened", "SensitivityLabeledFileRenamed")` when hunting for label lifecycle changes.

### MicrosoftPurviewInformationProtection: dynamic column population is sparse
Most dynamic columns (`Common`, `SensitiveInfoTypeData`, `ConditionMatch`, `RuleActions`, `SharePointMetaData`, `ExchangeMetaData`, `Receivers`, `AppAccessContext`) are null for `SensitivityLabeledFileAction` rows (the majority). `EmailInfo` is populated only on email-based `SensitivityLabelAction` rows. `CurrentProtectionType`/`PreviousProtectionType` are native dynamic dicts populated on file events. `DataState` and `Scope` are always blank in live data (2026-04).

### MicrosoftPurviewInformationProtection: official docs page 404s
The expected docs URL `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-microsoftpurviewinformationprotection-table` returns 404 (2026-04). Use the Azure Monitor reference instead: `https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftpurviewinformationprotection`.

### CloudStorageAggregatedEvents: major docs/live schema mismatch — docs columns live in AdditionalFields
Docs list `FirstEventTimestamp`, `LastEventTimestamp`, `CountryName`, `CityName`, `ProvinceName`, `ClientSystemServiceName`, `ClientCloudPlatformName`, `IsTorExitNode`, `IsKnownSuspiciousIp`, `IsPrivateIp`, `SuspiciousUserAgentName`, `HashReputationMd5List` as top-level columns. In the live schema **all of these are absent as top-level columns** — they are inside `AdditionalFields` (native dynamic, no `parse_json()` needed). `SuspiciousUserAgentName` and `HashReputationMd5List` not observed in live AdditionalFields keys either.

### CloudStorageAggregatedEvents: aggregation table, not event stream
One row per (storage account, IP, identity, auth type) per hour. `DataAggregationStartTime`/`DataAggregationEndTime` are the bucket boundaries. `Timestamp` = ingestion time (~1 hr after bucket end). Only `ActionType` value: `"Data Aggregation"`. Defender-only (Sentinel 400). Requires Defender for Cloud integration.

### CloudStorageAggregatedEvents: OperationNamesList and Md5Hashes are native dynamic arrays
Both `gettype()` = `"array"` — direct `mv-expand` and indexing work without `parse_json()`. `Md5Hashes` is usually an empty array `[]` even in active Defender for Storage tenants.

### CloudStorageAggregatedEvents: join to StorageBlobLogs for per-request detail
`StorageBlobLogs` (Sentinel) provides individual request rows. Use `StorageAccount` or `AzureResourceId` as the join bridge between `CloudStorageAggregatedEvents` (aggregated, Defender) and `StorageBlobLogs` (per-request, Sentinel). Always note both tables when writing Azure Storage hunting queries.

### Anomalies: Basic log — Sentinel-only, pre-filter aggressively
Sentinel-only (`SecurityInsights`). Basic log (more expensive per-query). Always pre-filter with `TimeGenerated` and ideally `AnomalyTemplateName` before accessing dynamic columns.

### Anomalies: Tactics/Techniques are JSON array strings despite string schema type
`Tactics` and `Techniques` are `string`-typed in schema but contain JSON arrays at rest (e.g. `["Persistence","Collection"]`). Use `parse_json(Tactics)` + `mv-expand` before indexing. Use `Tactics has "Persistence"` as a cheap bloom filter pre-check.

### Anomalies: ExtendedProperties double-serializes ActivityInsights/UserInsights/DeviceInsights
The `ExtendedProperties` dynamic dict contains copies of `ActivityInsights`, `UserInsights`, `DeviceInsights` as **JSON-encoded strings** — `parse_json(tostring(ExtendedProperties.ActivityInsights))` needed. Prefer the top-level columns which are already native dynamic.

### Anomalies: ActivityInsights boolean flags are strings ("True"/"False")
Same pattern as BehaviorAnalytics.ActivityInsights. Values are string `"True"`/`"False"`, not booleans. Use `tostring(ActivityInsights.SomeFlag) == "True"`, not `tobool()`.

### Anomalies: RuleStatus can be blank for UEBA rules
`RuleStatus` = `"Production"` for ML rules; blank `""` for UEBA rules. Do not filter `== "Production"` unless you intend to exclude UEBA anomalies.

### Anomalies: RuleId == AnomalyTemplateId for built-in rules
For out-of-box rules, `RuleId` and `AnomalyTemplateId` hold the same GUID. `RuleId` = analytics rule instance; `AnomalyTemplateId` = template. They diverge only if a custom copy of the rule is created.

### Anomalies: Entities uses $id/$ref JSON reference syntax
`Entities` is native dynamic array but elements use `{"$id": "N", ...}` and `{"$ref": "N"}` cross-reference syntax. Skip `$ref`-only elements with `where isnotempty(tostring(Entity.Type))`.

### Anomalies: ExtendedLinks contains raw KQL source queries
`ExtendedLinks[0].DetailBladeInputs` contains the full KQL query string that produced the anomaly's underlying events. Useful for drilldown into source tables (OfficeActivity, BehaviorAnalytics, etc.).

### Anomalies: BehaviorAnalytics companion join
UEBA anomalies derive from `BehaviorAnalytics`. Join via `UserPrincipalName` + overlapping `TimeGenerated` window. `UserInsights.AccountObjectID` joins to `IdentityInfo.AccountObjectId` for enrichment. When working on Anomalies queries, suggest BehaviorAnalytics drilldown for UEBA rows.

### Anomalies: no direct join key to SecurityAlert/SecurityIncident
No shared column for a direct join. Correlate via `UserPrincipalName` + time window overlap.

### FileMaliciousContentInfo: SHA256 is hex-encoded base64, NOT standard hex
`SHA256` column is 88 chars — the SHA256 hash stored as a base64 string (44 chars, e.g. `SEvDXjENk8zYdmqtgfCTKDp+y55TSPUF3+N8SvvA5lQ=`) where each ASCII char of the base64 is hex-encoded. All other Defender tables (EmailAttachmentInfo, DeviceFileEvents, etc.) use standard 64-char lowercase hex. Cannot join on SHA256 across tables without conversion. `unhex()` is not available in Defender KQL — cross-table file correlation must use FileName + time/user context.

### FileMaliciousContentInfo: majority of rows are clean scans
Despite the table name, most rows are benign files scanned by MDO Safe Attachments — `ThreatTypes`/`ThreatNames`/`DetectionMethods` are blank on clean files. Filter `isnotempty(ThreatTypes)` to isolate actual detections.

### FileMaliciousContentInfo: Sentinel is Basic log, Lake-only — rows absent in practice
Azure Monitor marks this as Basic log + Lake-only ingestion. In practice Sentinel returns no rows. Treat as Defender-only for query purposes.

### FileMaliciousContentInfo: ThreatTypes is string (not dynamic despite docs)
Official docs say `ThreatTypes` is `dynamic`. Live schema (both Defender and Sentinel): `string`. Use `has "Malware"` etc. — no `parse_json()` needed.

### FileMaliciousContentInfo: DetectionMethods diverges — dynamic in Defender, string in Sentinel
Live Defender schema: `dynamic`. Sentinel schema: `string`. Use `parse_json(tostring(DetectionMethods))` for cross-source portability.

### FileMaliciousContentInfo: DocumentID uses capital D (docs say DocumentId)
Live schema column name: `DocumentID`. Official docs say `DocumentId`. Capital D form is correct in queries.

### FileMaliciousContentInfo: FolderPath is SharePoint site URL, not filesystem path
Contains the SharePoint/OneDrive site URL (e.g. `https://contoso-my.sharepoint.com/personal/...`), not a file system path.

### FileMaliciousContentInfo: Workload values confirmed (2026-05)
`OneDrive`, `MicrosoftTeams`, `SharePoint`.
