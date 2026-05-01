# FileMaliciousContentInfo

**Status**: Preview (as of 2026-05)
**Source**: Defender for Office 365 (MDO) — Safe Attachments scanning of SharePoint Online, OneDrive, and Microsoft Teams files
**Requires**: MDO deployment. Table empty without it.
**Defender**: Yes (primary). **Sentinel**: Technically present (`SecurityInsights` solution, Basic log, Lake-only ingestion) but rows consistently absent in practice — treat as Defender-only for query purposes.

## Purpose

Records files processed by MDO Safe Attachments. Despite the name, the **majority of rows represent clean files** — every scanned file gets a row, not just malicious ones. `ThreatTypes`/`ThreatNames`/`DetectionMethods` are blank on benign rows. Use to audit what was scanned, or filter for malicious detections.

## Workload values (confirmed live)

`OneDrive`, `MicrosoftTeams`, `SharePoint`

## CRITICAL: SHA256 encoding is NOT standard hex

`SHA256` is stored as **hex-encoded base64** (88 chars), not the standard 64-char lowercase hex used by all other Defender tables.

- Standard SHA256 hex (64 chars): `0a9e89001f52351cfc61df359d569c1a...`
- FileMaliciousContentInfo SHA256 (88 chars): `53457644586a454e6b387a59646d7174...`

The 88-char value is the SHA256 base64 string (44 chars, e.g. `SEvDXjENk8zYdmqtgfCTKDp+y55TSPUF3+N8SvvA5lQ=`) with each ASCII character hex-encoded.

**Consequence: cannot directly join on SHA256 to `EmailAttachmentInfo`, `DeviceFileEvents`, `DeviceFileCertificateInfo`, or any other Defender table.** There is no built-in KQL function to convert between these formats in Defender Advanced Hunting (`unhex()` is not available). Cross-table file correlation must use alternative keys (`FileName`, `DocumentID`, or time + user context).

## DocumentID column name

Live schema uses `DocumentID` (capital D at end). Official docs write `DocumentId` (lowercase d). Use the capital-D form in queries.

## FolderPath

Contains the SharePoint/OneDrive **site URL**, not a filesystem path. Example: `https://contoso-my.sharepoint.com/personal/user_contoso_com`. Use `has` or `startswith` for filtering.

## ThreatTypes and DetectionMethods — type divergence

| Column | Defender type | Sentinel type | Notes |
|---|---|---|---|
| `ThreatTypes` | `string` | `string` | Docs incorrectly say `dynamic`. Plain string — no `parse_json()` needed. Known values from Threat Explorer: `Malware`, `Phish`, `Spam`, `Block`. Use `has "Malware"` to filter. |
| `DetectionMethods` | `dynamic` | `string` | Docs say `string` for both — live Defender schema says `dynamic`. Blank on most rows. When populated, use `parse_json(tostring(DetectionMethods))` for cross-source portability. Known detection technology values (from Threat Explorer): `File detonation`, `File detonation reputation`, `File reputation`, `Antimalware protection`, `Advanced filter`, `Fingerprint matching`, etc. |
| `ThreatNames` | `string` | `string` | Malware family name. Blank when no detection. |

## ReportId

GUID string — globally unique per event. Single-column join is safe (same as Email*/Identity* family).

## Hunting patterns

```kql
// Find confirmed malicious files in cloud storage
FileMaliciousContentInfo
| where Timestamp > ago(30d)
| where isnotempty(ThreatTypes)
| project Timestamp, Workload, FileName, FolderPath, FileOwnerUpn, ThreatTypes, ThreatNames, DetectionMethods, SHA256, DocumentID

// Audit scanned file volume by workload
FileMaliciousContentInfo
| where Timestamp > ago(7d)
| summarize Total=count(), Malicious=countif(isnotempty(ThreatTypes)) by Workload
| sort by Total desc

// Find malicious files by owner
FileMaliciousContentInfo
| where Timestamp > ago(30d)
| where ThreatTypes has "Malware" or ThreatTypes has "Phish"
| summarize MaliciousFiles=count(), Files=make_set(FileName, 20) by FileOwnerUpn
| sort by MaliciousFiles desc
```

## Cross-table joins

- **Cannot join on SHA256** to other Defender tables — encoding mismatch (see above).
- Join to `EmailAttachmentInfo` via `FileName` + time window as approximate correlation only.
- `DocumentID` (GUID) is SharePoint's unique file identifier — not present in other hunting tables.
- `FileOwnerUpn` / `LastModifyingAccountUpn` → `IdentityInfo` on `AccountUpn` for user enrichment.

## Schema notes (docs vs live)

| Issue | Detail |
|---|---|
| `ThreatTypes` docs type | Docs say `dynamic`; live schema `string` in both sources |
| `DetectionMethods` docs type | Docs say `string`; live Defender schema says `dynamic` |
| `DocumentId` vs `DocumentID` | Docs use lowercase `d`; live schema uses capital `D` |
| Sentinel availability | Azure Monitor marks as Basic log + Lake-only — rows absent in practice |
| Table name | Still Preview as of 2026-05 |
