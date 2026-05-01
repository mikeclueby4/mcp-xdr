# MicrosoftPurviewInformationProtection

Microsoft Purview Information Protection audit logs: sensitivity label lifecycle events (applied, changed, removed), protection events, DLP policy matches, and file sensitivity actions from across the M365 workloads.

## Sources

Both **Defender** (`run_hunting_query`) and **Sentinel** (`run_sentinel_query`, solution: `SecurityInsights`). Counts are identical between sources — confirmed same rows ingested both ways.

Time column: `TimeGenerated` (not `Timestamp`).

## Event taxonomy via RecordType / RecordTypeName

| RecordType | RecordTypeName | Primary Operations | Notes |
|---|---|---|---|
| 83 | `SensitivityLabelAction` | `SensitivityLabelApplied`, `SensitivityLabelUpdated` | Manual/auto label on email/file; `EmailInfo` populated for email |
| 84 | `SensitivityLabeledFileAction` | `SensitivityLabeledFileOpened`, `SensitivityLabeledFileRenamed` | High-volume file-open/rename tracking; sensitivity unchanged |
| SharePointFileOperation | `SharePointFileOperation` | `FileSensitivityLabelApplied`, `FileSensitivityLabelChanged` | SharePoint-sourced label ops |
| MIPLabel (int) | `MIPLabel` | `MipLabel` | Exchange/transport rule label matches |

`RecordTypeName` can be blank for some `SensitivityLabelApplied` rows — filter on `Operation` directly rather than `RecordTypeName` for reliable results.

## Confirmed Operation values (live, 2026-04)

```
SensitivityLabeledFileOpened     — highest volume by far; file opened in labelled state
SensitivityLabeledFileRenamed
SensitivityLabelApplied          — label applied to file or email
SensitivityLabelUpdated          — label changed (e.g. upgraded, changed same order)
MipLabel                         — Exchange transport rule match
FileSensitivityLabelApplied      — SharePoint-specific
FileSensitivityLabelChanged      — SharePoint-specific
```

## Key columns

| Column | Notes |
|---|---|
| `Operation` | Primary event discriminator — use this, not `RecordTypeName` |
| `UserId` | UPN of the user who performed the action |
| `ObjectId` | Full URL/path of the file (SharePoint/OneDrive) or item name |
| `LabelName` | Display name of the label applied (`SensitivityLabelAction` rows) |
| `SensitivityLabelId` | GUID of the label |
| `OldSensitivityLabelId` | Previous label GUID (when label was changed) |
| `LabelAction` | Additional label action detail (e.g. `ApplyHeader`, `Encrypt`, `None`) |
| `LabelEventType` | `LabelChangedSameOrder`, `LabelUpgraded`, etc. — blank in `SensitivityLabeledFileAction` rows |
| `ActionSource` | `Manual`, `Default`, `Automatic`, blank. Indicates if user or policy applied label |
| `ActionSourceDetail` | E.g. `AutoByReplyOrForward`, `None` — extra context for `ActionSource` |
| `JustificationText` | Populated only when policy requires justification for downgrade/removal |
| `PolicyId` / `PolicyName` | DLP/auto-labeling policy that triggered; blank for manual label ops |
| `ExecutionRuleId` / `ExecutionRuleName` | Rule within the policy that fired |
| `Workload` | `PublicEndpoint`, `Exchange`, `SharePoint`, `OneDrive` |
| `Application` | `Word`, `Excel`, `PowerPoint`, `Outlook`, blank (for SharePoint/OneDrive WAC) |
| `Platform` | `Windows`, `Mac`, `iOS`, `Android`, `WebBrowser`, `Wac`, `WinDesktop` |
| `DeviceName` | Endpoint hostname; `outlook.office.com` for web-based Outlook |
| `ClientIP` | IPv4 or IPv6 |
| `DataState` | Always blank in live data (2026-04) — do not rely on |
| `Scope` | Always blank in live data (2026-04) — do not rely on |

## Dynamic columns

All dynamic columns are `null` for the dominant `SensitivityLabeledFileAction` rows. Populate conditionally by event type.

| Column | Type | Keys / Structure | Populated when |
|---|---|---|---|
| `EmailInfo` | native dynamic dict | `bcc`, `cc`, `from`, `subject`, `to` | `SensitivityLabelAction` on email (`Application == "Outlook"`) |
| `CurrentProtectionType` | native dynamic dict | `documentEncrypted` (bool), `owner` (string), `protectionType` (int), `templateId` (string) | File-based events; reflects current protection state |
| `PreviousProtectionType` | native dynamic dict | same keys as above | File-based events; reflects prior protection state |
| `AppAccessContext` | native dynamic | app access context for service principal actions | Sparse — service/app-driven operations only |
| `SensitiveInfoTypeData` | dynamic | sensitive info type detection details | DLP policy match rows |
| `ConditionMatch` | dynamic | condition that triggered auto-label | Auto-labeling rows |
| `RuleActions` | dynamic | actions defined by the fired rule | DLP/auto-label policy match rows |
| `SharePointMetaData` | dynamic | SharePoint auto-labeling metadata | `SharePointFileOperation` rows |
| `ExchangeMetaData` | dynamic | Exchange auto-labeling metadata | Exchange/transport rule rows |
| `OverriddenActions` | dynamic | actions overridden by rule | Policy rows with overrides |
| `Receivers` | dynamic | array of receiver email addresses | Some email rows (distinct from `EmailInfo.to`) |
| `Common` | dynamic | AIP common event data | AIP client-side rows |

`CurrentProtectionType` and `PreviousProtectionType` are **native dynamic dicts** — direct property access works without `parse_json()`. Confirmed `gettype()` = `"dictionary"`.

`EmailInfo` is a **native dynamic dict** — direct property access works. Keys confirmed: `bcc` (array), `cc` (array), `from` (string), `subject` (string), `to` (array).

## Workload / Application distribution (confirmed 2026-04)

Dominant: `PublicEndpoint` + `Excel`/`Word`/`PowerPoint` on Windows, Mac, iOS, Android.
`Exchange` workload rows carry `EmailInfo`.
`SharePoint`/`OneDrive` with `Wac`/`WinDesktop` platform cover browser and sync client.

## Hunting patterns

### Find manual label downgrades or removals with justification

```kql
MicrosoftPurviewInformationProtection
| where TimeGenerated > ago(30d)
| where ActionSource == "Manual"
| where isnotempty(JustificationText)
| project TimeGenerated, UserId, ObjectId, LabelName, OldSensitivityLabelId, ActionSourceDetail, JustificationText
| sort by TimeGenerated desc
```

### Sensitivity label applied to email (Outlook)

```kql
MicrosoftPurviewInformationProtection
| where TimeGenerated > ago(30d)
| where Operation in ("SensitivityLabelApplied", "SensitivityLabelUpdated")
| where Application == "Outlook"
| extend Subject = tostring(EmailInfo.subject), From = tostring(EmailInfo.from)
| project TimeGenerated, UserId, LabelName, LabelEventType, ActionSource, Subject, From
| sort by TimeGenerated desc
```

### DLP / auto-label policy matches

```kql
MicrosoftPurviewInformationProtection
| where TimeGenerated > ago(30d)
| where isnotempty(PolicyName)
| summarize Count=count() by PolicyName, ExecutionRuleName, Operation, Severity
| sort by Count desc
```

### Label activity summary by user

```kql
MicrosoftPurviewInformationProtection
| where TimeGenerated > ago(7d)
| where Operation !in ("SensitivityLabeledFileOpened", "SensitivityLabeledFileRenamed")
| summarize Events=count(), Labels=dcount(LabelName) by UserId
| sort by Events desc
```

## Notes

- `SensitivityLabeledFileOpened` and `SensitivityLabeledFileRenamed` are very high-volume background telemetry (file tracking, not label change events). Exclude these when hunting for label lifecycle changes.
- `LabelEventType` is blank on `SensitivityLabeledFileAction` rows — only present on `SensitivityLabelAction` rows.
- No `ReportId` column — this table has no join key to Device* or Email* tables beyond `UserId`/`DeviceName`/`TimeGenerated` correlation.
- `ItemSize` is typed `string` despite being numeric bytes — cast with `tolong(ItemSize)` for comparisons.
- Table is classified as **Basic log** in Azure Monitor — higher query cost in Sentinel if queried against large time windows. Pre-filter aggressively on `TimeGenerated` and `Operation`.
