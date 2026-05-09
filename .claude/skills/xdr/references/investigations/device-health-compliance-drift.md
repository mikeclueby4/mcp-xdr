# Device Health & Compliance Drift

**When to use:** "Which devices are falling behind on Defender updates?", "Show me our compliance posture across the fleet", "Which devices have been offline for 30+ days?", "Is real-time protection enabled on all workstations?", "What Defender version are devices running?", seasonal fleet health reviews where devices go dark for weeks/months.

---

## Table strategy

| Signal | Table | Tool | Notes |
|---|---|---|---|
| Last heartbeat, sensor health, offline duration | `DeviceInfo` | `run_hunting_query` | Snapshot; `arg_max(Timestamp,*)` per device |
| AV versions, real-time protection, behavior monitoring, scan state | `DeviceTvmInfoGathering` | `run_hunting_query` | Defender-only; `AdditionalFields` is native dynamic |
| Intune compliance + managed state | `EntraIdSignInEvents` | `run_hunting_query` | Per-sign-in; last known values via `arg_max`. Absent for devices that haven't signed in. |
| DLP config + Defender protection state (alternate source) | `DeviceInfo.DlpInfo` | `run_hunting_query` | Defender-only JSON column; see parsing pattern below |
| Intune compliance state (richer, if configured) | `IntuneDeviceComplianceOrg` | `run_sentinel_query` | Daily snapshot. Only present if Intune Diagnostic Settings export is enabled — see below. |

---

## Seasonal offline device problem

`DeviceInfo` retains rows for devices that have gone dark — they don't disappear, they just stop updating. Use `SensorHealthState` + `DaysSinceLastSeen` to segment:

- `"Active"` — checked in within ~7 days
- `"Inactive"` — 7–30 days dark
- `"No sensor data"` — extended absence; sensor may be disabled
- `"Misconfigured"` — sensor present but not reporting correctly

`Timestamp` in `DeviceInfo` is the last heartbeat, not a query-time value. Always compute age at query time:

```kql
| extend DaysSinceLastSeen = datetime_diff('day', now(), Timestamp)
```

---

## Per-device health snapshot (full join)

Joins `DeviceInfo` + `DeviceTvmInfoGathering` (AV state) + `EntraIdSignInEvents` (Intune compliance).

```kql
let DeviceBase = DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | where OnboardingStatus == "Onboarded"
    | where DeviceType in ("Workstation", "Server")
    | extend DlpParsed = parse_json(tostring(DlpInfo))
    | extend
        IsRealTimeProtectionEnabled = tobool(DlpParsed.IsDefenderRealTimeProtectionEnabled),
        IsBehaviorMonitoringEnabled = tobool(DlpParsed.IsDefenderBehaviorMonitoringEnabled),
        IsDlpEnabled = tobool(DlpParsed.IsDlpEnabled),
        IsDlpConfigurationValid = tobool(DlpParsed.IsDlpConfigurationValid)
    | project
        DeviceId, DeviceName, OSPlatform, OSVersion, MachineGroup,
        SensorHealthState, LastHeartbeat = Timestamp,
        IsAzureADJoined, JoinType, AadDeviceId, OnboardingStatus,
        IsRealTimeProtectionEnabled, IsBehaviorMonitoringEnabled,
        IsDlpEnabled, IsDlpConfigurationValid;
let AvState = DeviceTvmInfoGathering
    | summarize arg_max(Timestamp, *) by DeviceId
    | extend
        AvMode = tostring(AdditionalFields.AvMode),
        AvEngineVersion = tostring(AdditionalFields.AvEngineVersion),
        AvSignatureVersion = tostring(AdditionalFields.AvSignatureVersion),
        AvPlatformVersion = tostring(AdditionalFields.AvPlatformVersion),
        AvSignatureUpdateTime = todatetime(AdditionalFields.AvSignatureUpdateTime),
        CloudProtectionState = tostring(AdditionalFields.CloudProtectionState)
    | project DeviceId, AvMode, AvEngineVersion, AvSignatureVersion,
        AvPlatformVersion, AvSignatureUpdateTime, CloudProtectionState;
let IntuneState = EntraIdSignInEvents
    | summarize arg_max(Timestamp, *) by EntraIdDeviceId
    | where isnotempty(EntraIdDeviceId)
    | project EntraIdDeviceId, IsManaged, IsCompliant, LastSignInUser = AccountUpn;
DeviceBase
| join kind=leftouter AvState on DeviceId
| join kind=leftouter IntuneState on $left.AadDeviceId == $right.EntraIdDeviceId
| extend DaysSinceLastSeen = datetime_diff('day', now(), LastHeartbeat)
| project
    DeviceName, OSPlatform, OSVersion, MachineGroup,
    SensorHealthState, DaysSinceLastSeen, LastHeartbeat,
    IsAzureADJoined, JoinType,
    IsManaged, IsCompliant,
    AvMode, AvSignatureVersion, AvEngineVersion, AvPlatformVersion,
    AvSignatureUpdateTime, CloudProtectionState,
    IsRealTimeProtectionEnabled, IsBehaviorMonitoringEnabled,
    IsDlpEnabled, IsDlpConfigurationValid,
    LastSignInUser
| sort by DaysSinceLastSeen desc
```

---

## Offline device summary (within 30-day retention window)

Defender Advanced Hunting retains 30 days — devices dark longer than that drop out of `DeviceInfo` entirely. Useful segmentation is within that window only.

```kql
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| where OnboardingStatus == "Onboarded"
| where DeviceType in ("Workstation", "Server")
| extend DaysSinceLastSeen = datetime_diff('day', now(), Timestamp)
| summarize
    TotalDevices  = count(),
    Active        = countif(SensorHealthState == "Active"),
    Inactive_1_7d = countif(SensorHealthState != "Active" and DaysSinceLastSeen between (1 .. 7)),
    Dark_8_30d    = countif(DaysSinceLastSeen between (8 .. 30))
  by OSPlatform, MachineGroup
| sort by TotalDevices desc
```

Devices seasonally offline beyond 30 days are invisible here — use `IntuneDeviceComplianceOrg.LastContact` (if Diagnostic Settings enabled) or Intune portal inventory for longer-horizon tracking.

---

## DlpInfo parsing

`DlpInfo` is a **Defender-only string column** in `DeviceInfo`. All values are `null` for IoT/printers — filter to `DeviceType in ("Workstation","Server")` before parsing.

Key fields for health tracking:
- `IsDefenderRealTimeProtectionEnabled` — bool: real-time protection on/off
- `IsDefenderBehaviorMonitoringEnabled` — bool: behavior monitoring on/off
- `IsDlpEnabled` — bool: Endpoint DLP policy active
- `IsDlpConfigurationValid` — bool: `false` indicates policy misconfiguration

**Note:** These are Intune/DLP compliance-reporting fields — they reflect what the reporting layer last observed, not real-time MDE sensor state. For authoritative current AV mode, use `DeviceTvmInfoGathering.AdditionalFields.AvMode`.

---

## AvMode semantics

`DeviceTvmInfoGathering.AdditionalFields.AvMode` is a **string despite numeric values**:

| Value | Meaning |
|---|---|
| `"0"` | Active — Defender is the primary AV, real-time protection on |
| `"1"` | Passive — another AV product is primary; Defender in passive mode |
| `"4"` | EDR Block mode — Defender operating without active AV (sensor only) |
| `null` | Sensor hasn't reported AV state (offline device, IoT, or macOS with different key names) |

macOS uses `XplatAvMode` / `WdavMode` keys instead of `AvMode`. `AvMode` will be `null` on Mac endpoints.

---

## Intune compliance via sign-in events

`EntraIdSignInEvents` carries `IsManaged` (1 = MDM-enrolled) and `IsCompliant` (1 = passed Intune compliance policy) **evaluated at sign-in time**. Limitations:
- **No data for offline devices** — if a device hasn't signed in during the retention window (~30 days), `IsManaged`/`IsCompliant` will be null after the left join.
- **Point-in-time** — a device can be `IsCompliant=1` at one sign-in and `IsCompliant=0` at the next if a policy check fails between sign-ins.
- Use `arg_max(Timestamp,*)` per `EntraIdDeviceId` to get last-known state.

For devices showing `IsManaged = null` after the join: they may still be enrolled, but haven't produced a sign-in event in the query window. Check `DeviceInfo.MachineGroup` — `"UEM Devices"` is a reliable operational proxy for Intune enrollment in tenants where this group is managed that way.

---

## If Intune Diagnostic Settings are enabled in your tenant

Some tenants export Intune data to Log Analytics via **Tenant administration → Diagnostic settings** in the Intune admin center. If enabled, these Sentinel tables provide richer, dedicated compliance tracking:

| Table | Type | Key columns | Notes |
|---|---|---|---|
| `IntuneDeviceComplianceOrg` | Daily snapshot | `ComplianceState`, `LastContact`, `InGracePeriodUntil`, `ManagementAgents`, `OS`, `OSVersion` | `ComplianceState`: `Compliant`, `NonCompliant`, `Conflict`, `Error`, `InGracePeriod`. Use `TimeGenerated` for historical trends. |
| `IntuneDevices` | Daily snapshot | `CompliantState`, `DeviceState`, `LastContact`, `ManagedBy`, `Ownership`, `DeviceRegistrationState` | Full device inventory with management authority. |
| `IntuneOperationalLogs` | Real-time events | Enrollment, compliance changes, policy processing | Event-driven; captures the moment of state transition — better for drift detection. Available in Log Analytics within ~30 min. |

These tables are **not present** in all tenants — verify with `get_schema()` (no-arg) before writing queries against them.

---

## Gotchas

- `DeviceTvmInfoGathering` is **Defender-only** — `run_sentinel_query` returns 400 Bad Request. Always use `run_hunting_query`.
- `DlpInfo` column does **not exist** in the Sentinel version of `DeviceInfo` — queries referencing it will error in `run_sentinel_query`.
- `DeviceInfo` rows for offline devices persist indefinitely — a device last seen 180 days ago still appears. The `Timestamp` / `DaysSinceLastSeen` is your staleness filter, not row absence.
- `EntraIdSignInEvents` is also Defender-only (no Sentinel equivalent). Use `SigninLogs` + `AADNonInteractiveUserSignInLogs` in Sentinel, but those tables do **not** carry `IsManaged`/`IsCompliant`.
