# DeviceInfo

Canonical device metadata table — one row per device per heartbeat (updated continuously, full snapshot per update). Primary enrichment source for `DeviceId → device metadata` joins.

## Key facts

- **Not an event stream** — each write replaces the prior row for that device. Use `arg_max` to get current state. Official docs recommend `arg_max(ingestion_time(), *)` (not `Timestamp`) for latest-state dedup:
  ```kql
  DeviceInfo
  | where isnotempty(OSPlatform)
  | summarize arg_max(ingestion_time(), *) by DeviceId
  ```
- `ProcessUniqueId` — **absent from live schema** (docs omit it here, consistent with other Device* tables).
- `ReportId` is `long` (local counter, not globally unique) — composite key: `ReportId + DeviceName + Timestamp`.

## Schema divergences (Defender vs Sentinel)

| Column | Defender | Sentinel |
|---|---|---|
| `LoggedOnUsers` | `string` (JSON array) | `dynamic` |
| `AdditionalFields` | `string` (JSON object) | `dynamic` |
| `ConnectivityType` | `string` | N/A |
| `DiscoverySources` | `string` | N/A |
| `FirmwareVersions` | `string` | N/A |
| `DlpInfo` | `string` | N/A |
| `DeviceObjectId` | N/A | `string` |
| `RestrictedDeviceSecurityOperations` | N/A | `string` |

Use `parse_json(LoggedOnUsers)` and `parse_json(AdditionalFields)` in both sources — parses the string in Defender, no-op on dynamic in Sentinel.

## LoggedOnUsers

JSON array of objects. Keys: `UserName`, `DomainName`, `Sid`. macOS rows may omit `DomainName`/`Sid`.

```kql
| mv-expand User = parse_json(LoggedOnUsers)
| extend UserName = tostring(User.UserName), Domain = tostring(User.DomainName)
```

## AdditionalFields — internet-facing metadata

Only populated when `IsInternetFacing == true`. Keys confirmed (2026-04):
- `InternetFacingLastSeen` (datetime string)
- `InternetFacingReason` — `"PublicScan"` or `"ExternalNetworkConnection"`
- `InternetFacingLocalIp`, `InternetFacingLocalPort`
- `InternetFacingPublicScannedIp`, `InternetFacingPublicScannedPort`
- `InternetFacingTransportProtocol`

Blank for non-internet-facing devices.

## JoinType — confirmed values (2026-04)

`"AAD Joined"`, `"Hybrid Azure AD Join"`, `"AAD Registered"`, or blank (not joined/unknown).

**Not authoritative — can lag/lie.** `DeviceInfo.JoinType` and `DeviceInfo.IsAzureADJoined` are Defender-side attributes that can become stale (e.g. when a hybrid-joined device migrates to pure AAD, or when a `.local` FQDN suffix confuses the heuristic). For ground truth, cross-check with `EntraIdSignInEvents.DeviceTrustType` (`"Azure AD joined"` / `"Hybrid Azure AD joined"` / `"Azure AD registered"`) — Entra evaluates this per sign-in. If they disagree, **trust Entra**. Confirm by looking for actual on-prem dependency: `IdentityLogonEvents` Kerberos against the on-prem domain, and `DeviceNetworkEvents` to DCs on ports 389/636 (LDAP/LDAPS) or 3268/3269 (Global Catalog) from `lsass.exe`/`gpsvc`. Ports 53/88/445 alone are not hybrid-join evidence — Cloud Kerberos Trust + DNS lookups produce the same fingerprint on pure-AAD devices.

## MachineGroup

**Defender RBAC scope label, NOT Intune/MDM state.** Per Microsoft Learn: *"Machine group of the device. This group is used by role-based access control to determine access to the device."* Common values like `"UEM Devices"`, `"UnassignedGroup"`, or pilot/business-unit names are admin-defined Defender device groups for SOC visibility and role assignment — they say nothing about Intune enrollment or compliance. Do not infer "not Intune-managed" from `MachineGroup`. For Intune state use `EntraIdSignInEvents.IsManaged` / `IsCompliant` (per sign-in).

## OnboardingStatus — confirmed values (2026-04)

`"Onboarded"`, `"Can be onboarded"`, `"Unsupported"`, `"Insufficient info"` (lost contact).

## ConnectivityType — confirmed values (2026-04)

`"Standard"`, `"Streamlined"`, or blank. Defender-only column.

## PublicIP

Egress IP as seen by the Defender cloud service. Snapshot-based (updated ~hourly). Represents the NAT/proxy IP, not necessarily the device's internal IP. May be blank when `OnboardingStatus == "Insufficient info"`. Use `DeviceNetworkInfo` for precise network-change timing.

Different VLANs/subnets may NAT through different IPs — do not assume all devices on the same domain share the same `PublicIP`.

## DlpInfo (Defender-only string column)

JSON object carrying both DLP policy state and Defender protection state. **All values are `null` for IoT/printer/network devices** — only populated for `DeviceType in ("Workstation","Server")` endpoints. Parse with `parse_json(tostring(DlpInfo))`.

| Key | Type | Semantics |
|---|---|---|
| `IsDefenderRealTimeProtectionEnabled` | bool/null | `true` = Defender real-time protection on |
| `IsDefenderBehaviorMonitoringEnabled` | bool/null | `true` = behavior monitoring on |
| `IsDlpEnabled` | bool/null | `true` = Endpoint DLP policy is enabled on the device |
| `IsDlpConfigurationValid` | bool/null | `true` = DLP configuration applied successfully; `false` = misconfigured or policy error |
| `DlpPolicyLastModifiedTimeUTC` | datetime string/null | Last time DLP policy was modified |
| `HasDlpACBandwidthExceeded` | bool/null | Activity classification bandwidth exceeded |
| `HasDlpValidUpn` | bool/null | UPN matches a licensed user for DLP |
| `DlpUpn` | string/null | UPN of the last logged-on user against which DLP is evaluated |

Pattern for device health queries:
```kql
| extend DlpParsed = parse_json(tostring(DlpInfo))
| extend
    IsRealTimeProtectionEnabled = tobool(DlpParsed.IsDefenderRealTimeProtectionEnabled),
    IsBehaviorMonitoringEnabled = tobool(DlpParsed.IsDefenderBehaviorMonitoringEnabled),
    IsDlpEnabled               = tobool(DlpParsed.IsDlpEnabled),
    IsDlpConfigurationValid    = tobool(DlpParsed.IsDlpConfigurationValid)
```

**Important:** `IsDefenderRealTimeProtectionEnabled` and `IsDefenderBehaviorMonitoringEnabled` are Intune/DLP reporting fields, not real-time MDE sensor telemetry. They reflect what the compliance reporting layer last observed. For definitive current AV/protection state, cross-check with `DeviceTvmInfoGathering.AdditionalFields.AvMode`.

## DiscoverySources (Defender-only string column)

JSON object mapping product name to last-seen date string, e.g. `{"Defender for Endpoint":"2026-04-27"}`.

## DeviceManualTags / DeviceDynamicTags

Both are JSON arrays stored as `string` in Defender. Use `parse_json(DeviceManualTags)` to access; use `has` for pre-filter before parsing:

```kql
| where DeviceManualTags has "Servers"
| where parse_json(DeviceManualTags) has_any ("Servers", "Critical")
```

## Enrichment join patterns

`DeviceInfo` is the canonical enrichment source. Join from any Device* table on `DeviceId`:

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
// ...filters...
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(1d)
    | summarize arg_max(Timestamp, OSPlatform, JoinType, MachineGroup, PublicIP) by DeviceId
) on DeviceId
```

`AadDeviceId` joins to Entra ID / `EntraIdSignInEvents.EntraIdDeviceId` for cross-table device-identity correlation. Also surfaced in Sentinel as `DeviceObjectId` column.

`MergedToDeviceId` / `MergedDeviceIds` — when a device is reimaged or renamed, the old `DeviceId` is linked here. Follow `MergedToDeviceId` for stable long-term device history.

## Cloud device columns (sparse)

`AzureResourceId`, `AzureVmId`, `AzureVmSubscriptionId` — Azure VMs.
`AwsResourceName` — AWS.
`GcpFullResourceName` — GCP.
`CloudPlatforms` — string listing which platforms apply.
All blank for standard endpoint devices.
