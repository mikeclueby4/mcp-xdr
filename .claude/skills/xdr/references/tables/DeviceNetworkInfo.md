# DeviceNetworkInfo

Snapshot table — network adapter state per device. One row per adapter per MDE heartbeat, not a continuous event stream. Source: MDE only (no MDI/MDO/MDCA).

**Time column**: `Timestamp` (Defender). Also has `TimeGenerated` (same value, Sentinel side).

**ReportId**: `long`, non-unique — composite key required: `ReportId + DeviceName + Timestamp`.

## Schema divergence: string (Defender) vs dynamic (Sentinel)

| Column | Defender type | Sentinel type |
|---|---|---|
| `IPAddresses` | `string` | `dynamic` |
| `ConnectedNetworks` | `string` | `dynamic` |
| `DnsAddresses` | `string` | `dynamic` |
| `DefaultGateways` | `string` | `dynamic` |

Use `parse_json(col)` for all four in Defender (no-op on already-dynamic in Sentinel). No `tostring()` wrapper needed — the string form is valid JSON.

## Multiple rows per snapshot — one per adapter

Each heartbeat produces one row per adapter including Down/Present/Unknown ones. Always filter `NetworkAdapterStatus == "Up"` to limit to active adapters. `NetworkAdapterStatus` confirmed values: `Up`, `Down`, `Present`, `Dormant`, `Unknown`.

## IPAddresses — mv-expand required

JSON array of objects: `{"IPAddress": "...", "SubnetPrefix": <int|null>, "AddressType": "..."}`.

`SubnetPrefix` can be `null` (confirmed in live data — some adapters don't report it).

`AddressType` confirmed values: `"Private"`, `"Public"`, `"LinkLocal"`.

```kql
DeviceNetworkInfo
| where Timestamp > ago(7d)
| where NetworkAdapterStatus == "Up"
| extend IPs = parse_json(IPAddresses)
| mv-expand IP = IPs
| where tostring(IP.AddressType) == "Private"
| extend LocalIP = tostring(IP.IPAddress)
| extend SubnetPrefix = toint(IP.SubnetPrefix)
```

When filtering by IP value, `ipv6_is_match()` is mandatory — IPs may be IPv6-mapped:

```kql
| where ipv6_is_match(tostring(IP.IPAddress), "10.1.2.3")
```

To exclude link-local explicitly (handles both native `169.254.x.x` and `::ffff:`-mapped form):

```kql
| where not(ipv6_is_match(tostring(IP.IPAddress), "169.254.0.0", 112))
| where not(ipv6_is_match(tostring(IP.IPAddress), "fe80::", 10))
```

## ConnectedNetworks — WiFi SSID, internet status, network category

JSON array: `{"Name": "...", "Description": "...", "IsConnectedToInternet": <bool|null>, "Category": <"Public"|"Private"|"Domain"|null>}`.

`Category` confirmed values: `"Public"`, `"Private"`, `"Domain"`, blank/null. On non-domain-joined devices, NLA cannot detect a DC — corporate network may appear as `"Public"` or `"Private"` rather than `"Domain"`.

```kql
| extend CN = parse_json(ConnectedNetworks)
| extend SSID       = tostring(CN[0].Name)
| extend NetCat     = tostring(CN[0].Category)
| extend HasInternet = tobool(CN[0].IsConnectedToInternet)
```

Combining `SSID` + `DefaultGateways` + `DnsAddresses` gives a reliable location fingerprint (office vs home vs guest WiFi).

## DefaultGateways and DnsAddresses

Simple JSON arrays of IP strings.

```kql
| extend Gateway = tostring(parse_json(DefaultGateways)[0])
| extend DNS1    = tostring(parse_json(DnsAddresses)[0])
```

## NetworkAdapterName is a Windows GUID, not a friendly name

On Windows, `NetworkAdapterName` contains GUIDs like `{B92CB009-294C-40F5-B851-86A80B223861}`. Use `MacAddress` to identify adapters across rows. `NetworkAdapterType` (`Wireless80211`, `Ethernet`, `Unknown`) is more readable.

## TunnelType

Present in schema; in practice always `"None"` where tunnels aren't active. Values listed in docs: `6to4`, `Teredo`, `ISATAP`, `PPTP`, `SSTP`, `SSH`.

## Docs-listed columns absent from live schema (as of 2026-04)

`OnboardingStatus` and `NetworkAdapterDnsSuffix` appear in official docs but are **absent from the live schema** in both Defender and Sentinel sources. Do not reference them in queries until confirmed present.

## Snapshot deduplication for current state

Not a time-series event stream — query the latest snapshot per device/adapter:

```kql
DeviceNetworkInfo
| where Timestamp > ago(1d)
| summarize arg_max(Timestamp, *) by DeviceId, MacAddress
```

## Cross-table joins

- Join to `DeviceInfo` on `DeviceId` for OS/machine group/join type context.
- This table is the primary source for device IP-to-identity resolution — join to `DeviceNetworkEvents` on `DeviceId` when correlating network connections to adapter state.
