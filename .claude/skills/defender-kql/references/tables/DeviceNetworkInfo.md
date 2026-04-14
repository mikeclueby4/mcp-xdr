# DeviceNetworkInfo — Accumulated Learnings

## IPAddresses is a dynamic JSON array — must mv-expand

`IPAddresses` is stored as a JSON array of objects. Direct string comparisons won't work. Use `mv-expand` to get one row per IP:

```kql
DeviceNetworkInfo
| where TimeGenerated > ago(7d)
| where DeviceName == "DEVICE-001"
| where NetworkAdapterStatus == "Up"
| extend IPs = parse_json(IPAddresses)
| mv-expand IP = IPs
| extend LocalIP = tostring(IP.IPAddress)
| extend SubnetPrefix = toint(IP.SubnetPrefix)
| extend AddressType = tostring(IP.AddressType)
```

`AddressType` values: `"Private"`, `"Public"`, `"LinkLocal"`.

## Filtering to the meaningful active IP

Link-local addresses (`169.254.x.x` and `fe80::`) are always present on adapters and are noise. Filtering by `AddressType == "Private"` is the most reliable approach. If you need to exclude link-local ranges explicitly, use `ipv6_is_match()` — never `startswith`, as IPv4 addresses may be stored in IPv6-mapped form (`::ffff:169.254.x.x`) which breaks string prefix matching.

Note: `ipv6_is_match()` requires a `string` argument, not `dynamic` — after `mv-expand`, `IP.IPAddress` is `dynamic`, so `tostring()` is mandatory.

```kql
| where tostring(IP.AddressType) == "Private"
// Alternative: exclude link-local by CIDR using ipv6_is_match (handles both native and ::ffff:-mapped forms)
| where not(ipv6_is_match(tostring(IP.IPAddress), "169.254.0.0", 112))  // 169.254.0.0/16: IPv4 prefix /16 → IPv6 prefix 112
| where not(ipv6_is_match(tostring(IP.IPAddress), "fe80::", 10))         // fe80::/10
```

When searching for a specific IP in `IPAddresses`, always use `ipv6_is_match()`:

```kql
| where ipv6_is_match(tostring(IP.IPAddress), "10.1.2.3")
```

## ConnectedNetworks reveals WiFi SSID and internet status

`ConnectedNetworks` is a JSON array. The first element covers the active association:

```kql
| extend Network = tostring(parse_json(ConnectedNetworks)[0].Name)
| extend NetCategory = tostring(parse_json(ConnectedNetworks)[0].Category)  // "Public" or "Private"
| extend HasInternet = tobool(parse_json(ConnectedNetworks)[0].IsConnectedToInternet)
```

This is the most reliable way to track which physical location (home, office, guest) a device was at for a given time window — more useful than IP ranges alone.

## NetworkAdapterName is a GUID, not a friendly name

The `NetworkAdapterName` column contains Windows interface GUIDs (e.g. `{B92CB009-294C-40F5-B851-86A80B223861}`), not friendly names like "Wi-Fi" or "Ethernet". Use `MacAddress` to identify adapters and correlate across rows. `NetworkAdapterType` (`Wireless80211`, `Ethernet`) is more readable.

## DefaultGateways and DnsAddresses are also JSON arrays

```kql
| extend Gateway = tostring(parse_json(DefaultGateways)[0])
| extend DNS1    = tostring(parse_json(DnsAddresses)[0])
```

## Multiple rows per snapshot — one per adapter

Each telemetry snapshot produces one row per network adapter (including inactive/Down ones). Always filter `NetworkAdapterStatus == "Up"` and then further filter to the adapter with a real IP to avoid noise from virtual/Down adapters.

## Useful for device location history investigations

Combining `ConnectedNetworks[0].Name` (SSID/network name) with `DefaultGateways` and `DnsAddresses` gives a precise location fingerprint — e.g. office vs home vs guest WiFi — without needing GPS or physical records. This is valuable when correlating "it worked from location A but fails from location B".
