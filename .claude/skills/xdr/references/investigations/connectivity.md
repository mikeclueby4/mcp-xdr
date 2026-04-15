# Web/Network Connectivity Investigation Playbook

Symptoms that trigger this playbook: `ERR_CONNECTION_TIMED_OUT`, site unreachable, intermittent web access, "works from home but not office" (or vice versa), browser connectivity failures on a specific device.

These symptoms are almost never answered by `DeviceNetworkEvents` alone. The full diagnostic table set is:

| Table | What it answers |
|---|---|
| `DeviceNetworkEvents` | Did the TCP connection attempt succeed or fail? Which process initiated it? Was it blocked by network protection? |
| `DeviceNetworkInfo` | What network was the device on at the time (SSID, gateway, DNS)? What IP was assigned? Was internet connectivity confirmed? See `references/tables/DeviceNetworkInfo.md`. |
| `DeviceInfo` | What is the device's OS version, join type (AAD/hybrid/workgroup), onboarding status? Was it even reporting to MDE at the time? See `references/tables/DeviceInfo.md`. |
| `DeviceEvents` + `ActionType == "SmartScreenUrlWarning"` or `"SmartScreenExploit"` | Did SmartScreen block or warn on the URL? This fires even when the browser shows `ERR_CONNECTION_TIMED_OUT` if network protection is the actual blocker. |
| `AlertEvidence` / `AlertInfo` | Was there an active MDE alert (e.g. network protection block) associated with the device or URL at the time? |

**Key insight:** A browser `ERR_CONNECTION_TIMED_OUT` can be caused by MDE network protection silently dropping the connection post-TCP-handshake — `ConnectionSuccess` in `DeviceNetworkEvents` will be `true` (handshake succeeded) but the session is then torn down. Check `DeviceEvents` for SmartScreen/network-protection action types on the same device+timestamp, and cross-reference `DeviceNetworkInfo` to confirm the device was on the expected network at the time.

**Correlation pattern** — time-window join across the three core tables:
```kql
// Step 1: find network connection attempts to the target domain
DeviceNetworkEvents
| where TimeGenerated > ago(3d)
| where DeviceName == "DEVICE-001"
| where RemoteUrl has "contoso.com" or RemoteIP == "<ip>"
| project TimeGenerated, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, ConnectionSuccess

// Step 2: separately check SmartScreen/network-protection events
DeviceEvents
| where TimeGenerated > ago(3d)
| where DeviceName == "DEVICE-001"
| where ActionType in ("SmartScreenUrlWarning", "SmartScreenExploit", "ExploitGuardNetworkProtectionBlocked", "NetworkProtectionUserBypassEvent")
| project TimeGenerated, DeviceName, ActionType, AdditionalFields

// Step 3: check what network the device was on (run_sentinel_query — DeviceNetworkInfo is Sentinel-routed in some tenants)
DeviceNetworkInfo
| where TimeGenerated > ago(3d)
| where DeviceName == "DEVICE-001"
| where NetworkAdapterStatus == "Up"
| extend IPs = parse_json(IPAddresses)
| mv-expand IP = IPs
| where tostring(IP.AddressType) == "Private"
| extend SSID = tostring(parse_json(ConnectedNetworks)[0].Name)
| extend HasInternet = tobool(parse_json(ConnectedNetworks)[0].IsConnectedToInternet)
| project TimeGenerated, DeviceName, SSID, HasInternet, LocalIP = tostring(IP.IPAddress), MacAddress, NetworkAdapterType
```
