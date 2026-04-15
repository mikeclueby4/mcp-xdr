# DeviceInfo — Accumulated Learnings

## PublicIP is the device's egress IP as seen by Defender cloud

`PublicIP` records the public-facing IP address the device was NATted behind when it last checked in with Defender. Updated approximately hourly. This is the IP that external servers see as the source of outbound connections.

Highly useful for:
- Determining which office/network egress IP a device is behind (especially when multiple subnets NAT to different public IPs)
- Correlating a device's location to a server-side IP block
- Confirming whether two devices share the same public egress path

```kql
DeviceInfo
| where TimeGenerated > ago(7d)
| where DeviceName == "DEVICE-001"
| project TimeGenerated, PublicIP, OnboardingStatus, SensorHealthState
| sort by TimeGenerated asc
```

## Devices on the same internal network can have different PublicIPs

On segmented corporate networks, different VLANs/subnets may NAT through different firewall interfaces to different public IPs. Do not assume all devices on `corp.local` share the same public egress — check `DeviceInfo.PublicIP` per device. This matters when investigating why one device is blocked by a site while another on the "same network" is not.

## PublicIP updates lag by up to ~1 hour

`PublicIP` is snapshot-based, not event-driven. If a device switches networks, the new public IP may not appear for up to an hour. Cross-reference with `DeviceNetworkInfo` (which captures network changes more granularly) for precise transition timing.

## OnboardingStatus and SensorHealthState

| Value | Meaning |
|---|---|
| `Onboarded` / `Active` | Device is enrolled in MDE and reporting normally |
| `Insufficient info` | Defender lost contact (e.g. device off network, VPN dropped) — `PublicIP` will be blank for that interval |
