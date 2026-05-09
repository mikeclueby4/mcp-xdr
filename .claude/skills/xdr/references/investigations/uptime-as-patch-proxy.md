# Boot Time / Uptime as Patch-Staleness Proxy

**Trigger phrases:** "when did this server last reboot", "how long has this host been up", "how stale is our Windows patching", "which servers haven't rebooted in N days", "patch compliance without WSUS/SCCM access", "reboot gap analysis"

## Key insight — use grandparent, not parent

`InitiatingProcessFileName =~ "wininit.exe"` returns near-zero rows. `wininit.exe` directly spawns only 3–4 processes (`services.exe`, `lsass.exe`, `lsm.exe`) and those early-boot events are filtered by MDE noise reduction before reaching `DeviceProcessEvents`.

**Use `InitiatingProcessParentFileName =~ "wininit.exe"` instead.**

Every service-launched process has `services.exe` as direct parent and `wininit.exe` as grandparent. `InitiatingProcessParentCreationTime` is the exact `CreateProcess` timestamp of `services.exe` — which is boot time. This value is **identical across all processes in the same boot session**, so:

- `max(InitiatingProcessParentCreationTime)` = most recent boot
- `dcount(InitiatingProcessParentCreationTime)` = distinct reboots observed in the time window

## Fleet sweep query

```kql
let WindowsServers =
    DeviceInfo
    | where Timestamp > ago(7d)
    | where DeviceType == "Server"
    | where OnboardingStatus == "Onboarded"
    | summarize arg_max(Timestamp, OSPlatform, OSVersion, MachineGroup) by DeviceId, DeviceName;
let Boots =
    DeviceProcessEvents
    | where Timestamp > ago(90d)
    | where InitiatingProcessParentFileName =~ "wininit.exe"
    | summarize LastBoot = max(InitiatingProcessParentCreationTime),
                RebootsObserved = dcount(InitiatingProcessParentCreationTime) by DeviceId;
WindowsServers
| join kind=leftouter Boots on DeviceId
| extend MinDaysSincePatch = datetime_diff('day', now(), LastBoot)
| project DeviceName, OSPlatform, LastBoot, MinDaysSincePatch, RebootsObserved, MachineGroup
| order by MinDaysSincePatch desc nulls last
```

`ago(90d)` requires Sentinel `DeviceProcessEvents` if Defender retention is 30 days — swap `run_hunting_query` for `run_sentinel_query` and use `TimeGenerated` instead of `Timestamp`.

## Framing / semantics

`LastBoot` is a **floor** on patch staleness for reboot-required updates (most monthly cumulative KBs). It is:
- NOT proof of patching — a fresh boot just means pending patches can now take effect
- NOT a ceiling — non-reboot patches (signature updates, some .NET hotfixes) apply without a boot

Cross-check with `DeviceTvmSoftwareVulnerabilities | summarize VulnCount=count() by DeviceId` as the ceiling-side signal. Two servers with the same role but sharply different vuln counts often correlate with one having missed monthly reboots.

## Limitations

- **Onboarded hosts only.** `InitiatingProcessParentCreationTime` is MDE-sensor data. Non-onboarded hosts are invisible.
- **Windows only.** Linux/macOS: use `DeviceInfo` heartbeat gaps or platform-native journal data.
- **Retention window.** `ago(90d)` on `DeviceProcessEvents` via Defender Advanced Hunting will silently return nothing beyond the tenant's retention limit (default 30d). Use `run_sentinel_query` for longer history if Sentinel is configured.
- **Single boot in window.** If a host rebooted only once and that reboot is older than the retention window, `Boots` join will produce null → `MinDaysSincePatch` null. Treat nulls-last sort order as "worst case — no reboot observed".

## What does not work (verified dead ends)

| Approach | Why it fails |
|---|---|
| `InitiatingProcessFileName =~ "wininit.exe"` | Near-zero rows — early-boot child events filtered by MDE |
| `lsass.exe` start events | Filtered out by MDE noise reduction |
| `IdentityDirectoryEvents` gap-then-burst pattern | Looks like reboot but is MDI sampling cadence (12h/24h cycles, ~03:00 UTC daily resume) — not boot signal |
| DC machine-account Kerberos AS-REQ (`computername$`) | MDI does not surface DC self-TGTs in `IdentityLogonEvents` |
| Network-protocol boot signals (NTP, NetBIOS, mDNS, SSDP) | Only visible if the onboarded host *initiates*; non-onboarded hosts are invisible by definition |
