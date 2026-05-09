# DNS Resolver Health Investigation Playbook

**Trigger phrases:** "Outlook autodiscover slow at login", "intermittent SERVFAIL", "name resolution flaky", "DNS server bug", "is one of our DNS servers broken", "asymmetric DNS errors", "stale DNS cache", "DNSSEC failures", "fleet-wide morning login slowness".

Also fires when an investigation that **started** as VPN/wifi/connectivity diagnostics reveals **DNS-error** asymmetry — DNS server health is a frequent root cause masquerading as networking issues.

## Canonical event source

`DeviceNetworkEvents` `ActionType == "DnsConnectionInspected"` is the **only** reliable source for DNS query/answer telemetry. It carries a Zeek-style payload in `AdditionalFields`:

```json
{
  "direction": "Out",
  "query": "autodiscover.example.com",
  "qtype_name": "A",
  "rcode_name": "NOERROR" | "SERVFAIL" | "NXDOMAIN" | "REFUSED" | ...,
  "answers": "[\"1.2.3.4\"]",
  "TTLs": "[300.0]",
  "trans_id": "...",
  "rejected": "false"
}
```

### Pitfalls — read before querying

- `RemotePort == 53` filter alone catches almost nothing. Most DNS shows up as `DnsConnectionInspected` (UDP/53) — a higher-tier inspection event, not raw `ConnectionSuccess`/`ConnectionRequest`. Filter `ActionType == "DnsConnectionInspected"` and supplement with `ActionType == "ConnectionFailed" and RemotePort == 53` for TCP fallback.
- `LocalIPType` and `RemoteIPType` are **always blank** on `DnsConnectionInspected` rows. `where LocalIPType != "Loopback"` will silently drop every DNS-inspection row.
- `InitiatingProcessFileName` is also always blank on these rows.
- DoH (DNS-over-HTTPS) traffic is invisible here — it goes to port 443 against `1.1.1.1`/`cloudflare-dns.com` and looks like ordinary HTTPS. Modern Edge/Chrome/Firefox use DoH by default and bypass the OS resolver entirely. The OS-resolver volume you see in this table is the **non-DoH** subset.

### KQL boilerplate

```kql
let CorpDns = dynamic(["10.0.0.10","10.0.0.11"]);  // tenant's resolver IPs
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsConnectionInspected"
| where RemoteIP in (CorpDns)
| extend AF = parse_json(tostring(AdditionalFields))
| extend Query = tolower(tostring(AF.query)),
         Qtype = tostring(AF.qtype_name),
         RcodeName = tostring(AF.rcode_name),
         Answers = tostring(AF.answers),
         TTLsRaw = tostring(AF.TTLs)
```

## Standard diagnostic ladder

When fleet-wide DNS errors are reported, walk these in order. Each step rules out a hypothesis cheaply.

### Step 1 — split by resolver IP

The single most diagnostic question: **is the failure rate symmetric across all DNS servers, or asymmetric?**

```kql
... | summarize Total=count(), SERVFAIL=countif(RcodeName=="SERVFAIL")
       by RemoteIP
    | extend ServfailRatePct = round(100.0*SERVFAIL/Total, 2)
```

If asymmetric → it's a **server-side config issue on the bad resolver**. Stop chasing client/wifi/zone-authority theories. The Windows DNS Client favors the first server in the resolver list, so the primary will see ~2× the secondary's query volume — that's normal; rate matters, not count.

### Step 2 — split by zone (parent domain)

If errors cluster on **one zone** while other zones are clean → it's a **per-zone config issue** (conditional forwarder, stub zone, secondary zone, DNSSEC trust anchor) on the failing resolver, not capacity or a global recursion problem.

```kql
... | extend Labels = split(Query, ".")
    | extend ParentZone = strcat(Labels[array_length(Labels)-2], ".", Labels[array_length(Labels)-1])
    | summarize Total=count(), SERVFAIL=countif(RcodeName=="SERVFAIL") by ParentZone
    | extend ServfailRatePct = round(100.0*SERVFAIL/Total, 2)
    | order by SERVFAIL desc
```

### Step 3 — pick canary names with known good vs bad behavior

Build a fixed canary set with three categories:

- **High-volume external CDN names** (`outlook.office.com`, `login.microsoftonline.com`, `graph.microsoft.com`) — these are hot in every cache on the internet; if your resolver returns SERVFAIL on these, it is broken globally, not zone-specifically.
- **High-volume names from the suspect zone** — direct child names like `www.<zone>`, `api.<zone>` that are heavily used.
- **Long-tail names from the suspect zone** — rarely-queried subzones (`<site>.<zone>`, `autodiscover.<site>.<zone>`) where cache misses are common.

Microsoft canaries returning 0% SERVFAIL on a resolver that fails 10% on `*.<corp-zone>` is **definitive evidence** that the problem is zone-specific, not capacity-related.

### Step 4 — TTL comparison (the killer evidence)

This is the strongest evidence pattern when both resolvers return identical RDATA but you suspect one is using an upstream forwarder.

```kql
... | where RcodeName == "NOERROR"
    | extend FirstTTL = toint(extract(@"^\[([0-9]+)", 1, TTLsRaw))
    | summarize P50=percentile(FirstTTL,50), P90=percentile(FirstTTL,90), Max=max(FirstTTL)
       by Query, RemoteIP
```

**Interpretation:**
- A resolver doing **direct recursion** to authoritative NS returns `FirstTTL ≈ Max` (the zone's configured TTL).
- A resolver **forwarding to an upstream cache** returns `FirstTTL ≈ Max - elapsed time in upstream cache`. P50 will be measurably lower.
- Compare per-name P50 TTL across resolvers. Same answer IPs + lower TTL on one resolver = forwarder in path.
- Microsoft canaries should show identical TTLs across resolvers (their answers churn so fast everywhere that no cache holds them long).
- A consistent TTL haircut on `*.<corp-zone>` only on one resolver = **smoking gun for misconfigured conditional-forwarder/stub-zone on that resolver**, even when error rates are low.

### Step 5 — rule out time-of-day / capacity

```kql
... | extend Hour = hourofday(Timestamp)
    | summarize Total=count(), SERVFAIL=countif(RcodeName=="SERVFAIL") by Hour, RemoteIP
    | extend ServfailRatePct = round(100.0*SERVFAIL/Total, 2)
```

If the **rate** (not the count) is flat across the day, it is **not** a capacity issue. Absolute SERVFAIL counts will spike at fleet login times because total query volume spikes — that fools naive analyses. Always look at the rate.

## Common diagnostic dead ends

| Hypothesis | Why it usually fails to explain asymmetric SERVFAIL | Quick disproof |
|---|---|---|
| WiFi packet loss | Packet loss → empty/no response, NOT SERVFAIL. SERVFAIL means the server processed the query and chose to fail. | Are failures bursty within seconds (wifi) or steady drip (server)? |
| Capacity / morning storm | Same resolver handles >10× more Microsoft queries cleanly while failing 10% of corp-zone queries. | Compare zone-A SERVFAIL rate vs zone-B at the same hour. |
| Broken authoritative zone | Zones with redundant anycast NS rarely return 100% SERVFAIL globally. Other resolvers serving same zone are clean. | Check the secondary corp resolver — if it's clean, the authority is fine. |
| Stuck DNS during VPN drop | Real but separate phenomenon. Affects DNS-server-list config on client, not the response rcode. | Cross-check public IP vs DNS-server addresses on `DeviceNetworkInfo`. |
| DNSSEC validation failure | Possible but usually all-or-nothing per zone, and consistent across resolvers using same trust anchors. | Asymmetry between two resolvers in the same domain rules this out unless their trust anchors differ. |
| Single-snapshot `arg_max` on `DeviceNetworkInfo` to detect DNS misconfig | Latest heartbeat may be from a transient/secondary adapter with no DHCP lease. False positives on multi-adapter devices (USB-C dock, virtual NICs). | Use "any heartbeat in window" not "arg_max latest" for DNS-config classification. |

## Forwarder fingerprints (what to look for in answers)

When you suspect a resolver is forwarding to a SaaS DNS provider:

- **Cisco Umbrella sinkhole IPs**: `146.112.61.106-110`, `67.215.65.130-132`. Search `AdditionalFields.answers` for these — presence proves Umbrella is in path AND is blocking. Absence does NOT prove Umbrella isn't in path (Umbrella relays normal answers when not blocking).
- **Quad9 / OpenDNS / Google DNS** servers: if the resolver IP itself appears in `AdditionalFields.answers` as an authority hint, it's been forwarded.
- **Lower TTLs across the board on a specific zone** = upstream cache. The forwarder doesn't have to be SaaS — could be a stale internal proxy, a decommissioned secondary, or an AD-integrated zone delegating wrong.

## Resolver-config audit checklist (handoff to DNS-team)

When handing off to the DNS-server admin, ask them to compare on the bad vs good resolver:

1. **Conditional Forwarders** — any rule for the suspect zone, or a wildcard `.` / `*` rule pointing at external DNS.
2. **Server-global Forwarders** — DNS Manager → Server Properties → Forwarders tab.
3. **Stub Zones / Secondary Zones** — present on one server but not the other.
4. **Root Hints** — should be default; non-default hints can route iterative queries oddly.
5. **DNSSEC trust anchors** — `Get-DnsServerTrustAnchor` on Windows DNS, `dig . dnskey` cross-check.
6. **AD-integrated zone replication** — if the suspect zone is AD-integrated and one DC has a stale replica.
7. **Per-zone scavenging / aging settings** — only relevant for stale records, not SERVFAIL itself.

## What good evidence looks like in a ticket

A persuasive DNS-server-health ticket needs three pieces:

1. **Asymmetry** — N% SERVFAIL on resolver A vs ~0% on resolver B for the same zone, same client population, same time window.
2. **Selectivity** — control zones (well-known external CDNs) show 0% on both resolvers, proving the bad resolver isn't globally broken.
3. **TTL haircut** — for *NOERROR* responses on the affected zone, the bad resolver returns identical answer IPs but **systematically lower TTLs**. This is the only data signature that distinguishes "forwarding through an upstream cache" from every other hypothesis.

Without the TTL evidence the diagnosis is just "your server fails sometimes." With it, the diagnosis is "your server is configured to forward this zone through a cache that fails sometimes" — and that points the DNS admin at a specific config audit.

## Time-window guidance

- 7 days is enough to see the asymmetry and per-zone pattern.
- 30 days is needed to confirm it's chronic (no recent regression) and not a recent incident.
- Defender retention is typically 30 days for `DeviceNetworkEvents`. For >30-day history use `run_sentinel_query` if Sentinel is onboarded — `DnsConnectionInspected` rows route there too.
- Filter to weekdays (`dayofweek(Timestamp) !in (0d, 6d)`) when looking at hour-of-day patterns to remove weekend-volume noise.
