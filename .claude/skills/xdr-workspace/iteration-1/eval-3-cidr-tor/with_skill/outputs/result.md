# Eval 3 WITH skill: CIDR Tor range query

## Final query
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ipv6_is_match(RemoteIP, "185.220.0.0", 112)
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    RemoteIPs = make_set(RemoteIP, 50),
    RemotePorts = make_set(RemotePort, 20),
    Processes = make_set(InitiatingProcessFileName, 20)
    by DeviceId, DeviceName
| order by ConnectionCount desc
```

## Key decisions
- `ipv6_is_match(RemoteIP, "185.220.0.0", 112)` — prefix 112 = IPv6 equivalent of /16 (128 - 32 + 16 = 112)
- 14-day time window as requested
- summarize rather than raw rows

## Results
0 rows — no Tor connections found. Confirmed genuine negative (other 185.x traffic present).
