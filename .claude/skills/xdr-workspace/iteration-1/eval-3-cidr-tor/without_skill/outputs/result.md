# Eval 3 WITHOUT skill: CIDR Tor range query (baseline)

## Final query
```kql
DeviceNetworkEvents
| where Timestamp >= ago(14d)
| where ipv4_is_in_range(RemoteIP, "185.220.0.0/16")   -- ipv4_is_in_range: won't match ::ffff:185.220.x.x
| project Timestamp, DeviceName, DeviceId, RemoteIP, RemotePort, RemoteUrl, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, ActionType
| sort by Timestamp desc
```

## Results
0 rows (~0.41s). Notes: used `ipv4_is_in_range()` which won't handle IPv6-mapped form. A regex alternative (`^185\.220\.`) was also validated — also fails for IPv6-mapped.
