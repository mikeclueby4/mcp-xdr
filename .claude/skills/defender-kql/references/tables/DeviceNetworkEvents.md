# DeviceNetworkEvents — Accumulated Learnings

## Protocol column inconsistency

The `Protocol` column contains `"Tcp"`, `"TcpV4"` and `"TcpV6"` for TCP connections — inconsistent within the same table. **Never use `== "Tcp"`** as a filter; it silently misses `"TcpV4"` rows.

```kql
// RIGHT
| where Protocol startswith "Tcp"
```

## ConnectionSuccess ≠ connection was allowed

Network protection blocks happen **after** the TCP three-way handshake, so a blocked site still logs `ActionType == "ConnectionSuccess"`. To find actually blocked connections, correlate with `AlertEvidence` — do not rely on `ActionType` alone.

```kql
// To find blocks, join with AlertEvidence:
DeviceNetworkEvents
| where Timestamp > ago(7d)
| join kind=inner AlertEvidence on DeviceId, ReportId
```

## ReportId is NOT globally unique

`ReportId` (`long`) is a local counter — only unique per `(DeviceName, Timestamp)`.

## InitiatingProcessSHA256 may be unpopulated

The `InitiatingProcessSHA256` column is sometimes empty. Default to relying on `InitiatingProcessSHA1` for now; SHA1 may be insecure but this is merely a fingerprint.

## LocalIPType / RemoteIPType are unreliable

These columns (`Public`, `Private`, `Reserved`, etc.) are frequently blank — Defender only fills them when confident. Do not use them as reliable filters; they will silently drop rows.

## AdditionalFields is double-serialized JSON (string, not dynamic)

Despite the column being typed `string`, it contains JSON. Use `parse_json()` before accessing any keys. For inbound connections with no initiating process, this column carries raw TCP metadata (flags, MACs, packet size).

```kql
| extend af = parse_json(AdditionalFields)
| extend TcpFlags = toint(af["Tcp Flags"])
| extend Direction = tostring(af.direction)
```

Live example from an inbound SMB connection:
```json
{"Tcp Flags":18,"direction":"In","Source Mac":"2c:58:b9:f5:9f:53","Destination Mac":"00:09:0f:09:0a:02","Packet Size":66}
```

## Timestamp vs TimeGenerated

- `Timestamp` — when the event occurred on the endpoint (use this for time filters via `run_hunting_query`)
- `TimeGenerated` — when the record was ingested into the workspace. Use this when querying via `run_sentinel_query` (Sentinel mirror of MDE tables).

## RemoteHostname does not exist

There is no `RemoteHostname` column. The destination hostname is in `RemoteUrl` (may include full path/scheme). `RemoteIP` holds the resolved IP.

## ActionType vocabulary — beyond ConnectionSuccess/Failed

| ActionType | Meaning |
|---|---|
| `ConnectionSuccess` | Outbound TCP handshake completed |
| `ConnectionFailed` | TCP connection attempt failed (no SYN-ACK received) |
| `ConnectionAcknowledged` | Inbound connection — device received a SYN-ACK (server role). No `InitiatingProcess*` context. |
| `DnsConnectionInspected` | Passive DNS traffic observation — DNS was seen in flight, not a TCP open/close event. `InitiatingProcessFileName` is typically empty. Does **not** reveal the query name or answer. |
| `IcmpConnectionInspected` | Zeek-style ICMP record. `AdditionalFields` contains Zeek fields: `conn_state`, `orig_pkts`, `orig_bytes`, `resp_pkts`, `resp_bytes`. `resp_pkts == 0` / `resp_bytes == 0` means the remote host is silently dropping packets — strong indicator of server-side IP block. |

```kql
// Detecting silent server-side IP block via ICMP:
| where ActionType == "IcmpConnectionInspected"
| extend af = parse_json(AdditionalFields)
| where toint(af.resp_pkts) == 0
// One-way traffic: device is sending, server is not responding at all
```

## ConnectionAcknowledged as a liveness probe

Presence of `ConnectionAcknowledged` for a destination IP means the server completed the TCP handshake at that point in time. If later attempts show `ConnectionFailed` to the same IP with **no** `ConnectionAcknowledged`, the server has stopped responding — consistent with a server-side firewall/WAF block rather than a local policy block.

## Inbound connections have no initiating process context

For `ConnectionAcknowledged` (inbound) rows, all `InitiatingProcess*` columns are empty/null. Process context is only available for outbound (initiated) connections.
