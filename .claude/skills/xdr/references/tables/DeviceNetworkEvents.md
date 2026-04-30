# DeviceNetworkEvents

MDE-sourced network connection telemetry. High-volume table — prefer aggregation.

## ActionType — full enum (confirmed 2026-04)

| ActionType | Notes |
|---|---|
| `ConnectionSuccess` | Outbound TCP handshake completed |
| `ConnectionFailed` | Outbound TCP attempt failed (no SYN-ACK) |
| `ConnectionRequest` | Outbound connection initiated; macOS/Linux: POSIX context in `AdditionalFields` |
| `ConnectionAttempt` | Inbound SYN observed (`direction":"In"` in `AdditionalFields`); no `InitiatingProcess*` |
| `ConnectionFound` | Existing connection discovered (e.g. already-open socket at sensor start) |
| `ConnectionAcknowledged` | Inbound — device received a SYN-ACK (server role); no `InitiatingProcess*` |
| `InboundConnectionAccepted` | Inbound connection fully accepted; macOS: POSIX context in `AdditionalFields` |
| `ListeningConnectionCreated` | Process opened a listening socket; `AdditionalFields` typically empty |
| `DnsConnectionInspected` | Zeek DNS record — contains full query/response data (see below) |
| `SslConnectionInspected` | Zeek TLS record — JA3/JA4 fingerprints + cert metadata (see below) |
| `HttpConnectionInspected` | Zeek HTTP record — method, URI, status, host, user-agent |
| `NetworkSignatureInspected` | Pattern-matched packet; `SignatureName`, `SignatureMatchedContent`, `SamplePacketContent` |
| `IcmpConnectionInspected` | Zeek ICMP; `orig_pkts`/`resp_pkts`/`orig_bytes`/`resp_bytes`/`conn_state` |
| `SshConnectionInspected` | Zeek SSH; `client`, `server`, `version`, `auth_attempts`, `host_key` |
| `NtlmAuthenticationInspected` | Zeek NTLM; `hostname`, `server_nb_*`, `server_dns_*`, `success` |
| `KerberosConnectionInspected` | Zeek Kerberos; `requestType`, `service`, `cipher`, `success`, `ticketHash` |
| `FtpConnectionInspected` | Zeek FTP |
| `InboundInternetScanInspected` | Scan observed from internet; `PublicScannedPort`, `PublicScannedIp` in `AdditionalFields` |

Highest volume (typical): `ConnectionSuccess` >> `ConnectionAcknowledged` > `DnsConnectionInspected` > `SslConnectionInspected` > `ConnectionFailed`.

## AdditionalFields — string, parse_json() required

Typed `string` in Defender, `dynamic` in Sentinel. Use `parse_json(AdditionalFields)` in both (no `tostring()` wrapper needed).

Key schemas by ActionType:

**DnsConnectionInspected** — Zeek DNS. Contains the actual query and response:
```json
{"direction":"Out","trans_id":"47471","rtt":"0.049","query":"example.com","qclass":"1","qclass_name":"C_INTERNET","qtype":"1","qtype_name":"A","rcode":"0","rcode_name":"NOERROR","AA":"false","TC":"false","RD":"true","RA":"true","answers":"[\"1.2.3.4\"]","TTLs":"[300.0]","rejected":"false","uid":"Cxxx","ts":"134220282595780030"}
```
- `query` — the DNS name queried
- `answers` — JSON-encoded array string (note: requires a second `parse_json()` for the answers array)
- `rcode_name` — `NOERROR`, `NXDOMAIN`, `SERVFAIL`, etc.
- `qtype_name` — `A`, `AAAA`, `MX`, `CNAME`, etc.
- **Not always present**: `rtt`, `answers`, `TTLs` absent when no response observed

```kql
// Extract DNS query and first answer
| extend af = parse_json(AdditionalFields)
| extend DnsQuery = tostring(af.query)
| extend DnsAnswers = parse_json(tostring(af.answers))
| extend FirstAnswer = tostring(DnsAnswers[0])
```

**SslConnectionInspected** — Zeek TLS. Contains JA3/JA4 fingerprints:
```json
{"direction":"Out","version":"TLSv12","curve":"secp384r1","server_name":"example.com","resumed":"false","established":"true","subject":"CN=example.com,O=...","issuer":"CN=...","cipher":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","ja3":"258a5a...","ja3s":"60a1c7...","ja4":"t12d180800_...","ja4s":"t120500_...","uid":"Cxxx","ts":"..."}
```
- `server_name` — SNI; `subject`/`issuer` — cert fields; `ja3`/`ja3s`/`ja4`/`ja4s` — fingerprints
- `resumed` — TLS session resumption; `established` — handshake completed

**HttpConnectionInspected** — Zeek HTTP:
```json
{"direction":"Out","host":"example.com","method":"GET","uri":"/path","status_code":"200","status_msg":"OK","user_agent":"...","version":"1.1","request_body_len":"0","response_body_len":"1234","trans_depth":"1","tags":"[]"}
```

**NetworkSignatureInspected** — protocol signature match:
```json
{"SignatureName":"Kerberos_TGS_REQ","SignatureMatchedContent":"...","SamplePacketContent":"[\"...\"]"}
```

**NtlmAuthenticationInspected** — Zeek NTLM:
```json
{"direction":"Out","hostname":"DEVICE-001","server_nb_computer_name":"DC01","server_nb_domain_name":"DOMAIN","server_dns_computer_name":"dc01.domain.local","server_dns_domain_name":"domain.local","server_tree_name":"domain.local","success":"true","server_version":"10.0 14393 15","uid":"Cxxx","ts":"..."}
```

**KerberosConnectionInspected** — Zeek Kerberos:
```json
{"direction":"Out","success":"true","ticketHash":"cf4d7b...","cipher":"aes256-cts-hmac-sha1-96","requestType":"AP","service":"cifs/dc01.domain.local/DOMAIN.LOCAL","uid":"Cxxx","ts":"..."}
```

**SshConnectionInspected** — Zeek SSH:
```json
{"direction":"Out","auth_attempts":"0","client":"SSH-2.0-OpenSSH_for_Windows_9.5","server":"SSH-2.0-...","host_key":"65:96:2d:...","version":"2","uid":"Cxxx"}
```

**ConnectionAttempt** (inbound SYN) / **ConnectionAcknowledged** / inbound rows:
```json
{"direction":"In","Source Mac":"xx:xx:xx:xx:xx:xx","Destination Mac":"xx:xx:xx:xx:xx:xx","Tcp Flags":2,"Packet Size":66}
```

**IcmpConnectionInspected**:
```json
{"conn_state":"OTH","orig_pkts":1,"orig_bytes":48,"resp_pkts":0,"resp_bytes":0}
```
`resp_pkts == 0` / `resp_bytes == 0` = remote host silently dropping — strong indicator of server-side firewall block.

**InboundInternetScanInspected**:
```json
{"PublicScannedPort":8040,"PublicScannedIp":"155.4.163.184"}
```

**ConnectionRequest / InboundConnectionAccepted** — macOS/Linux: POSIX identity in `AdditionalFields`:
```json
{"InitiatingProcessPosixEffectiveUser":{"Sid":"...","Name":"jdoe","DomainName":"MAC-...","AadUserUpn":"jdoe@example.com","PosixUserId":502,"PrimaryPosixGroup":{"Name":"staff","PosixGroupId":20}},"InitiatingProcessPosixEffectiveGroup":{"Name":"staff","PosixGroupId":20},"InitiatingProcessPosixProcessGroupId":39747,"InitiatingProcessPosixSessionId":1,"InitiatingProcessCurrentWorkingDirectory":"/","InitiatingProcessPosixFilePermissions":["None"],"InitiatingProcessPosixRealUser":{...}}
```

## Protocol column inconsistency

Contains `"Tcp"`, `"TcpV4"`, `"TcpV6"`, `"Udp"`. Never use `== "Tcp"` — silently misses `"TcpV4"` rows.

```kql
| where Protocol startswith "Tcp"
| where Protocol startswith "Udp"
```

## ConnectionSuccess ≠ connection was allowed

Network protection blocks happen after the TCP handshake — blocked sites still log `ActionType == "ConnectionSuccess"`. Correlate with `AlertEvidence` to confirm actual blocks.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| join kind=inner AlertEvidence on DeviceId, ReportId
```

## ReportId is NOT globally unique

`ReportId` (`long`) is a local counter — unique only per `(DeviceName, Timestamp)`. Always use three-column composite for joins.

## ProcessUniqueId — docs vs schema mismatch

Official docs list `ProcessUniqueId` as a column. It is **absent from the live schema** as of 2026-04 (same pattern as `DeviceLogonEvents`, `DeviceFileEvents`). `InitiatingProcessUniqueId` IS present and usable.

## InitiatingProcessSHA256 often unpopulated

Official docs note this explicitly. Default to `InitiatingProcessSHA1`.

## LocalIPType / RemoteIPType are unreliable

Frequently blank — Defender populates only when confident. Do not filter on these; they silently drop rows.

## Inbound ActionTypes have no InitiatingProcess* context

`ConnectionAcknowledged`, `ConnectionAttempt`, and `InboundInternetScanInspected` rows: all `InitiatingProcess*` columns are empty/null.

## Timestamp vs TimeGenerated

- `Timestamp` — event time on endpoint; use with `run_hunting_query`
- `TimeGenerated` — ingestion time; use with `run_sentinel_query` (Sentinel mirror of MDE tables)

Both columns exist in the schema; they are usually equal for this table.

## RemoteHostname does not exist

Destination hostname is in `RemoteUrl` (may include full path/scheme). `RemoteIP` holds the resolved IP.

## DnsConnectionInspected — DNS hunting

This ActionType is high-volume and the primary source for DNS-based TI matching. `RemoteUrl` is typically empty for DNS rows — use `AdditionalFields.query`.

```kql
// DNS lookups for a suspicious domain
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsConnectionInspected"
| extend af = parse_json(AdditionalFields)
| where tostring(af.query) endswith ".example-bad.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, DnsQuery=tostring(af.query)
```

## SslConnectionInspected — JA3/JA4 hunting

JA3/JA4 fingerprints available for TLS traffic detection without decryption.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "SslConnectionInspected"
| extend af = parse_json(AdditionalFields)
| summarize Count=count(), Devices=dcount(DeviceName) by tostring(af.ja4)
| sort by Count desc
```

## Listening port inventory

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ListeningConnectionCreated"
| summarize Count=count() by DeviceName, LocalPort, InitiatingProcessFileName
| sort by Count desc
```
