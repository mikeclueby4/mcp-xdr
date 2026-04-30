# DeviceTvmCertificateInfo

**Source**: Defender Advanced Hunting only (Preview). No Sentinel mirror. Populated by Microsoft Defender Vulnerability Management / MDE.

**Do not confuse with `DeviceFileCertificateInfo`** — that table covers file-signing certificates on disk. This table covers device-level TLS/SSL and system certificates in the Windows certificate store.

## Snapshot semantics

No `Timestamp` column (semantic error if used). This is a snapshot/inventory table — one row per `(DeviceId, Thumbprint)` as discovered by TVM assessment cycles. No event-stream semantics. Omit time filters entirely.

## Schema

| Column | Type | Notes |
|---|---|---|
| `DeviceId` | `string` | Standard MDE device ID — joins to `DeviceInfo.DeviceId` |
| `Thumbprint` | `string` | SHA-1 thumbprint (40-char hex) — primary cert identifier |
| `Path` | `string` | PowerShell cert provider path — see Path format below |
| `SerialNumber` | `string` | Serial number within the CA's namespace |
| `IssuedTo` | `dynamic` | Subject DN fields — native dynamic (dict), direct property access works |
| `IssuedBy` | `dynamic` | Issuer DN fields — native dynamic (dict), direct property access works |
| `FriendlyName` | `string` | Human-readable cert name (often blank) |
| `SignatureAlgorithm` | `string` | e.g. `sha256RSA`, `sha384ECDSA`, `sha1RSA`, `md5RSA`, `md2RSA` |
| `KeySize` | `int` | Key size in bits (not string, despite official docs listing it as string) |
| `ExpirationDate` | `datetime` | Cert validity end (not string, despite official docs) |
| `IssueDate` | `datetime` | Cert validity start (not string, despite official docs) |
| `SubjectType` | `string` | `"CA"`, `"End Entity"`, or blank |
| `KeyUsage` | `dynamic` | Native dynamic **array** of strings — direct indexing works |
| `ExtendedKeyUsage` | `dynamic` | Native dynamic **array** of strings — direct indexing works |
| `MachineGroup` | `string` | Device group as configured in MDE |
| `TenantId` | `string` | AAD tenant ID |
| `Type` | `string` | Always `"DeviceTvmCertificateInfo"` (internal type tag) |
| `SourceSystem` | `string` | Always blank in this table |

**Official docs type discrepancies**: `KeySize` is `int` in live schema (not string), `ExpirationDate`/`IssueDate` are `datetime` (not string). Always trust `get_schema()` over docs for types.

## Path format

```
Microsoft.PowerShell.Security\Certificate::LocalMachine\<StoreName>\<Thumbprint>
```

Extract store name:
```kql
| extend Store = tostring(split(Path, "\\")[2])
```

Confirmed store names (this tenant, 2026-04): `Root`, `CA`, `AuthRoot`, `My`, `TestSignRoot`, `TrustedPublisher`, `FlightRoot`, `TrustedAppRoot`, `Windows Live ID Token Issuer`, `Windows Azure Environment`, `Remote Desktop`, `AAD Token Issuer`, `DSCPolicyStore`, `TrustedPeople`, and dynamic runtime stores (`Runtime_Transport_Store_*`).

## IssuedTo / IssuedBy structure

Both are native dynamic dictionaries — no `parse_json()` needed.

Confirmed keys (vary by cert): `CommonName`, `Organization`, `OrganizationalUnit`, `Locality`, `StateOrProvinceName`, `CountryName`.

```kql
| extend CN = tostring(IssuedTo.CommonName)
| extend Org = tostring(IssuedTo.Organization)
| extend IssuerCN = tostring(IssuedBy.CommonName)
```

## KeyUsage / ExtendedKeyUsage

Both are native dynamic **arrays** (not dicts — `bag_keys()` returns empty). Use array indexing or `mv-expand`:

```kql
// Filter certs with a specific usage
| where KeyUsage has "Digital Signature"

// Enumerate all usages
| mv-expand KU = KeyUsage
| summarize Count=count() by tostring(KU)
```

Confirmed `KeyUsage` values: `Digital Signature`, `Certificate Signing`, `CRL Signing`, `Off-line CRL Signing`, `Key Encipherment`, `Data Encipherment`, `Non-Repudiation`.

Confirmed `ExtendedKeyUsage` values: `Server Authentication`, `Client Authentication`, `Code Signing`, `Time Stamping`, `Encrypting File System`, `KDC Authentication`, `Smart Card Logon`, `Windows Hardware Driver Verification`, `Microsoft Publisher`, `Unknown Key Usage`.

## SignatureAlgorithm values (confirmed 2026-04)

`sha256RSA`, `sha1RSA`, `sha384RSA`, `md5RSA`, `sha384ECDSA`, `md2RSA`, `sha1DSA`

Hunt for weak algorithms:
```kql
DeviceTvmCertificateInfo
| where SignatureAlgorithm in ("md5RSA", "md2RSA", "sha1RSA", "sha1DSA")
| summarize Count=count(), Devices=dcount(DeviceId) by SignatureAlgorithm, SubjectType
| sort by Count desc
```

## Expiry hunting

No `Timestamp` — use `now()` or fixed dates:
```kql
DeviceTvmCertificateInfo
| where ExpirationDate between (now() .. now() + 30d)
| where SubjectType == "End Entity"
| project DeviceId, Thumbprint, FriendlyName, ExpirationDate,
          CN=tostring(IssuedTo.CommonName), Store=tostring(split(Path,"\\")[2])
| sort by ExpirationDate asc
```

## Cross-table joins

- **`DeviceInfo`** on `DeviceId` — enrich with `DeviceName`, `OSPlatform`, `MachineGroup`. Always deduplicate DeviceInfo with `summarize arg_max(Timestamp, *) by DeviceId` first.
- No `ReportId` column — cannot join to alert/event tables by ReportId.
