# Eval 1 WITH skill: IP sign-in query

## Schema check (AADSignInEventsBeta)
Called `get_hunting_schema` first. Key columns: `Timestamp`, `IPAddress`, `ErrorCode` (0 = success), `AccountUpn`, `AccountDisplayName`, `Application`, `Country`, `City`, `DeviceName`, `ClientAppUsed`, `RiskLevelDuringSignIn`.

## Sample (take 3)
Ran 3-row sample. Confirmed IPs stored in **mixed formats** — native IPv4 (`78.82.51.190`) and native IPv6 (`2405:201:...`). Validates the need for `ipv6_is_match()`.

## Final query
```kql
AADSignInEventsBeta
| where Timestamp >= ago(7d)
| where ipv6_is_match(IPAddress, "203.0.113.42")
    or ipv6_is_match(IPAddress, "::ffff:203.0.113.42")
| project
    Timestamp,
    AccountUpn,
    AccountDisplayName,
    IPAddress,
    ErrorCode,
    SignInSucceeded = iff(ErrorCode == 0, "Success", strcat("Failure (", tostring(ErrorCode), ")")),
    Application,
    Country,
    City,
    DeviceName,
    ClientAppUsed,
    RiskLevelDuringSignIn
| sort by Timestamp desc
```

## Results
0 rows (203.0.113.42 is RFC 5737 TEST-NET-3 — no real sign-ins). Query is structurally correct.
