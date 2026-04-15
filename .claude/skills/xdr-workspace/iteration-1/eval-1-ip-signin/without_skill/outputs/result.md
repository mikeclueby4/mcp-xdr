# Eval 1 WITHOUT skill: IP sign-in query (baseline)

## Final query
```kql
let targetIP = "203.0.113.42";
let lookback = 7d;

let aadSignins = AADSignInEventsBeta
| where Timestamp >= ago(lookback)
| where IPAddress == targetIP   -- STRING EQUALITY: will miss ::ffff:203.0.113.42
| extend Source = "AADSignInEventsBeta"
| extend SignInResult = iff(ErrorCode == 0, "Success", strcat("Failure (ErrorCode: ", tostring(ErrorCode), ")"))
| project Timestamp, Source, AccountUpn, IPAddress, Country, City, Application, LogonType, DeviceName, OSPlatform, ErrorCode, FailureReason = "", SignInResult;

let identityLogons = IdentityLogonEvents
| where Timestamp >= ago(lookback)
| where IPAddress == targetIP   -- STRING EQUALITY: will miss ::ffff:203.0.113.42
| extend Source = "IdentityLogonEvents"
| extend SignInResult = iff(ActionType == "LogonSuccess", "Success", strcat("Failure (", coalesce(FailureReason, ActionType), ")"))
| project Timestamp, Source, AccountUpn, IPAddress, Country = Location, City = "", Application, LogonType, DeviceName, OSPlatform, ErrorCode = int(null), FailureReason, SignInResult;

aadSignins
| union identityLogons
| order by Timestamp desc
```

## Results
0 rows (~1.13s). RFC 5737 test IP — no real data. But query uses string equality `==` which would silently miss IPv6-mapped addresses.
