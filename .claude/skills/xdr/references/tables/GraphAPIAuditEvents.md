# GraphAPIAuditEvents — Table Notes

## Column types

**`ResponseStatusCode`** — type `long`. Arithmetic and comparisons work directly:
```kql
| where ResponseStatusCode >= 400
| summarize Errors=countif(ResponseStatusCode >= 400)
```

**`RequestDuration`** — stored as `string` despite containing numeric microsecond values. Wrap with `tolong()` before any math:
```kql
| summarize AvgSec=round(avg(tolong(RequestDuration)) / 1000000, 1)
```

## Column sizes

**`RequestUri`** — contains full URLs including Graph delta continuation tokens, which can be several kilobytes each. A handful of rows can push past the 10 KB inline result threshold.

Extract just the path for summarization:
```kql
| extend Path = tostring(parse_url(RequestUri).Path)
```

Or drop it entirely when it's not needed:
```kql
| project-away RequestUri
```

## Key hunting columns

`ApplicationId`, `RequestMethod`, `ResponseStatusCode`, `RequestUri` (or its extracted `Path`), `Scopes`, `IpAddress`, `TargetWorkload`, `RequestDuration`, `ApiVersion`

`ServicePrincipalId` is present but often empty for app-only calls; use `ApplicationId` as the stable app identity.
