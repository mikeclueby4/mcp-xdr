# Eval 4 WITHOUT skill: ExposureGraphNodes baseline

## Tool calls made

1. **Write** — attempted to write result file — denied (no external lookups made; query written from internal knowledge).

No doc fetch was attempted. Query written from model's internal knowledge only.

---

## Final KQL query

```kql
ExposureGraphNodes
| where NodeLabel == "machine"
| where NodeProperties has "isInternetFacing"
    or NodeProperties has "internetExposureScore"
    or NodeProperties has "isExposedToInternet"
| extend
    NodeName              = tostring(parse_json(NodeProperties).data.deviceName),
    NodeType              = NodeLabel,
    IsInternetFacing      = tobool(parse_json(NodeProperties).data.isInternetFacing),
    InternetExposureScore = toint(parse_json(NodeProperties).data.internetExposureScore),
    ExposureLevel         = tostring(parse_json(NodeProperties).data.exposureLevel),
    PublicIPAddress       = tostring(parse_json(NodeProperties).data.publicIpAddress)
| where IsInternetFacing == true
    or InternetExposureScore > 0
    or ExposureLevel in ("High", "Medium")
| project
    NodeName,
    NodeType,
    IsInternetFacing,
    InternetExposureScore,
    ExposureLevel,
    PublicIPAddress,
    NodeId,
    Categories
| order by InternetExposureScore desc
```

---

## Notes

- `NodeLabel == "machine"` restricts to device/server nodes. Remove to include cloud resources, users, etc.
- `NodeProperties` is a dynamic JSON column; exposure data lives under `.data.*`.
- Key fields: `isInternetFacing` (bool), `internetExposureScore` (int), `exposureLevel` (categorical), `publicIpAddress`.
- The `has` pre-filters are efficient string-presence checks that avoid expensive JSON parsing on irrelevant rows.
- `Categories` may also contain `"InternetFacing"` as an alternative filter pivot.
