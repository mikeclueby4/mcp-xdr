# Eval 6 WITH skill: CloudAppEvents doc fetch

## Tool calls made

1. **`mcp__defender__get_hunting_schema(table_name="CloudAppEvents")`** — key columns: OAuthAppId (string), ActivityType, ActionType, ObjectType, ObjectName, UncommonForUser (dynamic), LastSeenForUser (dynamic), AccountObjectId, AccountDisplayName, Application, IsAnonymousProxy, IPTags
2. **`mcp__microsoft-learn__microsoft_docs_fetch(url="https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table")`** — fetched full reference. Key findings: `UncommonForUser` is a JSON array of anomalous field names; `LastSeenForUser` is a JSON dict of attribute→days (negative = first-ever seen); `OAuthAppId` is the Entra OAuth 2.0 app identifier
3. **`mcp__defender__run_hunting_query("CloudAppEvents | take 3")`** — confirmed `UncommonForUser` is `[]` (enriched, no anomalies) or `None`; Exchange DLP events dominate raw sample
4. **`mcp__defender__run_hunting_query` (OAuthAppId-filtered 5-row sample)** — `OAuthAppId` is a GUID; `ObjectType` values include Task, Email, File, Folder; `LastSeenForUser` is `{'ActionType': 0, 'ISP': 0}`
5. **`mcp__defender__run_hunting_query` (7-day daily rollup)** — 58–86 distinct OAuth apps/day; 17K–68K events/day — good data density
6. **`mcp__defender__run_hunting_query` (per-app summary)** — high-volume outlier: `a7cd46df` — 79K Exchange events for 1 user (likely mail client)
7. **`mcp__defender__run_hunting_query` (UncommonForUser filter)** — confirmed `[] = enriched, no anomaly`; `["UserAgent"] = UserAgent anomalous`; `LastSeenForUser` negative int = first-ever seen

---

## Final KQL query

```kql
// Suspicious OAuth App Activity — Insider Threat Investigation
let LookbackBaseline  = 7d;
let RecentWindow      = 2d;
let BaselineWindow    = 5d;
let MinBaselineEvents = 10;
let VolumeSpikeFactor = 3.0;
let NewObjectTypeThreshold = 1;

let Baseline = CloudAppEvents
    | where Timestamp between (ago(LookbackBaseline) .. ago(RecentWindow))
    | where isnotempty(OAuthAppId) and isnotempty(AccountObjectId)
    | summarize
        BaselineEvents      = count(),
        BaselineObjectTypes = make_set(ObjectType, 20),
        BaselineActionTypes = make_set(ActionType, 20),
        BaselineApps        = make_set(Application, 10)
      by OAuthAppId, AccountObjectId
    | where BaselineEvents >= MinBaselineEvents
    | extend BaselineDailyRate = todouble(BaselineEvents) / todouble(BaselineWindow / 1d);

let Recent = CloudAppEvents
    | where Timestamp > ago(RecentWindow)
    | where isnotempty(OAuthAppId) and isnotempty(AccountObjectId)
    | summarize
        RecentEvents       = count(),
        RecentObjectTypes  = make_set(ObjectType, 20),
        RecentActionTypes  = make_set(ActionType, 20),
        RecentApps         = make_set(Application, 10),
        SampleUsers        = make_set(AccountDisplayName, 5),
        UncommonCount      = countif(array_length(todynamic(tostring(UncommonForUser))) > 0),
        FirstSeenCount     = countif(
                               isnotempty(tostring(LastSeenForUser)) and
                               tostring(LastSeenForUser) != "None" and
                               tostring(LastSeenForUser) contains "-"
                             ),
        AnonProxyEvents    = countif(IsAnonymousProxy == true)
      by OAuthAppId, AccountObjectId
    | extend RecentDailyRate = todouble(RecentEvents) / todouble(RecentWindow / 1d);

Baseline
| join kind=inner Recent on OAuthAppId, AccountObjectId
| extend
    VolumeRatio     = iff(BaselineDailyRate > 0, RecentDailyRate / BaselineDailyRate, todouble(RecentEvents)),
    NewObjectTypes  = set_difference(RecentObjectTypes, BaselineObjectTypes),
    NewActionTypes  = set_difference(RecentActionTypes, BaselineActionTypes),
    NewApplications = set_difference(RecentApps, BaselineApps)
| extend
    NewObjectTypeCount  = array_length(NewObjectTypes),
    NewActionTypeCount  = array_length(NewActionTypes),
    NewApplicationCount = array_length(NewApplications)
| where VolumeRatio >= VolumeSpikeFactor
    or NewObjectTypeCount >= NewObjectTypeThreshold
    or NewApplicationCount >= 1
    or UncommonCount > 0
    or FirstSeenCount > 0
    or AnonProxyEvents > 0
| extend AnomalyScore =
    iff(VolumeRatio >= VolumeSpikeFactor, 2, 0)
    + iff(NewObjectTypeCount >= 1, 2, 0)
    + iff(NewActionTypeCount >= 1, 1, 0)
    + iff(NewApplicationCount >= 1, 2, 0)
    + iff(UncommonCount > 0, 1, 0)
    + iff(FirstSeenCount > 0, 1, 0)
    + iff(AnonProxyEvents > 0, 3, 0)
| project
    OAuthAppId, AccountObjectId, SampleUsers,
    BaselineApps, RecentApps, NewApplications,
    BaselineObjectTypes, RecentObjectTypes, NewObjectTypes, NewObjectTypeCount,
    BaselineActionTypes, RecentActionTypes, NewActionTypes, NewActionTypeCount,
    BaselineEvents, BaselineDailyRate = round(BaselineDailyRate, 1),
    RecentEvents, RecentDailyRate = round(RecentDailyRate, 1),
    VolumeRatio = round(VolumeRatio, 2),
    UncommonCount, FirstSeenCount, AnonProxyEvents, AnomalyScore
| order by AnomalyScore desc, VolumeRatio desc
```

---

## Notes

- Per-(OAuthAppId, AccountObjectId) granularity: insider threat is user-level — one user's spike doesn't dilute across normal users of the same app.
- `UncommonForUser` and `LastSeenForUser` are Defender-native anomaly signals incorporated from live sampling.
- `IsAnonymousProxy` weighted +3 in AnomalyScore — high confidence signal.
- `set_difference()` on ObjectType catches lateral resource expansion (e.g., mail client suddenly downloading SharePoint files).
- MS Learn doc fetch surfaced key dynamic column semantics not visible in schema alone.
