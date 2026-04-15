# Eval 6 WITHOUT skill: CloudAppEvents baseline

## Tool calls made

No external tool calls were made. Query written from expert knowledge of Microsoft Defender Advanced Hunting and the CloudAppEvents table schema.

---

## Final KQL query

```kql
// Hunt for OAuth apps accessing significantly more data or new resource types
// compared to their recent baseline — insider threat / OAuth abuse investigation
let BaselineStart    = ago(30d);
let BaselineEnd      = ago(8d);
let DetectionStart   = ago(7d);
let DetectionEnd     = now();
let BaselineDays     = 22.0;
let DetectionDays    =  7.0;
let VolumeMultiplier = 3.0;
let MinBaselineEvents = 5;

let Baseline = CloudAppEvents
    | where Timestamp between (BaselineStart .. BaselineEnd)
    | where isnotempty(AccountObjectId)
    | summarize
        BaselineEvents       = count(),
        BaselineResTypes     = make_set(ObjectType, 500),
        BaselineActions      = make_set(ActionType, 200),
        BaselineAccountCount = dcount(AccountObjectId)
      by AppId, AppName
    | where BaselineEvents >= MinBaselineEvents
    | extend BaselineDailyRate = todouble(BaselineEvents) / BaselineDays;

let Detection = CloudAppEvents
    | where Timestamp between (DetectionStart .. DetectionEnd)
    | where isnotempty(AccountObjectId)
    | summarize
        DetectionEvents       = count(),
        DetectionResTypes     = make_set(ObjectType, 500),
        DetectionActions      = make_set(ActionType, 200),
        DetectionAccountCount = dcount(AccountObjectId),
        SampleAccounts        = make_set(AccountObjectId, 20),
        SampleUPNs            = make_set(AccountDisplayName, 20),
        FirstSeen             = min(Timestamp),
        LastSeen              = max(Timestamp)
      by AppId, AppName
    | extend DetectionDailyRate = todouble(DetectionEvents) / DetectionDays;

Baseline
| join kind=inner Detection on AppId
| extend
    RateRatio        = DetectionDailyRate / BaselineDailyRate,
    NewResourceTypes = set_difference(DetectionResTypes, BaselineResTypes),
    NewActionTypes   = set_difference(DetectionActions, BaselineActions),
    AccountSpike     = DetectionAccountCount > (BaselineAccountCount * 2)
| extend
    NewResourceTypeCount = array_length(NewResourceTypes),
    NewActionTypeCount   = array_length(NewActionTypes)
| where RateRatio >= VolumeMultiplier
      or NewResourceTypeCount > 0
| extend
    RiskScore = toint(
        min_of(50, toint((RateRatio - 1.0) * 10))
        + (NewResourceTypeCount * 10)
        + (NewActionTypeCount * 5)
        + iff(AccountSpike, 10, 0)
    )
| project
    AppId, AppName, RiskScore,
    BaselineDailyRate  = round(BaselineDailyRate, 1),
    DetectionDailyRate = round(DetectionDailyRate, 1),
    RateRatio          = round(RateRatio, 2),
    BaselineEvents, DetectionEvents,
    NewResourceTypes, NewResourceTypeCount,
    NewActionTypes, NewActionTypeCount,
    BaselineAccountCount, DetectionAccountCount,
    AccountSpike, SampleAccounts, SampleUPNs,
    FirstSeen, LastSeen
| sort by RiskScore desc, RateRatio desc
```

---

## Notes

- Two-window baseline: 22-day baseline ending 8 days ago, 7-day detection window.
- Daily-rate normalisation makes ratio window-length agnostic.
- `set_difference` on ObjectType catches lateral resource expansion.
- Composite RiskScore: volume spike + resource novelty + action novelty + account spread.
- No doc fetch performed — schema assumptions from model knowledge.
