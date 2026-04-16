# IdentityInfo

## Snapshot cadence — use ago(2d) minimum

`IdentityInfo` is sourced from Entra ID directory sync, not from activity signals — it reflects what exists in the directory, not who has been recently active. Disabled accounts, shared mailboxes, and resource accounts all appear just like active users.

Per the Microsoft docs, a new row is written per identity either when a change is detected **or after 24 hours** — so the snapshot cadence is at most 24h. However, `ago(1d)` sits right on that edge and can miss records due to processing delay. `ago(2d)` is the safe minimum; `ago(7d)` is conservatively safe with no downside.

**Always use at least `ago(2d)` (preferably `ago(7d)`) for this table**, even when you only care about current state:

```kql
IdentityInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, *) by AccountUpn
```

The `arg_max` deduplication is still required — multiple snapshot rows per user will exist within the window.


## GroupMembership requires Sentinel UEBA

`GroupMembership` (and several other useful columns like `Tags`, `BlastRadius`, `DeletedDateTime`, `EmployeeId`) are **only available if the tenant has Microsoft Sentinel onboarded with UEBA enabled**. In a pure Defender XDR deployment without Sentinel, these columns will be absent/null.

Columns always available (no Sentinel requirement): `AccountUpn`, `AccountName`, `AccountDisplayName`, `Department`, `JobTitle`, `IsAccountEnabled`, `EmailAddress`, `RiskLevel`, `RiskStatus`, `AssignedRoles`, `IdentityEnvironment`.

## Guest/external accounts

Guest accounts (B2B invites) appear with `#EXT#` in the UPN, e.g.:
`firstname.lastname_otherdomain.tld#EXT#@{tenant}.onmicrosoft.com`

Filter them out with `| where AccountUpn !has "#EXT#"` if you only want internal members.
