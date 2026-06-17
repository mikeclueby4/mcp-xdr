# EOL Client OS & Version Detection via Sign-in Logs

Detect end-of-life operating systems and client software authenticating to Entra ID, using `EntraIdSignInEvents` (Defender) and `DeviceInfo` as complementary sources.

**When to use:** Periodic hygiene sweeps; CA policy design (OS-version compliance); incident triage where you need to know if a victim device is patched; compliance reporting.

---

## Signal sources and what each covers

| Source | What it reveals | Gaps |
|---|---|---|
| `DeviceInfo.OSPlatform` + `OSVersionInfo` + `OSBuild` | Authoritative OS for Defender-enrolled endpoints. Distinguishes Win11 from Win10. | Only Defender-enrolled devices. No unmanaged/BYOD. |
| `EntraIdSignInEvents.OSPlatform` | OS family + version for mobile (iOS full version string, e.g. `"Ios 18.6.2"`). **Does NOT distinguish Win11 from Win10** — both appear as `"Windows10"`. | Not useful for Windows version granularity. |
| `EntraIdSignInEvents.UserAgent` | **Best Windows + Mac signal** from sign-in logs. Multiple UA families (see below) cover M365 desktop + mobile apps. Works for unmanaged devices too. | UA can be spoofed; absent (`""`) for some legacy auth flows. |
| Darwin kernel in `CFNetwork/…` UAs | Secondary iOS/macOS signal from JAMF Self Service and MS Authenticator app. `Darwin/<major>` encodes OS version: major − 9 = macOS/iOS major (Darwin 25 = macOS 26 / iOS 26; Darwin 24 = macOS 15 / iOS 18). | Only fires for these two client types; not present in MSAL rows. |
| `EntraIdSignInEvents.Browser` | Pre-parsed browser name+version extracted from UA by Entra. Useful for quick filtering. | Only covers browser auth; empty for MSAL/Dalvik clients. |

---

## UA pattern families — how to decode OS version

### 1. Windows — AAD broker / WebView (`Edge/18.<build>`)

Every M365 desktop app on Windows (Teams, Office suite, OneDrive sync, Edge, Authenticator) uses the Windows Web Authentication Manager (WAM) or the legacy EdgeHTML WebView for Entra auth. Both send this UA:

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ... Edge/18.<WinBuild>
```

The number after `18.` **is the Windows OS build number**. This is the primary EOL signal for Windows in sign-in logs. Extract with:

```kql
| extend WinBuild = toint(extract(@"Edge/18\.(\d+)", 1, UserAgent))
```

Build → version mapping:

| Build range | Windows version | EOL status (as of 2026) |
|---|---|---|
| `>= 26200` | Windows 11 25H2 | Current |
| `>= 26100` | Windows 11 24H2 | Current |
| `>= 22631` | Windows 11 23H2 | EOL Nov 2025 (Home/Pro); EOL Nov 2026 (Enterprise/Education) |
| `>= 22621` | Windows 11 22H2 | EOL Oct 2024 (Home/Pro); EOL Oct 2025 (Enterprise/Education) |
| `>= 22000` | Windows 11 21H2 | EOL Oct 2023 (Home/Pro/Enterprise) |
| `20348` | Windows Server 2022 | Extended support (2031) |
| `19045` | Windows 10 22H2 | EOL Oct 2025 |
| `19044` | Windows 10 21H2 | EOL Jun 2023 |
| `19041`–`19043` | Windows 10 2004/20H2/21H1 | EOL 2021–2022 |
| `18363` | Windows 10 1909 | EOL May 2021 |
| `18362` | Windows 10 1903 | EOL Dec 2019 |
| `17763` | Windows 10 1809 / Server 2019 | Win10: EOL Jan 2024 |
| `17134` | Windows 10 1803 | EOL Nov 2019 |
| `16299` | Windows 10 1709 | EOL Apr 2019 |
| `14393` | Windows Server 2016 | Extended support (2027) |

**Note:** `Edge/18.26100` is the dominant UA. Do NOT treat it as a threat — it is the normal Windows 11 24H2 WAM broker UA. See tenant.local.md for the `Edge/18.26100` + `WebView/3.0` variant (AAD.BrokerPlugin on older Windows 10 machines).

Alternative signal from Chromium Edge browser itself (only when user is browsing, not for MSAL auth):
```
... Edg/148.0.0.0 OS/10.0.<WinBuild>
```
```kql
| extend WinBuildAlt = toint(extract(@"OS/10\.0\.(\d+)", 1, UserAgent))
```

### 2. macOS — MSAL (`MSAL 1.x (Macintosh; Mac OS X <ver>...)`)

All Microsoft apps on macOS (Teams, Office, OneDrive, Outlook, Edge) use MSAL and send:

```
MSAL 1.1.0 (Macintosh; Mac OS X 15_7_3 arm64 sv-SE) PKeyAuth/1.0
```

Version format uses underscores: `15_7_3` = macOS 15.7.3 (Sequoia). Extract with:

```kql
| extend MacOSVer = replace_string(extract(@"Mac OS X ([\d_]+)", 1, UserAgent), "_", ".")
| extend MacOSMajor = toint(extract(@"Mac OS X (\d+)", 1, UserAgent))
```

macOS EOL reference (as of 2026):

| Major | Name | Status |
|---|---|---|
| 26 | Tahoe (beta) | Developer/public beta |
| 15 | Sequoia | Current |
| 14 | Sonoma | Supported |
| 13 | Ventura | Supported (borderline — Apple support ending ~2026) |
| 12 | Monterey | EOL Sept 2024 |
| 11 | Big Sur | EOL Sept 2023 |
| ≤ 10 | Catalina and older | EOL |

`accountsd/113 CFNetwork/...` UAs are the macOS native account daemon (Apple Internet Accounts syncing Exchange/calendar) — OS version is not in this UA; use `MSAL` rows for the same device for version.

**Additional macOS UA family** — JAMF Self Service / JAMF Connect:
```
Self Service+/7553 CFNetwork/macOS/3860.400.51 Darwin/25.3.0
```
The `CFNetwork/macOS/<ver>` token carries the exact macOS version string (3860.400.51 ≈ macOS 26.3) but requires a CFNetwork→macOS lookup table. The Darwin kernel major is simpler: **Darwin major − 9 = macOS major** (Darwin 25 = macOS 26 Tahoe; Darwin 24 = macOS 15 Sequoia; Darwin 23 = macOS 14 Sonoma).
```kql
| extend MacOSFromDarwin = case(
    UserAgent has "Darwin/" and UserAgent has "CFNetwork/macOS",
    toint(extract(@"Darwin/(\d+)\.", 1, UserAgent)) - 9,
    int(null))
```
Use `coalesce(MacOSMajor, MacOSFromDarwin)` in the platform classification to cover both MSAL and JAMF rows.

### 3. iOS — MSAL (`MSAL 1.x (iPhone; OS <ver>...)`)

```
MSAL 1.1.0 (iPhone; OS 18_7_8 like Mac OS X arm64 sv-SE) PKeyAuth/1.0
```

```kql
| extend iOSVer = replace_string(extract(@"OS ([\d_]+) like Mac OS X", 1, UserAgent), "_", ".")
| extend iOSMajor = toint(extract(@"OS (\d+)_", 1, UserAgent))
```

iOS EOL (as of 2026): iOS 18 is current. iOS 17 still gets security patches (17.7.x) but Apple is no longer developing it. iOS 16 and below: EOL — Apple ships only occasional patches for 16.7.x. iOS 15 and below: fully EOL, no patches.

Note: `EntraIdSignInEvents.OSPlatform` also carries full iOS version strings like `"Ios 18.6.2"` for sign-ins where UA is absent (e.g. some token-refresh flows). Use both.

**Additional iOS UA families** — same `iPhone OS (\d+)_` regex applies to all:

*iOS Safari / WebView (browser SSO flows):*
```
Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148
```

*Edge iOS browser (`EdgiOS/<browser_ver>`):*
```
Mozilla/5.0 (iPhone; CPU iPhone OS 26_4_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/147.0.3912.87 Version/26.0 Mobile/15E148 Safari/604.1
```
Note: `EdgiOS/<ver>` is the browser version, not the OS version — use `iPhone OS (\d+)_` regardless.

*Microsoft Authenticator app (MFA prompts, passwordless):*
```
Microsoft%20Authenticator/2 CFNetwork/3860.500.112 Darwin/25.4.0 ;iPhone
```
No `iPhone OS` string here — use the Darwin kernel formula instead:
```kql
| extend iOSFromDarwin = case(
    UserAgent has ";iPhone" and isnotempty(extract(@"Darwin/(\d+)\.", 1, UserAgent)),
    toint(extract(@"Darwin/(\d+)\.", 1, UserAgent)) - 9,
    int(null))
```
Darwin 25.4 → iOS 26.4; Darwin 24.x → iOS 18; Darwin 23.x → iOS 17.

### 4. Android — Dalvik / MSAL WebView (`Dalvik/2.x …` or `… Android <ver>; <model>… wv) … PKeyAuth/1.0`)

Three UA families carry real Android version numbers:

*Dalvik (Microsoft apps — Teams, Outlook, OneDrive, Intune):*
```
Dalvik/2.1.0 (Linux; U; Android 16; SM-S921B Build/BP2A...) ;SM-S921B
```

*MSAL-controlled WebView (broker-assisted auth in apps):*
```
Mozilla/5.0 (Linux; Android 16; Pixel 8a Build/CP1A.260405.005; wv) AppleWebKit/537.36 ... PKeyAuth/1.0
```
The `; wv)` flag (embedded WebView) combined with `PKeyAuth/1.0` identifies MSAL control. Carries real OS version; **not** affected by Chrome's privacy masking.

**Critical: Chrome privacy-masked UA — `Android 10; K`**

Chrome 109+ on Android sends `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 ...` regardless of actual OS version. A Pixel 8a on Android 16 sends `Android 10; K`. **Do not use `Android 10` extracted from this pattern as an EOL signal.** Only Dalvik, MSAL, and MSAL WebView (`; wv) … PKeyAuth/1.0`) UAs carry real OS versions.

Filter pattern — exclude privacy-masked Chrome rows before extracting:
```kql
| where UserAgent !has "Android 10; K"
| extend AndroidVer = toint(extract(@"Android (\d+)", 1, UserAgent))
```

Or accept only real-version families explicitly:
```kql
| where UserAgent startswith "Dalvik"
    or UserAgent startswith "MSAL"
    or (UserAgent has "; wv)" and UserAgent has "PKeyAuth/1.0")
| extend AndroidVer = toint(extract(@"Android (\d+)", 1, UserAgent))
```

Android EOL (as of 2026): Google supports current + 2 prior majors for security patches. Android 14+ supported; Android 13 borderline; Android 12 and below EOL.

---

## Reusable recipe: full EOL sign-in sweep

```kql
// EOL Client OS Detection — sign-in logs
// Covers: Windows (WAM broker UA), macOS (MSAL + JAMF Darwin), iOS (MSAL + Safari/WebView + Darwin),
//         Android (Dalvik + MSAL WebView/PKeyAuth)
// Source: EntraIdSignInEvents (run_hunting_query), last 30 days
// Scope: filter to M365 productivity apps only; adjust Application list as needed
let SCOPE_APPS = dynamic([
    "Microsoft Office", "Microsoft Teams", "Outlook Mobile",
    "OneDrive SyncEngine", "Office 365 Exchange Online",
    "Office 365 SharePoint Online", "OneDrive iOS App",
    "Microsoft Edge", "OfficeHome"
]);
let EOL_WIN_BUILDS = dynamic([
    // All Win10 (19045 = 22H2 is latest Win10, all EOL Oct 2025)
    // Win11 < 24H2 (26100) also EOL; uncomment second line to include them
    18363, 18362, 17763, 17134, 16299, 15063, 14393,
    19041, 19042, 19043, 19044, 19045
    // , 22000, 22621, 22631  // Win11 21H2/22H2/23H2 — EOL but may still be in grace period
]);
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where Application in (SCOPE_APPS) or isempty(SCOPE_APPS)
| where isnotempty(UserAgent)
// --- Windows via WAM/WebView broker UA ---
| extend WinBuild    = toint(extract(@"Edge/18\.(\d+)", 1, UserAgent))
| extend WinBuildAlt = toint(extract(@"OS/10\.0\.(\d+)", 1, UserAgent))
| extend WinBuildFinal = coalesce(WinBuild, WinBuildAlt)
// --- macOS via MSAL or JAMF (Darwin kernel: major - 9 = macOS major) ---
| extend MacOSMajor     = toint(extract(@"Mac OS X (\d+)_", 1, UserAgent))
| extend MacOSFromDarwin = case(
    UserAgent has "Darwin/" and UserAgent has "CFNetwork/macOS",
    toint(extract(@"Darwin/(\d+)\.", 1, UserAgent)) - 9, int(null))
| extend MacOSMajorFinal = coalesce(MacOSMajor, MacOSFromDarwin)
| extend MacOSVer = replace_string(extract(@"Mac OS X ([\d_]+)", 1, UserAgent), "_", ".")
// --- iOS via MSAL / Safari WebView / EdgiOS, or MS Authenticator (Darwin: major - 9 = iOS major) ---
| extend iOSMajor     = toint(extract(@"(?:iPhone OS|OS) (\d+)_\d+ like Mac OS X", 1, UserAgent))
| extend iOSFromDarwin = case(
    UserAgent has ";iPhone" and UserAgent has "Darwin/",
    toint(extract(@"Darwin/(\d+)\.", 1, UserAgent)) - 9, int(null))
| extend iOSMajorFinal = coalesce(iOSMajor, iOSFromDarwin)
| extend iOSVer = replace_string(extract(@"(?:iPhone OS|OS) ([\d_]+) like Mac OS X", 1, UserAgent), "_", ".")
// --- Android via Dalvik, MSAL, or MSAL WebView (PKeyAuth); exclude Chrome privacy-masked rows ---
| where UserAgent !has "Android 10; K"
| extend AndroidVer = toint(extract(@"Android (\d+)", 1, UserAgent))
// --- Classify platform + EOL status ---
| extend Platform = case(
    isnotempty(tostring(WinBuildFinal))   and WinBuildFinal > 0,   "Windows",
    isnotempty(tostring(MacOSMajorFinal)) and MacOSMajorFinal > 0, "macOS",
    isnotempty(tostring(iOSMajorFinal))   and iOSMajorFinal > 0,   "iOS",
    isnotempty(tostring(AndroidVer))      and AndroidVer > 0,      "Android",
    ""
  )
| extend OsVersion = case(
    Platform == "Windows", strcat("Build ", tostring(WinBuildFinal)),
    Platform == "macOS",   iff(isnotempty(MacOSVer), MacOSVer, strcat(tostring(MacOSMajorFinal), ".x")),
    Platform == "iOS",     iff(isnotempty(iOSVer), iOSVer, strcat(tostring(iOSMajorFinal), ".x")),
    Platform == "Android", tostring(AndroidVer),
    ""
  )
| extend IsEOL = case(
    Platform == "Windows" and WinBuildFinal in (EOL_WIN_BUILDS),              true,
    Platform == "Windows" and WinBuildFinal > 0 and WinBuildFinal < 14393,    true,  // pre-Server2016
    Platform == "macOS"   and MacOSMajorFinal > 0 and MacOSMajorFinal <= 12,  true,
    Platform == "iOS"     and iOSMajorFinal > 0 and iOSMajorFinal <= 15,      true,
    Platform == "Android" and AndroidVer > 0 and AndroidVer <= 12,            true,
    false
  )
| extend RiskTier = case(
    Platform == "Windows" and WinBuildFinal > 0 and WinBuildFinal < 18363,       "Critical",
    Platform == "Windows" and WinBuildFinal in (18363, 18362, 17134),            "Critical",
    Platform == "Windows" and WinBuildFinal in (19041,19042,19043,19044,19045),  "High",
    Platform == "macOS"   and MacOSMajorFinal > 0 and MacOSMajorFinal <= 11,     "Critical",
    Platform == "macOS"   and MacOSMajorFinal == 12,                             "High",
    Platform == "iOS"     and iOSMajorFinal > 0 and iOSMajorFinal <= 15,         "High",
    Platform == "Android" and AndroidVer > 0 and AndroidVer <= 11,              "High",
    Platform == "Android" and AndroidVer == 12,                                  "Medium",
    IsEOL, "Medium",
    "OK"
  )
| where IsEOL == true
| summarize
    SignIns   = count(),
    LastSeen  = max(Timestamp),
    Apps      = make_set(Application, 10),
    Users     = make_set(AccountUpn, 20)
    by Platform, OsVersion, RiskTier
| order by RiskTier asc, Platform asc, OsVersion asc
```

---

## Per-user EOL breakdown (for outreach list)

Pivot the above by user instead of version, to get a contact list:

```kql
// Per-user EOL summary for outreach
// (paste the same extraction block from above, then change the summarize)
// ...
| where IsEOL == true
| summarize
    SignIns   = count(),
    LastSeen  = max(Timestamp),
    Platforms = make_set(strcat(Platform, " ", OsVersion), 5),
    Apps      = make_set(Application, 5)
    by AccountUpn
| order by LastSeen desc
```

---

## DeviceInfo complement — enrolled endpoints only

For Defender-enrolled devices, `DeviceInfo` is more authoritative (not UA-based, not spoofable).

**Critical:** `DeviceInfo` includes passively-discovered network devices (`OnboardingStatus == "Can be onboarded"`) with no sensor. These inflate EOL counts dramatically — a single managed device can expose dozens of home-network neighbors. Always filter `OnboardingStatus == "Onboarded"` first.

```kql
DeviceInfo
| where isnotempty(OSPlatform)
| summarize arg_max(ingestion_time(), *) by DeviceId
| where OnboardingStatus == "Onboarded"
| where DeviceType in ("Workstation", "Server", "Mobile")
| extend IsEOL = case(
    OSPlatform == "Windows7",                                      true,
    OSPlatform == "WindowsXp",                                     true,
    OSPlatform == "Windows10" and OSBuild <= 19045,                true,  // all Win10 EOL Oct 2025
    OSPlatform == "Windows11" and OSBuild < 22621,                 true,  // 21H2 EOL all editions
    // 22H2 (22621) EOL Oct 2024 Home/Pro, Oct 2025 Enterprise — adjust threshold to your fleet edition
    // 23H2 (22631) EOL Nov 2025 Home/Pro, Nov 2026 Enterprise — not flagged here by default
    OSPlatform == "macOS" and OSVersionInfo startswith "10.",      true,
    OSPlatform == "macOS" and OSVersionInfo startswith "11.",      true,
    OSPlatform == "macOS" and OSVersionInfo startswith "12.",      true,
    OSPlatform == "iOS" and toint(extract(@"^(\d+)", 1, OSVersionInfo)) <= 15, true,
    OSPlatform == "Android" and toint(OSVersionInfo) <= 12,        true,
    false
  )
| where IsEOL == true
| summarize Devices = count(), DeviceList = make_set(DeviceName, 50)
    by OSPlatform, OSVersionInfo, OSBuild
| order by OSPlatform asc, OSBuild desc
```

---

## Sentinel cross-check (unmanaged BYOD via SigninLogs)

`SigninLogs.DeviceDetail.operatingSystem` carries OS name but NOT version — lower fidelity than the UA approach. Use only to catch devices that appear in Sentinel but not in `EntraIdSignInEvents`:

```kql
// Sentinel: OS names from DeviceDetail (no version, but catches BYOD not in Defender)
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| where ResultType == "0"
| extend OS = tostring(parse_json(tostring(DeviceDetail)).operatingSystem)
| where OS in ("Windows", "Android", "iOS", "MacOs")
| summarize SignIns = count(), Users = make_set(UserPrincipalName, 10) by OS
```

---

## Gotchas

- **`OnboardingStatus == "Can be onboarded"`** — passive network discovery, no sensor. Always filter `OnboardingStatus == "Onboarded"` in `DeviceInfo` EOL queries or counts will be massively inflated by neighbor devices seen on home/open networks.
- **`Edge/18.26100` is NOT a threat** — it is the normal Windows 11 24H2 WAM broker UA used by all M365 apps. The `WebView/3.0` variant (same build number) is the AAD.BrokerPlugin on the same machine, also benign.
- **`Edge/18.19045`** = Win10 22H2 — the latest Windows 10 build. EOL Oct 2025. Active users on this build should be prioritised for Win11 upgrade.
- **`Edge/18.22631`** = Win11 23H2 — EOL Nov 2025 (Home/Pro), Nov 2026 (Enterprise/Education). Corporate Intune-managed devices are almost certainly Enterprise — check edition before treating as EOL. Defender has no reliable table column for Windows edition SKU; `DeviceRegistryEvents` only fires on registry *changes*, not static reads.
- **iOS 26.x** is NOT EOL — it is the 2026 developer/public beta. Do not flag it.
- **macOS version `10_15_7`** in MSAL UAs = macOS Catalina — EOL. `14_6_1` = Sonoma — supported.
- **`Mozilla/5.0 (compatible; MSAL 1.0)`** — generic fallback UA from some Microsoft Office COM/legacy paths. No OS version extractable. Do not include in EOL count.
- **`BAV2ROPC`** — basic auth password grant UA (SMTP AUTH). Separate concern from OS EOL; flag separately for legacy auth policy.
- **Build 20348** in `Edge/18.20348` = Windows Server 2022 (not Windows 10). The case statement must handle this before the Win10 catch-all.
- **Teams external users**: exclude UPNs containing "#EXT#" before reporting.
- **`Android 10; K`** — Chrome 109+ privacy-masked UA. All modern Android phones (Android 9+) running Chrome send this string regardless of actual OS version. A Pixel 8a on Android 16 sends `Android 10; K`. **Never treat this as an EOL signal.** Only Dalvik, MSAL, and MSAL WebView (`; wv) … PKeyAuth/1.0`) UAs carry real Android version numbers. Filter with `| where UserAgent !has "Android 10; K"` before extracting `AndroidVer`.
- **`Self Service+/<N> CFNetwork/macOS/<ver> Darwin/<N>`** — JAMF Self Service / JAMF Connect. No `Mac OS X` token; use Darwin kernel formula (`DarwinMajor - 9 = macOS major`). Only fires for JAMF-managed Macs; use `coalesce(MacOSMajor, MacOSFromDarwin)` to cover both MSAL and JAMF rows.
- **`Microsoft%20Authenticator/<N> CFNetwork/<N> Darwin/<N> ;iPhone`** — MS Authenticator on iOS (MFA prompts, passwordless). No `iPhone OS` token; use Darwin formula (`DarwinMajor - 9 = iOS major`). These are the same user/device as the MSAL rows but a different auth path, so they fill gaps when MSAL rows are absent.
- **Darwin major − 9 formula** is valid for macOS 11+ (Darwin 20+) and iOS 14+ (same kernel lineage). Darwin 19 = macOS 10.15 Catalina (EOL). Do not apply below Darwin 20.
- **`EdgiOS/<ver>`** in iOS UAs is the Edge browser version, not the iOS version. Always extract from `iPhone OS (\d+)_` not from the `EdgiOS/` token.
- **`Mozilla/5.0 (Linux; Android 16; … wv) … PKeyAuth/1.0`** — MSAL WebView on Android. The `; wv)` flag + `PKeyAuth/1.0` suffix identify MSAL control. Carries real OS version; not affected by Chrome privacy masking. Covered by the `Android (\d+)` regex after excluding `Android 10; K` rows.
