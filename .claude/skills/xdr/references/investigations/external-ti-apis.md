# External IP / Domain / URL Reputation APIs

For spot-checking IPs, domains, or URLs against external threat intelligence and reputation feeds when Microsoft's built-in `ThreatIntelIndicators` table returns no results.

**Two-tier model:**
- **Tier 1** — no key required; always available; call these immediately
- **Tier 2** — requires an API key pre-stored in a named environment variable by a human operator; check whether the var is set before attempting

**Important:** All free tiers are for non-commercial/research use only. No service listed here supports automated account creation — keys must be registered by a human and stored in the environment before agent use.

**Tool compatibility — which HTTP client to use:**

| Auth mechanism | Services | HTTP client |
|---|---|---|
| No auth | Google DoH, ip-api, GreyNoise (unauth) | `web_read` (web-utility-belt MCP) |
| Key in URL path or query param | IPQualityScore, IPinfo | `web_read` — key goes in the URL, no header needed |
| Custom request header | AbuseIPDB, VirusTotal, GreyNoise (auth), AlienVault OTX | `curl` via Bash — `web_read` has no headers parameter |

When using `curl` for Tier 2 calls, always read the env var inside the shell command rather than interpolating it into the command string logged to the conversation — prevents the key appearing in tool call output.

---

## Tier 1 — No key required

### Google DNS-over-HTTPS — Resolve domain → IP before reputation checks

When you have a hostname but need an IP for ip-api or GreyNoise, use Google's public DoH endpoint — no key, no account, no rate limit published (reasonable use):

```
GET https://dns.google/resolve?name={hostname}&type=A    # IPv4
GET https://dns.google/resolve?name={hostname}&type=AAAA  # IPv6
GET https://dns.google/resolve?name={hostname}&type=MX   # mail servers
```

Response: `Answer[].data` contains the resolved address(es). If `Answer` is absent, the record doesn't exist. Check `Authority` for the nameserver — useful for identifying Azure DNS, Cloudflare, etc. which gives hosting context even before the IP lookup.

---

### ip-api.com — Geolocation, ASN, proxy/VPN/hosting flags

```
GET http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query
```

- **Rate limit:** 45 requests/minute
- **Covers:** Country, region, city, ISP, ASN (`as`), VPN/proxy flag (`proxy`), datacenter/hosting flag (`hosting`)
- **Caveats:** Free tier is HTTP only — do not pass credentials over this endpoint. Non-commercial use only.
- **Useful for:** "Is this IP a cloud provider / datacenter / VPN exit node?" before concluding it's a user's egress.

Example response fields to check:
```json
{ "proxy": true, "hosting": false, "isp": "Example ISP AB", "as": "AS12345 Example ISP AB", "country": "SE" }
```

---

### GreyNoise Community API (unauthenticated) — Internet noise / scanner classification

```
GET https://api.greynoise.io/v3/community/{ip}
```

- **Rate limit:** 10 requests/day (unauthenticated)
- **Covers:** Whether the IP is a known internet scanner/crawler (`benign`), a known threat actor (`malicious`), or unknown. Returns tags like `"scanner"`, `"tor-exit-node"`, `"vpn"`.
- **Caveats:** Returns HTTP 404 for IPs not in GreyNoise's dataset — treat 404 as "no opinion / not observed", not an error. Not appropriate for high-volume lookups.

Example response:
```json
{ "ip": "94.246.79.230", "noise": false, "riot": false, "classification": "unknown", "name": "unknown", "link": "https://viz.greynoise.io/ip/94.246.79.230" }
```

---

## Tier 2 — API key required (check env var first)

Before calling any Tier 2 service, check whether the relevant environment variable is set. If it is not set, skip that service silently and fall back to Tier 1 only.

---

### AbuseIPDB — IP abuse report history

**Env var:** `ABUSEIPDB_API_KEY`

```
GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90
Headers:
  Key: {ABUSEIPDB_API_KEY}
  Accept: application/json
```

- **Rate limit:** 1,000 requests/day
- **Covers:** Abuse confidence score (0–100), total reports, categories (SSH brute force, port scan, web spam, etc.), ISP, usage type, domain
- **Best for:** Structured, crowdsourced abuse report data. The `abuseConfidenceScore` field is the primary signal — >50 is meaningful, >80 is strong.

Key response fields:
```json
{
  "data": {
    "abuseConfidenceScore": 0,
    "totalReports": 0,
    "usageType": "Fixed Line ISP",
    "isp": "Example ISP AB",
    "domain": "example-isp.example",
    "countryCode": "XX"
  }
}
```

---

### VirusTotal — Multi-engine IP, domain, and URL scanning

**Env var:** `VIRUSTOTAL_API_KEY`

```
# IP lookup
GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
Headers:
  x-apikey: {VIRUSTOTAL_API_KEY}

# Domain lookup
GET https://www.virustotal.com/api/v3/domains/{domain}
Headers:
  x-apikey: {VIRUSTOTAL_API_KEY}

# URL lookup — requires base64url-encoding the URL (strip trailing =)
POST https://www.virustotal.com/api/v3/urls
Headers:
  x-apikey: {VIRUSTOTAL_API_KEY}
  Content-Type: application/x-www-form-urlencoded
Body: url={url}
# Then GET /api/v3/analyses/{id} or /api/v3/urls/{base64url_id}
```

- **Rate limit:** 4 requests/minute, 500 requests/day — always wait ≥15 seconds between VT calls in a loop
- **Covers:** 70+ antivirus/reputation engine verdicts for IPs, domains, and URLs
- **Key response path:** `data.attributes.last_analysis_stats` → `{ malicious: N, suspicious: N, undetected: N, harmless: N }`
- **Caveats:** URL lookup via POST returns an analysis ID; fetch the result with a separate GET. Don't batch multiple URL lookups without respecting the rate limit.

---

### GreyNoise Community API (authenticated) — Higher quota

**Env var:** `GREYNOISE_API_KEY`

```
GET https://api.greynoise.io/v3/community/{ip}
Headers:
  key: {GREYNOISE_API_KEY}
```

- **Rate limit:** 50 searches/week (vs 10/day unauthenticated)
- **Covers:** Same as Tier 1 unauthenticated endpoint — use the keyed version if the env var is available to preserve the unauthenticated daily budget

---

### AlienVault OTX — Community threat intelligence pulses

**Env var:** `OTX_API_KEY`

```
# IP indicators
GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general
Headers:
  X-OTX-API-KEY: {OTX_API_KEY}

# Domain indicators
GET https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general
Headers:
  X-OTX-API-KEY: {OTX_API_KEY}
```

- **Rate limit:** Not published; community/research rate — keep to single spot-checks, not loops
- **Covers:** Associated threat pulses (community-tagged campaigns), passive DNS, geo, ASN, malware families referenced
- **Key response fields:** `pulse_info.count` (number of pulses referencing this indicator), `pulse_info.pulses[].name`

---

### IPQualityScore — Fraud/proxy/VPN scoring for IPs and URLs

**Env var:** `IPQS_API_KEY`

```
# IP lookup
GET https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}

# URL lookup (URL-encode the target URL)
GET https://ipqualityscore.com/api/json/url/{IPQS_API_KEY}/{encoded_url}
```

- **Rate limit:** 5,000 requests/month
- **Covers:** Fraud score (0–100), VPN, proxy, TOR, bot activity, recent abuse, ISP, country. URL endpoint covers phishing/malware/parking status.
- **Key fields:** `fraud_score`, `vpn`, `proxy`, `tor`, `recent_abuse`, `bot_status`
- **Note:** The API key goes in the URL path, not a header.

---

### IPinfo — Geolocation, ASN, org, abuse contact

**Env var:** `IPINFO_TOKEN`

```
GET https://ipinfo.io/{ip}?token={IPINFO_TOKEN}
```

- **Rate limit:** 50,000 requests/month
- **Covers:** Country, region, city, org (ASN + name), hostname, abuse contact (email, phone). The `org` field combines ASN number and name (e.g. `"AS1257 Tele2 Sverige AB"`).
- **Best for:** Authoritative ASN/org attribution when ip-api's `as` field isn't sufficient.

---

## Agent decision workflow

### IP reputation spot-check

```
1. Always: ip-api.com (Tier 1) — get geo/ASN/proxy/hosting context
2. Always: GreyNoise unauthenticated (Tier 1) — noise/scanner classification
   → If GREYNOISE_API_KEY set, use authenticated endpoint instead (saves unauth budget)
3. If ABUSEIPDB_API_KEY set → AbuseIPDB — abuse report history + confidence score
4. If VIRUSTOTAL_API_KEY set → VirusTotal IP — multi-engine verdict
   → Wait ≥15s after any prior VT call
5. If OTX_API_KEY set → AlienVault OTX — pulse/campaign associations
```

### IP geolocation/ASN

```
1. ip-api.com (Tier 1) — always available, includes proxy/hosting flags
2. If IPINFO_TOKEN set → IPinfo — richer org/abuse contact data
```

### Domain reputation

```
1. If VIRUSTOTAL_API_KEY set → VT /domains/{domain}
2. If OTX_API_KEY set → OTX /domain/{domain}/general
3. If IPQS_API_KEY set → IPQS /url/{key}/{encoded_domain}
```

### URL reputation

```
1. If VIRUSTOTAL_API_KEY set → VT URL lookup (POST + GET analysis)
2. If IPQS_API_KEY set → IPQS /url/{key}/{encoded_url}
```

---

## Caveats

- **Non-commercial only** — all free tiers listed here. Do not use for production/commercial security products.
- **VirusTotal rate limit is strict** — 4 req/min; always insert a 15-second sleep between VT calls.
- **ip-api is HTTP only** — no TLS on the free endpoint; never pass credentials or sensitive data in the request.
- **GreyNoise 404 ≠ error** — means the IP is not in their dataset ("unknown/not observed"); log as such, not as a lookup failure.
- **VirusTotal URL encoding** — URL lookup ID is `base64url(url)` with trailing `=` stripped. Use Python: `base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')`.
- **Never log full API keys** — in query results, Defender findings, or reference docs.
- **Key acquisition** — none of these services support automated registration. A human must sign up at each provider's website and store the key as an environment variable before agent use.
