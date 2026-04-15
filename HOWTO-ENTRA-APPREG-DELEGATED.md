# Entra ID app registration — delegated auth (interactive browser)

This guide configures a **public client** app registration in Entra ID so that
`mcp-xdr` can authenticate as the signed-in user (delegated auth) without
requiring a certificate or client secret.

> **API migration note (Feb 2027 deadline):** This server now uses the
> **Microsoft Graph Security API** (`graph.microsoft.com/v1.0/security/runHuntingQuery`)
> instead of the old `api.security.microsoft.com/api/advancedhunting/run` endpoint,
> which Microsoft retired on February 6, 2026 (stops returning data February 1, 2027).
> The required permission has changed from `AdvancedHunting.Read` (Microsoft Threat
> Protection) to `ThreatHunting.Read.All` (Microsoft Graph). If you have an existing
> app registration with only `AdvancedHunting.Read`, follow step 4 below to add the
> new permission.

**Prerequisites:**
- To create the app registration and grant admin consent in step 4, you need one
  of: **Cloud Application Administrator**, Application Administrator,
  Privileged Role Administrator, or Global Administrator.
  (`ThreatHunting.Read.All` is a Microsoft Graph delegated permission,
  so Cloud Application Administrator is sufficient.)
- The signed-in user must have **Security Reader** (or equivalent Defender
  "View Data" role) in the tenant.

> 💡 With Defender Unified RBAC enabled, the Entra built-in **Security Reader**
> role is automatically imported and maps to Defender's "View Data" permission —
> if you have it, you do not need to create a separate custom Defender RBAC role.

---

## 1. Create the app registration

1. Go to [entra.microsoft.com](https://entra.microsoft.com)
2. Navigate to **Identity → Applications → App registrations → New registration**
3. Fill in:
   - **Name:** `MCP-XDR (delegated auth)` (or any name you prefer)
   - **Supported account types:** Accounts in this organizational directory only
   - **Redirect URI:** Platform = **Public client/native (mobile & desktop)**,
     URI = `http://localhost`
4. Click **Register**

Note the **Application (client) ID** and **Directory (tenant) ID** shown on the
Overview page — you will need both below.

---

## 2. Enable public client flows

5. In the app's left nav, click **Authentication**
6. Scroll to **Advanced settings**
7. Set **Allow public client flows** to **Yes**
8. Click **Save**

> 💡 "Allow public client flows" enables the auth code flow for clients that
> present no secret, i.e. mobile and desktop software. Without it, Entra rejects
>  the token request even though the user has successfully signed in — the
>  browser redirect completes but the server-side token exchange fails with a `401`.

---

## 3. Lock down who can sign in

By default, any user in your tenant can authenticate to a newly registered app.
Since this app provides access to security data, consider restricting it:

9. In Entra, go to **Enterprise applications** → search for your app name → select it
10. Click **Properties**
11. Set **User assignment required** to **Yes**
12. Click **Save**
13. Go to **Users and groups → Add user/group** and assign only the people who
    should be able to run Advanced Hunting queries

It should be safe to *not* do this, as this app uses the user's own delegated rights.
It's simply good cyber hygience to not leave unnecessary surfaces exposed. You may
also elect to set a Conditional Access policy for the enterprise app.

> 💡 This setting lives on the **Enterprise Application** object (the service
> principal in your tenant), not the App Registration. They are two sides of the
> same coin — the App Registration is the app's identity definition, the Enterprise
> Application is its instantiation in your tenant. Without this step, any tenant
> user can authenticate, though they would still be blocked by Defender RBAC.

---

## 4. Add the API permissions

### 4a. Microsoft Graph — Advanced Hunting (required)

14. Go back to **App registrations** → select your app
15. Click **API permissions → Add a permission**
16. Select **Microsoft Graph**
17. Choose **Delegated permissions**
18. Search for and tick **`ThreatHunting.Read.All`**
19. Click **Add permissions**

> 💡 `ThreatHunting.Read.All` is the Graph Security API permission for Advanced
> Hunting. It covers both Defender XDR tables and — when a Sentinel workspace is
> onboarded to the unified Defender portal — Sentinel tables. This permission
> replaced the old `AdvancedHunting.Read` on `Microsoft Threat Protection`
> (api.security.microsoft.com), which is retired.

### 4b. Log Analytics API — Sentinel queries (optional)

Only needed if you want to use `run_sentinel_query` / `get_sentinel_tables` to query
Sentinel tables that are *not* surfaced in Defender Advanced Hunting (CommonSecurityLog,
Syslog, custom tables, Auxiliary/Basic logs), or if your workspace is not onboarded to
the Defender portal.

20. Click **Add a permission** again
21. Select the **APIs my organization uses** tab
22. Search for **Log Analytics API** and select it
23. Choose **Delegated permissions**
24. Tick **`Data.Read`**
25. Click **Add permissions**

Additionally, assign the signed-in user the **Reader** role (or **Log Analytics Reader**)
on the Log Analytics workspace in Azure portal → the workspace's **Access control (IAM)**.

---

## 5. Grant admin consent

26. Back on the **API permissions** page, click
    **Grant admin consent for [your tenant]**
27. Confirm by clicking **Yes**
28. The Status column for `ThreatHunting.Read.All` (and `Data.Read` if added) should
    show a green tick

> 💡 Admin consent is not optional for `ThreatHunting.Read.All`. It is hardcoded
> `adminConsentRequired: true` in the Microsoft Graph service principal manifest —
> individual users cannot consent to it regardless of the tenant's user consent
> policy. Cloud Application Administrator is sufficient for this step.

---

## 4-legacy. Migrating from the old AdvancedHunting.Read permission

If you have an existing app registration with `AdvancedHunting.Read` on
**Microsoft Threat Protection** (`api.security.microsoft.com`):

- Add the new `ThreatHunting.Read.All` permission on **Microsoft Graph** (step 4a above)
- Grant admin consent
- The old `AdvancedHunting.Read` permission can be removed after confirming the new API
  works — it is harmless to leave it, but it will stop being used after February 1, 2027
- Delete `~/.mcp-xdr/auth-record.json` so the server re-authenticates and picks up
  the new scope on first run

---

## 6. Configure environment variables

Set the following — **no secret or certificate is needed**:

```bash
AZURE_TENANT_ID=<Directory (tenant) ID from step 1>
AZURE_CLIENT_ID=<Application (client) ID from step 1>
```

Do **not** set `AZURE_CLIENT_SECRET` or `AZURE_CLIENT_CERTIFICATE_PATH` — their
presence causes the server to use application auth instead of interactive auth.

For a `.env` file in the repo root:

```ini
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

## 7. First run

On first start the server opens a browser tab for the user to sign in. After
successful sign-in the token is stored in an OS-encrypted persistent cache
(`mcp-xdr`, isolated from the shared `msal.cache` used by Azure CLI and
VS Code). An `AuthenticationRecord` is written to `~/.mcp-xdr/auth-record.json`.

On all subsequent starts the server authenticates silently from the cache — **no
browser prompt** — until the refresh token expires. Refresh tokens for
non-interactive (non-PIM) sessions typically last 90 days with activity, so in
practice you should rarely need to re-authenticate. To force a fresh login, delete
`~/.mcp-xdr/auth-record.json`.

> 💡 `InteractiveBrowserCredential` opens the browser via a local loopback
> redirect (`http://localhost`) — it spins up a temporary HTTP listener to receive
> the auth code after sign-in, then immediately shuts it down. No server
> infrastructure is needed, and the loopback origin is exempt from the redirect URI
> restrictions that apply to public internet URIs.

---

## Why not device code flow?

Microsoft rolled out a default Conditional Access policy — **Block device code
flow** — to eligible tenants from February 2025. Interactive browser
(`InteractiveBrowserCredential`) uses the authorization code flow with PKCE
instead, which is not affected by that policy.

> 💡 Device code flow was designed for input-constrained devices (smart TVs, CLI
> tools on headless servers) where opening a browser is impossible. Using it on a
> desktop is architecturally wrong and creates a phishing risk: an attacker can
> initiate a device code request and socially engineer a victim into completing the
> sign-in on the attacker's behalf. PKCE-based auth code flow prevents this because
> the code verifier is cryptographically bound to the client that initiated the
> request.

## Why are you not explaining Certificate / Client Secret setup?

Service principal credentials (certificate or client secret) require the **Application**
permission `ThreatHunting.Read.All` on Microsoft Graph, which grants tenant-wide Advanced
Hunting access with no per-user RBAC enforcement. Any process that holds the credential can query all
device, identity, email, and cloud app data across the entire organisation — there is no
"the user only sees what they're entitled to" safety net. That is a significant blast
radius for a developer tool.

For an unattended pipeline or automation service, service principal auth is the correct
approach and worth that trade-off. For a tool that a human runs interactively, delegated
auth is strictly better: the token carries the user's own Defender RBAC permissions, and
if the credential is compromised it can only be used interactively (browser required).

This guide covers only the delegated case. If you are setting up service principal auth,
you own that security boundary — Defender exposes sensitive user and enterprise data and
the `ThreatHunting.Read.All` application permission should be treated with the same care
as any other tenant-wide credential.

