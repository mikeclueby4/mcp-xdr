# Entra ID app registration — delegated auth (interactive browser)

This guide configures a **public client** app registration in Entra ID so that
`mcp-defender` can authenticate as the signed-in user (delegated auth) without
requiring a certificate or client secret.

**Prerequisites:**
- To create the app registration and grant admin consent in step 4, you need one
  of: **Cloud Application Administrator**, Application Administrator,
  Privileged Role Administrator, or Global Administrator.
  (`AdvancedHunting.Read` is a Microsoft Threat Protection delegated permission,
  not a Microsoft Graph app role, so Cloud Application Administrator is sufficient.)
- The signed-in user must have **Security Reader** (or equivalent Defender
  "View Data" role) in the tenant.

> 💡 With Defender Unified RBAC enabled, the Entra built-in **Security Reader**
> role is automatically imported and maps to Defender's "View Data" permission —
> you do not need to create a separate custom Defender RBAC role.

---

## 1. Create the app registration

1. Go to [entra.microsoft.com](https://entra.microsoft.com)
2. Navigate to **Identity → Applications → App registrations → New registration**
3. Fill in:
   - **Name:** `mcp-defender-interactive` (or any name you prefer)
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
> present no secret. Without it, Entra rejects the token request even though the
> user has successfully signed in — the browser redirect completes but the
> server-side token exchange fails with a `401`.

---

## 3. Lock down who can sign in

By default, any user in your tenant can authenticate to a newly registered app.
Since this app provides access to security data, restrict it:

9. In Entra, go to **Enterprise applications** → search for your app name → select it
10. Click **Properties**
11. Set **User assignment required** to **Yes**
12. Click **Save**
13. Go to **Users and groups → Add user/group** and assign only the people who
    should be able to run Advanced Hunting queries

> 💡 This setting lives on the **Enterprise Application** object (the service
> principal in your tenant), not the App Registration. They are two sides of the
> same coin — the App Registration is the app's identity definition, the Enterprise
> Application is its instantiation in your tenant. Without this step, any tenant
> user can authenticate; they would still be blocked by Defender RBAC, but
> there is no reason to allow unnecessary auth attempts.

---

## 4. Add the API permission

14. Go back to **App registrations** → select your app
15. Click **API permissions → Add a permission**
16. Select the **APIs my organization uses** tab
17. Search for **Microsoft Threat Protection** and select it

> 💡 **Microsoft Threat Protection** is the legacy display name for the Defender
> XDR service principal that owns `api.security.microsoft.com`. Do not confuse it
> with **Microsoft Defender for Endpoint**, which is a separate service principal
> for the older `api.securitycenter.microsoft.com` endpoint. Picking the wrong one
> will result in tokens that are accepted by the wrong API and rejected by this
> server.

18. Choose **Delegated permissions**
19. Tick **`AdvancedHunting.Read`** (Run advanced queries)
20. Click **Add permissions**

> 💡 Delegated tokens carry the granted scopes in the `scp` claim (e.g.
> `AdvancedHunting.Read`), while application tokens use the `roles` claim. The
> Defender API validates these separately — `user_impersonation` alone (what the
> Azure CLI's built-in app provides) is never accepted as a substitute for
> `AdvancedHunting.Read`.

---

## 5. Grant admin consent

21. Back on the **API permissions** page, click
    **Grant admin consent for [your tenant]**
22. Confirm by clicking **Yes**
23. The Status column for `AdvancedHunting.Read` should show a green tick

> 💡 Admin consent is not optional here. `AdvancedHunting.Read` is hardcoded
> `adminConsentRequired: true` in the Microsoft Threat Protection service principal
> manifest — individual users cannot consent to it regardless of the tenant's user
> consent policy. This is independent of the July 2025 change where Microsoft
> tightened *default* user consent policies across tenants; that change affects
> lower-privilege permissions, not security data permissions like this one.
>
> Cloud Application Administrator is sufficient for this step — Global Admin is
> not required, since `AdvancedHunting.Read` is not a Microsoft Graph app role.
>
> **Best practice — admin consent workflow:** Rather than requiring each new user to
> ask an admin to run through this portal flow, enable the
> [admin consent workflow](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow)
> in Entra (Enterprise apps → Consent and permissions → Admin consent settings).
> Users who need access can then self-request, admins receive an approval
> notification, and can approve or deny from a queue — no portal navigation needed.

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

On the first MCP tool call the server will open a browser tab for the user to
sign in with their Microsoft 365 account. After successful sign-in the token is
cached in memory for the duration of the server process. Subsequent calls within
the same session are silent.

> 💡 `InteractiveBrowserCredential` opens the browser via a local loopback
> redirect (`http://localhost`) — it spins up a temporary HTTP listener to receive
> the auth code after sign-in, then immediately shuts it down. No server
> infrastructure is needed, and the loopback origin is exempt from the redirect URI
> restrictions that apply to public internet URIs.

> **Note:** The token cache is in-memory only. The browser prompt will reappear
> each time the MCP server process restarts. To persist the cache across restarts,
> add `msal-extensions` to the project — it provides a DPAPI-encrypted token cache
> on Windows.

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
