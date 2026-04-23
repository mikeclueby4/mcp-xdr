# Security Policy

## Supported Versions

This is a solo-maintained project. Only the **latest release** receives security fixes.
Older tags are provided as-is; please upgrade to the current version before reporting a vulnerability.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | ✅ Yes             |
| Older   | ❌ No              |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, use GitHub's private vulnerability reporting feature:
**[Security tab → Report a vulnerability](../../security/advisories/new)**

This keeps the report confidential until a fix is in place.  
You will receive an acknowledgement within **7 days** and a status update as the investigation progresses.
If a fix is feasible, it will be prioritised and released as soon as reasonably possible.

## Security Update Cadence

- **Dependencies** are monitored continuously by [Dependabot](./../dependabot.yml) and patched weekly or sooner for critical CVEs.
- **Releases** are tagged on `main` after all CI checks (CodeQL static analysis, unit tests) pass.
- Every release ships a **Software Bill of Materials (SBOM)** in SPDX JSON format, attached to the GitHub Release as an artifact, so you can audit the exact dependency tree that was packaged.

## Trust & Provenance for Entra / M365 Admins

This tool authenticates to Microsoft Graph and Azure Log Analytics on behalf of the signed-in user using OAuth 2.0 delegated permissions (auth code + PKCE). It does **not** store credentials, secrets, or tokens outside of the standard MSAL token cache on the local machine.

Key trust signals for regulated environments:

| Signal | Detail |
|--------|--------|
| **Minimal permissions** | Requires only `ThreatHunting.Read.All` (Delegated, Microsoft Graph) — no write access to your tenant |
| **SBOM on every release** | Full dependency inventory attached to each GitHub Release |
| **CodeQL on every PR & push** | Static analysis results visible in the Security tab |
| **Dependabot enabled** | Automated dependency updates for pip, Docker, and GitHub Actions |
| **Branch protections** | `main` is protected; all changes flow through pull requests with required status checks |
| **Open source (MIT)** | Full source available for review at any time |

## Scope

The following are **in scope** for vulnerability reports:

- Credential handling or token leakage in `src/mcp_xdr/server.py`
- Unsafe query construction that could lead to injection against the Microsoft APIs
- Dependency vulnerabilities with a credible exploit path in this tool's context
- Anything that would allow a local attacker to escalate privilege via this MCP server

The following are **out of scope**:

- Vulnerabilities in Microsoft Graph / Defender APIs themselves (report those to Microsoft MSRC)
- Theoretical issues with no practical impact in this tool's threat model
- Social engineering or phishing attacks unrelated to the codebase
