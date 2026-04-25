"""Azure credential management and token acquisition.

All azure-identity imports are isolated here so no other module needs them.
"""

import mcp_xdr._config as _config

import truststore
truststore.inject_into_ssl()  # IMPORTANT: must run BEFORE importing httpx or azure.identity

from azure.identity import (
    AuthenticationRecord,
    CertificateCredential,
    ClientSecretCredential,
    InteractiveBrowserCredential,
    TokenCachePersistenceOptions,
)
from dotenv import load_dotenv

load_dotenv()

import os

_credential: CertificateCredential | ClientSecretCredential | InteractiveBrowserCredential | None = None


def get_credential() -> CertificateCredential | ClientSecretCredential | InteractiveBrowserCredential:
    """Get or create Azure credential.

    Priority:
    1. CertificateCredential   – if AZURE_CLIENT_CERTIFICATE_PATH is set
    2. ClientSecretCredential  – if AZURE_CLIENT_SECRET is set
    3. InteractiveBrowserCredential – fallback; opens browser on first use,
       caches token persistently via msal-extensions (DPAPI on Windows).
    """
    global _credential
    if _credential is None:
        tenant_id = os.environ.get("AZURE_TENANT_ID")
        client_id = os.environ.get("AZURE_CLIENT_ID")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET")
        certificate_path = os.environ.get("AZURE_CLIENT_CERTIFICATE_PATH")
        certificate_password = os.environ.get("AZURE_CLIENT_CERTIFICATE_PASSWORD")

        if not tenant_id or not client_id:
            raise ValueError(
                "Missing Azure credentials. "
                "Set AZURE_TENANT_ID and AZURE_CLIENT_ID environment variables."
            )

        if certificate_path:
            _credential = CertificateCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                certificate_path=certificate_path,
                password=certificate_password,
            )
        elif client_secret:
            _credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            # Public client: opens browser for interactive sign-in (auth code + PKCE).
            # Private cache name isolates tokens from shared msal.cache used by Azure CLI / VS Code.
            cache_options = TokenCachePersistenceOptions(
                name="mcp-xdr",
                allow_unencrypted_storage=False,
            )
            auth_record_path = _config.xdr_dir / "auth-record.json"
            auth_record = None
            if auth_record_path.exists():
                auth_record = AuthenticationRecord.deserialize(
                    auth_record_path.read_text(encoding="utf-8")
                )
            _credential = InteractiveBrowserCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                cache_persistence_options=cache_options,
                authentication_record=auth_record,
            )
            if auth_record is None:
                # First run: authenticate and persist the record so future starts can
                # find the right cache entry without re-opening the browser.
                # Only pass GRAPH_SCOPE — each resource must be acquired separately.
                new_record = _credential.authenticate(scopes=[_config.GRAPH_SCOPE])
                auth_record_path.write_text(new_record.serialize(), encoding="utf-8")

    return _credential


def get_access_token() -> str:
    """Get access token for the Graph Security API."""
    credential = get_credential()
    token = credential.get_token(_config.GRAPH_SCOPE)
    return token.token


def get_sentinel_access_token() -> str:
    """Get access token for the Log Analytics (Sentinel) API."""
    credential = get_credential()
    token = credential.get_token(_config.SENTINEL_SCOPE)
    return token.token
