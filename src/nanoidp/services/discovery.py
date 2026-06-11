"""
Single source of truth for the OIDC discovery document.

Both the HTTP endpoint (``/.well-known/openid-configuration``) and the MCP
``get_oidc_discovery`` tool build their response here, so the two can never
drift apart (issue #40 — the MCP tool used to return an abbreviated dict that
omitted ``claims_supported``/``azp`` and the auth-method metadata).
"""

from typing import Any, Dict

from ..config import Settings


def build_discovery_document(settings: Settings) -> Dict[str, Any]:
    """Build the OIDC discovery metadata for the given settings.

    Every value advertised here must reflect what the endpoints actually
    implement — the document is a contract, and for a dev IdP a misleading
    entry is worse than a missing feature (see issue #41: ``token`` was
    advertised in ``response_types_supported`` while ``/authorize`` only
    accepts ``code``).
    """
    issuer = settings.issuer
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "introspection_endpoint": f"{issuer}/introspect",
        "revocation_endpoint": f"{issuer}/revoke",
        "end_session_endpoint": f"{issuer}/logout",
        "device_authorization_endpoint": f"{issuer}/device_authorization",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        # Only the authorization code flow is implemented; the implicit flow is
        # deprecated by the OAuth 2.0 Security BCP and intentionally absent.
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "claims_supported": [
            "sub", "iss", "aud", "azp", "exp", "iat", "nbf",
            "auth_time", "nonce", "at_hash",
            "email", "email_verified", "preferred_username",
            "roles", "tenant", "identity_class", "entitlements",
            "source_acl", "attributes", "authorities"
        ],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "password",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        # stricter-dev rejects 'plain' at /authorize, so don't advertise it
        # there (#47)
        "code_challenge_methods_supported": (
            ["S256"]
            if settings.security_profile == "stricter-dev"
            else ["plain", "S256"]
        ),
    }
