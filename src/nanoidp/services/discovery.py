"""
Single source of truth for the OIDC discovery document.

Both the HTTP endpoint (``/.well-known/openid-configuration``) and the MCP
``get_oidc_discovery`` tool build their response here, so the two can never
drift apart (issue #40 - the MCP tool used to return an abbreviated dict that
omitted ``claims_supported``/``azp`` and the auth-method metadata).
"""

from typing import Any, Dict, Optional

from ..config import Settings


def build_discovery_document(
    settings: Settings, issuer: Optional[str] = None
) -> Dict[str, Any]:
    """Build the OIDC discovery metadata for the given settings.

    Every value advertised here must reflect what the endpoints actually
    implement - the document is a contract, and for a dev IdP a misleading
    entry is worse than a missing feature (see issue #41: ``token`` was
    advertised in ``response_types_supported`` while ``/authorize`` only
    accepts ``code``).

    ``issuer`` lets a caller with a live request override ``settings.issuer``
    (``issuer_from_request``, so the same NanoIDP can advertise a different,
    per-request-correct issuer at more than one hostname). Callers with no
    request of their own - the MCP ``get_oidc_discovery`` tool - omit it and
    always get the fixed, configured issuer back.
    """
    issuer = issuer or settings.issuer
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
        # 'none' = public clients (#188). Deliberately NOT in the
        # introspection list: RFC 7662 requires an authenticated caller,
        # and a public client_id is not authentication.
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        # Only the authorization code flow is implemented; the implicit flow is
        # deprecated by the OAuth 2.0 Security BCP and intentionally absent.
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": ["RS256"],
        # Settings-driven (#186), default unchanged - see Settings.scopes_supported.
        "scopes_supported": settings.scopes_supported,
        "claims_supported": [
            "sub", "iss", "aud", "azp", "exp", "iat", "nbf",
            "auth_time", "nonce", "at_hash",
            "email", "email_verified", "preferred_username",
            "roles", "groups", "tenant", "identity_class", "entitlements",
            "source_acl", "attributes", "authorities"
        ],
        # The OIDC `claims` request parameter is honoured at /authorize to
        # deliver requested claims in the ID Token / UserInfo (§5.5, #104).
        "claims_parameter_supported": True,
        # The password grant is removed by OAuth 2.1 and rejected under the
        # oauth21 profile, so it must not be advertised there (#68).
        "grant_types_supported": [
            grant
            for grant in (
                "authorization_code",
                "client_credentials",
                "password",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            )
            if grant != "password" or settings.password_grant_enabled
        ],
        # stricter-dev and oauth21 reject 'plain' at /authorize, so don't
        # advertise it there (#47, #68)
        "code_challenge_methods_supported": (
            ["plain", "S256"] if settings.pkce_plain_allowed else ["S256"]
        ),
    }
