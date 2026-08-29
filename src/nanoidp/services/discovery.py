"""
Single source of truth for the OIDC discovery document.

Both the HTTP endpoint (``/.well-known/openid-configuration``) and the MCP
``get_oidc_discovery`` tool build their response here, so the two can never
drift apart (issue #40 - the MCP tool used to return an abbreviated dict that
omitted ``claims_supported``/``azp`` and the auth-method metadata).
"""

from typing import Any, Dict, Optional
from urllib.parse import urlparse

from ..config import Settings


def issuer_qualifies_for_iss_parameter(issuer: str) -> bool:
    """Whether the issuer is a valid RFC 9207 §2 / RFC 8414 issuer identifier:
    an ``https`` URL with a host and no query or fragment component (#189).

    This is the single predicate for both directions of the RFC 9207
    contract (#258 review): ``iss`` is appended to the authorization response
    exactly when it is advertised as supported, so metadata and behaviour can
    never disagree. nanoidp usually runs on ``http://localhost:8000``, which
    does not qualify - so by default no ``iss`` is sent and the metadata is
    ``false``; point the issuer at an ``https`` URL (directly or reflected via
    ``issuer_from_request`` behind a TLS proxy) to turn RFC 9207 on.

    A query or fragment is forbidden as a component, so a bare ``?`` or ``#``
    (an empty component) disqualifies too; the value must have a host; and a
    malformed issuer (bad IPv6 literal, non-numeric port) is rejected, never
    a discovery 500."""
    # An empty query/fragment component still counts (urlparse would report
    # "" for both), so reject the delimiter outright (#258 review).
    if "?" in issuer or "#" in issuer:
        return False
    try:
        parsed = urlparse(issuer)
        _ = parsed.port  # validates the port: a non-numeric one raises here.
    except ValueError:
        return False
    return parsed.scheme == "https" and bool(parsed.hostname)


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
        # RFC 9207 (#189): /authorize returns iss in the response, advertised
        # here, exactly when the effective issuer qualifies (a
        # query/fragment-free https URL with a host). The same predicate
        # gates the emission (#258 review), so with an http dev issuer iss is
        # neither advertised NOR sent - see issuer_qualifies_for_iss_parameter.
        "authorization_response_iss_parameter_supported": (
            issuer_qualifies_for_iss_parameter(issuer)
        ),
    }
