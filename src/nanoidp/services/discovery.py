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
        # Advertised only while registration is accepted (#190): metadata
        # never promises an endpoint that answers 404.
        **(
            {"registration_endpoint": f"{issuer}/register"}
            if settings.dynamic_registration_enabled
            else {}
        ),
        # Advertised only while a document could actually be honoured
        # (#196). allowed_hosts is empty by default and nothing is fetched
        # until an operator names a host, so "enabled" alone would advertise
        # a capability that refuses every client with no way to tell it is
        # inert - which the registration endpoint above cannot do, since it
        # needs no second setting to work.
        **(
            {"client_id_metadata_document_supported": True}
            if settings.client_id_metadata_documents_enabled
            and settings.client_id_metadata_documents_allowed_hosts
            else {}
        ),
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
            # amr is only ever minted when totp_active is true (routes/_auth's
            # authenticate_interactively gates it on that, not the raw
            # settings.totp) - persona mode makes totp inert (#348), so
            # gating on settings.totp alone would advertise a claim that
            # login.mode: persona + login.totp: true can never actually
            # mint (#348 review round 2, blocking): tokens.md documents the
            # claim as opt-in "on the wire too", which this must match.
            *(["amr"] if settings.totp_active else []),
            "email", "email_verified", "preferred_username",
            "roles", "groups", "tenant", "identity_class", "entitlements",
            # source_acl and authorities are NOT advertised (#316).
            # OpenID Connect Discovery 1.0 §3 defines this field as the
            # Claim Names the provider may be able to supply VALUES for, and
            # nanoidp reads that as its own invariant: only claims that can
            # appear in an ID Token or a UserInfo response belong here. Those
            # two appear in neither - they are authorization facts a resource
            # server reads off an access token - so advertising them broke
            # the rule #41 set for this document. `attributes` stays: it is a
            # Claim Name (Core §5.6.1: in Normal Claims the member name IS
            # the Claim Name) and /userinfo supplies it, even though
            # resolve_user_claim does not address the composite map.
            "attributes"
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
