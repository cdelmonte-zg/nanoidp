"""
Token service for generating JWT tokens with authorities.
"""

import base64
import hashlib
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from ..config import User, get_config
from .crypto import get_crypto_service

logger = logging.getLogger(__name__)

# Claims ``create_token`` sets authoritatively from the grant and therefore
# strips from caller-supplied ``extra`` before setting them (#102/#104/#112).
# ``_RESERVED_CLAIMS`` is derived from this tuple, so a claim added here is
# automatically refused by ``resolve_user_claim`` as well - the strip list and
# the reserved list cannot drift apart.
_AUTHORITATIVE_CLAIMS = ("scope", "req_userinfo_claims", "req_id_token_claims")

# Claim names a client must never be able to request through the OIDC ``claims``
# parameter (#110). Registered JWT claims are set by ``create_jwt`` and the
# protocol claims are set authoritatively by ``create_token``; letting a
# requested name resolve to a user attribute of the same name would overwrite
# them (``create_jwt`` applies ``payload.update(extra)`` after the registered
# claims), e.g. a user attribute ``aud``/``exp`` hijacking the ID Token. None of
# these are legitimately requestable, so the resolver refuses them outright.
_RESERVED_CLAIMS = frozenset({
    # registered JWT claims (RFC 7519)
    "iss", "sub", "aud", "exp", "iat", "nbf", "jti",
    # nanoidp protocol claims
    "token_use", "auth_time", "at_hash", "azp", "nonce",
    *_AUTHORITATIVE_CLAIMS,
})


def sanitize_claim_names(value: Any) -> Optional[List[str]]:
    """Coerce a requested-claims value to a list of claim names, or ``None``.

    The requested-claims lists cross trust boundaries: MCP arguments reach
    ``create_token`` without SDK-side schema enforcement, and on refresh the
    names are recovered from the refresh-token payload, which may be
    hand-crafted with the IdP key (a first-class dev workflow). Anything but a
    list is ignored and non-string entries are dropped, always with a warning
    and never an exception - token issuance must not be able to fail on a
    malformed value after the refresh token has been consumed.
    """
    if value is None:
        return None
    if not isinstance(value, list):
        logger.warning(
            "Ignoring malformed requested-claims value: expected a list of "
            "claim names, got %s", type(value).__name__
        )
        return None
    names = [name for name in value if isinstance(name, str)]
    if len(names) != len(value):
        logger.warning("Dropping non-string entries from requested-claims value")
    return names or None


def resolve_user_claim(user: User, name: str) -> tuple[bool, Any]:
    """Resolve a requested OIDC/custom claim name to the user's value.

    Backs the OIDC ``claims`` request parameter (OIDC Core §5.5): the standard
    ``email``/``profile`` claims plus nanoidp's custom claims and any user
    attribute can be requested for the ID Token or UserInfo. Returns
    ``(found, value)``; ``found`` is False when nanoidp cannot supply the claim,
    so voluntary claims are simply omitted rather than emitted as null (§5.5.1).

    Reserved registered/protocol claim names (``_RESERVED_CLAIMS``) are always
    refused so a requested name can never overwrite them (#110).
    """
    if name in _RESERVED_CLAIMS:
        return False, None
    if name == "email":
        return True, user.email
    if name == "email_verified":
        return True, True
    if name == "preferred_username":
        return True, user.username
    if name == "roles":
        return True, user.roles
    if name == "groups":
        return (True, user.groups) if user.groups else (False, None)
    if name == "tenant":
        return True, user.tenant
    if name == "identity_class":
        return (True, user.identity_class) if user.identity_class else (False, None)
    if name == "entitlements":
        return (True, user.entitlements) if user.entitlements else (False, None)
    if name in user.attributes:
        return True, user.attributes[name]
    return False, None


class TokenService:
    """Service for generating JWT tokens."""

    def __init__(self) -> None:
        self.config = get_config()
        self.crypto = get_crypto_service(self.config.settings.keys_dir)

    def build_authorities(self, user: User) -> List[str]:
        """Build authorities array from user attributes."""
        prefixes = self.config.settings.authority_prefixes
        authorities = []

        # Add ROLE_ prefix for user roles
        role_prefix = prefixes.get("roles", "ROLE_")
        if user.roles:
            authorities.extend([f"{role_prefix}{role.upper()}" for role in user.roles])

        # Add GROUP_ prefix for user groups
        group_prefix = prefixes.get("groups", "GROUP_")
        if user.groups:
            authorities.extend([f"{group_prefix}{group.upper()}" for group in user.groups])

        # Add IDENTITY_ prefix for identity class
        identity_prefix = prefixes.get("identity_class", "IDENTITY_")
        if user.identity_class:
            authorities.append(f"{identity_prefix}{user.identity_class}")

        # Add ENT_ prefix for entitlements
        ent_prefix = prefixes.get("entitlements", "ENT_")
        if user.entitlements:
            authorities.extend([f"{ent_prefix}{ent}" for ent in user.entitlements])

        # Add ACL entries (no prefix)
        if user.source_acl:
            authorities.extend(user.source_acl)

        # Add authorities from custom attributes if they have a configured prefix
        for attr_key, attr_value in user.attributes.items():
            if attr_key in prefixes and attr_value:
                prefix = prefixes[attr_key]
                if isinstance(attr_value, list):
                    authorities.extend([f"{prefix}{v}" for v in attr_value])
                else:
                    authorities.append(f"{prefix}{attr_value}")

        return authorities

    def _resolve_id_token_audience(
        self, client_id: Optional[str]
    ) -> tuple[Any, Optional[str]]:
        """Resolve the (aud, azp) pair for an ID Token.

        Per OpenID Connect Core 1.0 §2, the ID Token ``aud`` MUST contain the
        Relying Party's ``client_id``. Any ``additional_audiences`` configured
        on the client are appended, turning ``aud`` into an array. With a single
        audience, ``aud`` is a plain string and ``azp`` is omitted.

        When multiple audiences are present, nanoidp emits ``azp`` with the
        requesting ``client_id`` to support testing clients that implement
        authorized-party validation. OIDC Core defines ``azp`` as optional, but
        if present it must contain the OAuth 2.0 Client ID of the party to which
        the ID Token was issued.

        When no client is known we fall back to the configured resource audience
        (a safety fallback - a real OIDC token endpoint always has a client).

        The resource audience (``settings.audience``, used by access/refresh
        tokens) is never allowed into the ID Token ``aud``: otherwise
        ``verify_jwt(token, settings.audience)`` would accept an ID Token at the
        access-token endpoints, letting it be spent as an access token (issue #34).
        """
        if not client_id:
            return self.config.settings.audience, None

        resource_audience = self.config.settings.audience
        client = self.config.get_client(client_id)
        extras = client.additional_audiences if client else []

        aud = [client_id]
        for extra in extras:
            if extra == resource_audience and extra != client_id:
                logger.warning(
                    "Ignoring additional_audience %r for client %r: it matches the "
                    "resource audience (oauth.audience) and must not appear in an "
                    "ID Token aud.",
                    extra,
                    client_id,
                )
                continue
            if extra and extra not in aud:
                aud.append(extra)

        if len(aud) == 1:
            return aud[0], None
        return aud, client_id

    @staticmethod
    def _compute_at_hash(access_token: str) -> str:
        """Compute the OIDC ``at_hash`` claim for an access token.

        Per OIDC Core §3.1.3.6 (with RS256): base64url of the left half of
        the SHA-256 hash of the ASCII access token, without padding.
        """
        digest = hashlib.sha256(access_token.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")

    def create_token(
        self,
        user: User,
        exp_minutes: Optional[int] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
        nonce: Optional[str] = None,
        scope: Optional[str] = None,
        client_id: Optional[str] = None,
        auth_time: Optional[int] = None,
        refresh_family: Optional[str] = None,
        id_token_claims: Optional[List[str]] = None,
        userinfo_claims: Optional[List[str]] = None,
        issuer: Optional[str] = None,
        issue_refresh_token: bool = True,
        resource: Optional[List[str]] = None,
        refresh_resource: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a JWT token for a user.

        ``auth_time`` is the Unix timestamp of the original end-user
        authentication (issue #42): callers pass it when they know it (auth
        code creation time, device authorization time, value preserved from a
        refresh token); when omitted it defaults to "now", which is correct
        for grants that authenticate the user in the same request (password).

        ``id_token_claims``/``userinfo_claims`` are the claim names a client
        asked for through the OIDC ``claims`` request parameter (OIDC Core
        §5.5, #104): the former are resolved into the ID Token here, the latter
        are stamped on the access token so ``/userinfo`` can honour them. Both
        lists are also persisted in the refresh token (like ``scope`` and
        ``auth_time``), so refreshed tokens keep honouring the request (#112).

        ``issuer`` overrides ``settings.issuer`` for the ``iss`` claim on every
        token minted here (access, ID, refresh), so it must be whatever the
        caller's own discovery document just advertised (``issuer_from_request``)
        - a token whose ``iss`` doesn't match what discovery said is rejected by
        any spec-compliant client.

        ``issue_refresh_token`` is False for grants without an end user
        (client_credentials, RFC 6749 §4.4.3: "A refresh token SHOULD NOT be
        included", #239): the client authenticates itself on every call, so a
        refresh token would only be a second, long-lived credential bound to a
        user the grant never involved. When False no refresh JWT is minted and
        the response carries no ``refresh_token`` key at all.
        """
        settings = self.config.settings
        effective_issuer = issuer or settings.issuer

        if exp_minutes is None:
            exp_minutes = settings.token_expiry_minutes

        # Defense in depth at the single choke point every issuance path goes
        # through: requested-claims values may come from a hand-crafted refresh
        # token or an unvalidated MCP call (see sanitize_claim_names).
        id_token_claims = sanitize_claim_names(id_token_claims)
        userinfo_claims = sanitize_claim_names(userinfo_claims)

        # Build extra claims
        extra: Dict[str, Any] = {}

        # Add core user attributes
        if user.identity_class:
            extra["identity_class"] = user.identity_class
        if user.entitlements:
            extra["entitlements"] = user.entitlements
        if user.groups:
            extra["groups"] = user.groups
        if user.source_acl:
            extra["source_acl"] = user.source_acl

        # Add custom attributes
        if user.attributes:
            extra["attributes"] = user.attributes

        # Build authorities
        authorities = self.build_authorities(user)
        if authorities:
            extra["authorities"] = authorities

        # Merge extra claims
        if extra_claims:
            extra.update(extra_claims)

        # The authoritative claims must reflect the actual grant, never a
        # caller-supplied `extra`. Drop any spoofed copy the merge may have
        # introduced before setting them below. Without this, a request like
        # extra={"scope": "openid email"} or extra={"req_userinfo_claims":
        # ["email"]} would smuggle scope-gated claims past /userinfo when the
        # authoritative value is absent (#102/#104 hardening).
        for reserved in _AUTHORITATIVE_CLAIMS:
            extra.pop(reserved, None)

        # Advertise the granted scope on the access token (RFC 9068 §2.2.3), so
        # resource endpoints (e.g. /userinfo, /introspect) can gate scope-based
        # claims (#102).
        if scope:
            extra["scope"] = scope

        # Carry the claim names the client requested for UserInfo via the OIDC
        # `claims` parameter (§5.5, #104), so /userinfo can return them on top of
        # whatever the granted scope already allows. Access-token only; never an
        # ID Token claim.
        if userinfo_claims:
            extra["req_userinfo_claims"] = userinfo_claims

        # Bind the access token to the client it was issued to (#188): what
        # RFC 9068 §2.2 requires of a JWT access token's 'client_id' claim,
        # and what /revoke's ownership check for public clients reads.
        # Refresh tokens have carried the same claim since #56.
        if client_id:
            extra["client_id"] = client_id

        # Mark the token type so access-token endpoints can reject ID/refresh
        # tokens presented as access tokens (issue #34). Set last so it cannot be
        # overridden by caller-supplied extra_claims.
        extra["token_use"] = "access"

        # Access token audience (#187, RFC 8707): when the request bound one
        # or more resource indicators, the aud IS those resources (a plain
        # string for one, an array for several), so a token minted for
        # resource A is rejected by resource server B. With no resource, the
        # aud stays oauth.audience - no change for existing clients.
        access_audience: Union[str, List[str]] = settings.audience
        if resource:
            access_audience = resource[0] if len(resource) == 1 else list(resource)

        # Create access token JWT
        token = self.crypto.create_jwt(
            sub=user.username,
            issuer=effective_issuer,
            audience=access_audience,
            roles=user.roles,
            tenant=user.tenant,
            extra=extra,
            exp_minutes=exp_minutes,
        )

        id_token = None
        effective_auth_time = None
        if scope and "openid" in scope.split():
            # auth_time is REQUIRED on re-authentication checks (OIDC Core
            # §2): when the caller didn't supply the original authentication
            # time, the user authenticated within this very request.
            effective_auth_time = (
                auth_time
                if auth_time is not None
                else int(datetime.now(timezone.utc).timestamp())
            )
            id_aud, azp = self._resolve_id_token_audience(client_id)
            id_extra = {
                "token_use": "id",
                "auth_time": effective_auth_time,
                # at_hash lets clients that validate it bind this ID Token to
                # the access token issued alongside (OIDC Core §3.1.3.6).
                "at_hash": self._compute_at_hash(token),
            }
            if azp:
                id_extra["azp"] = azp
            # Claims the client asked for in the ID Token via the OIDC `claims`
            # parameter (§5.5, #104). Resolved from the user and added only when
            # available (voluntary claims, §5.5.1). resolve_user_claim refuses
            # reserved registered/protocol names (#110), so a requested claim can
            # never overwrite iss/sub/aud/exp/... (which create_jwt sets after
            # applying `extra`) nor the id_extra protocol claims; setdefault is a
            # belt-and-suspenders guard for the id_extra keys.
            for claim_name in id_token_claims or []:
                found, value = resolve_user_claim(user, claim_name)
                if found:
                    id_extra.setdefault(claim_name, value)
            id_token = self.crypto.create_jwt(
                sub=user.username,
                issuer=effective_issuer,
                audience=id_aud,
                exp_minutes=exp_minutes,
                nonce=nonce,
                extra=id_extra,
            )


        # Create refresh token (valid for 7 days). Its claims persist the
        # context needed at refresh time:
        # - scope and auth_time, so the grant re-issues an ID Token with the
        #   same authentication context (OIDC Core §12.2, #39/#42);
        # - client_id, binding the token to the client it was issued to so no
        #   other client can spend it (RFC 9700 §4.14, #56) - which also keeps
        #   the refreshed ID Token aud identical to the original;
        # - rt_family, a stable id across rotations: reuse of a consumed token
        #   revokes the whole family (RFC 9700 §4.14.2, #56);
        # - req_id_token_claims/req_userinfo_claims, the claim names requested
        #   via the OIDC `claims` parameter, so a refreshed ID Token keeps the
        #   requested claims and /userinfo keeps honouring them for the
        #   refreshed access token (OIDC Core §12.2, #112).
        # Skipped entirely for grants with no end-user context (#239).
        response: Dict[str, Any] = {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": exp_minutes * 60,
        }
        if issue_refresh_token:
            refresh_extra: Dict[str, Any] = {"token_type": "refresh", "token_use": "refresh"}
            if scope:
                refresh_extra["scope"] = scope
            if effective_auth_time is not None:
                refresh_extra["auth_time"] = effective_auth_time
            if client_id:
                refresh_extra["client_id"] = client_id
            if id_token_claims:
                refresh_extra["req_id_token_claims"] = id_token_claims
            if userinfo_claims:
                refresh_extra["req_userinfo_claims"] = userinfo_claims
            # Remember the FULL original grant's resources (#187, RFC 8707
            # §2.2), NOT the narrowed subset this access token used: a later
            # refresh may request any resource the original authorization
            # covered. Falls back to the access-token resources for grants
            # with no prior step (the request is the original grant). The
            # refresh token's own aud stays oauth.audience: it is spent at
            # nanoidp's /token, not at a resource server.
            rt_resources = refresh_resource if refresh_resource is not None else resource
            if rt_resources:
                refresh_extra["resource"] = list(rt_resources)
            refresh_extra["rt_family"] = refresh_family or str(uuid.uuid4())
            response["refresh_token"] = self.crypto.create_jwt(
                sub=user.username,
                issuer=effective_issuer,
                audience=settings.audience,
                roles=user.roles,
                tenant=user.tenant,
                extra=refresh_extra,
                exp_minutes=7 * 24 * 60,  # 7 days
            )
        # RFC 6749 §5.1: report the scope actually granted - it may have been
        # narrowed on refresh (§6) and was previously hardcoded to "openid"
        # regardless of the grant (#56). Omitted when no scope was involved.
        if scope:
            response["scope"] = scope

        if id_token is not None:
            response["id_token"] = id_token

        return response


# Global token service instance
_token_service: Optional[TokenService] = None
_token_service_lock = threading.Lock()


def get_token_service() -> TokenService:
    """Get or create the global token service (thread-safe lazy init, #43)."""
    global _token_service
    if _token_service is None:
        with _token_service_lock:
            if _token_service is None:
                _token_service = TokenService()
    return _token_service
