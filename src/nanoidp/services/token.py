"""
Token service for generating JWT tokens with authorities.
"""

import base64
import hashlib
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import User, get_config
from .crypto import get_crypto_service

logger = logging.getLogger(__name__)

def resolve_user_claim(user: User, name: str) -> tuple[bool, Any]:
    """Resolve a requested OIDC/custom claim name to the user's value.

    Backs the OIDC ``claims`` request parameter (OIDC Core §5.5): the standard
    ``email``/``profile`` claims plus nanoidp's custom claims and any user
    attribute can be requested for the ID Token or UserInfo. Returns
    ``(found, value)``; ``found`` is False when nanoidp cannot supply the claim,
    so voluntary claims are simply omitted rather than emitted as null (§5.5.1).
    """
    if name == "email":
        return True, user.email
    if name == "email_verified":
        return True, True
    if name == "preferred_username":
        return True, user.username
    if name == "roles":
        return True, user.roles
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
        are stamped on the access token so ``/userinfo`` can honour them.
        """
        settings = self.config.settings

        if exp_minutes is None:
            exp_minutes = settings.token_expiry_minutes

        # Build extra claims
        extra: Dict[str, Any] = {}

        # Add core user attributes
        if user.identity_class:
            extra["identity_class"] = user.identity_class
        if user.entitlements:
            extra["entitlements"] = user.entitlements
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

        # `scope` and `req_userinfo_claims` are authoritative: they must reflect
        # the actual grant, never a caller-supplied `extra`. Drop any spoofed
        # copy the merge may have introduced before setting them below. Without
        # this, a request like extra={"scope": "openid email"} or
        # extra={"req_userinfo_claims": ["email"]} would smuggle scope-gated
        # claims past /userinfo when the authoritative value is absent
        # (#102/#104 hardening).
        for reserved in ("scope", "req_userinfo_claims"):
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

        # Mark the token type so access-token endpoints can reject ID/refresh
        # tokens presented as access tokens (issue #34). Set last so it cannot be
        # overridden by caller-supplied extra_claims.
        extra["token_use"] = "access"

        # Create access token JWT
        token = self.crypto.create_jwt(
            sub=user.username,
            issuer=settings.issuer,
            audience=settings.audience,
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
            # available (voluntary claims, §5.5.1). setdefault so a requested
            # name can never overwrite a protocol claim (auth_time/at_hash/azp).
            for claim_name in id_token_claims or []:
                found, value = resolve_user_claim(user, claim_name)
                if found:
                    id_extra.setdefault(claim_name, value)
            id_token = self.crypto.create_jwt(
                sub=user.username,
                issuer=settings.issuer,
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
        #   revokes the whole family (RFC 9700 §4.14.2, #56).
        refresh_extra: Dict[str, Any] = {"token_type": "refresh", "token_use": "refresh"}
        if scope:
            refresh_extra["scope"] = scope
        if effective_auth_time is not None:
            refresh_extra["auth_time"] = effective_auth_time
        if client_id:
            refresh_extra["client_id"] = client_id
        refresh_extra["rt_family"] = refresh_family or str(uuid.uuid4())
        refresh_token = self.crypto.create_jwt(
            sub=user.username,
            issuer=settings.issuer,
            audience=settings.audience,
            roles=user.roles,
            tenant=user.tenant,
            extra=refresh_extra,
            exp_minutes=7 * 24 * 60,  # 7 days
        )

        response = {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": exp_minutes * 60,
            "refresh_token": refresh_token,
        }
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
