"""
Token service for generating JWT tokens with authorities.
"""

import logging
from typing import Dict, List, Any, Optional

from ..config import User, Settings, get_config
from .crypto import get_crypto_service

logger = logging.getLogger(__name__)


class TokenService:
    """Service for generating JWT tokens."""

    def __init__(self):
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
        (a safety fallback — a real OIDC token endpoint always has a client).

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

    def create_token(
        self,
        user: User,
        exp_minutes: Optional[int] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
        nonce: Optional[str] = None,
        scope: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a JWT token for a user."""
        settings = self.config.settings

        if exp_minutes is None:
            exp_minutes = settings.token_expiry_minutes

        # Build extra claims
        extra = {}

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
        if scope and "openid" in scope.split():
            id_aud, azp = self._resolve_id_token_audience(client_id)
            id_extra = {"token_use": "id"}
            if azp:
                id_extra["azp"] = azp
            id_token = self.crypto.create_jwt(
                sub=user.username,
                issuer=settings.issuer,
                audience=id_aud,
                exp_minutes=exp_minutes,
                nonce=nonce,
                extra=id_extra,
            )


        # Create refresh token (valid for 7 days)
        refresh_extra = {"token_type": "refresh", "token_use": "refresh"}
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
            "scope": "openid",
        }

        if id_token is not None:
            response["id_token"] = id_token

        return response


# Global token service instance
_token_service: Optional[TokenService] = None


def get_token_service() -> TokenService:
    """Get or create the global token service."""
    global _token_service
    if _token_service is None:
        _token_service = TokenService()
    return _token_service
