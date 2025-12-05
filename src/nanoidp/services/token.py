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

    def create_token(
        self,
        user: User,
        exp_minutes: Optional[int] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
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

        # Create refresh token (valid for 7 days)
        refresh_extra = {"token_type": "refresh"}
        refresh_token = self.crypto.create_jwt(
            sub=user.username,
            issuer=settings.issuer,
            audience=settings.audience,
            roles=user.roles,
            tenant=user.tenant,
            extra=refresh_extra,
            exp_minutes=7 * 24 * 60,  # 7 days
        )

        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": exp_minutes * 60,
            "refresh_token": refresh_token,
            "scope": "openid",
        }


# Global token service instance
_token_service: Optional[TokenService] = None


def get_token_service() -> TokenService:
    """Get or create the global token service."""
    global _token_service
    if _token_service is None:
        _token_service = TokenService()
    return _token_service
