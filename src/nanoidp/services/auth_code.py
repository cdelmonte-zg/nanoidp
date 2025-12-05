"""
Authorization Code service with PKCE support.
Manages authorization codes for OAuth2 Authorization Code Flow.
"""

import hashlib
import base64
import secrets
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class AuthorizationCode:
    """Represents an OAuth2 authorization code."""
    code: str
    client_id: str
    redirect_uri: str
    scope: str
    username: str
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    nonce: Optional[str] = None
    state: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=10))
    used: bool = False


class AuthCodeStore:
    """
    In-memory storage for authorization codes.
    Codes expire after 10 minutes (per RFC 6749).
    """

    def __init__(self):
        self._codes: Dict[str, AuthorizationCode] = {}

    def create_code(
        self,
        client_id: str,
        redirect_uri: str,
        username: str,
        scope: str = "openid",
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        nonce: Optional[str] = None,
        state: Optional[str] = None,
    ) -> str:
        """
        Create a new authorization code.

        Args:
            client_id: The OAuth client ID
            redirect_uri: The redirect URI for the callback
            username: The authenticated user's username
            scope: Requested scopes (space-separated)
            code_challenge: PKCE code challenge (optional)
            code_challenge_method: PKCE method ("plain" or "S256")
            nonce: OIDC nonce for ID token (optional)
            state: OAuth state parameter (optional)

        Returns:
            The generated authorization code
        """
        # Clean up expired codes
        self._cleanup_expired()

        # Generate a secure random code
        code = secrets.token_urlsafe(32)

        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            username=username,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            state=state,
        )

        self._codes[code] = auth_code
        logger.debug(f"Created authorization code for user '{username}', client '{client_id}'")

        return code

    def consume_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> Optional[AuthorizationCode]:
        """
        Consume (validate and mark as used) an authorization code.

        Args:
            code: The authorization code to consume
            client_id: The client ID (must match the code's client_id)
            redirect_uri: The redirect URI (must match the code's redirect_uri)
            code_verifier: PKCE code verifier (required if code was created with code_challenge)

        Returns:
            The AuthorizationCode if valid, None otherwise
        """
        auth_code = self._codes.get(code)

        if not auth_code:
            logger.warning(f"Authorization code not found: {code[:8]}...")
            return None

        # Check if code is expired
        if datetime.now(timezone.utc) > auth_code.expires_at:
            logger.warning(f"Authorization code expired: {code[:8]}...")
            del self._codes[code]
            return None

        # Check if code was already used (one-time use per RFC 6749)
        if auth_code.used:
            logger.warning(f"Authorization code already used: {code[:8]}...")
            # Revoke all tokens issued with this code (security measure)
            del self._codes[code]
            return None

        # Validate client_id
        if auth_code.client_id != client_id:
            logger.warning(f"Client ID mismatch for code {code[:8]}...")
            return None

        # Validate redirect_uri
        if auth_code.redirect_uri != redirect_uri:
            logger.warning(f"Redirect URI mismatch for code {code[:8]}...")
            return None

        # Validate PKCE if code_challenge was provided during authorization
        if auth_code.code_challenge:
            if not code_verifier:
                logger.warning(f"PKCE code_verifier required but not provided for code {code[:8]}...")
                return None

            if not self._verify_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method):
                logger.warning(f"PKCE verification failed for code {code[:8]}...")
                return None

        # Mark as used
        auth_code.used = True

        logger.debug(f"Authorization code consumed for user '{auth_code.username}'")
        return auth_code

    def _verify_pkce(self, code_verifier: str, code_challenge: str, method: Optional[str]) -> bool:
        """
        Verify PKCE code_verifier against code_challenge.

        Args:
            code_verifier: The code verifier from the token request
            code_challenge: The code challenge from the authorization request
            method: The challenge method ("plain" or "S256")

        Returns:
            True if verification succeeds, False otherwise
        """
        if method == "plain" or method is None:
            return code_verifier == code_challenge
        elif method == "S256":
            # S256: BASE64URL(SHA256(code_verifier)) == code_challenge
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            return computed_challenge == code_challenge
        else:
            logger.warning(f"Unknown PKCE method: {method}")
            return False

    def _cleanup_expired(self):
        """Remove expired authorization codes."""
        now = datetime.now(timezone.utc)
        expired = [code for code, auth in self._codes.items() if now > auth.expires_at]
        for code in expired:
            del self._codes[code]
        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired authorization codes")

    def get_code_info(self, code: str) -> Optional[AuthorizationCode]:
        """Get info about a code without consuming it (for debugging)."""
        return self._codes.get(code)


# Global instance
_auth_code_store: Optional[AuthCodeStore] = None


def get_auth_code_store() -> AuthCodeStore:
    """Get or create the global authorization code store."""
    global _auth_code_store
    if _auth_code_store is None:
        _auth_code_store = AuthCodeStore()
    return _auth_code_store
