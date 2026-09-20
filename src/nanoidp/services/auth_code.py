"""
Authorization Code service with PKCE support.
Manages authorization codes for OAuth2 Authorization Code Flow.
"""

import base64
import copy
import dataclasses
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Optional, Sequence, Union

from ..config import get_config_if_loaded
from .runtime_identities import MemoryRuntimeRepository, get_runtime_identity_store
from .runtime_repository import RepositoryTransaction

logger = logging.getLogger(__name__)

# How long a code may be redeemed for (RFC 6749 recommends ten minutes).
# Named because #196 needs it too: a client learned from a metadata
# document lives in a cache, and that entry has to outlive any code issued
# against it.
CODE_LIFETIME_SECONDS = 600


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
    # RFC 8707 resource indicators requested at /authorize (#187), carried to
    # the token exchange so the access token aud can be bound to them.
    resource: Optional[list] = None
    # Claim names requested via the OIDC `claims` parameter (§5.5, #104),
    # normalized to {"id_token": [...], "userinfo": [...]}. Carried from
    # /authorize to the token exchange so the ID Token / UserInfo can honour it.
    claims: Optional[Dict[str, Any]] = None
    # OIDC amr (RFC 8176 §2, #348): how the interactive login that produced
    # this code authenticated - ("pwd",) or ("pwd", "otp"); None under
    # persona mode, which checks no password (see routes/_auth.AuthMethod).
    # Carried to the token exchange the same way auth_time is, so a refresh
    # can keep honouring it (#112's pattern).
    amr: Optional[Sequence[str]] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
        + timedelta(seconds=CODE_LIFETIME_SECONDS)
    )
    used: bool = False


class AuthorizationCodeCodec:
    """How a code is copied, written down and read back (#404).

    A dataclass with two things JSON has no type for: datetimes, written as
    ISO 8601, and ``amr``, a tuple, written as a list and read back as the
    tuple it was (``create_code`` normalises it, so that what comes back is
    what went in whatever the caller passed)."""

    def copy(self, value: AuthorizationCode) -> AuthorizationCode:
        return dataclasses.replace(
            value,
            resource=list(value.resource) if value.resource is not None else None,
            claims=copy.deepcopy(value.claims),
        )

    def dump(self, value: AuthorizationCode) -> Any:
        written = dataclasses.asdict(value)
        written["created_at"] = value.created_at.isoformat()
        written["expires_at"] = value.expires_at.isoformat()
        written["amr"] = list(value.amr) if value.amr is not None else None
        return written

    def load(self, data: Any) -> AuthorizationCode:
        read = dict(data)
        read["created_at"] = datetime.fromisoformat(read["created_at"])
        read["expires_at"] = datetime.fromisoformat(read["expires_at"])
        read["amr"] = tuple(read["amr"]) if read["amr"] is not None else None
        return AuthorizationCode(**read)


class _Refused(Enum):
    """Why a redemption did not go through: decided inside the decision,
    logged after it, since a decision may be run again and has no effect
    outside its view (#404)."""

    NOT_FOUND = "Authorization code not found"
    EXPIRED = "Authorization code expired"
    ALREADY_USED = "Authorization code already used"
    WRONG_CLIENT = "Client ID mismatch for code"
    WRONG_REDIRECT = "Redirect URI mismatch for code"
    NO_VERIFIER = "PKCE code_verifier required but not provided for code"
    BAD_VERIFIER = "PKCE verification failed for code"


class AuthCodeStore:
    """Authorization codes, kept in the runtime store (#363).

    A view, with no state of its own: the codes live in a repository the
    runtime store lends, so they are reset with it and, with a backend that
    several processes share (#354), seen by all of them. Each operation that
    is more than one look is one decision of the repository's. Codes expire
    after 10 minutes (per RFC 6749); the store is told when, so that
    creating one drops the ones past their time without reading a value.
    """

    @property
    def _repository(self) -> MemoryRuntimeRepository[AuthorizationCode]:
        # Looked up on every use: the runtime store owns the state, whatever
        # replaces it (a reset, #354's durable backend).
        return get_runtime_identity_store().repository(
            "authorization_codes", lambda auth_code: auth_code.code, AuthorizationCodeCodec()
        )

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
        claims: Optional[Dict[str, Any]] = None,
        resource: Optional[list] = None,
        amr: Optional[Sequence[str]] = None,
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
            claims: Normalized OIDC `claims` request (§5.5, optional)
            amr: OIDC amr for the login that produced this code (#348, optional)

        Returns:
            The generated authorization code
        """
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
            claims=claims,
            resource=resource,
            amr=tuple(amr) if amr is not None else None,
        )

        def decide(view: RepositoryTransaction[AuthorizationCode]) -> None:
            # No cap, as ever: a code is only created for a login that went
            # through. What is past its time goes first.
            view.delete_expired(time.time())
            view.create(auth_code, expires_at=auth_code.expires_at.timestamp())

        self._repository.transact(decide)

        loaded = get_config_if_loaded()
        verbose = loaded.settings.verbose_logging if loaded is not None else True

        if verbose:
            logger.debug(f"Created authorization code for user '{username}', client '{client_id}'")
        else:
            logger.debug("Created authorization code")

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

        One decision (#43, #363): two concurrent redemptions cannot both
        pass. A code is marked used and kept, so that a second redemption
        is recognised as one and takes the code away; a request that does
        not match the code (another client, another redirect URI, a wrong
        or missing verifier) is refused and leaves it as it was, for the
        client it was issued to.

        Args:
            code: The authorization code to consume
            client_id: The client ID (must match the code's client_id)
            redirect_uri: The redirect URI (must match the code's redirect_uri)
            code_verifier: PKCE code verifier (required if code was created with code_challenge)

        Returns:
            The AuthorizationCode if valid, None otherwise
        """

        def decide(
            view: RepositoryTransaction[AuthorizationCode],
        ) -> Union[AuthorizationCode, _Refused]:
            entry = view.entry(code)
            if entry is None:
                return _Refused.NOT_FOUND
            auth_code = entry.value
            if datetime.now(timezone.utc) > auth_code.expires_at:
                view.delete(code)
                return _Refused.EXPIRED
            if auth_code.used:
                view.delete(code)
                return _Refused.ALREADY_USED
            if auth_code.client_id != client_id:
                return _Refused.WRONG_CLIENT
            if auth_code.redirect_uri != redirect_uri:
                return _Refused.WRONG_REDIRECT
            if auth_code.code_challenge:
                if not code_verifier:
                    return _Refused.NO_VERIFIER
                if not self._verify_pkce(
                    code_verifier, auth_code.code_challenge, auth_code.code_challenge_method
                ):
                    return _Refused.BAD_VERIFIER
            return view.replace(code, dataclasses.replace(auth_code, used=True)).value

        outcome = self._repository.transact(decide)
        if isinstance(outcome, _Refused):
            logger.warning(f"{outcome.value}: {code[:8]}...")
            return None
        logger.debug(f"Authorization code consumed for user '{outcome.username}'")
        return outcome

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
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            return computed_challenge == code_challenge
        else:
            logger.warning(f"Unknown PKCE method: {method}")
            return False

    def get_code_info(self, code: str) -> Optional[AuthorizationCode]:
        """A copy of the code, without consuming it (for tests and
        debugging). It used to be the stored object itself; a read of a
        runtime repository is by value."""
        return self._repository.get(code)


def get_auth_code_store() -> AuthCodeStore:
    """The authorization codes of this process: a view over the runtime
    store, which is where the state and its one lock are (#363)."""
    return AuthCodeStore()
