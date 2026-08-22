"""
Device Authorization Grant state (RFC 8628).

Extracted from ``routes/oauth.py`` module globals (#84): the grant state was a
``dict[str, Any]`` holding heterogeneous values (state dicts plus
``"user:<code>" -> device_code`` back-references encoded in key strings). It is
now a typed store with the user-code index as a separate mapping.

Concurrency semantics are unchanged from #43: the polling client races against
the user's verification and against its own retries, so every compound
lookup-check-transition runs under one lock - ``poll`` cannot double-issue an
authorized code, ``verify`` cannot double-claim a pending one. Credential
verification during ``verify`` intentionally happens inside the lock, exactly
as before, so a concurrent poll can never observe a half-transitioned entry.
"""

import logging
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Callable, Dict, Optional, Tuple

if TYPE_CHECKING:
    from ..config import User

logger = logging.getLogger(__name__)

# Uppercase letters and digits that are easy to read and type; excludes the
# confusable 0, O, I, 1, L.
_USER_CODE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

DEVICE_CODE_EXPIRES_IN = 600  # seconds (RFC 8628 leaves this to the AS)
DEVICE_POLL_INTERVAL = 5  # seconds


@dataclass
class DeviceCodeGrant:
    """State of one device authorization (RFC 8628 §3.2)."""

    user_code: str
    client_id: str
    scope: str
    expires_at: float
    interval: int
    status: str = "pending"  # pending, authorized, denied, expired
    username: Optional[str] = None
    auth_time: Optional[int] = None


class DevicePollOutcome(Enum):
    """Result of a token-endpoint poll (RFC 8628 §3.4/§3.5 error codes)."""

    NOT_FOUND = "not_found"
    WRONG_CLIENT = "wrong_client"
    EXPIRED = "expired"
    PENDING = "pending"
    DENIED = "denied"
    USER_NOT_FOUND = "user_not_found"
    UNKNOWN_STATUS = "unknown_status"
    AUTHORIZED = "authorized"


class DeviceVerifyOutcome(Enum):
    """Result of a user's verification attempt at /device."""

    INVALID_CODE = "invalid_code"
    ALREADY_USED = "already_used"
    EXPIRED = "expired"
    DENIED = "denied"
    MISSING_CREDENTIALS = "missing_credentials"
    INVALID_CREDENTIALS = "invalid_credentials"
    AUTHORIZED = "authorized"


class DeviceCodeStore:
    """In-memory device authorization state with atomic transitions (#43)."""

    def __init__(self) -> None:
        self._codes: Dict[str, DeviceCodeGrant] = {}
        self._by_user_code: Dict[str, str] = {}
        # RLock because create() prunes while holding it.
        self._lock = threading.RLock()

    def create(
        self,
        client_id: str,
        scope: str,
        expires_in: int = DEVICE_CODE_EXPIRES_IN,
        interval: int = DEVICE_POLL_INTERVAL,
    ) -> Tuple[str, str]:
        """Create a device authorization; returns (device_code, user_code).

        Stale entries are pruned on each creation so they don't pile up on
        long-running servers.
        """
        device_code = secrets.token_urlsafe(32)
        user_code = "".join(secrets.choice(_USER_CODE_CHARS) for _ in range(8))

        with self._lock:
            self.prune_expired()
            self._codes[device_code] = DeviceCodeGrant(
                user_code=user_code,
                client_id=client_id,
                scope=scope,
                expires_at=time.time() + expires_in,
                interval=interval,
            )
            self._by_user_code[user_code] = device_code
        return device_code, user_code

    def poll(
        self,
        device_code: str,
        client_id: Optional[str],
        get_user: Callable[[str], Optional["User"]],
    ) -> Tuple[DevicePollOutcome, Optional["User"], Optional[DeviceCodeGrant]]:
        """Token-endpoint poll: atomic lookup-check-claim (one-time use, #43).

        On AUTHORIZED the entry is consumed (deleted) and the grant snapshot is
        returned for scope/auth_time; the user lookup happens inside the lock
        so a concurrent poll can never also claim the same authorization.
        """
        with self._lock:
            grant = self._codes.get(device_code)
            if not grant:
                return DevicePollOutcome.NOT_FOUND, None, None
            if grant.client_id != client_id:
                return DevicePollOutcome.WRONG_CLIENT, None, None
            if time.time() > grant.expires_at:
                grant.status = "expired"
                return DevicePollOutcome.EXPIRED, None, None
            if grant.status == "pending":
                return DevicePollOutcome.PENDING, None, None
            if grant.status == "denied":
                return DevicePollOutcome.DENIED, None, None
            if grant.status == "expired":
                return DevicePollOutcome.EXPIRED, None, None
            if grant.status == "authorized":
                user = get_user(grant.username) if grant.username else None
                if not user:
                    # Entry intentionally NOT consumed (matches pre-#84 code).
                    return DevicePollOutcome.USER_NOT_FOUND, None, None
                del self._codes[device_code]
                self._by_user_code.pop(grant.user_code, None)
                return DevicePollOutcome.AUTHORIZED, user, grant
            return DevicePollOutcome.UNKNOWN_STATUS, None, None

    def verify(
        self,
        user_code: str,
        action: str,
        username: str,
        password: str,
        authenticate: Callable[[str, str], Optional["User"]],
    ) -> Tuple[DeviceVerifyOutcome, Optional["User"]]:
        """User verification at /device: atomic check-status + transition (#43).

        The credential check runs inside the lock, as it always did, so two
        concurrent verifications cannot both claim the same pending code.
        ``authenticate`` is the single choke point for both password and
        persona login (see ``ConfigManager.interactive_authenticate``) - this
        store no longer needs to know which mode is active.
        """
        with self._lock:
            device_code = self._by_user_code.get(user_code)
            grant = self._codes.get(device_code) if device_code else None
            if not grant:
                return DeviceVerifyOutcome.INVALID_CODE, None
            if grant.status != "pending":
                return DeviceVerifyOutcome.ALREADY_USED, None
            if time.time() > grant.expires_at:
                grant.status = "expired"
                return DeviceVerifyOutcome.EXPIRED, None
            if action == "deny":
                grant.status = "denied"
                return DeviceVerifyOutcome.DENIED, None

            if not username:
                return DeviceVerifyOutcome.MISSING_CREDENTIALS, None
            user = authenticate(username, password)

            if not user:
                return DeviceVerifyOutcome.INVALID_CREDENTIALS, None
            grant.status = "authorized"
            grant.username = user.username
            grant.auth_time = int(time.time())
            return DeviceVerifyOutcome.AUTHORIZED, user

    def prune_expired(self) -> int:
        """Drop expired entries together with their user-code index."""
        now = time.time()
        with self._lock:
            expired = [
                code for code, grant in self._codes.items() if now > grant.expires_at
            ]
            for code in expired:
                self._by_user_code.pop(self._codes[code].user_code, None)
                del self._codes[code]
        if expired:
            logger.debug(f"Pruned {len(expired)} expired device codes")
        return len(expired)

    def clear(self) -> None:
        """Drop all device authorization state (test isolation)."""
        with self._lock:
            self._codes.clear()
            self._by_user_code.clear()


_device_code_store: Optional[DeviceCodeStore] = None
_device_code_store_lock = threading.Lock()


def get_device_code_store() -> DeviceCodeStore:
    """Get or create the global device code store (thread-safe lazy init, #43)."""
    global _device_code_store
    if _device_code_store is None:
        with _device_code_store_lock:
            if _device_code_store is None:
                _device_code_store = DeviceCodeStore()
    return _device_code_store
