"""
In-memory revocation state for tokens and refresh-token rotation families.

Extracted from ``routes/oauth.py`` module globals (#84). Semantics are
unchanged from #46/#56:

- Plain membership tests and single additions are lock-free — individual
  ``set`` operations are atomic under the GIL — and serve ``/userinfo``,
  ``/introspect``, ``/revoke`` and ``/logout``.
- The refresh grant's compound check-then-claim goes through the lock, so two
  concurrent refreshes of the same token cannot both pass the check and both
  rotate (#56). Reuse of an already-consumed token revokes its whole rotation
  family — attacker's copy and legitimate descendant alike (RFC 9700 §4.14.2).
"""

import threading
from typing import Optional

_UNSET = object()


class RevocationStore:
    """Revoked token ids (jti or token hash) and revoked rotation families."""

    def __init__(self) -> None:
        self._revoked_tokens: set[str] = set()
        self._revoked_families: set[str] = set()
        self._lock = threading.Lock()

    def revoke(self, token_id: str) -> None:
        """Mark a single token id (jti or fallback hash) as revoked."""
        self._revoked_tokens.add(token_id)

    def is_revoked(self, token_id: Optional[str]) -> bool:
        """Lock-free membership test (single set op, atomic under the GIL)."""
        return token_id is not None and token_id in self._revoked_tokens

    def check_and_claim_refresh(
        self, jti: Optional[str], family: Optional[str], rotate: bool
    ) -> bool:
        """Atomic revocation check and (with rotation) consumption of a
        refresh token. Returns True when reuse was detected.

        Must be the LAST validation in the refresh grant: from the moment it
        claims the jti, a rejected request would have consumed the token
        (#56 review; see the call site's ordering comment).
        """
        with self._lock:
            family_revoked = bool(family) and family in self._revoked_families
            token_revoked = jti in self._revoked_tokens
            if token_revoked or family_revoked:
                if rotate and family and not family_revoked:
                    self._revoked_families.add(family)
                return True
            if rotate and jti:
                self._revoked_tokens.add(jti)
            return False

    def clear(self) -> None:
        """Drop all revocation state (test isolation)."""
        with self._lock:
            self._revoked_tokens.clear()
            self._revoked_families.clear()


_revocation_store: Optional[RevocationStore] = None
_revocation_store_lock = threading.Lock()


def get_revocation_store() -> RevocationStore:
    """Get or create the global revocation store (thread-safe lazy init, #43)."""
    global _revocation_store
    if _revocation_store is None:
        with _revocation_store_lock:
            if _revocation_store is None:
                _revocation_store = RevocationStore()
    return _revocation_store
