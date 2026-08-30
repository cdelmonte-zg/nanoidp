"""
In-memory revocation state for tokens and refresh-token rotation families.

Extracted from ``routes/oauth.py`` module globals (#84). Semantics are
unchanged from #46/#56:

- Plain membership tests and single additions are lock-free - individual
  dict operations are atomic under the GIL - and serve ``/userinfo``,
  ``/introspect``, ``/revoke`` and ``/logout``.
- The refresh grant's compound check-then-claim goes through the lock, so two
  concurrent refreshes of the same token cannot both pass the check and both
  rotate (#56). Reuse of an already-consumed token revokes its whole rotation
  family - attacker's copy and legitimate descendant alike (RFC 9700 §4.14.2).

Entries expire (#288): a revoked jti only needs remembering until the token
it names expires - after ``exp`` the signature check rejects it anyway - so
every entry carries an expiry and the store sweeps opportunistically on the
mutating paths (which already serialize under the lock). Before this, both
sets grew without bound: every revocation and every rotation on a long-lived
instance was a permanent memory increment.
"""

import threading
import time
from typing import Dict, Optional

# The longest a revocation entry can matter when the caller cannot supply the
# token's own exp: no nanoidp token outlives the 7-day refresh JWT
# (services/token.py mints refresh tokens with a fixed 7-day expiry; access
# and ID tokens are shorter). One extra day absorbs clock skew.
_MAX_RETENTION_SECONDS = 8 * 24 * 3600


class RevocationStore:
    """Revoked token ids (jti or token hash) and revoked rotation families,
    each remembered until its expiry."""

    def __init__(self) -> None:
        self._revoked_tokens: Dict[str, float] = {}
        self._revoked_families: Dict[str, float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _effective_expiry(expires_at: Optional[float]) -> float:
        """The caller's exp when it has one (a verified payload's ``exp``),
        else the conservative retention bound."""
        now = time.time()
        if expires_at is None:
            return now + _MAX_RETENTION_SECONDS
        # Never trust an attacker-influenced exp to EXTEND retention past the
        # bound (e.g. /logout decodes id_token_hint unverified), and treat a
        # past exp as "still worth a short memory" rather than an instant
        # no-op, so a just-revoked, just-expired token cannot flicker back.
        return min(max(expires_at, now + 60), now + _MAX_RETENTION_SECONDS)

    def _sweep_locked(self) -> None:
        """Drop expired entries; caller holds the lock."""
        now = time.time()
        for entries in (self._revoked_tokens, self._revoked_families):
            expired = [key for key, exp in entries.items() if exp <= now]
            for key in expired:
                del entries[key]

    def revoke(self, token_id: str, expires_at: Optional[float] = None) -> None:
        """Mark a single token id (jti or fallback hash) as revoked until
        ``expires_at`` (the token's own ``exp`` when the caller has a
        verified payload; bounded default otherwise)."""
        with self._lock:
            self._sweep_locked()
            self._revoked_tokens[token_id] = self._effective_expiry(expires_at)

    def is_revoked(self, token_id: Optional[str]) -> bool:
        """Lock-free membership test (single dict op, atomic under the GIL).

        A swept-but-not-yet-removed entry can only concern an expired token,
        which every verification path already rejects on ``exp``."""
        return token_id is not None and token_id in self._revoked_tokens

    def check_and_claim_refresh(
        self,
        jti: Optional[str],
        family: Optional[str],
        rotate: bool,
        expires_at: Optional[float] = None,
    ) -> bool:
        """Atomic revocation check and (with rotation) consumption of a
        refresh token. Returns True when reuse was detected.

        ``expires_at`` is the presented refresh token's ``exp``: the claimed
        jti needs remembering exactly that long. A family marker set on reuse
        detection gets the retention bound instead - descendants minted
        before detection can outlive the presented ancestor, and the bound
        covers the longest-lived possible descendant.

        Must be the LAST validation in the refresh grant: from the moment it
        claims the jti, a rejected request would have consumed the token
        (#56 review; see the call site's ordering comment).
        """
        with self._lock:
            self._sweep_locked()
            family_revoked = bool(family) and family in self._revoked_families
            token_revoked = jti in self._revoked_tokens
            if token_revoked or family_revoked:
                if rotate and family and not family_revoked:
                    self._revoked_families[family] = self._effective_expiry(None)
                return True
            if rotate and jti:
                self._revoked_tokens[jti] = self._effective_expiry(expires_at)
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
