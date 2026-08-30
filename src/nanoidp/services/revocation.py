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
instance was a permanent memory increment. The expiry follows a three-state
trust contract (#293 review rounds 1+2, spelled out on RevocationStore): a
VERIFIED exp is kept exactly (tokens minted via /api or MCP can outlive any
fixed bound); a verified payload WITHOUT exp - which verify_jwt accepts -
gets indefinite retention, because a token that never expires can never
have its revocation forgotten; callers holding only unverified claims pass
nothing and get the bounded default. Writes are monotonic - re-revoking
never shortens retention.
"""

import threading
import time
from typing import Dict, Optional, Union

# The retention when the caller cannot supply a TRUSTED exp: covers the
# 7-day refresh JWT (services/token.py mints refresh tokens with a fixed
# 7-day expiry) plus one day of clock skew. NOT a cap on trusted expiries:
# /api/users/<username>/token and MCP generate_token mint access tokens with
# arbitrary exp_minutes, so a verified exp can legitimately exceed this -
# capping it let a revoked 14-day token flicker back after the day-8 sweep
# (#293 review round 1, blocker 1).
_DEFAULT_RETENTION_SECONDS = 8 * 24 * 3600


class _Unset:
    """Sentinel type: the caller has NO trusted expiry to offer (an
    unverified payload, or no payload at all). Distinct from None, which a
    verified caller passes when its payload genuinely carries no exp claim
    (#293 review round 2): verify_jwt does not require exp, so a signed
    token without one verifies - and such a token NEVER expires, meaning
    its revocation can never be forgotten either."""


_UNSET = _Unset()

_ExpiresAt = Union[float, None, _Unset]


class RevocationStore:
    """Revoked token ids (jti or token hash) and revoked rotation families,
    each remembered until its expiry.

    TRUST CONTRACT, three states (#293 review rounds 1+2):

    - ``expires_at`` OMITTED (the ``_UNSET`` default): the caller has no
      trusted expiry - an unverified payload (/logout's id_token_hint) or
      none at all. Bounded default retention.
    - ``expires_at=None`` from a VERIFIED payload: the token carries no exp
      claim, which verify_jwt accepts - it never expires, so the entry gets
      INDEFINITE retention (never swept). This is the pre-#288 behavior for
      exactly the tokens where forgetting would be wrong.
    - ``expires_at=<number>`` from a VERIFIED payload: kept exactly,
      however long (no cap - /api and MCP mint arbitrary lifetimes).

    The trust decision lives at the call site, never in a store-side cap.
    """

    def __init__(self) -> None:
        self._revoked_tokens: Dict[str, float] = {}
        self._revoked_families: Dict[str, float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _effective_expiry(expires_at: _ExpiresAt) -> float:
        """Resolve the three-state contract (see the class docstring). A
        past numeric exp still earns a short memory so a just-revoked,
        just-expired token cannot flicker back before the caller's own exp
        check catches it. A trusted exp is normalized to float at this
        boundary (PyJWT can hand back a value it merely coerced for its own
        check); a trusted exp that does not coerce fails SAFE, toward
        indefinite retention - never toward forgetting a revocation."""
        now = time.time()
        if isinstance(expires_at, _Unset):
            return now + _DEFAULT_RETENTION_SECONDS
        if expires_at is None:
            return float("inf")
        try:
            numeric = float(expires_at)
        except (TypeError, ValueError):
            return float("inf")
        return max(numeric, now + 60)

    def _sweep_locked(self) -> None:
        """Drop expired entries; caller holds the lock."""
        now = time.time()
        for entries in (self._revoked_tokens, self._revoked_families):
            expired = [key for key, exp in entries.items() if exp <= now]
            for key in expired:
                del entries[key]

    def revoke(self, token_id: str, expires_at: _ExpiresAt = _UNSET) -> None:
        """Mark a single token id (jti or fallback hash) as revoked per the
        three-state trust contract on the class: omitted = bounded default;
        None from a verified payload = the token never expires, indefinite
        retention; a number from a verified payload = kept exactly.

        Monotonic: re-revoking an id can only EXTEND its retention, never
        shorten it - the old set.add() was naturally idempotent, and a plain
        assignment would let a later revoke with a shorter expiry (a second
        /logout, say) cut an existing revocation short (#293 review round 1,
        blocker 2).
        """
        with self._lock:
            self._sweep_locked()
            self._revoked_tokens[token_id] = max(
                self._revoked_tokens.get(token_id, 0.0),
                self._effective_expiry(expires_at),
            )

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
        expires_at: _ExpiresAt = _UNSET,
    ) -> bool:
        """Atomic revocation check and (with rotation) consumption of a
        refresh token. Returns True when reuse was detected.

        ``expires_at`` is the presented refresh token's verified ``exp``
        (three-state contract, see the class docstring): the claimed jti
        needs remembering exactly that long - indefinitely for a verified
        token without exp, which never stops being presentable. A family
        marker set on reuse detection gets the retention bound when the
        presented ancestor carries an exp (every nanoidp-minted descendant
        lives at most 7 more days), and indefinite retention when it does
        not (its descendants may be equally undying).

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
                    family_retention = (
                        float("inf") if expires_at is None else _UNSET
                    )
                    self._revoked_families[family] = self._effective_expiry(
                        family_retention
                    )
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
