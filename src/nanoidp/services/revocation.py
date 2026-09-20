"""
In-memory revocation state for tokens and refresh-token rotation families.

Extracted from ``routes/oauth.py`` module globals (#84). Semantics are
unchanged from #46/#56:

- A membership test is one read and serves ``/userinfo`` and
  ``/introspect``; a single addition is one decision and serves ``/revoke``
  and ``/logout``.
- The refresh grant's compound check-then-claim is one decision, so two
  concurrent refreshes of the same token cannot both pass the check and both
  rotate (#56). Reuse of an already-consumed token revokes its whole rotation
  family - attacker's copy and legitimate descendant alike (RFC 9700 §4.14.2).

The state lives in the runtime store (#363), in ONE repository it lends:
token ids and rotation families are markers under typed names, ``jti:<id>``
and ``family:<id>``, because the check-then-claim reads and writes both and
there is no transaction across two repositories (#404). A marker says nothing
but that it is there; how long it is remembered is its entry's
``expires_at``, and indefinite retention is ``None`` there, which a backend
can write down where ``float("inf")`` is not JSON.

Entries expire (#288): a revoked jti only needs remembering until the token
it names expires - after ``exp`` the signature check rejects it anyway - so
every entry carries an expiry and the store sweeps opportunistically on the
mutating paths, inside their decision. Before this, both
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

import dataclasses
import time
from dataclasses import dataclass
from typing import Any, Optional, Union

from .runtime_identities import MemoryRuntimeRepository, get_runtime_identity_store
from .runtime_repository import RepositoryTransaction, checked_time

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


@dataclass
class RevocationMarker:
    """That a token id or a rotation family is revoked. The name says which
    (``jti:<id>``, ``family:<id>``) and the entry's ``expires_at`` for how
    long; there is nothing else to say."""

    name: str


class _MarkerCodec:
    def copy(self, value: RevocationMarker) -> RevocationMarker:
        return dataclasses.replace(value)

    def dump(self, value: RevocationMarker) -> Any:
        return dataclasses.asdict(value)

    def load(self, data: Any) -> RevocationMarker:
        return RevocationMarker(**data)


def _name_of(marker: RevocationMarker) -> str:
    return marker.name


# Given to the store once: a repository keeps what it was created with.
_CODEC = _MarkerCodec()


def _token(token_id: str) -> str:
    return f"jti:{_text(token_id)}"


def _family(family: str) -> str:
    return f"family:{_text(family)}"


def _text(identifier: str) -> str:
    """An id is text. A name is made by formatting, which would take
    anything: 5 would become the token "5", and a list its repr. /logout
    hands over the jti of a hint it did not verify, so this is where what
    is not an id stops (there, as an invalid hint like any other)."""
    if not isinstance(identifier, str):
        raise TypeError(f"a token id or a family is text, not {type(identifier).__name__}")
    return identifier


class RevocationStore:
    """Revoked token ids (jti or token hash) and revoked rotation families,
    each remembered until its expiry.

    A view, with no state of its own (#363): the markers live in a
    repository the runtime store lends, so that with a backend several
    processes share (#354) a revocation made in one is seen by all.

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

    @property
    def _markers(self) -> MemoryRuntimeRepository[RevocationMarker]:
        # Looked up on every use: the runtime store owns the state, whatever
        # replaces it (a reset, #354's durable backend).
        return get_runtime_identity_store().repository("revocations", _name_of, _CODEC)

    @staticmethod
    def _effective_expiry(expires_at: _ExpiresAt, now: float) -> Optional[float]:
        """Resolve the three-state contract (see the class docstring) into
        what the entry is told: a time, or None for "never". A past numeric
        exp still earns a short memory so a just-revoked, just-expired token
        cannot flicker back before the caller's own exp check catches it. A
        trusted exp is normalized to float at this boundary (PyJWT can hand
        back a value it merely coerced for its own check); a trusted exp
        that is no time - one that does not coerce, a NaN, an infinity, a
        number too large for a float, a bool - fails SAFE, toward indefinite
        retention, never toward forgetting a revocation. What a time is, is
        the store's to say (``checked_time``), so that this cannot hand it
        one it would refuse."""
        if isinstance(expires_at, _Unset):
            return now + _DEFAULT_RETENTION_SECONDS
        if expires_at is None or isinstance(expires_at, bool):
            return None
        try:
            numeric = checked_time(float(expires_at))
        except (TypeError, ValueError, OverflowError):
            return None
        assert numeric is not None
        return max(numeric, now + 60)

    @staticmethod
    def _remember(
        view: RepositoryTransaction[RevocationMarker], name: str, until: Optional[float]
    ) -> None:
        """Monotonic: what is already remembered is never remembered for
        less, and "never forgotten" is the longest there is."""
        existing = view.entry(name)
        if existing is None:
            view.create(RevocationMarker(name), expires_at=until)
        elif existing.expires_at is not None and (until is None or until > existing.expires_at):
            view.set_expires_at(name, until)

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

        One decision, and the clock is read in it: a revocation that had to
        wait for the store is remembered from when it is made (#404).
        """

        def decide(view: RepositoryTransaction[RevocationMarker]) -> None:
            now = time.time()
            view.delete_expired(now)
            self._remember(view, _token(token_id), self._effective_expiry(expires_at, now))

        self._markers.transact(decide)

    def is_revoked(self, token_id: Optional[str]) -> bool:
        """Whether the marker is there: one read, and no cleanup.

        A marker past its time and not yet swept still answers, as it always
        has; it can only concern an expired token, which every verification
        path already rejects on ``exp``."""
        return isinstance(token_id, str) and self._markers.entry(_token(token_id)) is not None

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

        One decision over the one repository: the token's marker and the
        family's are looked at and written together.
        """

        def decide(view: RepositoryTransaction[RevocationMarker]) -> bool:
            now = time.time()
            view.delete_expired(now)
            family_revoked = bool(family) and view.entry(_family(family or "")) is not None
            token_revoked = jti is not None and view.entry(_token(jti)) is not None
            if token_revoked or family_revoked:
                if rotate and family and not family_revoked:
                    family_retention: _ExpiresAt = None if expires_at is None else _UNSET
                    view.create(
                        RevocationMarker(_family(family)),
                        expires_at=self._effective_expiry(family_retention, now),
                    )
                return True
            if rotate and jti:
                view.create(
                    RevocationMarker(_token(jti)),
                    expires_at=self._effective_expiry(expires_at, now),
                )
            return False

        return self._markers.transact(decide)

    def clear(self) -> None:
        """Drop all revocation state (test isolation)."""
        self._markers.delete_all()


def get_revocation_store() -> RevocationStore:
    """The revocations of this process: a view over the runtime store,
    which is where the state and its one lock are (#363)."""
    return RevocationStore()
