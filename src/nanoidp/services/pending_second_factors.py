"""Pending second factors: a verified password waiting for its TOTP code (#373).

On ``/login``, ``/saml/sso`` and ``/device`` a login whose password has been
verified and whose code is still outstanding is recorded here, so the code
screen carries an opaque reference instead of sending the password back to
the browser. ``/authorize`` keeps the same state inside its authorization
transaction (#346) and does not use this module.

A record holds no secret: no password and no ``User``, only the name of the
user whose password was verified. It belongs to one browser (the binding
every temporary capability of that browser shares), to one surface
(``purpose``) and to one context on that surface (``context_digest``: the
SAML request in flight, the device ``user_code``), and is used at most once.

Unlike an authorization transaction a record never changes once created: a
wrong code leaves it as it is, a correct code consumes it, and everything
else discards it. Each operation that is more than one look at the
repository (create under the cap, consume, discard, prune) is one decision
of the repository's (#404), so it is whole for whoever shares the store, not
only for the threads of this process; a read is a single look and needs
nothing.
"""

import hashlib
import hmac
import json
import secrets
import time
from typing import List, Literal, Mapping, Optional, Sequence

from pydantic import BaseModel

from .runtime_identities import (
    MemoryRuntimeRepository,
    PydanticCodec,
    get_runtime_identity_store,
)
from .runtime_repository import consume as consume_entry
from .runtime_repository import create_within, delete_where

# A code screen is a continuation of the login that just happened, not a
# page to come back to.
PENDING_SECOND_FACTOR_LIFETIME_SECONDS = 300

# Creating a record takes a valid password, so filling this is less exposed
# than /authorize's transactions, but the structure is bounded all the same.
# A live record is never evicted to make room: at the cap a new one is
# refused, and a login already waiting for its code is left alone.
MAX_PENDING_SECOND_FACTORS = 1000

Purpose = Literal["login", "saml_sso", "device"]


class PendingSecondFactorStoreFull(Exception):
    """Every slot is held by a live record."""


def context_digest(context: Mapping[str, str]) -> str:
    """SHA-256 of the surface's context, serialized canonically: compact
    JSON with sorted keys, so two spellings of one context cannot differ and
    two contexts cannot collide by concatenation."""
    serialized = json.dumps(dict(context), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class PendingSecondFactor(BaseModel):
    id: str
    browser_binding: str
    purpose: Purpose
    context_digest: str
    username: str
    amr: Optional[List[str]] = None
    verified_at: float
    expires_at: float

    def is_live(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) < self.expires_at

    def is_for(
        self, browser_binding: Optional[str], purpose: Purpose, context: Mapping[str, str]
    ) -> bool:
        """This browser's record, for this surface and this context."""
        return (
            browser_binding is not None
            and hmac.compare_digest(self.browser_binding, browser_binding)
            and self.purpose == purpose
            and hmac.compare_digest(self.context_digest, context_digest(context))
        )

    def is_live_for(
        self, browser_binding: Optional[str], purpose: Purpose, context: Mapping[str, str]
    ) -> bool:
        """``is_for``, and live now: the one rule for which record a read
        or a consume may touch. "Now" is when it is asked, so a consume
        asks from inside its decision, after any wait."""
        return self.is_for(browser_binding, purpose, context) and self.is_live()


class PendingSecondFactorStore:
    """The operations on pending second factors, each one atomic with
    respect to the others."""

    @property
    def _repository(self) -> MemoryRuntimeRepository[PendingSecondFactor]:
        # Looked up on every use, like the authorization transactions: the
        # runtime store owns the state, whatever replaces it.
        return get_runtime_identity_store().repository(
            "pending_second_factors", lambda record: record.id, PydanticCodec(PendingSecondFactor)
        )

    def create(
        self,
        *,
        browser_binding: str,
        purpose: Purpose,
        context: Mapping[str, str],
        username: str,
        amr: Optional[Sequence[str]],
    ) -> PendingSecondFactor:
        """Record a verified password; raises PendingSecondFactorStoreFull."""
        now = time.time()
        record = PendingSecondFactor(
            id=secrets.token_urlsafe(32),
            browser_binding=browser_binding,
            purpose=purpose,
            context_digest=context_digest(context),
            username=username,
            amr=list(amr) if amr else None,
            verified_at=now,
            expires_at=now + PENDING_SECOND_FACTOR_LIFETIME_SECONDS,
        )
        return create_within(
            self._repository,
            record,
            MAX_PENDING_SECOND_FACTORS,
            is_expired=lambda stored: not stored.is_live(),
            full=PendingSecondFactorStoreFull(
                f"{MAX_PENDING_SECOND_FACTORS} logins already waiting for a code"
            ),
        ).value

    def get_bound(
        self,
        record_id: str,
        browser_binding: Optional[str],
        *,
        purpose: Purpose,
        context: Mapping[str, str],
    ) -> Optional[PendingSecondFactor]:
        """The live record with this id, if it is this browser's, for this
        surface and this context."""
        record = self._repository.get(record_id)
        if record is None or not record.is_live_for(browser_binding, purpose, context):
            return None
        return record

    def consume(
        self,
        record_id: str,
        browser_binding: Optional[str],
        *,
        purpose: Purpose,
        context: Mapping[str, str],
    ) -> Optional[PendingSecondFactor]:
        """Remove the record and return it, exactly once. ``None`` when it is
        gone, expired, or not this browser's, surface's or context's."""
        taken = consume_entry(
            self._repository,
            record_id,
            lambda entry: entry.value.is_live_for(browser_binding, purpose, context),
        )
        return taken.value if taken is not None else None

    def discard(
        self,
        record_id: str,
        browser_binding: Optional[str],
        *,
        purpose: Purpose,
        context: Mapping[str, str],
    ) -> Optional[PendingSecondFactor]:
        """Drop the record and return it: the user abandoned the login, or
        it can no longer complete. Bound exactly like ``consume``: only this
        browser's record, for this surface and this context, so abandoning
        one flow never ends another flow of the same browser. ``None`` when
        there was no such record. An expired record is dropped too."""
        taken = consume_entry(
            self._repository,
            record_id,
            lambda entry: entry.value.is_for(browser_binding, purpose, context),
        )
        return taken.value if taken is not None else None

    def prune_expired(self) -> int:
        return delete_where(self._repository, lambda stored: not stored.is_live())


def get_pending_second_factor_store() -> PendingSecondFactorStore:
    """The pending second factors of this process."""
    return PendingSecondFactorStore()
