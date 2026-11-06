"""Opaque references for an ``id_token_hint`` sent in a form POST (#468).

A form-serialized authorization request (#467) is answered with a 303 to
its GET form, and an ID token is not something to carry into a URL. The
body's hint is parked here under a random, short-lived, single-use
reference, which travels in the ``Location`` as ``ref:<id>``; the GET that
follows takes it back and verifies the token as if the request had carried
it. A reference not taken within its lifetime is dropped; one taken twice
is unknown the second time.
"""

import secrets
import time
from typing import Optional

from pydantic import BaseModel

from .runtime_repository import consume as consume_entry
from .runtime_repository import create_within
from .runtime_store import PydanticCodec, RuntimeRepository, get_runtime_store

# The browser follows the 303 at once; a minute covers a slow one.
REFERENCE_LIFETIME_SECONDS = 60
MAX_PARKED_HINTS = 1000
REFERENCE_PREFIX = "ref:"


class ParkedHintStoreFull(Exception):
    """Every slot is held by a reference not yet taken."""


class ParkedHint(BaseModel):
    id: str
    value: str
    expires_at: float


class ParkedHintStore:
    @property
    def _repository(self) -> RuntimeRepository[ParkedHint]:
        return get_runtime_store().repository(
            "id_token_hint_references", lambda record: record.id, PydanticCodec(ParkedHint)
        )

    def park(self, value: str) -> str:
        """Keep ``value`` for one GET; the reference to carry in its place.
        Raises ParkedHintStoreFull."""
        now = time.time()
        record = ParkedHint(
            id=secrets.token_urlsafe(32), value=value, expires_at=now + REFERENCE_LIFETIME_SECONDS
        )
        create_within(
            self._repository,
            record,
            MAX_PARKED_HINTS,
            expires_at=record.expires_at,
            full=ParkedHintStoreFull(f"{MAX_PARKED_HINTS} hints already parked"),
        )
        return REFERENCE_PREFIX + record.id

    def take(self, reference: str) -> Optional[str]:
        """The value a reference stands for, exactly once; None when the
        reference is unknown, expired or already taken."""
        if not reference.startswith(REFERENCE_PREFIX):
            return None
        taken = consume_entry(
            self._repository,
            reference[len(REFERENCE_PREFIX) :],
            lambda entry: entry.value.expires_at > time.time(),
        )
        return taken.value.value if taken is not None else None


def is_reference(value: str) -> bool:
    return value.startswith(REFERENCE_PREFIX)


def get_parked_hint_store() -> ParkedHintStore:
    return ParkedHintStore()
