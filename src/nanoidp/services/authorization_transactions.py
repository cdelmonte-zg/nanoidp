"""Authorization transactions: one server-side record per /authorize request (#346).

A valid ``GET /authorize`` creates a transaction holding the request as it
was validated and normalized, a snapshot of the client it was validated
against, and later the state of the login. The login POST names the
transaction and completes it; issuing the code consumes it. Nothing about a
pending request lives in the Flask session except one stable random value,
the browser binding, which every transaction created by that browser
carries. A transaction id alone is therefore not enough to use one.

A transaction holds no secret: no password, no ``User`` (it carries
``password`` and ``totp_secret``), no ``OAuthClient`` (it carries
``client_secret``). The authenticated user is kept by name, the client as a
snapshot of what the login page renders.

A transaction is a snapshot of the request at the time its GET was
accepted. Configuration changes do not revalidate it; the route only
requires, before issuing a code, that the client still resolve.

The records live in the runtime store (#235), which is storage by value
with no update or compare-and-set. The transitions are this module's: each
one is a single critical section under this module's lock, so the route
calls them and never composes repository visits of its own.
"""

import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Literal, Optional, Sequence

from pydantic import BaseModel

from ..models import OAuthClient
from .auth_code import CODE_LIFETIME_SECONDS
from .identities import ClientOrigin
from .runtime_identities import MemoryRuntimeRepository, get_runtime_identity_store

# As long as the code the transaction will produce, as the starting value:
# a login page left open longer than a code would live is a new request.
TRANSACTION_LIFETIME_SECONDS = CODE_LIFETIME_SECONDS

# How many transactions may be pending at once. They are created by an
# unauthenticated GET, so a lifetime is not a bound. A live transaction is
# never evicted to make room: at the cap a new request is refused, because
# breaking a login already under way to start another is the worse outcome
# (the rule the CIMD cache follows too).
MAX_PENDING_TRANSACTIONS = 1000


class TransactionStoreFull(Exception):
    """Every slot is held by a live transaction."""


class TransactionState(str, Enum):
    PENDING = "pending"
    # The password was verified and a second factor is still required.
    PRIMARY_VERIFIED = "primary_verified"


class AuthorizationParameters(BaseModel):
    """The OAuth request parameters, validated and normalized once."""

    response_type: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str
    nonce: str
    claims: str
    resources: List[str]


class ClientSnapshot(BaseModel):
    """What the login page shows about the client, and nothing else.

    Spelled out field by field rather than derived from ``OAuthClient``, so
    a field added there (a secret among them) never reaches a transaction
    unless someone adds it here on purpose.
    """

    client_id: str
    description: str
    background_color: Optional[str]
    header_color: Optional[str]
    footer_color: Optional[str]
    show_client_id: bool
    show_description: bool
    layout: Literal["vertical", "horizontal"]

    @classmethod
    def of(cls, client: OAuthClient) -> "ClientSnapshot":
        return cls.model_validate(client.model_dump(include=set(cls.model_fields)))


class AuthorizationTransaction(BaseModel):
    id: str
    browser_binding: str
    created_at: float
    expires_at: float
    params: AuthorizationParameters
    # The OAuth request fields of the query string that created it, exactly
    # as sent: a POST naming this transaction from a query string of its own
    # must carry this one.
    requested: Dict[str, List[str]]
    client_snapshot: ClientSnapshot
    client_origin: ClientOrigin
    state: TransactionState = TransactionState.PENDING
    primary_username: Optional[str] = None
    primary_amr: Optional[List[str]] = None
    primary_verified_at: Optional[float] = None

    def is_live(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) < self.expires_at

    def is_bound_to(self, browser_binding: Optional[str]) -> bool:
        return browser_binding is not None and hmac.compare_digest(
            self.browser_binding, browser_binding
        )


class LookupOutcome(Enum):
    NONE = "none"
    UNIQUE = "unique"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class Lookup:
    outcome: LookupOutcome
    transaction: Optional[AuthorizationTransaction] = None


# One lock for every operation, whichever store object makes it: the store
# below is a view over the runtime store's repository, not an owner of state.
# Reads take it too: a transition replaces a record with a delete and a
# create, and a read between the two would see a live transaction as gone.
# Reentrant, because the transitions read through get_bound while holding it.
_store_lock = threading.RLock()


class AuthorizationTransactionStore:
    """The operations on transactions, each one atomic with respect to the
    others, reads included."""

    def __init__(self) -> None:
        self._lock = _store_lock

    @property
    def _repository(self) -> MemoryRuntimeRepository[AuthorizationTransaction]:
        # Looked up on every use rather than kept: the runtime store is the
        # owner, and whatever replaces it (a reset, #354's durable backend)
        # is what the transactions must be read from.
        return get_runtime_identity_store().repository(
            "authorization_transactions", lambda transaction: transaction.id
        )

    def create(
        self,
        *,
        browser_binding: str,
        params: AuthorizationParameters,
        requested: Dict[str, List[str]],
        client: OAuthClient,
        client_origin: ClientOrigin,
    ) -> AuthorizationTransaction:
        """Store a new pending transaction; raises TransactionStoreFull."""
        now = time.time()
        transaction = AuthorizationTransaction(
            id=secrets.token_urlsafe(32),
            browser_binding=browser_binding,
            created_at=now,
            expires_at=now + TRANSACTION_LIFETIME_SECONDS,
            params=params,
            requested=requested,
            client_snapshot=ClientSnapshot.of(client),
            client_origin=client_origin,
        )
        with self._lock:
            self._prune_expired(now)
            if len(self._repository.list()) >= MAX_PENDING_TRANSACTIONS:
                raise TransactionStoreFull(
                    f"{MAX_PENDING_TRANSACTIONS} authorization requests already pending"
                )
            return self._repository.create(transaction)

    def get_bound(
        self, transaction_id: str, browser_binding: Optional[str]
    ) -> Optional[AuthorizationTransaction]:
        """The live transaction with this id, if this browser created it."""
        with self._lock:
            transaction = self._repository.get(transaction_id)
        if transaction is None or not transaction.is_bound_to(browser_binding):
            return None
        return transaction if transaction.is_live() else None

    def find_unique_for_binding(self, browser_binding: Optional[str]) -> Lookup:
        """The one live transaction of this browser, for a request that does
        not name one. Several candidates are ambiguous: the caller refuses
        rather than guesses."""
        if browser_binding is None:
            return Lookup(LookupOutcome.NONE)
        now = time.time()
        with self._lock:
            transactions = self._repository.list()
        candidates = [
            transaction
            for transaction in transactions
            if transaction.is_bound_to(browser_binding) and transaction.is_live(now)
        ]
        if not candidates:
            return Lookup(LookupOutcome.NONE)
        if len(candidates) > 1:
            return Lookup(LookupOutcome.AMBIGUOUS)
        return Lookup(LookupOutcome.UNIQUE, candidates[0])

    def mark_primary_verified(
        self,
        transaction_id: str,
        browser_binding: Optional[str],
        *,
        username: str,
        amr: Optional[Sequence[str]],
    ) -> Optional[AuthorizationTransaction]:
        """Record a verified password on a pending transaction. ``None`` when
        the transaction is gone, not this browser's, or no longer pending."""
        with self._lock:
            current = self.get_bound(transaction_id, browser_binding)
            if current is None or current.state is not TransactionState.PENDING:
                return None
            return self._replace(
                current,
                state=TransactionState.PRIMARY_VERIFIED,
                primary_username=username,
                primary_amr=list(amr) if amr else None,
                primary_verified_at=time.time(),
            )

    def reset_login(
        self, transaction_id: str, browser_binding: Optional[str]
    ) -> Optional[AuthorizationTransaction]:
        """Back to the username step: forget any verified password."""
        with self._lock:
            current = self.get_bound(transaction_id, browser_binding)
            if current is None:
                return None
            if current.state is TransactionState.PENDING:
                return current
            return self._replace(
                current,
                state=TransactionState.PENDING,
                primary_username=None,
                primary_amr=None,
                primary_verified_at=None,
            )

    def consume(
        self,
        transaction_id: str,
        browser_binding: Optional[str],
        *,
        verified_username: Optional[str] = None,
    ) -> Optional[AuthorizationTransaction]:
        """Remove the transaction and return it, exactly once. ``None`` when
        it is gone, expired, not this browser's, or already consumed.

        ``verified_username`` is for a completion that rests on a password
        verified earlier: the transaction must still record it for that
        user, checked under the lock, since a concurrent "Change username"
        may have reset it after the caller read it.
        """
        with self._lock:
            current = self.get_bound(transaction_id, browser_binding)
            if current is None:
                return None
            if verified_username is not None and (
                current.state is not TransactionState.PRIMARY_VERIFIED
                or current.primary_username != verified_username
            ):
                return None
            if not self._repository.delete(transaction_id):
                return None
            return current

    def prune_expired(self) -> int:
        with self._lock:
            return self._prune_expired(time.time())

    def delete_all(self) -> int:
        with self._lock:
            return self._repository.delete_all()

    def _prune_expired(self, now: float) -> int:
        dropped = 0
        for transaction in self._repository.list():
            if not transaction.is_live(now) and self._repository.delete(transaction.id):
                dropped += 1
        return dropped

    def _replace(self, current: AuthorizationTransaction, **changes: object) -> AuthorizationTransaction:
        # Caller holds the lock. model_copy(update=) does not validate, so
        # the changed record is rebuilt through the model.
        updated = AuthorizationTransaction.model_validate({**current.model_dump(), **changes})
        self._repository.delete(current.id)
        return self._repository.create(updated)


def get_authorization_transaction_store() -> AuthorizationTransactionStore:
    """The authorization transactions of this process."""
    return AuthorizationTransactionStore()
