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

The records live in the runtime store (#235). The transitions are this
module's, and each one is one decision of the repository's (#404): read the
record, check it is this browser's, live and in the right state, and change
or remove it, as a single step for whoever shares the store. The route calls
them and never composes repository visits of its own.
"""

import hmac
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Literal, Optional, Sequence

from pydantic import BaseModel

from ..models import OAuthClient
from .auth_code import CODE_LIFETIME_SECONDS
from .identities import ClientOrigin
from .runtime_repository import (
    Entry,
    RepositoryTransaction,
    create_within,
)
from .runtime_repository import consume as consume_entry
from .runtime_store import (
    PydanticCodec,
    RuntimeRepository,
    get_runtime_store,
)

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

    def is_live_for(self, browser_binding: Optional[str]) -> bool:
        """This browser's, and live now: the one rule for which transaction
        a read or a transition may touch. "Now" is when it is asked, so a
        transition asks from inside its decision, after any wait."""
        return self.is_bound_to(browser_binding) and self.is_live()


class LookupOutcome(Enum):
    NONE = "none"
    UNIQUE = "unique"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class Lookup:
    outcome: LookupOutcome
    transaction: Optional[AuthorizationTransaction] = None


class AuthorizationTransactionStore:
    """The operations on transactions, each one atomic with respect to the
    others. A read is a single look at the repository: a transition changes
    a record in place, so there is no moment at which a live transaction is
    absent for a read to find."""

    @property
    def _repository(self) -> RuntimeRepository[AuthorizationTransaction]:
        # Looked up on every use rather than kept: the runtime store is the
        # owner, and whatever replaces it (a reset, #354's durable backend)
        # is what the transactions must be read from.
        return get_runtime_store().repository(
            "authorization_transactions", lambda transaction: transaction.id, PydanticCodec(AuthorizationTransaction)
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
        return create_within(
            self._repository,
            transaction,
            MAX_PENDING_TRANSACTIONS,
            # The store is told when the record becomes removable; whether
            # it is still live stays this module's to say (is_live).
            expires_at=transaction.expires_at,
            full=TransactionStoreFull(
                f"{MAX_PENDING_TRANSACTIONS} authorization requests already pending"
            ),
        ).value

    def get_bound(
        self, transaction_id: str, browser_binding: Optional[str]
    ) -> Optional[AuthorizationTransaction]:
        """The live transaction with this id, if this browser created it."""
        transaction = self._repository.get(transaction_id)
        if transaction is None or not transaction.is_live_for(browser_binding):
            return None
        return transaction

    def find_unique_for_binding(self, browser_binding: Optional[str]) -> Lookup:
        """The one live transaction of this browser, for a request that does
        not name one. Several candidates are ambiguous: the caller refuses
        rather than guesses."""
        if browser_binding is None:
            return Lookup(LookupOutcome.NONE)
        now = time.time()
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
        def decide(
            view: RepositoryTransaction[AuthorizationTransaction],
        ) -> Optional[AuthorizationTransaction]:
            current = _bound(view, transaction_id, browser_binding)
            if current is None or current.state is not TransactionState.PENDING:
                return None
            changed = _changed(
                current,
                state=TransactionState.PRIMARY_VERIFIED,
                primary_username=username,
                primary_amr=list(amr) if amr else None,
                primary_verified_at=time.time(),
            )
            return view.replace(transaction_id, changed).value

        return self._repository.transact(decide)

    def reset_login(
        self, transaction_id: str, browser_binding: Optional[str]
    ) -> Optional[AuthorizationTransaction]:
        """Back to the username step: forget any verified password."""
        def decide(
            view: RepositoryTransaction[AuthorizationTransaction],
        ) -> Optional[AuthorizationTransaction]:
            current = _bound(view, transaction_id, browser_binding)
            if current is None or current.state is TransactionState.PENDING:
                return current
            changed = _changed(
                current,
                state=TransactionState.PENDING,
                primary_username=None,
                primary_amr=None,
                primary_verified_at=None,
            )
            return view.replace(transaction_id, changed).value

        return self._repository.transact(decide)

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
        user, checked inside the decision, since a concurrent "Change username"
        may have reset it after the caller read it.
        """
        def this_one(entry: Entry[AuthorizationTransaction]) -> bool:
            current = entry.value
            if not current.is_live_for(browser_binding):
                return False
            return verified_username is None or (
                current.state is TransactionState.PRIMARY_VERIFIED
                and current.primary_username == verified_username
            )

        taken = consume_entry(self._repository, transaction_id, this_one)
        return taken.value if taken is not None else None

    def delete_all(self) -> int:
        return self._repository.delete_all()


def _bound(
    view: RepositoryTransaction[AuthorizationTransaction],
    transaction_id: str,
    browser_binding: Optional[str],
) -> Optional[AuthorizationTransaction]:
    """What ``get_bound`` answers, from inside a decision."""
    entry = view.entry(transaction_id)
    return entry.value if entry is not None and entry.value.is_live_for(browser_binding) else None


def _changed(current: AuthorizationTransaction, **changes: object) -> AuthorizationTransaction:
    # model_copy(update=) does not validate, so the changed record is
    # rebuilt through the model.
    return AuthorizationTransaction.model_validate({**current.model_dump(), **changes})


def get_authorization_transaction_store() -> AuthorizationTransactionStore:
    """The authorization transactions of this process."""
    return AuthorizationTransactionStore()
