"""
Device Authorization Grant state (RFC 8628).

Extracted from ``routes/oauth.py`` module globals (#84): the grant state was a
``dict[str, Any]`` holding heterogeneous values (state dicts plus
``"user:<code>" -> device_code`` back-references encoded in key strings). It is
now a typed store with the user-code index as a separate mapping.

Concurrency semantics are unchanged from #43: the polling client races against
the user's verification and against its own retries, so ``poll`` cannot
double-issue an authorized code and ``verify`` cannot double-claim a pending
one. Credential verification itself runs in the caller, before ``verify`` is
called (#348 review, cleanup): ``verify`` only takes the already-resolved
user and does the atomic check-status + transition, so a concurrent poll can
never observe a half-transitioned entry.

The state lives in the runtime store (#363), in two repositories it lends:
the grants, by device code, and an index from the user's code to the grant.
There is no lock around the two and no transaction across them (#404). What
keeps them right with each other is the grant's instance identity: an index
entry names the instance it was made for, so one whose grant is gone, or
whose device code has since been given to another grant, opens nothing
(the pattern of #411). Every transition is one decision on the grant.
"""

import dataclasses
import logging
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Optional, Sequence, Tuple, Union

from .runtime_identities import MemoryRuntimeRepository, get_runtime_identity_store
from .runtime_repository import (
    Entry,
    RepositoryTransaction,
    RuntimeObjectExists,
    consume,
    create_within,
    delete_if,
)

if TYPE_CHECKING:
    # From the model's real home (#285): config only re-exports it for
    # compatibility, and importing through the facade teaches a dependency
    # that does not need to exist.
    from ..models import User

logger = logging.getLogger(__name__)

# Uppercase letters and digits that are easy to read and type; excludes the
# confusable 0, O, I, 1, L.
_USER_CODE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

DEVICE_CODE_EXPIRES_IN = 600  # seconds (RFC 8628 leaves this to the AS)
DEVICE_POLL_INTERVAL = 5  # seconds

# A hard cap on concurrently pending device authorizations, so the in-memory
# store cannot grow without bound. It matters now that a public client can
# create entries with its client_id alone (#255): an unauthenticated device
# authorization request is cheaper to spam than a credentialed one. The cap is
# generous for real dev/test use (each entry lives at most
# DEVICE_CODE_EXPIRES_IN and is pruned on the next create); reaching it refuses
# NEW authorizations rather than evicting live ones, so an in-flight legitimate
# code is never dropped.
MAX_PENDING_DEVICE_CODES = 10_000


class DeviceCodeStoreFull(Exception):
    """Raised by create() when MAX_PENDING_DEVICE_CODES pending entries exist."""


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
    # OIDC amr (RFC 8176 §2, #348): how the interactive login at /device
    # authenticated - set by verify() on a successful authorization, from
    # the caller's own TOTP-phase check (this store has no TOTP logic of
    # its own, same "no mode of its own" contract as username/password).
    amr: Optional[Sequence[str]] = None
    # RFC 8707 resource indicators requested at /device_authorization (#187).
    resource: Optional[list] = None
    # The key the grant is kept under. Last, with a default, so that the
    # fields above keep their positions.
    device_code: str = ""

    def __post_init__(self) -> None:
        # The shape of a grant, for one made anywhere (#404): the methods
        # are a tuple and the resources a list, so that what a backend
        # writes down reads back equal. A bare string is not a list of
        # methods and is left for the token choke point to drop.
        if isinstance(self.amr, list):
            self.amr = tuple(self.amr)
        if isinstance(self.resource, tuple):
            self.resource = list(self.resource)

    def is_past_its_time(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class UserCodeIndex:
    """What the user types, and the grant it is for: the device code, and
    the instance of the grant, since a device code alone would also name
    whatever grant came to hold it later."""

    user_code: str
    device_code: str
    grant_instance_id: str


class _GrantCodec:
    def copy(self, value: DeviceCodeGrant) -> DeviceCodeGrant:
        return dataclasses.replace(
            value, resource=list(value.resource) if value.resource is not None else None
        )

    def dump(self, value: DeviceCodeGrant) -> Any:
        written = dataclasses.asdict(value)
        written["amr"] = list(value.amr) if isinstance(value.amr, tuple) else value.amr
        return written

    def load(self, data: Any) -> DeviceCodeGrant:
        return DeviceCodeGrant(**data)


class _IndexCodec:
    def copy(self, value: UserCodeIndex) -> UserCodeIndex:
        return dataclasses.replace(value)

    def dump(self, value: UserCodeIndex) -> Any:
        return dataclasses.asdict(value)

    def load(self, data: Any) -> UserCodeIndex:
        return UserCodeIndex(**data)


def _device_code_of(grant: DeviceCodeGrant) -> str:
    return grant.device_code


def _user_code_of(index: UserCodeIndex) -> str:
    return index.user_code


# Given to the store once: a repository keeps what it was created with.
_GRANTS = _GrantCodec()
_INDEX = _IndexCodec()
# How many pairs create() will try before giving up. One is enough unless a
# user code collides, which eight characters of thirty-one make rare.
_PAIR_ATTEMPTS = 5


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
    """Device authorization state with atomic transitions (#43), kept in the
    runtime store (#363). A view, with no state of its own."""

    @property
    def _grants(self) -> MemoryRuntimeRepository[DeviceCodeGrant]:
        return get_runtime_identity_store().repository("device_grants", _device_code_of, _GRANTS)

    @property
    def _index(self) -> MemoryRuntimeRepository[UserCodeIndex]:
        return get_runtime_identity_store().repository("device_user_codes", _user_code_of, _INDEX)

    def create(
        self,
        client_id: str,
        scope: str,
        expires_in: int = DEVICE_CODE_EXPIRES_IN,
        interval: int = DEVICE_POLL_INTERVAL,
        resource: Optional[list] = None,
    ) -> Tuple[str, str]:
        """Create a device authorization; returns (device_code, user_code).

        A grant and the index entry for it, in two repositories, as a small
        saga: the grant, under the cap, in one decision that also drops what
        is past its time (so stale entries do not pile up on long-running
        servers, without a value being read); the index entry, naming the
        grant's instance; then a look back at the grant. A user code that
        is taken is refused by the index, the grant is withdrawn and another
        pair is tried; it used to take the older mapping over in silence. A
        grant that is gone by the look back takes its index entry with it,
        and no half-made pair is handed out.
        """
        for _ in range(_PAIR_ATTEMPTS):
            device_code = secrets.token_urlsafe(32)
            user_code = "".join(secrets.choice(_USER_CODE_CHARS) for _ in range(8))
            expires_at = time.time() + expires_in
            grant = create_within(
                self._grants,
                DeviceCodeGrant(
                    device_code=device_code,
                    user_code=user_code,
                    client_id=client_id,
                    scope=scope,
                    expires_at=expires_at,
                    interval=interval,
                    resource=resource,
                ),
                MAX_PENDING_DEVICE_CODES,
                expires_at=expires_at,
                full=DeviceCodeStoreFull(
                    f"{MAX_PENDING_DEVICE_CODES} device authorizations already pending"
                ),
            )
            indexed = self._index_for(grant, expires_at)
            if indexed is None:
                delete_if(self._grants, device_code, grant.instance_id)
                continue
            if self._is_still(grant):
                return device_code, user_code
            delete_if(self._index, user_code, indexed.instance_id)
        raise RuntimeError("could not create a device authorization")

    def _index_for(
        self, grant: Entry[DeviceCodeGrant], expires_at: float
    ) -> Optional[Entry[UserCodeIndex]]:
        """The index entry for that grant, or None when its user code is
        taken. One decision, which drops the entries past their time first:
        they go with their grants, each by its own time."""
        entry = UserCodeIndex(grant.value.user_code, grant.name, grant.instance_id)

        def decide(view: RepositoryTransaction[UserCodeIndex]) -> Optional[Entry[UserCodeIndex]]:
            view.delete_expired(time.time())
            try:
                return view.create(entry, expires_at=expires_at)
            except RuntimeObjectExists:
                return None

        return self._index.transact(decide)

    def _is_still(self, grant: Entry[DeviceCodeGrant]) -> bool:
        current = self._grants.entry(grant.name)
        return current is not None and current.instance_id == grant.instance_id

    def _grant_for(self, user_code: str) -> Optional[Entry[DeviceCodeGrant]]:
        """The grant a user code is for, if it is still that grant."""
        indexed = self._index.get(user_code)
        if indexed is None:
            return None
        grant = self._grants.entry(indexed.device_code)
        if grant is None or grant.instance_id != indexed.grant_instance_id:
            return None
        return grant

    def poll(
        self,
        device_code: str,
        client_id: Optional[str],
        get_user: Callable[[str], Optional["User"]],
    ) -> Tuple[DevicePollOutcome, Optional["User"], Optional[DeviceCodeGrant]]:
        """Token-endpoint poll: atomic lookup-check-claim (one-time use, #43).

        On AUTHORIZED the entry is consumed (deleted) and the grant snapshot is
        returned for scope/auth_time. Two decisions and a lookup between
        them, because a decision reaches no other repository (#404) and
        looking a user up does: classify the grant; for an authorized one,
        resolve the user, outside; then consume that instance, if it is
        still authorized for that user and still in time. A concurrent poll
        cannot also claim it, since the consume takes it once; and if the
        grant changed in between, it is classified again instead of its
        successor being consumed. A user who cannot be found costs nothing:
        the grant stays as it was.
        """
        for _ in range(_PAIR_ATTEMPTS):
            classified = self._grants.transact(
                lambda view: self._classify(view, device_code, client_id)
            )
            if isinstance(classified, DevicePollOutcome):
                return classified, None, None
            username = classified.value.username
            user = get_user(username) if username else None
            if not user:
                return DevicePollOutcome.USER_NOT_FOUND, None, None
            claimed = self._claim(classified)
            if claimed is not None:
                return DevicePollOutcome.AUTHORIZED, user, claimed
        return DevicePollOutcome.NOT_FOUND, None, None

    def _claim(self, seen: Entry[DeviceCodeGrant]) -> Optional[DeviceCodeGrant]:
        """Take the grant that was seen authorized, once: that instance,
        still authorized for that user and still in time. None if it is no
        longer all of that, and the caller looks again. Its index entry goes
        with it.

        With the transitions there are today the instance and the time say
        it all: an authorized instance never changes its user, and leaves
        that status only by running out. The status and the user are asked
        anyway, so that a transition added later (a grant withdrawn, say)
        cannot make this claim something it was not authorized for."""

        def still_that_one(current: Entry[DeviceCodeGrant]) -> bool:
            return (
                current.instance_id == seen.instance_id
                and current.value.status == "authorized"
                and current.value.username == seen.value.username
                and not current.value.is_past_its_time()
            )

        claimed = consume(self._grants, seen.name, still_that_one)
        if claimed is None:
            return None
        consume(
            self._index,
            claimed.value.user_code,
            lambda indexed: indexed.value.grant_instance_id == seen.instance_id,
        )
        return claimed.value

    @staticmethod
    def _classify(
        view: RepositoryTransaction[DeviceCodeGrant], device_code: str, client_id: Optional[str]
    ) -> Union[DevicePollOutcome, Entry[DeviceCodeGrant]]:
        """What a poll is answered, for everything but an authorized grant,
        which is handed back for its user to be resolved."""
        entry = view.entry(device_code)
        if entry is None:
            return DevicePollOutcome.NOT_FOUND
        grant = entry.value
        if grant.client_id != client_id:
            return DevicePollOutcome.WRONG_CLIENT
        if grant.is_past_its_time():
            view.replace(device_code, dataclasses.replace(grant, status="expired"))
            return DevicePollOutcome.EXPIRED
        if grant.status == "pending":
            return DevicePollOutcome.PENDING
        if grant.status == "denied":
            return DevicePollOutcome.DENIED
        if grant.status == "expired":
            return DevicePollOutcome.EXPIRED
        if grant.status == "authorized":
            return entry
        return DevicePollOutcome.UNKNOWN_STATUS

    @staticmethod
    def _status_of(grant: Optional[DeviceCodeGrant]) -> Optional[DeviceVerifyOutcome]:
        """Classify a user code's grant: ``None`` when it is pending and
        live, else the outcome ``pending_status``/``verify`` reports for it -
        the one rule both read, so the oracle guard and the transition
        cannot drift onto two spellings of the same classification (#348
        review, cleanup).
        """
        if not grant:
            return DeviceVerifyOutcome.INVALID_CODE
        if grant.status != "pending":
            return DeviceVerifyOutcome.ALREADY_USED
        if grant.is_past_its_time():
            return DeviceVerifyOutcome.EXPIRED
        return None

    def pending_status(self, user_code: str) -> Optional[DeviceVerifyOutcome]:
        """Non-mutating look at a user code: ``None`` when it is pending and
        live, else the outcome verify() would report for it (#348 review).

        Lets /device decide whether a submission is even worth a credential
        check before it runs one: without this, the TOTP pre-check ran the
        password before the code was looked at, so a correct password
        answered with the code screen and a wrong one with "invalid code" -
        a password oracle needing no live device code. Nothing transitions
        here - an expired entry is reported, not marked - so a concurrent
        poll observes the same state it did before.
        """
        grant = self._grant_for(user_code)
        return self._status_of(grant.value if grant is not None else None)

    def verify(
        self,
        user_code: str,
        action: str,
        user: Optional["User"],
        *,
        amr: Optional[Sequence[str]] = None,
    ) -> Tuple[DeviceVerifyOutcome, Optional["User"]]:
        """User verification at /device: atomic check-status + transition (#43).

        The credential check itself runs in the caller, before this call
        (routes/_auth's TOTP-aware ``authenticate_interactively``) - this
        store receives the already-resolved ``user`` (``None`` on a
        failed, incomplete, or "deny" attempt) and only does the atomic
        check-status + transition, so two concurrent verifications still
        cannot both claim the same pending code. ``amr`` (#348) is likewise
        decided entirely by the caller - this store has no TOTP logic of
        its own, it only records what it is given on a successful
        authorization.

        The user code is looked up first, and the decision is on the grant
        it names, by instance: a grant that came to hold the device code
        since is not the one this user code is for.
        """
        found = self._grant_for(user_code)
        if found is None:
            return DeviceVerifyOutcome.INVALID_CODE, None
        username = user.username if user else None

        def decide(view: RepositoryTransaction[DeviceCodeGrant]) -> DeviceVerifyOutcome:
            entry = view.entry(found.name)
            if entry is None or entry.instance_id != found.instance_id:
                return DeviceVerifyOutcome.INVALID_CODE
            grant = entry.value
            status = self._status_of(grant)
            if status is DeviceVerifyOutcome.EXPIRED:
                view.replace(found.name, dataclasses.replace(grant, status="expired"))
            if status is not None:
                return status
            if action == "deny":
                view.replace(found.name, dataclasses.replace(grant, status="denied"))
                return DeviceVerifyOutcome.DENIED
            if username is None:
                return DeviceVerifyOutcome.INVALID_CREDENTIALS
            view.replace(
                found.name,
                dataclasses.replace(
                    grant, status="authorized", username=username, auth_time=int(time.time()), amr=amr
                ),
            )
            return DeviceVerifyOutcome.AUTHORIZED

        outcome = self._grants.transact(decide)
        return outcome, user if outcome is DeviceVerifyOutcome.AUTHORIZED else None


def get_device_code_store() -> DeviceCodeStore:
    """The device authorizations of this process: a view over the runtime
    store, which is where the state and its one lock are (#363)."""
    return DeviceCodeStore()
