"""The runtime repository: the contract every piece of runtime state is kept
behind, and its in-memory backend (#235, #404).

A repository holds objects of one type by name and by value. The type is
whatever its **codec** can copy, write down and read back: whoever owns a
record type says so when asking for the repository, so that no backend has
to guess what it is keeping, and pydantic is one such type among others.
What the repository adds to
create, get, list and delete is what a caller cannot build from those: an
operation that is several visits to the repository and must look like one to
every other caller, in this process or, with a durable backend (#354), in
another. A lock of the caller's own gives that to threads and to nobody
else, so the guarantee belongs here.

- An **entry** is the object with what the store knows about it: an
  ``instance_id`` no other entry ever had, so that the object somebody
  deleted and the one created under its name afterwards can be told apart,
  and optionally a **hold**, the claim of an operation in progress (#405).
  Neither is a field of the object: identity is execution state.
- ``transact(decide)`` runs one decision against a view of the repository.
  Everything the decision did becomes visible at once, or, if it raises, not
  at all. A decision has no effect outside its view; it may read the clock,
  because expiry is judged at the moment the decision is made, not when its
  caller started waiting. The OAuth semantics stay in the services, which write the
  decision; SQL, when there is some, stays in the backend, which runs it.
- ``replace``, ``consume``, ``delete_if``, ``delete_where``,
  ``delete_expired`` and ``create_within`` are the
  decisions most callers need, written once on top of ``transact`` so that
  every backend gets them by implementing it.

One repository per transaction, and no transaction that outlives the call:
this is not a unit of work. What touches two repositories is built from
instance identity, a conditional operation and a compensation or a
postcondition (see ``routes.registration``).

How expired objects leave a large or unbounded collection (#363): an entry
may say when it becomes removable, ``delete_expired`` takes what is past its
time and ``count`` says how many are left, all from what the store knows
about its entries and without reading a value. ``entries()`` on the view
remains a scan, right for a decision that has to look at the values of a
collection with a small cap (a cache's eviction policy) and wrong as the way
through ten thousand device codes or an unbounded set of revocations.
"""

import dataclasses
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass
from heapq import heapify, heappop, heappush
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Protocol,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from pydantic import BaseModel

# Any type at all. The first records kept here were pydantic models, and the
# protocol state that comes next is not (#363: authorization codes, device
# codes and audit entries are dataclasses, revocations are keys and
# expiries), so the repository asks nothing of a value but what its codec
# can do with it.
T = TypeVar("T")
R = TypeVar("R")
M = TypeVar("M", bound=BaseModel)


class RuntimeObjectExists(ValueError):
    """A runtime object with that name is already in the repository."""


class RuntimeObjectMissing(LookupError):
    """The decision named an object that is not in the repository."""


class EntryHeld(ValueError):
    """The entry already carries a hold."""


class RepositoryFull(Exception):
    """``create_within`` found the repository at its limit."""


class TransactionClosed(RuntimeError):
    """A view was used after its decision was over. Whatever it was told
    then would bypass both the atomicity and the lock."""


class NestedRepositoryUse(RuntimeError):
    """A decision reached a repository other than through its view.

    On a backend with real transactions that is a nested one, and a decision
    may be run again (a busy retry), so whatever it does outside the view is
    done twice or not undone.
    """


class Codec(Protocol[T]):
    """What a repository needs to know about the type it keeps: how a value
    is copied, how it is written down and how it is read back.

    Declared with the repository, by whoever owns the type. The in-memory
    backend only copies; a backend that serializes (#354) writes down and
    reads back, and must not have to guess the type of what it finds. So the
    way is stated here, once, and ``verify_codecs`` lets the tests hold every
    codec to it on every value that goes through a repository, long before
    there is such a backend.
    """

    def copy(self, value: T) -> T:
        """An independent copy: changing one never changes the other."""

    def dump(self, value: T) -> Any:
        """``value`` as JSON: what ``json.dumps`` accepts and returns
        unchanged from ``json.loads``."""

    def load(self, data: Any) -> T:
        """The value ``dump`` was given: ``load(dump(value)) == value``."""


class PydanticCodec(Generic[M]):
    """The codec of a pydantic model."""

    def __init__(self, model: Type[M]) -> None:
        self._model = model

    def copy(self, value: M) -> M:
        return value.model_copy(deep=True)

    def dump(self, value: M) -> Any:
        return value.model_dump(mode="json")

    def load(self, data: Any) -> M:
        return self._model.model_validate(data)


@dataclass(frozen=True)
class Hold:
    """The claim of an operation in progress on one entry (#405).

    ``hold_id`` is the store's, so that a continuation or a recovery changes
    or releases the hold it installed and not one installed later by someone
    else. ``payload`` is opaque here: what a hold means, and what it forbids,
    are rules of whoever installed it. It is a JSON object and nothing a
    backend that serializes could not keep, whichever backend is in use.
    ``since`` is wall-clock time, because the reader of a hold may be another
    process (#354), to which a monotonic clock means nothing.
    """

    hold_id: str
    since: float
    payload: Dict[str, Any]


@dataclass(frozen=True)
class Entry(Generic[T]):
    """An object with what the store knows about it.

    ``name`` is the key it is stored under. ``instance_id`` is generated by
    the store, opaque and random, and never reused: a replace keeps it, a
    create after a delete gets a new one.

    ``expires_at`` is when the entry becomes removable by a cleanup, as
    wall-clock seconds, or None for never (#363). It means that and nothing
    else: an entry past its time is still returned until somebody removes
    it, and whether it is still good is its owner's to say. An owner may
    have to answer "expired" for something that is past its time and still
    there (RFC 8628's ``expired_token``), which a store that hid it would
    turn into "unknown". It lives here and not in the value because a
    cleanup must be able to find what is removable without reading, or
    copying, a single value.
    """

    name: str
    value: T
    instance_id: str
    hold: Optional[Hold] = None
    expires_at: Optional[float] = None


class RepositoryTransaction(Protocol[T]):
    """What a decision sees and may do: this one repository, atomically.

    By value like the repository itself. A decision is domain logic over
    what the view shows and over inputs captured before the call, and
    nothing else: no I/O, no other repository, no service, no hook, no
    audit. It may be run more than once.

    The clock is the exception, and belongs inside: whether a record is
    still live is a question about the moment the decision is made, and a
    caller may have waited for the store since it read the time. Reading it
    has no effect, and a run that comes later only judges later.
    """

    def name_of(self, obj: T) -> str:
        """The name this repository keeps ``obj`` under."""

    def entry(self, name: str) -> Optional[Entry[T]]:
        """The entry with that name, or None."""

    def entries(self) -> List[Entry[T]]:
        """Every entry, in creation order. A scan: for collections with a
        small cap, not for the way through a large one."""

    def count(self) -> int:
        """How many entries there are, removable ones included. Reads no
        value."""

    def create(self, obj: T, expires_at: Optional[float] = None) -> Entry[T]:
        """Store ``obj`` under a new identity; raises RuntimeObjectExists."""

    def replace(self, name: str, obj: T) -> Entry[T]:
        """Change the value of the entry with that name, which keeps its
        identity, its hold, its expiry and its place. Raises
        RuntimeObjectMissing, and ValueError when ``obj`` goes by another
        name."""

    def set_expires_at(self, name: str, expires_at: Optional[float]) -> Entry[T]:
        """Change when the entry becomes removable, and nothing else about
        it. Raises RuntimeObjectMissing."""

    def delete_expired(self, now: float) -> int:
        """Remove every entry strictly past its time (``expires_at < now``)
        that nobody holds, and say how many.

        Strictly: owners draw the line differently (live while ``now <
        expires_at`` for one, expired only when ``now > expires_at`` for
        another), and an entry removed while its owner still calls it good
        would turn a valid code into an unknown one, so the store errs on
        the side of keeping. Not a held one: a hold is the claim of an
        operation in progress, and like ``delete_if`` a cleanup does not
        take an entry from under it.

        Reads no value. What it costs is no part of this contract, and
        worth knowing all the same: it sits inside the writing decision of
        every service that keeps expiring state, so a backend that scans
        makes every write cost what is kept. The one in memory keeps a heap
        of the expiries (#417); one with rows has an index on the time."""

    def delete(self, name: str) -> bool:
        """Remove the entry with that name; False when there was none."""

    def hold(self, name: str, payload: Dict[str, Any]) -> Hold:
        """Install a hold; raises RuntimeObjectMissing or EntryHeld."""

    def update_hold(self, name: str, hold_id: str, payload: Dict[str, Any]) -> bool:
        """Replace the payload of that hold; False when the entry does not
        carry it."""

    def release_hold(self, name: str, hold_id: str) -> bool:
        """Remove that hold; False when the entry does not carry it."""


class RuntimeRepository(Protocol[T]):
    """The operations a runtime repository offers; a later durable backend
    (#354) implements the same contract (tests/test_runtime_identities.py,
    tests/test_runtime_repository_contract.py).

    By value: every object handed in or out is a copy, so changing one never
    changes the repository.
    """

    def create(self, obj: T, expires_at: Optional[float] = None) -> T:
        """Store ``obj``; raises RuntimeObjectExists when its name is taken."""

    def create_entry(self, obj: T, expires_at: Optional[float] = None) -> Entry[T]:
        """``create``, returning the entry actually stored: how a caller
        learns the new identity without a second read."""

    def get(self, name: str) -> Optional[T]:
        """The object with that name, or None."""

    def entry(self, name: str) -> Optional[Entry[T]]:
        """The entry with that name, or None."""

    def list(self) -> List[T]:
        """Every object, in creation order."""

    def entries(self) -> List[Entry[T]]:
        """Every entry, in creation order."""

    def delete(self, name: str) -> bool:
        """Remove the object with that name; False when there was none."""

    def delete_all(self) -> int:
        """Remove every object and return how many there were."""

    def transact(self, decide: Callable[[RepositoryTransaction[T]], R]) -> R:
        """Run ``decide`` against a view of this repository and return what
        it returns. Its changes become visible together; if it raises,
        nothing has changed and the exception propagates."""


# ---- decisions most callers need ---------------------------------------------


class _Keep:
    """The default of ``replace(expires_at=...)``: leave the time alone.
    Not None, which is a time: never."""


_KEEP = _Keep()


def replace(
    repository: RuntimeRepository[T],
    name: str,
    change: Callable[[T], T],
    expires_at: Union[Optional[float], _Keep] = _KEEP,
) -> Optional[Entry[T]]:
    """Apply ``change`` to the current value, as one step: no reader finds
    the object absent in between, and concurrent changes each start from
    what the one before left. None when there is no such object.

    ``expires_at`` moves the entry's time in the same step. An owner that
    keeps a time in its value as well has two of them, and a replace keeps
    the store's: when the change extends the value's, the store's has to
    follow, or a cleanup takes an entry its owner has just extended."""

    def decide(view: RepositoryTransaction[T]) -> Optional[Entry[T]]:
        current = view.entry(name)
        if current is None:
            return None
        replaced = view.replace(name, change(current.value))
        return replaced if isinstance(expires_at, _Keep) else view.set_expires_at(name, expires_at)

    return repository.transact(decide)


def consume(
    repository: RuntimeRepository[T],
    name: str,
    accept: Optional[Callable[[Entry[T]], bool]] = None,
) -> Optional[Entry[T]]:
    """Remove the entry and return it, exactly once. None when it is not
    there, or when ``accept`` says this is not the one to take."""

    def decide(view: RepositoryTransaction[T]) -> Optional[Entry[T]]:
        current = view.entry(name)
        if current is None or (accept is not None and not accept(current)):
            return None
        view.delete(name)
        return current

    return repository.transact(decide)


def delete_if(
    repository: RuntimeRepository[T],
    name: str,
    instance_id: str,
    hold_id: Optional[str] = None,
) -> bool:
    """Remove that instance and no other that goes by the name.

    ``hold_id`` is the hold the instance is expected to carry: left out, it
    is expected to carry none. So an instance somebody holds is never
    removed by a caller who did not know, and one whose hold was released
    in the meantime is not removed on the strength of a hold it no longer
    has.
    """

    def decide(view: RepositoryTransaction[T]) -> bool:
        current = view.entry(name)
        if current is None or current.instance_id != instance_id:
            return False
        if (current.hold.hold_id if current.hold is not None else None) != hold_id:
            return False
        return view.delete(name)

    return repository.transact(decide)


def delete_where(repository: RuntimeRepository[T], condemned: Callable[[T], bool]) -> int:
    """Remove every object ``condemned`` names, as one step, and say how
    many. A scan of the values, so for a decision that has to look at them
    in a collection with a small cap. What is merely past its time leaves
    through ``delete_expired``, which reads no value."""

    def decide(view: RepositoryTransaction[T]) -> int:
        dropped = 0
        for current in view.entries():
            if condemned(current.value) and view.delete(current.name):
                dropped += 1
        return dropped

    return repository.transact(decide)


def transact_refusing(
    repository: RuntimeRepository[T],
    decide: Callable[[RepositoryTransaction[T]], Union[R, Exception]],
) -> R:
    """``transact`` for a decision that can refuse and still mean what it
    did: it returns the exception instead of raising it, and the exception
    is raised here, once its changes are in. Raising inside would take them
    back, which is right for a failure and wrong for a refusal that comes
    after some tidying (expired objects dropped, then no room)."""
    outcome = repository.transact(decide)
    if isinstance(outcome, Exception):
        raise outcome
    return outcome


def delete_expired(repository: RuntimeRepository[T], now: Optional[float] = None) -> int:
    """Remove every entry whose time is up, as one step, and say how many."""
    return repository.transact(
        lambda view: view.delete_expired(time.time() if now is None else now)
    )


def create_within(
    repository: RuntimeRepository[T],
    obj: T,
    limit: int,
    expires_at: Optional[float] = None,
    full: Optional[Exception] = None,
    now: Optional[float] = None,
) -> Entry[T]:
    """Store ``obj`` unless the repository already holds ``limit`` entries,
    after removing the ones whose time is up. Raises RuntimeObjectExists for
    a name still taken after that, whether or not there was room, and
    otherwise ``full``, the caller's own word for it, or RepositoryFull.

    Nothing here reads a value: the cleanup and the count work on what the
    store knows about its entries, so the cap may be large (#363: ten
    thousand device codes cost a fraction of a millisecond, where scanning
    their values cost tens). What expired is dropped whatever the answer
    (see ``transact_refusing``). ``now`` is the moment to clean up to, for
    an owner that judges liveness by a clock of its own and wants the store
    to agree with it; left out, the clock is read inside the decision.
    """

    def decide(view: RepositoryTransaction[T]) -> Union[Entry[T], Exception]:
        view.delete_expired(time.time() if now is None else now)
        name = view.name_of(obj)
        if view.entry(name) is not None:
            return RuntimeObjectExists(f"runtime object {name!r} already exists")
        if view.count() >= limit:
            if full is not None:
                return full
            return RepositoryFull(f"the repository already holds {limit} objects")
        return view.create(obj, expires_at)

    return transact_refusing(repository, decide)


# ---- the in-memory backend -----------------------------------------------------


# Which thread is inside a decision, whatever the repository: a decision must
# not reach any of them except through its view.
_deciding = threading.local()


def refuse_inside_a_decision() -> None:
    """Raise NestedRepositoryUse on a thread that is inside a decision. For
    whatever hands out or creates repositories, as well as for them."""
    if getattr(_deciding, "active", False):
        raise NestedRepositoryUse(
            "a decision works on the view it was given and on nothing else"
        )


def _payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """A copy of a hold's payload, which is also the check that it is one:
    through JSON and back, and the same on return. So a datetime, a model,
    a tuple or a key that is not a string is refused here as it would be by
    a backend that has to write it down."""
    try:
        copied = json.loads(json.dumps(payload, allow_nan=False))
    except (TypeError, ValueError) as unserializable:
        raise ValueError(f"a hold's payload must be a JSON object: {unserializable}") from unserializable
    if not isinstance(payload, dict) or copied != payload:
        raise ValueError("a hold's payload must be a JSON object")
    return dict(copied)


def checked_time(moment: Any, or_none: bool = False) -> Optional[float]:
    """A time a backend can keep and compare: a real, finite number. Not a
    bool, which is a number only by accident; not an infinity, which
    "never" is spelled None for, and None is accepted only where
    ``or_none`` says so. Part of the contract, so that every backend
    refuses the same things: ValueError."""
    if moment is None and or_none:
        return None
    if isinstance(moment, bool) or not isinstance(moment, (int, float)):
        raise ValueError(f"a time must be a finite number, not {moment!r}")
    try:
        finite = math.isfinite(moment)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError(f"a time must be a finite number, not {moment!r}")
    return float(moment)


def _out(entry: Entry[T], codec: Codec[T]) -> Entry[T]:
    """The copy of an entry that leaves the repository."""
    hold = entry.hold
    return dataclasses.replace(
        entry,
        value=codec.copy(entry.value),
        hold=Hold(hold.hold_id, hold.since, _payload(hold.payload)) if hold is not None else None,
    )


# An expiry the in-memory backend knows of: when, of which instance, under
# which name. See ``MemoryRuntimeRepository._due``.
_Due = Tuple[float, str, str]

# How far the heap of expiries may outgrow the entries before it is rebuilt:
# twice their number, plus this, so that a small collection never rebuilds.
_DUE_SLACK = 1024


class _MemoryTransaction(Generic[T]):
    """The view a decision gets. It works on a copy of the repository's index
    made at the first change; the repository adopts that copy when the
    decision returns and drops it when the decision raises. The entries
    themselves are never changed in place, so the copy is a shallow one.

    The heap of expiries is transactional state in the same way, by other
    means (#417). What the decision adds is staged here (``pushed``) and
    reaches the heap when the decision returns. What a cleanup takes off the
    heap it takes off the repository's own, under the lock, and writes down
    (``popped``), so that the repository can put it back when the decision
    raises or is one that is thrown away."""

    def __init__(
        self,
        objects: Dict[str, Entry[T]],
        name_of: Callable[[T], str],
        codec: Codec[T],
        stored: Callable[[T], T],
        due: List[_Due],
    ) -> None:
        self._committed = objects
        self._staged: Optional[Dict[str, Entry[T]]] = None
        self._due = due
        self.pushed: List[_Due] = []
        self.popped: List[_Due] = []
        self._name_of = name_of
        self._codec = codec
        self._stored = stored
        self._closed = False

    def close(self) -> None:
        self._closed = True

    def _open(self) -> None:
        if self._closed:
            raise TransactionClosed("this view belonged to a decision that is over")

    def name_of(self, obj: T) -> str:
        self._open()
        return self._name_of(obj)

    @property
    def _current(self) -> Dict[str, Entry[T]]:
        return self._staged if self._staged is not None else self._committed

    @property
    def _writable(self) -> Dict[str, Entry[T]]:
        if self._staged is None:
            self._staged = dict(self._committed)
        return self._staged

    def result(self) -> Dict[str, Entry[T]]:
        return self._current

    def entry(self, name: str) -> Optional[Entry[T]]:
        self._open()
        stored = self._current.get(name)
        return _out(stored, self._codec) if stored is not None else None

    def entries(self) -> List[Entry[T]]:
        self._open()
        return [_out(stored, self._codec) for stored in self._current.values()]

    def count(self) -> int:
        self._open()
        return len(self._current)

    def create(self, obj: T, expires_at: Optional[float] = None) -> Entry[T]:
        self._open()
        name = self._name_of(obj)
        if name in self._current:
            raise RuntimeObjectExists(f"runtime object {name!r} already exists")
        # By value, both ways: neither the caller's instance nor the one
        # returned is the stored one, as with a backend that serializes.
        stored = Entry(name, self._stored(obj), uuid.uuid4().hex, None, checked_time(expires_at, or_none=True))
        self._writable[name] = stored
        self._will_expire(stored)
        return _out(stored, self._codec)

    def set_expires_at(self, name: str, expires_at: Optional[float]) -> Entry[T]:
        self._open()
        stored = dataclasses.replace(self._require(name), expires_at=checked_time(expires_at, or_none=True))
        self._writable[name] = stored
        # The item of the time it had stays where it is and no longer says
        # anything true; it is recognised as such when it reaches the top.
        self._will_expire(stored)
        return _out(stored, self._codec)

    def _will_expire(self, stored: Entry[T]) -> None:
        if stored.expires_at is not None:
            self.pushed.append((stored.expires_at, stored.instance_id, stored.name))

    def delete_expired(self, now: float) -> int:
        """In proportion to what is due, not to what is kept (#417): this
        sits inside the writing decision of every service that keeps
        expiring state, under the store's one lock. No value is read, let
        alone copied, and an entry that is not due is not looked at. (What
        is due and held is, each time, for as long as it is held.)"""
        self._open()
        moment = checked_time(now)
        assert moment is not None
        candidates: List[_Due] = []
        # Due is strictly past its time (#413), so the loop stops at the
        # first item that is not. Written down before it is taken off: an
        # interrupt between the two then leaves an item twice, which is a
        # stale one more, and not an entry with no item, which no cleanup
        # would ever find again.
        while self._due and self._due[0][0] < moment:
            self.popped.append(self._due[0])
            candidates.append(heappop(self._due))
        # And what this very decision added, which is not on the heap yet.
        if self.pushed:
            staged, self.pushed = self.pushed, []
            for item in staged:
                (candidates if item[0] < moment else self.pushed).append(item)
        removed = 0
        held: List[_Due] = []
        for item in candidates:
            if self._settle(item, held):
                removed += 1
        # A held item goes back on the heap, and like everything this
        # decision puts there it is staged: on the heap at once it would be
        # there twice if the decision raised and its pops were put back (and
        # taken off while the loop above was still running, it would be on
        # top again and the loop would never get past it).
        self.pushed.extend(held)
        return removed

    def _settle(self, item: _Due, held: List[_Due]) -> bool:
        """What becomes of one item that is due: whether its entry was
        removed. Nothing is ever looked for in the middle of the heap: an
        item that no longer says anything true is recognised here, when its
        turn comes, and one whose entry is held is handed to ``held``."""
        when, instance_id, name = item
        stored = self._current.get(name)
        if stored is None or stored.instance_id != instance_id:
            return False  # stale: gone, or the name was given to a successor
        if stored.expires_at != when:
            return False  # stale: its time was moved, and that move pushed an item of its own
        if stored.hold is not None:
            held.append(item)  # past its time and not removable: it waits on the heap
            return False
        del self._writable[name]
        return True

    def replace(self, name: str, obj: T) -> Entry[T]:
        self._open()
        if self._name_of(obj) != name:
            raise ValueError(f"a replace cannot rename {name!r} to {self._name_of(obj)!r}")
        current = self._require(name)
        stored = dataclasses.replace(current, value=self._stored(obj))
        self._writable[name] = stored  # same key: the place in the order is kept
        return _out(stored, self._codec)

    def delete(self, name: str) -> bool:
        self._open()
        if name not in self._current:
            return False
        del self._writable[name]
        return True

    def hold(self, name: str, payload: Dict[str, Any]) -> Hold:
        self._open()
        current = self._require(name)
        if current.hold is not None:
            raise EntryHeld(f"runtime object {name!r} is already held")
        installed = Hold(uuid.uuid4().hex, time.time(), _payload(payload))
        self._writable[name] = dataclasses.replace(current, hold=installed)
        return Hold(installed.hold_id, installed.since, _payload(installed.payload))

    def update_hold(self, name: str, hold_id: str, payload: Dict[str, Any]) -> bool:
        self._open()
        checked = _payload(payload)
        current = self._carrying(name, hold_id)
        if current is None or current.hold is None:
            return False
        updated = Hold(current.hold.hold_id, current.hold.since, checked)
        self._writable[name] = dataclasses.replace(current, hold=updated)
        return True

    def release_hold(self, name: str, hold_id: str) -> bool:
        self._open()
        current = self._carrying(name, hold_id)
        if current is None:
            return False
        self._writable[name] = dataclasses.replace(current, hold=None)
        return True

    def _require(self, name: str) -> Entry[T]:
        current = self._current.get(name)
        if current is None:
            raise RuntimeObjectMissing(f"no runtime object {name!r}")
        return current

    def _carrying(self, name: str, hold_id: str) -> Optional[Entry[T]]:
        current = self._current.get(name)
        if current is None or current.hold is None or current.hold.hold_id != hold_id:
            return None
        return current


class MemoryRuntimeRepository(Generic[T]):
    """A runtime repository in process memory, keyed by the object's name."""

    # For tests. This backend has no reason of its own to run a decision
    # again, so a decision that is not safe to repeat would pass every test
    # here and fail on a backend that retries. Set, each decision is first
    # run against a view that is thrown away.
    run_decisions_twice = False
    # For tests, in the same spirit. This backend copies and never writes a
    # value down, so a codec whose dump loses something, or is not JSON,
    # would go unnoticed until a backend that serializes. Set, every value
    # stored is first taken through dump, JSON and load, and must come back
    # equal.
    verify_codecs = False

    def __init__(
        self, lock: threading.RLock, name_of: Callable[[T], str], codec: Codec[T]
    ) -> None:
        self._lock = lock
        self._name_of: Callable[[T], str] = name_of
        self._codec: Codec[T] = codec
        self._objects: Dict[str, Entry[T]] = {}
        # A min-heap of the expiries there are, so that a cleanup costs what
        # is due and not what is kept (#417). Lazy: an item is pushed when
        # an entry gets a time and never looked for again, so some items say
        # nothing true any more (the entry is gone, was recreated, or had
        # its time moved) and are dropped when they reach the top. Part of
        # no contract: a backend with rows has an index on the time.
        #
        # An item carries the entry's name, so the name of an entry that was
        # deleted or consumed stays in this process's memory until the
        # item's time comes or the heap is rebuilt, where before it went
        # with the entry. For a code that is its own name that is the code,
        # already spent; nothing reads the heap but the cleanup.
        self._due: List[_Due] = []

    def _stored(self, obj: T) -> T:
        """The copy of ``obj`` the repository keeps."""
        if self.verify_codecs:
            try:
                written = json.dumps(self._codec.dump(obj), allow_nan=False)
                read_back = self._codec.load(json.loads(written))
            except Exception as failure:
                raise ValueError(f"{type(obj).__name__} does not survive its codec: {failure}") from failure
            if read_back != obj:
                raise ValueError(f"{type(obj).__name__} does not survive its codec: it comes back changed")
        return self._codec.copy(obj)

    def create(self, obj: T, expires_at: Optional[float] = None) -> T:
        return self.create_entry(obj, expires_at).value

    def create_entry(self, obj: T, expires_at: Optional[float] = None) -> Entry[T]:
        return self.transact(lambda view: view.create(obj, expires_at))

    def get(self, name: str) -> Optional[T]:
        stored = self.entry(name)
        return stored.value if stored is not None else None

    def entry(self, name: str) -> Optional[Entry[T]]:
        refuse_inside_a_decision()
        with self._lock:
            stored = self._objects.get(name)
            return _out(stored, self._codec) if stored is not None else None

    def list(self) -> List[T]:
        return [stored.value for stored in self.entries()]

    def entries(self) -> List[Entry[T]]:
        refuse_inside_a_decision()
        with self._lock:
            return [_out(stored, self._codec) for stored in self._objects.values()]

    def delete(self, name: str) -> bool:
        return self.transact(lambda view: view.delete(name))

    def delete_all(self) -> int:
        refuse_inside_a_decision()
        with self._lock:
            count = len(self._objects)
            self._objects = {}
            self._due = []
            return count

    def transact(self, decide: Callable[[RepositoryTransaction[T]], R]) -> R:
        refuse_inside_a_decision()
        with self._lock:
            if self.run_decisions_twice:
                _, thrown_away = self._decide(decide)
                self._put_back(thrown_away)
            result, view = self._decide(decide)
            # Reached only when the decision returned. The items first: an
            # interrupt between the two then leaves items for entries that
            # are not there, which are stale ones, and not entries with no
            # item. The index is adopted in one assignment, so a reader sees
            # all of it or none.
            for item in view.pushed:
                heappush(self._due, item)
            self._objects = view.result()
            self._compact_when_mostly_stale()
            return result

    def _put_back(self, view: "_MemoryTransaction[T]") -> None:
        """A decision that did not happen took nothing off the heap."""
        for item in view.popped:
            heappush(self._due, item)

    def _compact_when_mostly_stale(self) -> None:
        """Keep the heap within sight of the entries. Items that say nothing
        true go when they reach the top, which for a time far away is far
        away: a time moved again and again, or entries deleted long before
        they are due, would otherwise trade the scan for memory. Rare, one
        pass, and the result is the heap as if it had just been built."""
        if len(self._due) <= 2 * len(self._objects) + _DUE_SLACK:
            return
        self._due = [
            (stored.expires_at, stored.instance_id, name)
            for name, stored in self._objects.items()
            if stored.expires_at is not None
        ]
        heapify(self._due)

    def _decide(
        self, decide: Callable[[RepositoryTransaction[T]], R]
    ) -> "tuple[R, _MemoryTransaction[T]]":
        """Run the decision against a fresh view. Caller holds the lock."""
        view: _MemoryTransaction[T] = _MemoryTransaction(
            self._objects, self._name_of, self._codec, self._stored, self._due
        )
        _deciding.active = True
        try:
            return decide(view), view
        except BaseException:
            self._put_back(view)
            raise
        finally:
            _deciding.active = False
            # Whether it returned or raised, the view is done: kept by the
            # decision and used later, it would change what the repository
            # adopted from it, outside the lock.
            view.close()
