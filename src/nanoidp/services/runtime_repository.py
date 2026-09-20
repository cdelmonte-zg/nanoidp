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
- ``replace``, ``consume``, ``delete_if``, ``delete_where`` and
  ``create_within`` are the
  decisions most callers need, written once on top of ``transact`` so that
  every backend gets them by implementing it.

One repository per transaction, and no transaction that outlives the call:
this is not a unit of work. What touches two repositories is built from
instance identity, a conditional operation and a compensation or a
postcondition (see ``routes.registration``).

How expired objects leave a large or unbounded collection is not settled
here. ``entries()`` on the view is a scan, right for a collection with a
small cap and wrong for revocations in a durable store; #363 and #354 decide
that path, and until then no backend is promised that ``transact`` and the
plain create, get, list and delete are all it will ever be asked for.
"""

import json
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Generic, List, Optional, Protocol, Type, TypeVar, Union

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
    """

    name: str
    value: T
    instance_id: str
    hold: Optional[Hold] = None


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

    def create(self, obj: T) -> Entry[T]:
        """Store ``obj`` under a new identity; raises RuntimeObjectExists."""

    def replace(self, name: str, obj: T) -> Entry[T]:
        """Change the value of the entry with that name, which keeps its
        identity, its hold and its place. Raises RuntimeObjectMissing, and
        ValueError when ``obj`` goes by another name."""

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

    def create(self, obj: T) -> T:
        """Store ``obj``; raises RuntimeObjectExists when its name is taken."""

    def create_entry(self, obj: T) -> Entry[T]:
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


def replace(
    repository: RuntimeRepository[T], name: str, change: Callable[[T], T]
) -> Optional[Entry[T]]:
    """Apply ``change`` to the current value, as one step: no reader finds
    the object absent in between, and concurrent changes each start from
    what the one before left. None when there is no such object."""

    def decide(view: RepositoryTransaction[T]) -> Optional[Entry[T]]:
        current = view.entry(name)
        return view.replace(name, change(current.value)) if current is not None else None

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
    many. A scan, so for collections with a small cap: how expired objects
    leave a large one is not settled here (see the module docstring)."""

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


def create_within(
    repository: RuntimeRepository[T],
    obj: T,
    limit: int,
    is_expired: Optional[Callable[[T], bool]] = None,
    full: Optional[Exception] = None,
) -> Entry[T]:
    """Store ``obj`` unless the repository already holds ``limit`` objects,
    after dropping the ones ``is_expired`` names. Raises RuntimeObjectExists
    for a name still taken after that, whether or not there was room, and
    otherwise ``full``, the caller's own word for it, or RepositoryFull.

    Counts by scanning, so for collections with a small cap. What expired is
    dropped whatever the answer (see ``transact_refusing``).
    """

    def decide(view: RepositoryTransaction[T]) -> Union[Entry[T], Exception]:
        live = 0
        for current in view.entries():
            if is_expired is not None and is_expired(current.value):
                view.delete(current.name)
            else:
                live += 1
        name = view.name_of(obj)
        if view.entry(name) is not None:
            return RuntimeObjectExists(f"runtime object {name!r} already exists")
        if live >= limit:
            if full is not None:
                return full
            return RepositoryFull(f"the repository already holds {limit} objects")
        return view.create(obj)

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


def _out(entry: Entry[T], codec: Codec[T]) -> Entry[T]:
    """The copy of an entry that leaves the repository."""
    hold = entry.hold
    return Entry(
        name=entry.name,
        value=codec.copy(entry.value),
        instance_id=entry.instance_id,
        hold=Hold(hold.hold_id, hold.since, _payload(hold.payload)) if hold is not None else None,
    )


class _MemoryTransaction(Generic[T]):
    """The view a decision gets. It works on a copy of the repository's index
    made at the first change; the repository adopts that copy when the
    decision returns and drops it when the decision raises. The entries
    themselves are never changed in place, so the copy is a shallow one."""

    def __init__(
        self,
        objects: Dict[str, Entry[T]],
        name_of: Callable[[T], str],
        codec: Codec[T],
        stored: Callable[[T], T],
    ) -> None:
        self._committed = objects
        self._staged: Optional[Dict[str, Entry[T]]] = None
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

    def create(self, obj: T) -> Entry[T]:
        self._open()
        name = self._name_of(obj)
        if name in self._current:
            raise RuntimeObjectExists(f"runtime object {name!r} already exists")
        # By value, both ways: neither the caller's instance nor the one
        # returned is the stored one, as with a backend that serializes.
        stored = Entry(name, self._stored(obj), uuid.uuid4().hex)
        self._writable[name] = stored
        return _out(stored, self._codec)

    def replace(self, name: str, obj: T) -> Entry[T]:
        self._open()
        if self._name_of(obj) != name:
            raise ValueError(f"a replace cannot rename {name!r} to {self._name_of(obj)!r}")
        current = self._require(name)
        stored = Entry(name, self._stored(obj), current.instance_id, current.hold)
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
        self._writable[name] = Entry(name, current.value, current.instance_id, installed)
        return Hold(installed.hold_id, installed.since, _payload(installed.payload))

    def update_hold(self, name: str, hold_id: str, payload: Dict[str, Any]) -> bool:
        self._open()
        checked = _payload(payload)
        current = self._carrying(name, hold_id)
        if current is None or current.hold is None:
            return False
        updated = Hold(current.hold.hold_id, current.hold.since, checked)
        self._writable[name] = Entry(name, current.value, current.instance_id, updated)
        return True

    def release_hold(self, name: str, hold_id: str) -> bool:
        self._open()
        current = self._carrying(name, hold_id)
        if current is None:
            return False
        self._writable[name] = Entry(name, current.value, current.instance_id, None)
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

    def create(self, obj: T) -> T:
        return self.create_entry(obj).value

    def create_entry(self, obj: T) -> Entry[T]:
        return self.transact(lambda view: view.create(obj))

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
            return count

    def transact(self, decide: Callable[[RepositoryTransaction[T]], R]) -> R:
        refuse_inside_a_decision()
        with self._lock:
            if self.run_decisions_twice:
                self._decide(decide)
            result, view = self._decide(decide)
            # Reached only when the decision returned: adopted in one
            # assignment, so a reader sees all of it or none.
            self._objects = view.result()
            return result

    def _decide(
        self, decide: Callable[[RepositoryTransaction[T]], R]
    ) -> "tuple[R, _MemoryTransaction[T]]":
        """Run the decision against a fresh view. Caller holds the lock."""
        view: _MemoryTransaction[T] = _MemoryTransaction(
            self._objects, self._name_of, self._codec, self._stored
        )
        _deciding.active = True
        try:
            return decide(view), view
        finally:
            _deciding.active = False
            # Whether it returned or raised, the view is done: kept by the
            # decision and used later, it would change what the repository
            # adopted from it, outside the lock.
            view.close()
