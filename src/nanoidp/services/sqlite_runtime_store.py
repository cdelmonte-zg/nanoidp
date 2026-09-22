"""The runtime store in a pair of SQLite files, for several NanoIDP
processes on one host (#354, second and third steps): the repositories in
one, the audit in the other (``runtime.db`` and ``runtime-audit.db``). A file
has one writer, and the audit must not wait for the repositories, so the two
are two concurrency domains and nothing is transactional across them.

Not selectable from ``settings.yaml`` yet: the schema names it only once a
store shared by several processes keeps every invariant it has to (#354,
fourth step). Until then it is a backend, and the contract tests run over it.

One table for every repository:

    entries(seq, repository, name, value, instance_id, hold, expires_at)

``seq`` is the row's place in the order of creation, which is what ``list()``
and ``entries()`` promise: a replace keeps it, a delete and a create give a new
one. ``(repository, name)`` is unique. ``value`` is the codec's JSON, ``hold``
a JSON object. A partial index on ``(repository, expires_at)`` for what has a
time and is not held makes a cleanup cost what is due.

A decision is a transaction: ``BEGIN IMMEDIATE``, the decision against a view
whose operations are statements in it, ``COMMIT``, and a rollback when the
decision raises. ``BEGIN IMMEDIATE`` takes the file's write lock at once, so
two decisions in two processes come one after the other and neither has to be
retried. Reads outside a decision are plain selects.

WAL, ``synchronous=NORMAL``: atomicity, consistency and isolation are kept; a
commit may be lost to a power loss, which a disposable file never promised,
at a fraction of the cost of FULL. ``busy_timeout`` is how long a process
waits for another's transaction; past it, ``RuntimeStoreUnavailable``.

One connection per thread. No connection crosses a fork: SQLite asks that
none be open when a process forks, since the child inherits the parent's
bookkeeping of the file's locks, and a connection opened afresh in the child
does not undo that (a parent that then closes its own believes it is the
file's last user, and deletes the WAL under the child). So an at-fork hook
waits until no operation of any store is in progress, blocks new ones, and
closes every connection of the process; parent and child each open their own
afterwards. This holds for a fork made through Python (``os.fork()``, and the
pre-fork servers built on it, such as gunicorn ``--preload``); a fork made
from C without Python's at-fork calls skips the hook. A fork must not be made
from inside a decision, or from inside any operation of a store, its audit
included: the hook would wait for the thread that is forking.

The file is the process's secret and NanoIDP's own: created ``0600`` (and so
are ``-wal`` and ``-shm``, which SQLite makes with the database's mode, and
which are brought to ``0600`` all the same), an existing one brought to
``0600``, and a file that is not a NanoIDP runtime store refused, never adopted.
"""

import json
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
import weakref
from contextlib import contextmanager
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
    cast,
)

from ..config import OAuthClient, User
from .audit_store import (
    AuditEntry,
    AuditEntryCodec,
    AuditStore,
    checked_bound,
    checked_increments,
    checked_limit,
    outside_the_domain,
)
from .runtime_repository import (
    Codec,
    Entry,
    EntryHeld,
    Hold,
    PydanticCodec,
    R,
    RepositorySwitches,
    RepositoryTransaction,
    RuntimeObjectExists,
    RuntimeObjectMissing,
    RuntimeRepository,
    RuntimeStoreUnavailable,
    T,
    TransactionClosed,
    _deciding,
    _payload,
    checked_time,
    refuse_inside_a_decision,
    verified,
)

__all__ = [
    "RuntimeStoreFileRefused",
    "RuntimeStoreUnsupported",
    "SqliteAuditStore",
    "SqliteRuntimeRepository",
    "SqliteRuntimeStore",
    "audit_path_of",
]

# The schema a file must carry to be adopted, and the one written to a new
# one. A file of another version is refused: it is disposable, and nothing
# migrates it.
SCHEMA_VERSION = 1
_MARKER = "nanoidp-runtime-store"

# How long a process waits for another's transaction, in milliseconds.
_BUSY_TIMEOUT_MS = 5000

# The primary result codes of contention (sqlite3.h), spelled out: the module
# constants are not there before Python 3.11.
_SQLITE_BUSY = 5
_SQLITE_LOCKED = 6

# The repositories the store keeps under these names itself.
_OWN = ("users", "clients")

_SCHEMA = (
    """CREATE TABLE entries (
        seq         INTEGER PRIMARY KEY,
        repository  TEXT NOT NULL,
        name        TEXT NOT NULL,
        value       TEXT NOT NULL,
        instance_id TEXT NOT NULL,
        hold        TEXT,
        expires_at  REAL,
        UNIQUE (repository, name)
    )""",
    "CREATE INDEX entries_order ON entries (repository, seq)",
    """CREATE INDEX entries_due ON entries (repository, expires_at)
        WHERE expires_at IS NOT NULL AND hold IS NULL""",
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
)


class _Kind:
    """What a file of the pair is: the marker it carries in ``meta``, its
    schema, and what it is called in a refusal."""

    def __init__(self, marker: str, schema: Tuple[str, ...], noun: str) -> None:
        self.marker = marker
        self.schema = schema
        self.noun = noun


_STORE = _Kind(_MARKER, _SCHEMA, "runtime store")
_AUDIT = _Kind(
    "nanoidp-runtime-audit",
    (
        # value is the codec's JSON and the one authority; the three columns
        # are projections for the filters, and nothing reads them back.
        """CREATE TABLE events (
            seq        INTEGER PRIMARY KEY,
            event_type TEXT NOT NULL,
            username   TEXT,
            client_id  TEXT,
            value      TEXT NOT NULL
        )""",
        "CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL)",
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    ),
    "runtime audit",
)

# The upsert of a counter.
_OLDEST_SQLITE = (3, 24, 0)


class RuntimeStoreUnsupported(RuntimeError):
    """The SQLite this Python has is older than the store needs. A property
    of the environment, not of a file: nothing is made or changed."""


def _require_upsert() -> None:
    if sqlite3.sqlite_version_info < _OLDEST_SQLITE:
        raise RuntimeStoreUnsupported(
            f"the SQLite runtime store requires SQLite >= 3.24; running {sqlite3.sqlite_version}"
        )


def owners_path_of(path: Path) -> Path:
    """The directory of the owner leases, named after the store's file:
    ``runtime.db`` has them in ``runtime-owners`` (#354, step 4b)."""
    return path.with_name(f"{path.stem}-owners")


# An owner id: 128 random bits, as hex. Anything else found in a claim names
# no lease this store can look at, and proves nothing.
_OWNER_ID = re.compile(r"[0-9a-f]{32}")


def _try_lock(fd: int) -> bool:
    """An exclusive lock on the whole file, without waiting: whether it was
    had. The lock of the open file, so a descriptor inherited by a fork and
    closed there does not release it."""
    if os.name == "posix":
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True
    import msvcrt  # pragma: no cover - Windows

    try:  # pragma: no cover - Windows
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
    except OSError:  # pragma: no cover - Windows
        return False
    return True  # pragma: no cover - Windows


def _names(path: Path, fd: int) -> bool:
    """Whether ``path`` still names the file open as ``fd``."""
    try:
        named = os.stat(path)
    except FileNotFoundError:
        return False
    held = os.fstat(fd)
    return (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino)


class _OwnerLeases:
    """This process as an owner of the claims it makes in one store (#354,
    step 4b): a lease file in the store's owners directory, held under an
    exclusive lock for as long as the process lives, made the first time a
    claim needs it. A peer that can take the lock has proved the owner dead;
    a peer that finds the file gone too, since only a proof of death removes
    it. No timeout is a proof."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._lock = threading.Lock()
        self._owner: Optional[str] = None
        self._fd: Optional[int] = None

    def owner(self) -> str:
        with self._lock:
            if self._owner is None:
                self._directory.mkdir(mode=0o700, exist_ok=True)
                _Database._make_private_directory(self._directory)
                self._remove_the_dead()
                self._fd, self._owner = self._new_lease()
            return self._owner

    def _new_lease(self) -> Tuple[int, str]:
        """A lease made and held, and still the one its name names. Between
        its creation and its lock, a peer's sweep can take it for a dead
        one and remove it; the lock then held would be on a file nobody can
        find, and this process would look dead for as long as it lives. So
        the name is looked at again once the lock is held, and a lease that
        is not there any more is made anew, under another id (nobody knows
        this one yet: it is in no claim)."""
        for _ in range(8):
            owner = uuid.uuid4().hex
            path = self._directory / f"{owner}.lock"
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            if _try_lock(fd) and _names(path, fd):
                return fd, owner
            os.close(fd)
        raise RuntimeError(f"no owner lease could be made in {self._directory}")

    def may_be_dead(self, owner: Optional[str]) -> bool:
        """Whether ``owner`` could be proved dead now: its lease gone or its
        lock free. No lock is kept and nothing removed; for a caller that
        would otherwise go through the files for a claim nobody can recover
        (#354, step 4b, review). The proof that decides is prove_dead's."""
        if owner is None or not isinstance(owner, str) or not _OWNER_ID.fullmatch(owner):
            return False
        with self._lock:
            if owner == self._owner:
                return False
        try:
            fd = os.open(self._directory / f"{owner}.lock", os.O_RDWR)
        except FileNotFoundError:
            return True
        try:
            return _try_lock(fd)
        finally:
            os.close(fd)

    def _remove_the_dead(self) -> None:
        """The leases of owners that are gone, and that no claim may still
        name: removed once each is proved dead. A claim that names one later
        finds it missing, which is death too."""
        for lease in self._directory.glob("*.lock"):
            if not _OWNER_ID.fullmatch(lease.stem):
                continue
            try:
                fd = os.open(lease, os.O_RDWR)
            except FileNotFoundError:
                continue
            try:
                if _try_lock(fd):
                    lease.unlink(missing_ok=True)
            finally:
                os.close(fd)

    @contextmanager
    def prove_dead(self, owner: Optional[str]) -> Iterator[bool]:
        """Whether ``owner`` is proved dead: its lease is gone, or its lock
        can be taken, and is then held until the caller is done, and the
        lease removed after. False for no owner, for this process, for an id
        that names no lease, and for a lease whose lock is held."""
        if owner is None or not isinstance(owner, str) or not _OWNER_ID.fullmatch(owner):
            yield False
            return
        with self._lock:
            mine = owner == self._owner
        if mine:
            yield False
            return
        lease = self._directory / f"{owner}.lock"
        try:
            fd = os.open(lease, os.O_RDWR)
        except FileNotFoundError:
            yield True
            return
        try:
            if not _try_lock(fd):
                yield False
                return
            yield True
            lease.unlink(missing_ok=True)
        finally:
            os.close(fd)

    def _forget_inherited(self) -> None:
        # In a forked child: not this process's lease.
        fd, self._fd, self._owner = self._fd, None, None
        self._lock = threading.Lock()
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


_LEASES: "weakref.WeakSet[_OwnerLeases]" = weakref.WeakSet()


def audit_path_of(path: Path) -> Path:
    """The audit's file, named after the store's: ``runtime.db`` has its
    audit in ``runtime-audit.db``. The two are the store."""
    return path.with_name(f"{path.stem}-audit{path.suffix}")


class RuntimeStoreFileRefused(ValueError):
    """The file is not one this store can use: not a NanoIDP runtime store,
    of another schema version, or not a file at all. Nothing in it is
    changed. It is disposable: delete it, or choose another."""


def _is_busy(failure: sqlite3.Error) -> bool:
    """SQLITE_BUSY or SQLITE_LOCKED, and nothing else: contention, not a
    fault. By code where Python gives it (3.11), by message before."""
    code = getattr(failure, "sqlite_errorcode", None)
    if code is not None:
        return (code & 0xFF) in (_SQLITE_BUSY, _SQLITE_LOCKED)
    return str(failure).startswith(("database is locked", "database table is locked"))


def _unavailable(failure: sqlite3.Error) -> BaseException:
    if isinstance(failure, sqlite3.OperationalError) and _is_busy(failure):
        return RuntimeStoreUnavailable(
            f"the runtime store is held by another process for longer than {_BUSY_TIMEOUT_MS} ms: {failure}"
        )
    return failure


class _ForkGate:
    """What makes a fork wait until no store's connection is in use, and
    closes them all before it. One for the process: every connection of
    every store has to be closed, not those of one file.

    An operation of a store (opening one included) is an activity: it waits
    while a fork is pending, and is counted until it ends. The hook, before
    the fork, blocks new activities, waits until none is left, and closes
    every connection; after it, the parent opens the gate again, and the
    child starts with a gate of its own. The hook does nothing that can fail
    but a close: CPython ignores what an at-fork hook raises and forks all
    the same."""

    def __init__(self) -> None:
        self._reset()

    def _reset(self) -> None:
        self._condition = threading.Condition(threading.Lock())
        self._active = 0
        self._forking = False

    @contextmanager
    def activity(self) -> Iterator[None]:
        with self._condition:
            while self._forking:
                self._condition.wait()
            self._active += 1
        try:
            yield
        finally:
            with self._condition:
                self._active -= 1
                if self._active == 0:
                    self._condition.notify_all()

    def before_fork(self) -> None:
        with self._condition:
            self._forking = True
            while self._active:
                self._condition.wait()
        for database in list(_DATABASES):
            database._close_all()

    def after_in_parent(self) -> None:
        with self._condition:
            self._forking = False
            self._condition.notify_all()

    def after_in_child(self) -> None:
        # The other threads are gone, and with them whatever they held.
        self._reset()
        # The parent's owner leases are the parent's: the child closes its
        # copy of each descriptor (the parent's lease holds, since the lock is
        # the open file's, not this descriptor's) and becomes an owner of its
        # own when it first needs to (#354, step 4b). No filesystem work here.
        for leases in list(_LEASES):
            leases._forget_inherited()


_FORK_GATE = _ForkGate()
_DATABASES: "weakref.WeakSet[_Database]" = weakref.WeakSet()
if hasattr(os, "register_at_fork"):
    os.register_at_fork(
        before=_FORK_GATE.before_fork,
        after_in_parent=_FORK_GATE.after_in_parent,
        after_in_child=_FORK_GATE.after_in_child,
    )


class _Database:
    """The file, its schema, and the connections to it."""

    def __init__(self, path: Union[str, Path], kind: _Kind, settled: Optional[Dict[str, str]] = None) -> None:
        self.path = Path(path).expanduser().resolve()
        self._kind = kind
        # What the file is made with and every opener must share: written in
        # meta by the one that makes it, and a file made otherwise refused.
        self._settled = dict(settled or {})
        if self.path.is_dir():
            raise RuntimeStoreFileRefused(f"{self.path} is a directory, not a {kind.noun} file")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        # Every connection open, by the thread it belongs to, for the fork
        # hook to close; and the count of those closings, by which a thread
        # knows its own was closed.
        self._connections: Dict[threading.Thread, sqlite3.Connection] = {}
        self._connections_lock = threading.Lock()
        self._generation = 0
        with _FORK_GATE.activity():
            created = self._create_private()
            self._initialise(created)
            _DATABASES.add(self)

    def _create_private(self) -> bool:
        """Create the file 0600 if it is not there. Whether it was made now."""
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False
        os.close(fd)
        return True

    @staticmethod
    def _make_private_directory(path: Path) -> None:
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) != 0o700:
            os.chmod(path, 0o700)

    @staticmethod
    def _make_private(path: Path) -> None:
        if os.name != "posix":
            return
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except FileNotFoundError:
            return
        if mode != 0o600:
            os.chmod(path, 0o600)

    def _initialise(self, created: bool) -> None:
        """Adopt the file or give it the schema, under the file's write lock:
        two processes opening a new file at once must not both create it. A
        file that was not made here and carries no NanoIDP schema is refused
        and left as it was."""
        try:
            connection = self._open()
        except sqlite3.DatabaseError as failure:
            raise self._refused(failure) from failure
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.DatabaseError as failure:
                raise self._refused(failure) from failure
            try:
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
                if not tables:
                    if not created and self.path.stat().st_size > 0:
                        raise RuntimeStoreFileRefused(
                            f"{self.path} is a SQLite database that is not a NanoIDP {self._kind.noun}; "
                            f"the {self._kind.noun} is disposable: choose another file"
                        )
                    for statement in self._kind.schema:
                        connection.execute(statement)
                    connection.executemany(
                        "INSERT INTO meta (key, value) VALUES (?, ?)",
                        [("kind", self._kind.marker), ("schema_version", str(SCHEMA_VERSION)), *self._settled.items()],
                    )
                else:
                    self._check(connection, tables)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            # Persistent in the file, and set outside a transaction.
            connection.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError as failure:
            raise self._refused(failure) from failure
        finally:
            connection.close()
        # Only now that it is known to be ours: a file that is refused is
        # left as it was, its mode included.
        for part in ("", "-wal", "-shm"):
            self._make_private(Path(f"{self.path}{part}"))

    def _check(self, connection: sqlite3.Connection, tables: set) -> None:
        if "meta" not in tables:
            raise RuntimeStoreFileRefused(
                f"{self.path} is a SQLite database that is not a NanoIDP {self._kind.noun}; "
                f"the {self._kind.noun} is disposable: choose another file"
            )
        meta = dict(connection.execute("SELECT key, value FROM meta").fetchall())
        if meta.get("kind") != self._kind.marker:
            raise RuntimeStoreFileRefused(
                f"{self.path} is a SQLite database that is not a NanoIDP {self._kind.noun}; "
                f"the {self._kind.noun} is disposable: choose another file"
            )
        if meta.get("schema_version") != str(SCHEMA_VERSION):
            raise RuntimeStoreFileRefused(
                f"{self.path} is a NanoIDP {self._kind.noun} of schema version {meta.get('schema_version')}, "
                f"and this NanoIDP uses version {SCHEMA_VERSION}; the {self._kind.noun} is disposable: "
                "delete the file (and its -wal and -shm) or choose another"
            )
        for key, wanted in self._settled.items():
            if meta.get(key) != wanted:
                raise RuntimeStoreFileRefused(
                    f"{self.path} is a NanoIDP {self._kind.noun} made with a {key} of {meta.get(key)}, "
                    f"and this NanoIDP uses {wanted}; the {self._kind.noun} is disposable: "
                    "delete the file (and its -wal and -shm) or choose another"
                )

    def _refused(self, failure: sqlite3.DatabaseError) -> BaseException:
        if isinstance(failure, sqlite3.OperationalError) and _is_busy(failure):
            return _unavailable(failure)
        return RuntimeStoreFileRefused(f"{self.path} cannot be used as a {self._kind.noun}: {failure}")

    def _open(self) -> sqlite3.Connection:
        # Not shared between threads: another thread may only close it, in
        # the fork hook, once nothing is using it.
        connection = sqlite3.connect(
            str(self.path), timeout=_BUSY_TIMEOUT_MS / 1000, isolation_level=None, check_same_thread=False
        )
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA synchronous = NORMAL")
        return connection

    def connection(self) -> sqlite3.Connection:
        """This thread's connection; a new one if the fork hook closed it.
        Only within an activity of the fork gate."""
        local = self._local
        if getattr(local, "generation", None) != self._generation:
            connection = self._open()
            with self._connections_lock:
                ended = self._ended()
                self._connections[threading.current_thread()] = connection
            for gone in ended:
                gone.close()
            local.connection = connection
            local.generation = self._generation
        return cast(sqlite3.Connection, local.connection)

    def _ended(self) -> List[sqlite3.Connection]:
        """Take out of the registry the connections of threads that are
        gone, for the caller to close: a server that starts a thread per
        request would otherwise keep two descriptors per request until the
        next fork. Nothing is using them, and within an activity no fork can
        come in between. Under the registry's lock."""
        ended = [thread for thread in self._connections if not thread.is_alive()]
        return [self._connections.pop(thread) for thread in ended]

    def _close_all(self) -> None:
        """Close every connection, of every thread. Only from the fork hook,
        once no activity is left."""
        with self._connections_lock:
            connections = list(self._connections.values())
            self._connections.clear()
            self._generation += 1
        for connection in connections:
            try:
                connection.close()
            except Exception:  # noqa: BLE001 - nothing may stop the hook
                pass


def _hold_of(text: Optional[str]) -> Optional[Hold]:
    if text is None:
        return None
    data = json.loads(text)
    return Hold(data["hold_id"], data["since"], data["payload"])


def _hold_text(hold: Hold) -> str:
    return json.dumps({"hold_id": hold.hold_id, "since": hold.since, "payload": hold.payload}, allow_nan=False)


_Row = Tuple[str, str, Optional[str], Optional[float]]


class _SqliteTransaction(Generic[T]):
    """The view a decision gets: statements in the decision's transaction."""

    def __init__(
        self, connection: sqlite3.Connection, repository: str, name_of: Callable[[T], str], codec: Codec[T]
    ) -> None:
        self._connection = connection
        self._repository = repository
        self._name_of = name_of
        self._codec = codec
        self._closed = False

    def close(self) -> None:
        self._closed = True

    def _open(self) -> None:
        if self._closed:
            raise TransactionClosed("this view belonged to a decision that is over")

    def _row(self, name: str) -> Optional[_Row]:
        return cast(
            Optional[_Row],
            self._connection.execute(
                "SELECT value, instance_id, hold, expires_at FROM entries WHERE repository = ? AND name = ?",
                (self._repository, name),
            ).fetchone(),
        )

    def _entry(self, name: str, row: _Row) -> Entry[T]:
        value, instance_id, hold, expires_at = row
        return Entry(name, self._codec.load(json.loads(value)), instance_id, _hold_of(hold), expires_at)

    def _require(self, name: str) -> _Row:
        row = self._row(name)
        if row is None:
            raise RuntimeObjectMissing(f"no runtime object {name!r}")
        return row

    def name_of(self, obj: T) -> str:
        self._open()
        return self._name_of(obj)

    def entry(self, name: str) -> Optional[Entry[T]]:
        self._open()
        row = self._row(name)
        return self._entry(name, row) if row is not None else None

    def entries(self) -> List[Entry[T]]:
        self._open()
        rows = self._connection.execute(
            "SELECT name, value, instance_id, hold, expires_at FROM entries WHERE repository = ? ORDER BY seq",
            (self._repository,),
        ).fetchall()
        return [self._entry(row[0], row[1:]) for row in rows]

    def count(self) -> int:
        self._open()
        return int(
            self._connection.execute("SELECT COUNT(*) FROM entries WHERE repository = ?", (self._repository,)).fetchone()[0]
        )

    def create(self, obj: T, expires_at: Optional[float] = None) -> Entry[T]:
        self._open()
        name = self._name_of(obj)
        if self._row(name) is not None:
            raise RuntimeObjectExists(f"runtime object {name!r} already exists")
        text = verified(self._codec, obj)
        instance_id = uuid.uuid4().hex
        moment = checked_time(expires_at, or_none=True)
        self._connection.execute(
            "INSERT INTO entries (repository, name, value, instance_id, hold, expires_at) VALUES (?, ?, ?, ?, NULL, ?)",
            (self._repository, name, text, instance_id, moment),
        )
        return Entry(name, self._codec.load(json.loads(text)), instance_id, None, moment)

    def replace(self, name: str, obj: T) -> Entry[T]:
        self._open()
        if self._name_of(obj) != name:
            raise ValueError(f"a replace cannot rename {name!r} to {self._name_of(obj)!r}")
        _, instance_id, hold, expires_at = self._require(name)
        text = verified(self._codec, obj)
        self._connection.execute(
            "UPDATE entries SET value = ? WHERE repository = ? AND name = ?", (text, self._repository, name)
        )
        return Entry(name, self._codec.load(json.loads(text)), instance_id, _hold_of(hold), expires_at)

    def set_expires_at(self, name: str, expires_at: Optional[float]) -> Entry[T]:
        self._open()
        moment = checked_time(expires_at, or_none=True)
        value, instance_id, hold, _ = self._require(name)
        self._connection.execute(
            "UPDATE entries SET expires_at = ? WHERE repository = ? AND name = ?", (moment, self._repository, name)
        )
        return self._entry(name, (value, instance_id, hold, moment))

    def delete_expired(self, now: float) -> int:
        self._open()
        moment = checked_time(now)
        cursor = self._connection.execute(
            "DELETE FROM entries WHERE repository = ? AND expires_at IS NOT NULL AND expires_at < ? AND hold IS NULL",
            (self._repository, moment),
        )
        return int(cursor.rowcount)

    def delete(self, name: str) -> bool:
        self._open()
        cursor = self._connection.execute(
            "DELETE FROM entries WHERE repository = ? AND name = ?", (self._repository, name)
        )
        return cursor.rowcount > 0

    def hold(self, name: str, payload: Dict[str, Any]) -> Hold:
        self._open()
        _, _, hold, _ = self._require(name)
        if hold is not None:
            raise EntryHeld(f"runtime object {name!r} is already held")
        installed = Hold(uuid.uuid4().hex, time.time(), _payload(payload))
        self._connection.execute(
            "UPDATE entries SET hold = ? WHERE repository = ? AND name = ?",
            (_hold_text(installed), self._repository, name),
        )
        return Hold(installed.hold_id, installed.since, _payload(installed.payload))

    def update_hold(self, name: str, hold_id: str, payload: Dict[str, Any]) -> bool:
        self._open()
        checked = _payload(payload)
        current = self._carrying(name, hold_id)
        if current is None:
            return False
        self._connection.execute(
            "UPDATE entries SET hold = ? WHERE repository = ? AND name = ?",
            (_hold_text(Hold(current.hold_id, current.since, checked)), self._repository, name),
        )
        return True

    def release_hold(self, name: str, hold_id: str) -> bool:
        self._open()
        if self._carrying(name, hold_id) is None:
            return False
        self._connection.execute(
            "UPDATE entries SET hold = NULL WHERE repository = ? AND name = ?", (self._repository, name)
        )
        return True

    def _carrying(self, name: str, hold_id: str) -> Optional[Hold]:
        row = self._row(name)
        if row is None:
            return None
        hold = _hold_of(row[2])
        if hold is None or hold.hold_id != hold_id:
            return None
        return hold


class SqliteRuntimeRepository(RepositorySwitches, Generic[T]):
    """A runtime repository in the store's file: the rows of one
    ``repository`` name."""

    def __init__(self, database: _Database, repository: str, name_of: Callable[[T], str], codec: Codec[T]) -> None:
        self._database = database
        self._repository = repository
        self._name_of = name_of
        self._codec = codec

    def create(self, obj: T, expires_at: Optional[float] = None) -> T:
        return self.create_entry(obj, expires_at).value

    def create_entry(self, obj: T, expires_at: Optional[float] = None) -> Entry[T]:
        return self.transact(lambda view: view.create(obj, expires_at))

    def get(self, name: str) -> Optional[T]:
        found = self.entry(name)
        return found.value if found is not None else None

    def entry(self, name: str) -> Optional[Entry[T]]:
        refuse_inside_a_decision()
        return self._read(lambda view: view.entry(name))

    def list(self) -> List[T]:
        return [found.value for found in self.entries()]

    def entries(self) -> List[Entry[T]]:
        refuse_inside_a_decision()
        return self._read(lambda view: view.entries())

    def delete(self, name: str) -> bool:
        return self.transact(lambda view: view.delete(name))

    def delete_all(self) -> int:
        refuse_inside_a_decision()

        def decide(view: RepositoryTransaction[T]) -> int:
            connection = cast(_SqliteTransaction[T], view)._connection
            return int(connection.execute("DELETE FROM entries WHERE repository = ?", (self._repository,)).rowcount)

        return self.transact(decide)

    def _read(self, read: Callable[["_SqliteTransaction[T]"], R]) -> R:
        """A read outside a decision: one statement, its own snapshot."""
        with _FORK_GATE.activity():
            view = _SqliteTransaction(self._database.connection(), self._repository, self._name_of, self._codec)
            try:
                return read(view)
            except sqlite3.Error as failure:
                raise _unavailable(failure) from failure
            finally:
                view.close()

    def transact(self, decide: Callable[[RepositoryTransaction[T]], R]) -> R:
        refuse_inside_a_decision()
        with _FORK_GATE.activity():
            return self._transact(decide)

    def _transact(self, decide: Callable[[RepositoryTransaction[T]], R]) -> R:
        connection = self._database.connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as failure:
            raise _unavailable(failure) from failure
        try:
            if RepositorySwitches.run_decisions_twice:
                # The first run against a view that is thrown away, as the
                # memory backend does: its changes are undone, and if it
                # raises there is no second run and nothing is committed.
                connection.execute("SAVEPOINT discarded")
                try:
                    self._decide(connection, decide)
                finally:
                    connection.execute("ROLLBACK TO discarded")
                    connection.execute("RELEASE discarded")
            result = self._decide(connection, decide)
            connection.execute("COMMIT")
            return result
        except BaseException as failure:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            if isinstance(failure, sqlite3.Error):
                raise _unavailable(failure) from failure
            raise

    def _decide(self, connection: sqlite3.Connection, decide: Callable[[RepositoryTransaction[T]], R]) -> R:
        view: _SqliteTransaction[T] = _SqliteTransaction(connection, self._repository, self._name_of, self._codec)
        _deciding.active = True
        try:
            return decide(view)
        finally:
            _deciding.active = False
            view.close()


class SqliteAuditStore:
    """The audit in a SQLite file of its own (#354, third step): a file has
    one writer, and the audit must not wait for the repositories, so it
    cannot share the store's.

    An append is one transaction: the event, the delete of what is past the
    bound, and one upsert per counter named. What can be refused is refused
    before it: the increments, and the event, which is dumped to JSON first;
    so the file's lock is never held by an event that will not be written.
    The bound is the audit's, for every process that appends to it. Reads
    are single statements. Every operation is an activity of the fork gate,
    and the connections are in the registry the gate closes."""

    def __init__(self, path: Union[str, Path], max_entries: Optional[int] = None) -> None:
        _require_upsert()
        # Before the file is made: a bound that is refused makes nothing.
        self._bound = checked_bound(max_entries)
        # The file's, not this process's: the audit is one for every process
        # that appends to it, and so is how much of it is kept.
        self._database = _Database(path, _AUDIT, {"bound": str(self._bound)})
        self._codec = AuditEntryCodec()

    @property
    def path(self) -> Path:
        return self._database.path

    def _written(self, entry: AuditEntry) -> str:
        """The event as the JSON the file keeps. Outside the contract's
        domain, refused: this backend writes the event down."""
        if not isinstance(entry, AuditEntry):
            raise TypeError(f"an audit event is an AuditEntry, not {type(entry).__name__}")
        outside = outside_the_domain(entry.details)
        if outside is not None:
            raise ValueError(
                f"the audit event does not survive its codec: the details of an event are a JSON object, and {outside}"
            )
        text = json.dumps(self._codec.dump(entry), allow_nan=False)
        if RepositorySwitches.verify_codecs and self._codec.load(json.loads(text)) != entry:
            raise ValueError("the audit event does not survive its codec: it comes back changed")
        return text

    def append(self, entry: AuditEntry, increments: Sequence[str]) -> None:
        refuse_inside_a_decision()
        names = checked_increments(increments)
        text = self._written(entry)
        row = (entry.event_type, entry.username, entry.client_id, text)

        def appending(connection: sqlite3.Connection) -> None:
            seq = connection.execute(
                "INSERT INTO events (event_type, username, client_id, value) VALUES (?, ?, ?, ?)", row
            ).lastrowid
            connection.execute("DELETE FROM events WHERE seq <= ?", (cast(int, seq) - self._bound,))
            for name in names:
                connection.execute(
                    "INSERT INTO counters (name, value) VALUES (?, 1) "
                    "ON CONFLICT (name) DO UPDATE SET value = value + 1",
                    (name,),
                )

        self._write(appending)

    def entries(
        self,
        limit: int,
        event_type: Optional[str] = None,
        username: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> List[AuditEntry]:
        refuse_inside_a_decision()
        checked_limit(limit)
        conditions, arguments = [], []
        for column, wanted in (("event_type", event_type), ("username", username), ("client_id", client_id)):
            if wanted is not None:
                conditions.append(f"{column} = ?")
                arguments.append(wanted)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        # No more is kept than the bound, which fits a SQLite integer: a limit
        # need not (#354, third step, review).
        rows = self._read(
            f"SELECT value FROM events{where} ORDER BY seq DESC LIMIT ?", (*arguments, min(limit, self._bound))
        )
        return [self._codec.load(json.loads(value)) for (value,) in rows]

    def client_ids(self) -> List[str]:
        refuse_inside_a_decision()
        rows = self._read(
            "SELECT DISTINCT client_id FROM events WHERE client_id IS NOT NULL AND client_id != '' ORDER BY client_id"
        )
        return [client_id for (client_id,) in rows]

    def counters(self) -> Dict[str, int]:
        refuse_inside_a_decision()
        return dict(self._read("SELECT name, value FROM counters"))

    def clear(self) -> None:
        refuse_inside_a_decision()

        def clearing(connection: sqlite3.Connection) -> None:
            connection.execute("DELETE FROM events")
            connection.execute("DELETE FROM counters")

        self._write(clearing)

    def _read(self, sql: str, arguments: Tuple[Any, ...] = ()) -> List[Tuple[Any, ...]]:
        with _FORK_GATE.activity():
            try:
                return self._database.connection().execute(sql, arguments).fetchall()
            except sqlite3.Error as failure:
                raise _unavailable(failure) from failure

    def _write(self, apply: Callable[[sqlite3.Connection], None]) -> None:
        with _FORK_GATE.activity():
            connection = self._database.connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as failure:
                raise _unavailable(failure) from failure
            try:
                apply(connection)
                connection.execute("COMMIT")
            except BaseException as failure:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                if isinstance(failure, sqlite3.Error):
                    raise _unavailable(failure) from failure
                raise


class SqliteRuntimeStore:
    """The runtime store in a pair of SQLite files: the repositories in
    ``path``, the audit in the file named after it (``audit_path_of``)."""

    def __init__(self, path: Union[str, Path]) -> None:
        # Before either file is made: the audit's upsert needs it.
        _require_upsert()
        store_path = Path(path).expanduser().resolve()
        audit_path = audit_path_of(store_path)
        # What exists is opened before what is missing is made, so that a
        # file that is refused leaves no new one behind.
        if audit_path.exists():
            self._audit: AuditStore = SqliteAuditStore(audit_path)
            self._database = _Database(store_path, _STORE)
        else:
            self._database = _Database(store_path, _STORE)
            self._audit = SqliteAuditStore(audit_path)
        self._users: SqliteRuntimeRepository[User] = SqliteRuntimeRepository(
            self._database, "users", lambda user: user.username, PydanticCodec(User)
        )
        self._clients: SqliteRuntimeRepository[OAuthClient] = SqliteRuntimeRepository(
            self._database, "clients", lambda client: client.client_id, PydanticCodec(OAuthClient)
        )
        self._lent: Dict[str, SqliteRuntimeRepository[Any]] = {}
        self._lock = threading.Lock()
        self._leases = _OwnerLeases(owners_path_of(self._database.path))
        _LEASES.add(self._leases)

    @property
    def path(self) -> Path:
        return self._database.path

    def claim_owner(self) -> Optional[str]:
        """This process as the owner of a claim it is about to make: its
        lease, made and held before the id is returned (#354, step 4b)."""
        return self._leases.owner()

    def owner_may_be_dead(self, owner: Optional[str]) -> bool:
        """Whether the owner of a claim could be proved dead now."""
        return self._leases.may_be_dead(owner)

    @contextmanager
    def prove_owner_dead(self, owner: Optional[str]) -> Iterator[bool]:
        """Whether the owner of a claim is proved dead; see _OwnerLeases."""
        with self._leases.prove_dead(owner) as dead:
            yield dead

    @property
    def shared(self) -> bool:
        # Its files are for every process on the host that opens them.
        return True

    @property
    def users(self) -> RuntimeRepository[User]:
        return self._users

    @property
    def clients(self) -> RuntimeRepository[OAuthClient]:
        return self._clients

    @property
    def audit(self) -> AuditStore:
        return self._audit

    def repository(self, name: str, key_of: Callable[[T], str], codec: Codec[T]) -> RuntimeRepository[T]:
        """The repository a service keeps here under ``name``: its rows in
        the file. Not from inside a decision, as with the memory store."""
        refuse_inside_a_decision()
        if name in _OWN:
            raise ValueError(f"{name!r} is the store's own repository")
        # An activity of the fork gate, although it touches no connection:
        # a fork must not find the lock held by a thread the child will not
        # have.
        with _FORK_GATE.activity(), self._lock:
            existing = self._lent.get(name)
            if existing is None:
                existing = SqliteRuntimeRepository(self._database, name, key_of, codec)
                self._lent[name] = existing
            return cast(RuntimeRepository[T], existing)
