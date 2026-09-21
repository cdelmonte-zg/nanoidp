"""The runtime store in a SQLite file, for several NanoIDP processes on one
host (#354, second step).

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
from inside a decision, or from inside any operation of a store: the hook
would wait for the thread that is forking.

The file is the process's secret and NanoIDP's own: created ``0600`` (and so
are ``-wal`` and ``-shm``, which SQLite makes with the database's mode, and
which are brought to ``0600`` all the same), an existing one brought to
``0600``, and a file that is not a NanoIDP runtime store refused, never adopted.
"""

import json
import os
import sqlite3
import stat
import threading
import time
import uuid
import weakref
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Generic, Iterator, List, Optional, Set, Tuple, Union, cast

from ..config import OAuthClient, User
from .audit_store import AuditStore
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

__all__ = ["RuntimeStoreFileRefused", "SqliteRuntimeRepository", "SqliteRuntimeStore"]

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

    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path).expanduser().resolve()
        if self.path.is_dir():
            raise RuntimeStoreFileRefused(f"{self.path} is a directory, not a runtime store file")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        # Every connection open, whichever thread it belongs to, for the
        # fork hook to close; and the count of those closings, by which a
        # thread knows its own was closed.
        self._connections: Set[sqlite3.Connection] = set()
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
                            f"{self.path} is a SQLite database that is not a NanoIDP runtime store; "
                            "the runtime store is disposable: choose another file"
                        )
                    for statement in _SCHEMA:
                        connection.execute(statement)
                    connection.executemany(
                        "INSERT INTO meta (key, value) VALUES (?, ?)",
                        [("kind", _MARKER), ("schema_version", str(SCHEMA_VERSION))],
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
                f"{self.path} is a SQLite database that is not a NanoIDP runtime store; "
                "the runtime store is disposable: choose another file"
            )
        meta = dict(connection.execute("SELECT key, value FROM meta").fetchall())
        if meta.get("kind") != _MARKER:
            raise RuntimeStoreFileRefused(
                f"{self.path} is a SQLite database that is not a NanoIDP runtime store; "
                "the runtime store is disposable: choose another file"
            )
        if meta.get("schema_version") != str(SCHEMA_VERSION):
            raise RuntimeStoreFileRefused(
                f"{self.path} is a NanoIDP runtime store of schema version {meta.get('schema_version')}, "
                f"and this NanoIDP uses version {SCHEMA_VERSION}; the runtime store is disposable: "
                "delete the file (and its -wal and -shm) or choose another"
            )

    def _refused(self, failure: sqlite3.DatabaseError) -> BaseException:
        if isinstance(failure, sqlite3.OperationalError) and _is_busy(failure):
            return _unavailable(failure)
        return RuntimeStoreFileRefused(f"{self.path} cannot be used as a runtime store: {failure}")

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
                self._connections.add(connection)
            local.connection = connection
            local.generation = self._generation
        return cast(sqlite3.Connection, local.connection)

    def _close_all(self) -> None:
        """Close every connection, of every thread. Only from the fork hook,
        once no activity is left."""
        with self._connections_lock:
            connections = list(self._connections)
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


class SqliteRuntimeStore:
    """The runtime store in one SQLite file. The audit is handed in: its own
    SQLite store is the next step (#354), and until then the audit of each
    process is its own."""

    def __init__(self, path: Union[str, Path], audit: AuditStore) -> None:
        self._database = _Database(path)
        self._audit = audit
        self._users: SqliteRuntimeRepository[User] = SqliteRuntimeRepository(
            self._database, "users", lambda user: user.username, PydanticCodec(User)
        )
        self._clients: SqliteRuntimeRepository[OAuthClient] = SqliteRuntimeRepository(
            self._database, "clients", lambda client: client.client_id, PydanticCodec(OAuthClient)
        )
        self._lent: Dict[str, SqliteRuntimeRepository[Any]] = {}
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._database.path

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
