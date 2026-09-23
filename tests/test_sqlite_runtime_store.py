"""The runtime store in a SQLite file (#354, second step): what is its own.

The contract every backend owes runs over this one too
(``tests/runtime_store_contract.py``). What is pinned here is what only a
store in a file has: the file itself (its schema, what it refuses, its
permissions), the order of creation kept in ``seq``, the transaction a
decision is, contention, a fork, and the atomic compositions of the services
with the contenders in different processes, which a lock in one process could
never have shown.

Not selectable from settings.yaml yet (the fourth step), so nothing here goes
through a configuration.
"""

import datetime as dt
import json
import multiprocessing
import os
import sqlite3
import stat
import threading
import time

import pytest

from nanoidp.config import User
from nanoidp.services import sqlite_runtime_store as sqlite_module
from nanoidp.services.runtime_repository import (
    EntryHeld,
    NestedRepositoryUse,
    PydanticCodec,
    RepositorySwitches,
    RuntimeStoreUnavailable,
    consume,
    create_within,
    replace,
)
from nanoidp.services.sqlite_runtime_store import (
    RuntimeStoreFileRefused,
    SqliteAuditStore,
    SqliteRuntimeStore,
)

_SPAWN = multiprocessing.get_context("spawn")
_POSIX = os.name == "posix"


def _store(path):
    return SqliteRuntimeStore(path)


def _user(name):
    return User(username=name, password="pw")


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class TestTheFile:
    def test_a_new_file_gets_the_schema_and_is_found_again(self, tmp_path):
        path = tmp_path / "state" / "runtime.db"
        _store(path).users.create(_user("alice"))

        assert [user.username for user in _store(path).users.list()] == ["alice"]

    def test_the_parent_directory_is_made(self, tmp_path):
        path = tmp_path / "a" / "b" / "runtime.db"

        _store(path)

        assert path.is_file()

    def test_a_directory_is_no_file(self, tmp_path):
        with pytest.raises(RuntimeStoreFileRefused, match="is a directory"):
            _store(tmp_path)

    def test_a_file_that_is_not_a_database_is_refused_and_left_as_it_was(self, tmp_path):
        path = tmp_path / "notes.txt"
        path.write_text("my notes, which are not a database")
        path.chmod(0o644)

        with pytest.raises(RuntimeStoreFileRefused, match="cannot be used as a runtime store"):
            _store(path)

        assert path.read_text() == "my notes, which are not a database"
        if _POSIX:
            assert _mode(path) == 0o644

    def test_a_database_of_somebody_else_is_refused_and_left_as_it_was(self, tmp_path):
        path = tmp_path / "theirs.db"
        theirs = sqlite3.connect(path)
        theirs.execute("CREATE TABLE accounts (id INTEGER)")
        theirs.execute("INSERT INTO accounts VALUES (1)")
        theirs.commit()
        theirs.close()
        path.chmod(0o644)
        before = path.read_bytes()

        with pytest.raises(RuntimeStoreFileRefused, match="not a NanoIDP runtime store"):
            _store(path)

        assert path.read_bytes() == before
        if _POSIX:
            assert _mode(path) == 0o644
        tables = {row[0] for row in sqlite3.connect(path).execute("SELECT name FROM sqlite_master")}
        assert tables == {"accounts"}

    def test_a_store_of_another_schema_version_is_refused(self, tmp_path):
        path = tmp_path / "runtime.db"
        _store(path)
        connection = sqlite3.connect(path)
        connection.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        connection.commit()
        connection.close()

        with pytest.raises(RuntimeStoreFileRefused, match="schema version 99.*disposable"):
            _store(path)

    def test_an_empty_file_is_one_nobody_wrote_anything_in(self, tmp_path):
        path = tmp_path / "runtime.db"
        path.touch()

        _store(path).users.create(_user("alice"))

        assert _store(path).users.get("alice") is not None

    @pytest.mark.skipif(not _POSIX, reason="POSIX file modes")
    def test_the_file_and_its_sidecars_are_the_owners_alone(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "umask", os.umask)  # restored whatever happens
        previous = os.umask(0o022)
        try:
            path = tmp_path / "runtime.db"
            # Kept while the sidecars are looked at: when the last
            # connection to the file closes, SQLite removes them.
            store = _store(path)
            store.users.create(_user("alice"))
        finally:
            os.umask(previous)

        for name in ("runtime.db", "runtime.db-wal", "runtime.db-shm"):
            assert _mode(tmp_path / name) == 0o600, name
        assert store.users.get("alice") is not None

    @pytest.mark.skipif(not _POSIX, reason="POSIX file modes")
    def test_a_new_file_is_private_from_the_moment_it_exists(self, tmp_path, monkeypatch):
        """Not made private afterwards: between its creation and a chmod the
        file would be anybody's to open, under the usual umask."""
        seen = []
        initialise = sqlite_module._Database._initialise

        def looking(self, created):
            seen.append(_mode(self.path))
            return initialise(self, created)

        monkeypatch.setattr(sqlite_module._Database, "_initialise", looking)
        previous = os.umask(0o022)
        try:
            _store(tmp_path / "runtime.db")
        finally:
            os.umask(previous)

        # The store's file and the audit's.
        assert seen == [0o600, 0o600]

    @pytest.mark.skipif(not _POSIX, reason="POSIX file modes")
    def test_a_store_that_is_there_already_is_made_private(self, tmp_path):
        path = tmp_path / "runtime.db"
        # Kept open, so that the sidecars are there to be found: when the
        # last connection to the file closes, SQLite removes them.
        first = _store(path)
        first.users.create(_user("alice"))
        for name in ("runtime.db", "runtime.db-wal", "runtime.db-shm"):
            (tmp_path / name).chmod(0o644)

        _store(path)

        for name in ("runtime.db", "runtime.db-wal", "runtime.db-shm"):
            assert _mode(tmp_path / name) == 0o600, name
        assert first.users.get("alice") is not None

    def test_wal_is_the_journal(self, tmp_path):
        path = tmp_path / "runtime.db"
        _store(path)

        assert sqlite3.connect(path).execute("PRAGMA journal_mode").fetchone()[0] == "wal"

    def test_processes_opening_a_new_file_together_all_get_one_store(self, tmp_path):
        path = str(tmp_path / "runtime.db")
        results = _in_processes(_open_and_create, [(path, f"u{index}") for index in range(4)])

        assert [kind for kind, _ in results] == ["ok"] * 4, results
        assert sorted(user.username for user in _store(path).users.list()) == ["u0", "u1", "u2", "u3"]


class _Answer:
    """What sqlite3 hands back from execute(): something with fetchone()."""

    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return (self.value,)


class TestWalActivationUnderContention:
    """Putting a file in WAL needs it to itself for a moment, and SQLite
    answers contention there in two ways (measured): against a plain reader
    the busy handler waits, and one attempt can spend the whole timeout;
    against a connection that has written, and so holds the file reserved,
    it fails at once. Several processes creating one store are the second
    shape, and that is what CI met (#354).

    These go at the switch itself rather than through the constructor: a
    constructor's own BEGIN IMMEDIATE waits for whoever holds the file, so
    by the time it reaches the switch the contention it was given is over.
    The composition of real processes is pinned by
    TestTheFile::test_processes_opening_a_new_file_together_all_get_one_store.
    """

    @staticmethod
    def _database_of(path):
        return _store(path)._database

    @staticmethod
    def _in_rollback_journal(path):
        connection = sqlite3.connect(path, isolation_level=None)
        connection.execute("PRAGMA journal_mode = delete")
        connection.close()

    @staticmethod
    def _holding_it_reserved(path, seconds, held):
        def hold():
            connection = sqlite3.connect(path, timeout=10, isolation_level=None)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE meta SET value = value")
            held.set()
            time.sleep(seconds)
            connection.execute("COMMIT")
            connection.close()

        return threading.Thread(target=hold, daemon=True)

    def _switch(self, path, database):
        connection = sqlite3.connect(path, timeout=10, isolation_level=None)
        connection.execute(f"PRAGMA busy_timeout = {sqlite_module._BUSY_TIMEOUT_MS}")
        try:
            began = time.monotonic()
            database._activate_wal(connection)
            return time.monotonic() - began
        finally:
            connection.close()

    def test_a_file_another_process_holds_is_waited_for(self, tmp_path):
        path = tmp_path / "runtime.db"
        database = self._database_of(path)
        self._in_rollback_journal(path)
        held = threading.Event()
        holder = self._holding_it_reserved(str(path), 1.2, held)
        holder.start()
        assert held.wait(5)

        waited = self._switch(path, database)

        holder.join(10)
        assert sqlite3.connect(path).execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert waited >= 0.5, "the switch did not wait for the other side"

    def test_a_file_held_past_the_budget_is_the_store_held(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sqlite_module, "_BUSY_TIMEOUT_MS", 400)
        path = tmp_path / "runtime.db"
        database = self._database_of(path)
        self._in_rollback_journal(path)
        held = threading.Event()
        holder = self._holding_it_reserved(str(path), 3, held)
        holder.start()
        assert held.wait(5)

        began = time.monotonic()
        with pytest.raises(RuntimeStoreUnavailable, match="held by another process"):
            self._switch(path, database)
        waited = time.monotonic() - began

        holder.join(10)
        assert waited >= 0.4, "it gave up before its budget was spent"
        assert waited < 3, "it waited for the other side instead of its budget"
        assert sqlite3.connect(path).execute("PRAGMA journal_mode").fetchone()[0] == "delete"

    @staticmethod
    def _reading_it(path, seconds, held):
        """The other shape: a reader, which the busy handler does wait for,
        long enough to spend a whole budget inside one attempt."""

        def read():
            connection = sqlite3.connect(path, timeout=10, isolation_level=None)
            connection.execute("BEGIN")
            connection.execute("SELECT count(*) FROM meta").fetchall()
            held.set()
            time.sleep(seconds)
            connection.execute("COMMIT")
            connection.close()

        return threading.Thread(target=read, daemon=True)

    def test_a_reader_does_not_stretch_the_budget(self, tmp_path, monkeypatch):
        """The budget is the whole wait, not one attempt's: an attempt that
        waited for the reader itself would answer when the reader is done,
        however long that is."""
        monkeypatch.setattr(sqlite_module, "_BUSY_TIMEOUT_MS", 400)
        path = tmp_path / "runtime.db"
        database = self._database_of(path)
        self._in_rollback_journal(path)
        held = threading.Event()
        reader = self._reading_it(str(path), 2.5, held)
        reader.start()
        assert held.wait(5)

        began = time.monotonic()
        with pytest.raises(RuntimeStoreUnavailable, match="held by another process"):
            self._switch(path, database)
        waited = time.monotonic() - began

        reader.join(10)
        assert 0.4 <= waited < 2, f"the budget was not the whole wait ({waited:.2f}s)"

    class _AnsweringTheSwitch:
        """A connection whose switch answers with a mode instead of raising,
        which SQLite documents as a refusal too: the conversion did not
        happen and the file is in the mode it names."""

        def __init__(self, answers, failing=None, busy_first=False, busy_always=False):
            self.answers = list(answers)
            self.failing = failing
            self.busy_first = busy_first
            self.busy_always = busy_always
            self.switches = 0
            self.timeouts = []

        def execute(self, statement):
            if statement.startswith("PRAGMA busy_timeout ="):
                self.timeouts.append(int(statement.split("=")[1]))
                return _Answer("0")
            if statement.startswith("PRAGMA journal_mode ="):
                self.switches += 1
                if self.failing is not None:
                    raise self.failing
                if self.busy_always or (self.busy_first and self.switches == 1):
                    raise sqlite3.OperationalError("database is locked")
                answer = self.answers.pop(0) if self.answers else "delete"
            else:
                answer = "delete"
            return _Answer(answer)

    def test_a_switch_that_answers_another_mode_is_tried_again(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sqlite_module, "_BUSY_TIMEOUT_MS", 400)
        database = self._database_of(tmp_path / "runtime.db")
        connection = self._AnsweringTheSwitch(["delete", "delete", "wal"])

        database._activate_wal(connection)

        assert connection.switches == 3

    def test_an_answer_is_read_however_it_is_spelled(self, tmp_path, monkeypatch):
        """The mode is SQLite's word, and this store compares it as one
        spelling, here and where the file's mode is read."""
        monkeypatch.setattr(sqlite_module, "_BUSY_TIMEOUT_MS", 200)
        database = self._database_of(tmp_path / "runtime.db")
        connection = self._AnsweringTheSwitch(["WAL"])

        database._activate_wal(connection)

        assert connection.switches == 1

    def test_no_attempt_is_given_more_than_what_is_left(self, tmp_path, monkeypatch):
        """The budget is the whole wait even when the contention changes
        shape: SQLite waits inside an attempt, so an attempt begun late must
        be given what is left, not a budget of its own. Otherwise a run of
        immediate refusals followed by one the handler waits out spends
        twice what was promised."""
        monkeypatch.setattr(sqlite_module, "_BUSY_TIMEOUT_MS", 300)
        database = self._database_of(tmp_path / "runtime.db")
        connection = self._AnsweringTheSwitch([], busy_always=True)

        with pytest.raises(RuntimeStoreUnavailable):
            database._activate_wal(connection)

        attempts = connection.timeouts[:-1]  # the last one restores the store's own
        assert attempts, "no attempt was given a timeout at all"
        assert attempts[0] <= 300, f"the first attempt was given more than the budget ({attempts[0]})"
        assert attempts[-1] < attempts[0], "a later attempt was given as much as the first"
        assert connection.timeouts[-1] == 300, "the connection was left without its own timeout"

    def test_no_attempt_begins_past_the_budget(self, tmp_path, monkeypatch):
        """The pause between attempts is time too: a loop that looked at the
        clock only after an attempt would begin one with nothing left, and
        could even turn the file at a budget already spent. On a clock this
        test moves itself, so the window is not a matter of luck."""

        class _Clock:
            def __init__(self):
                self.now = 0.0

            def monotonic(self):
                return self.now

            def sleep(self, seconds):
                self.now += seconds

        clock = _Clock()
        monkeypatch.setattr(sqlite_module, "time", clock)
        monkeypatch.setattr(sqlite_module, "_BUSY_TIMEOUT_MS", 300)
        monkeypatch.setattr(sqlite_module, "_WAL_ATTEMPT_INTERVAL", 10)
        database = self._database_of(tmp_path / "runtime.db")
        connection = self._AnsweringTheSwitch([], busy_always=True)

        with pytest.raises(RuntimeStoreUnavailable):
            database._activate_wal(connection)

        assert connection.switches == 1, "an attempt began with nothing left of the budget"

    def test_a_file_that_never_turns_is_refused_as_the_file_it_is(self, tmp_path, monkeypatch):
        """Nobody ever answered busy, so no peer is holding anything: the
        file cannot be put in WAL, and that is what is said."""
        monkeypatch.setattr(sqlite_module, "_BUSY_TIMEOUT_MS", 200)
        database = self._database_of(tmp_path / "runtime.db")
        connection = self._AnsweringTheSwitch([])

        began = time.monotonic()
        with pytest.raises(RuntimeStoreFileRefused, match="stays in journal mode 'delete'") as raised:
            database._activate_wal(connection)

        assert time.monotonic() - began >= 0.2, "it gave up before its budget was spent"
        assert connection.switches > 1, "it tried only once"
        assert not isinstance(raised.value, RuntimeStoreUnavailable)
        assert "held by another process" not in str(raised.value)

    def test_a_switch_that_was_busy_once_is_the_store_held(self, tmp_path, monkeypatch):
        """Busy at least once, and never WAL afterwards: a peer had it, so
        the answer is the one contention always gets."""
        monkeypatch.setattr(sqlite_module, "_BUSY_TIMEOUT_MS", 200)
        database = self._database_of(tmp_path / "runtime.db")
        connection = self._AnsweringTheSwitch([], busy_first=True)

        with pytest.raises(RuntimeStoreUnavailable, match="held by another process"):
            database._activate_wal(connection)

    @pytest.mark.skipif(not _POSIX, reason="the read-only open is POSIX here")
    def test_a_failure_that_is_not_contention_is_itself(self, tmp_path):
        """Only contention is worth another attempt: anything else is what
        it is, and is not dressed as the store being held."""
        path = tmp_path / "runtime.db"
        database = self._database_of(path)
        self._in_rollback_journal(path)
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, isolation_level=None)

        with pytest.raises(sqlite3.OperationalError, match="readonly database") as raised:
            database._activate_wal(connection)

        connection.close()
        assert not isinstance(raised.value, RuntimeStoreUnavailable)

    def test_a_failure_that_is_not_contention_is_not_tried_again(self, tmp_path, monkeypatch):
        """Counted rather than timed: under load a clock says nothing."""
        monkeypatch.setattr(sqlite_module, "_BUSY_TIMEOUT_MS", 2000)
        database = self._database_of(tmp_path / "runtime.db")
        connection = self._AnsweringTheSwitch([], failing=sqlite3.OperationalError("attempt to write a readonly database"))

        with pytest.raises(sqlite3.OperationalError, match="readonly database"):
            database._activate_wal(connection)

        assert connection.switches == 1

    def test_a_file_already_in_wal_is_not_switched_again(self, tmp_path):
        """Nothing to take the file for, so contention is no delay at all,
        and the journal mode is the file's, not the connection's."""
        path = tmp_path / "runtime.db"
        database = self._database_of(path)
        held = threading.Event()
        holder = self._holding_it_reserved(str(path), 1.5, held)
        holder.start()
        assert held.wait(5)

        waited = self._switch(path, database)

        holder.join(10)
        assert waited < 0.2, "a file in WAL was switched again"


class TestTheOrderOfCreation:
    def test_a_replace_keeps_its_place_and_a_recreation_takes_a_new_one(self, tmp_path):
        users = _store(tmp_path / "runtime.db").users
        for name in ("c", "a", "b"):
            users.create(_user(name))

        replace(users, "c", lambda user: user.model_copy(update={"email": "c@example.test"}))
        users.delete("a")
        users.create(_user("a"))

        assert [user.username for user in users.list()] == ["c", "b", "a"]
        assert [entry.name for entry in users.entries()] == ["c", "b", "a"]

    def test_the_order_is_asked_of_the_database_not_left_to_its_plan(self, tmp_path):
        """Without ORDER BY the rows come out in whatever order the planner
        walks them, which today happens to be seq: not a promise to lean on."""
        users = _store(tmp_path / "runtime.db").users
        users.create(_user("a"))
        statements = []
        connection = users._database.connection()
        connection.set_trace_callback(statements.append)
        try:
            users.list()
        finally:
            connection.set_trace_callback(None)

        listings = [sql for sql in statements if sql.lstrip().upper().startswith("SELECT NAME")]
        assert listings and all("ORDER BY seq" in sql for sql in listings), statements

    def test_the_order_is_the_repositorys_own(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        other = store.repository("others", lambda user: user.username, PydanticCodec(User))
        store.users.create(_user("z"))
        other.create(_user("y"))
        store.users.create(_user("x"))

        assert [user.username for user in store.users.list()] == ["z", "x"]
        assert [user.username for user in other.list()] == ["y"]


class TestTheIndexes:
    def _plan(self, store, sql, arguments):
        connection = store._database.connection()
        return " ".join(row[-1] for row in connection.execute(f"EXPLAIN QUERY PLAN {sql}", arguments))

    def test_a_cleanup_goes_through_the_index_of_what_can_be_due(self, tmp_path):
        store = _store(tmp_path / "runtime.db")

        plan = self._plan(
            store,
            "DELETE FROM entries WHERE repository = ? AND expires_at IS NOT NULL AND expires_at < ? AND hold IS NULL",
            ("codes", 1.0),
        )

        assert "entries_due" in plan

    def test_a_listing_goes_through_the_index_of_the_order(self, tmp_path):
        store = _store(tmp_path / "runtime.db")

        plan = self._plan(store, "SELECT name FROM entries WHERE repository = ? ORDER BY seq", ("codes",))

        assert "entries_order" in plan and "TEMP B-TREE" not in plan

    def test_a_cleanup_is_of_one_repository(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        codes = store.repository("codes", lambda user: user.username, PydanticCodec(User))
        grants = store.repository("grants", lambda user: user.username, PydanticCodec(User))
        codes.create(_user("c"), expires_at=1.0)
        grants.create(_user("g"), expires_at=1.0)

        assert codes.transact(lambda view: view.delete_expired(10.0)) == 1

        assert codes.list() == [] and [user.username for user in grants.list()] == ["g"]

    def test_a_held_entry_past_its_time_is_not_in_the_index_and_is_kept(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        codes = store.repository("codes", lambda user: user.username, PydanticCodec(User))
        codes.create(_user("held"), expires_at=1.0)
        codes.create(_user("due"), expires_at=1.0)
        codes.transact(lambda view: view.hold("held", {"why": "test"}))

        assert codes.transact(lambda view: view.delete_expired(10.0)) == 1
        assert [user.username for user in codes.list()] == ["held"]


class TestADecisionIsATransaction:
    def test_what_a_decision_did_is_undone_when_it_raises(self, tmp_path):
        users = _store(tmp_path / "runtime.db").users
        users.create(_user("alice"))

        def decide(view):
            view.create(_user("bob"))
            view.delete("alice")
            raise RuntimeError("no")

        with pytest.raises(RuntimeError):
            users.transact(decide)

        assert [user.username for user in users.list()] == ["alice"]

    def test_run_twice_the_first_run_leaves_nothing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(RepositorySwitches, "run_decisions_twice", True)
        users = _store(tmp_path / "runtime.db").users
        runs = []

        def decide(view):
            runs.append(view.count())
            view.create(_user(f"u{len(runs)}"))
            return view.count()

        assert users.transact(decide) == 1
        assert runs == [0, 0], "the second run saw nothing of the first"
        assert [user.username for user in users.list()] == ["u2"]

    def test_run_twice_a_first_run_that_raises_is_the_end_of_it(self, tmp_path, monkeypatch):
        monkeypatch.setattr(RepositorySwitches, "run_decisions_twice", True)
        users = _store(tmp_path / "runtime.db").users
        runs = []

        def decide(view):
            runs.append(1)
            view.create(_user("bob"))
            raise RuntimeError("no")

        with pytest.raises(RuntimeError):
            users.transact(decide)

        assert runs == [1]
        assert users.list() == []

    def test_a_decision_reaches_nothing_but_its_view(self, tmp_path):
        store = _store(tmp_path / "runtime.db")

        with pytest.raises(NestedRepositoryUse):
            store.users.transact(lambda view: store.clients.list())
        with pytest.raises(NestedRepositoryUse):
            store.users.transact(lambda view: store.repository("x", lambda u: u.username, PydanticCodec(User)))

    def test_the_stores_own_names_are_not_lent(self, tmp_path):
        store = _store(tmp_path / "runtime.db")

        for name in ("users", "clients"):
            with pytest.raises(ValueError, match="own repository"):
                store.repository(name, lambda u: u.username, PydanticCodec(User))

    def test_one_name_in_two_repositories_is_two_entries(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        others = store.repository("others", lambda user: user.username, PydanticCodec(User))
        store.users.create(User(username="same", password="pw", email="users@example.test"))
        others.create(User(username="same", password="pw", email="others@example.test"))

        assert store.users.get("same").email == "users@example.test"
        assert others.get("same").email == "others@example.test"
        assert others.transact(lambda view: view.entry("same").value.email) == "others@example.test"
        others.delete("same")
        assert store.users.get("same") is not None and others.get("same") is None

    def test_delete_all_is_of_one_repository(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        other = store.repository("others", lambda user: user.username, PydanticCodec(User))
        store.users.create(_user("a"))
        store.users.create(_user("b"))
        other.create(_user("c"))

        assert store.users.delete_all() == 2
        assert store.users.list() == [] and [user.username for user in other.list()] == ["c"]


class TestContention:
    def test_a_store_held_past_the_wait_is_unavailable_not_broken(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sqlite_module, "_BUSY_TIMEOUT_MS", 100)
        path = tmp_path / "runtime.db"
        store = _store(path)
        store.users.create(_user("alice"))
        holder = sqlite3.connect(path, isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        try:
            with pytest.raises(RuntimeStoreUnavailable, match="held by another process"):
                store.users.create(_user("bob"))
            # Readers are not held up by a writer in WAL.
            assert [user.username for user in store.users.list()] == ["alice"]
        finally:
            holder.execute("ROLLBACK")
            holder.close()

        assert store.users.create(_user("bob")).username == "bob"

    def test_an_error_that_is_not_contention_is_not_called_one(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        connection = store._database.connection()
        connection.execute("DROP TABLE entries")

        with pytest.raises(sqlite3.OperationalError) as raised:
            store.users.create(_user("alice"))
        assert not isinstance(raised.value, RuntimeStoreUnavailable)

    @pytest.mark.parametrize(
        "message, busy",
        [("database is locked", True), ("database table is locked", True), ("disk I/O error", False), ("no such table: x", False)],
    )
    def test_contention_is_told_by_its_code_or_before_311_by_its_message(self, message, busy):
        failure = sqlite3.OperationalError(message)

        assert sqlite_module._is_busy(failure) is busy

    def test_the_endpoints_say_come_back(self, client, monkeypatch):
        from nanoidp.services import auth_code

        def held(*args, **kwargs):
            raise RuntimeStoreUnavailable("the runtime store is held by another process")

        monkeypatch.setattr(auth_code.AuthCodeStore, "consume_code", held)
        response = client.post(
            "/token",
            data={"grant_type": "authorization_code", "code": "x", "redirect_uri": "http://localhost:3000/callback"},
            headers={"Authorization": "Basic ZGVtby1jbGllbnQ6ZGVtby1zZWNyZXQ="},
        )

        assert response.status_code == 503
        assert response.headers["Retry-After"]
        assert response.get_json()["error"] == "runtime_store_unavailable"

    def test_threads_each_have_their_connection_and_lose_nothing(self, tmp_path):
        users = _store(tmp_path / "runtime.db").users
        start = threading.Barrier(8)

        def many(index):
            start.wait()
            for number in range(25):
                users.create(_user(f"t{index}-{number}"))

        threads = [threading.Thread(target=many, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(users.list()) == 200

_FORK = pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")


# How long a step of these tests may take before it counts as stuck: each
# is bounded here, so that a gate left shut fails the test that shows it and
# never hangs the run.
_BOUND = 5


def _child_body(child):  # pragma: no cover - the child
    import signal

    code = 0
    try:
        signal.alarm(_BOUND)
        child()
    except BaseException:
        code = 3
    os._exit(code)


def _forked(child):
    """Run ``child`` in a forked process, bounded: a child that hangs is
    killed by its alarm and counts as a failure. Its exit code, 0 when it
    returned."""
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child
        _child_body(child)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def _within(action):
    """``action`` on a thread of its own, which must end within the bound:
    what it returned."""
    done = []
    worker = threading.Thread(target=lambda: done.append(action()), daemon=True)
    worker.start()
    worker.join(_BOUND)
    assert done, "stuck: the store never let the operation through"
    return done[0]


def _thread(target, *args):
    worker = threading.Thread(target=target, args=args, daemon=True)
    worker.start()
    return worker


def _rows(path):
    """What a connection of nobody else's sees, in order of creation."""
    connection = sqlite3.connect(path)
    try:
        return [row[0] for row in connection.execute("SELECT name FROM entries WHERE repository = 'users' ORDER BY seq")]
    finally:
        connection.close()


def _registered(database):
    return len(database._connections)


class TestAFork:
    """SQLite asks that no connection be open across a fork: a connection
    opened afresh in the child is not enough, since the child inherits the
    parent's bookkeeping of the file's locks, and a parent that then closes
    its connection believes it is the file's last user, checkpoints and
    deletes the WAL under the child. So every connection of the process is
    closed before a fork (an at-fork hook, once nothing is using one), and
    both sides open their own afterwards."""

    @_FORK
    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    def test_a_childs_commits_survive_the_parent_closing_its_connection(self, tmp_path):
        path = tmp_path / "runtime.db"
        store = _store(path)
        store.users.create(_user("parent"))
        assert store.users.list()  # a connection of the parent's, open at the fork
        first, then = os.pipe(), os.pipe()

        def child():
            store.users.create(_user("c1"))
            os.write(first[1], b"x")
            os.read(then[0], 1)
            store.users.create(_user("c2"))
            store.users.create(_user("c3"))
            assert [user.username for user in store.users.list()] == ["parent", "c1", "c2", "c3"]

        pid = os.fork()
        if pid == 0:  # pragma: no cover - the child
            os.close(first[0])
            os.close(then[1])
            _child_body(child)
        # A child that dies is an end of file here, not a wait.
        os.close(first[1])
        os.close(then[0])
        assert os.read(first[0], 1) == b"x"
        # The parent goes on, and closes its connection while the child is
        # still writing: what a parent does at its exit.
        _within(store.users.list)
        _within(lambda: store._database.connection().close())
        os.write(then[1], b"x")
        _, status = os.waitpid(pid, 0)

        assert os.waitstatus_to_exitcode(status) == 0
        assert _rows(path) == ["parent", "c1", "c2", "c3"]

    def test_before_a_fork_no_connection_of_any_store_is_open(self, tmp_path):
        stores = [_store(tmp_path / "a.db"), _store(tmp_path / "b.db")]
        opened = []

        def use(store):
            store.users.list()
            opened.append(store._database.connection())

        for store in stores:
            use(store)
            _thread(use, store).join(_BOUND)
        assert [_registered(store._database) for store in stores] == [2, 2]

        _within(sqlite_module._FORK_GATE.before_fork)
        try:
            assert [_registered(store._database) for store in stores] == [0, 0]
            for connection in opened:
                with pytest.raises(sqlite3.ProgrammingError):
                    connection.execute("SELECT 1")
        finally:
            sqlite_module._FORK_GATE.after_in_parent()

    def test_after_a_fork_every_thread_opens_a_connection_again(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        store.users.create(_user("before"))
        ready, go, done, seen = threading.Event(), threading.Event(), threading.Event(), []

        def worker():
            store.users.list()
            ready.set()
            go.wait(_BOUND)
            seen.append([user.username for user in store.users.list()])
            done.set()

        thread = _thread(worker)
        assert ready.wait(_BOUND)
        _within(sqlite_module._FORK_GATE.before_fork)
        sqlite_module._FORK_GATE.after_in_parent()
        _within(lambda: store.users.create(_user("after")))
        go.set()
        thread.join(_BOUND)

        assert seen == [["before", "after"]]

    def test_the_hook_waits_for_an_operation_in_progress(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        inside, release = threading.Event(), threading.Event()

        def decide(view):
            inside.set()
            release.wait(_BOUND)
            return view.create(_user("slow"))

        writer = _thread(store.users.transact, decide)
        assert inside.wait(_BOUND)
        forked = threading.Event()

        def fork_hook():
            sqlite_module._FORK_GATE.before_fork()
            forked.set()

        hook = _thread(fork_hook)
        try:
            assert not forked.wait(0.3)
            release.set()
            writer.join(_BOUND)
            assert forked.wait(_BOUND)
            assert _registered(store._database) == 0
        finally:
            hook.join(_BOUND)
            sqlite_module._FORK_GATE.after_in_parent()

        assert [user.username for user in _within(store.users.list)] == ["slow"]

    def test_an_operation_begun_during_the_fork_waits_for_it(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        store.users.create(_user("alice"))
        _within(sqlite_module._FORK_GATE.before_fork)
        finished = threading.Event()

        def read():
            store.users.list()
            finished.set()

        try:
            reader = _thread(read)
            assert not finished.wait(0.3)
            assert _registered(store._database) == 0
        finally:
            sqlite_module._FORK_GATE.after_in_parent()
        assert finished.wait(_BOUND)
        reader.join(_BOUND)

    def test_a_connection_being_opened_is_waited_for_and_closed(self, tmp_path, monkeypatch):
        store = _store(tmp_path / "runtime.db")
        database = store._database
        opening, release = threading.Event(), threading.Event()
        real_open = database._open

        def slow_open():
            opening.set()
            release.wait(_BOUND)
            return real_open()

        monkeypatch.setattr(database, "_open", slow_open)
        reader = _thread(store.users.list)
        assert opening.wait(_BOUND)
        forked = threading.Event()

        def fork_hook():
            sqlite_module._FORK_GATE.before_fork()
            forked.set()

        hook = _thread(fork_hook)
        try:
            assert not forked.wait(0.3)
            release.set()
            reader.join(_BOUND)
            assert forked.wait(_BOUND)
            assert _registered(database) == 0
        finally:
            hook.join(_BOUND)
            sqlite_module._FORK_GATE.after_in_parent()

    def test_a_store_being_opened_is_waited_for(self, tmp_path, monkeypatch):
        opening, release = threading.Event(), threading.Event()
        real_initialise = sqlite_module._Database._initialise

        def slow_initialise(database, created):
            opening.set()
            release.wait(_BOUND)
            return real_initialise(database, created)

        monkeypatch.setattr(sqlite_module._Database, "_initialise", slow_initialise)
        opener = _thread(_store, tmp_path / "runtime.db")
        assert opening.wait(_BOUND)
        forked = threading.Event()

        def fork_hook():
            sqlite_module._FORK_GATE.before_fork()
            forked.set()

        hook = _thread(fork_hook)
        try:
            assert not forked.wait(0.3)
            release.set()
            opener.join(_BOUND)
            assert forked.wait(_BOUND)
        finally:
            hook.join(_BOUND)
            sqlite_module._FORK_GATE.after_in_parent()

    @_FORK
    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    def test_a_child_uses_the_store_while_the_parent_is_forking_elsewhere(self, tmp_path):
        """The child's gate is its own: it is not left closed by the fork
        that made it."""
        path = tmp_path / "runtime.db"
        store = _store(path)
        store.users.create(_user("parent"))

        assert _forked(lambda: store.users.create(_user("child"))) == 0
        assert _rows(path) == ["parent", "child"]
        # And the parent's is open again.
        _within(lambda: store.users.create(_user("again")))
        assert _rows(path) == ["parent", "child", "again"]

    @_FORK
    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    def test_a_real_fork_leaves_no_connection_open(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        store.users.list()
        assert _registered(store._database) == 1

        assert _forked(lambda: None) == 0
        assert _registered(store._database) == 0

    def test_the_connection_of_a_thread_that_ended_is_closed(self, tmp_path):
        """The registry the hook closes from must not keep the connections
        of threads that are gone: a server that starts a thread per request
        would otherwise hold two descriptors per request until it forks."""
        store = _store(tmp_path / "runtime.db")
        left = []

        def request():
            store.users.list()
            left.append(store._database.connection())

        for _ in range(50):
            _thread(request).join(_BOUND)

        assert _registered(store._database) <= 1
        for connection in left[:-1]:
            with pytest.raises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

    def test_the_connection_of_a_thread_still_there_is_kept(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        ready, go = threading.Event(), threading.Event()
        kept = []

        def long_lived():
            store.users.list()
            kept.append(store._database.connection())
            ready.set()
            go.wait(_BOUND)
            kept.append(store._database.connection())

        worker = _thread(long_lived)
        assert ready.wait(_BOUND)
        for _ in range(5):
            _thread(store.users.list).join(_BOUND)
        go.set()
        worker.join(_BOUND)

        assert kept[0] is kept[1]
        kept[0].execute("SELECT 1")

    @_FORK
    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    def test_an_audit_append_in_progress_is_waited_for(self, tmp_path, monkeypatch):
        """The audit is the store's too, in a file of its own: a fork waits
        for an append in progress, closes the audit's connections with the
        store's, and the child appends and reads its own way."""
        store = _store(tmp_path / "runtime.db")
        audit = store.audit
        database = audit._database
        inside, release = threading.Event(), threading.Event()
        real_connection = database.connection

        def slow_connection():
            if not release.is_set():
                inside.set()
                release.wait(_BOUND)
            return real_connection()

        monkeypatch.setattr(database, "connection", slow_connection)
        writer = _thread(audit.append, _event(), ["logins"])
        assert inside.wait(_BOUND)
        forked = threading.Event()

        def fork_hook():
            sqlite_module._FORK_GATE.before_fork()
            forked.set()

        hook = _thread(fork_hook)
        try:
            assert not forked.wait(0.3)
            release.set()
            writer.join(_BOUND)
            assert forked.wait(_BOUND)
            assert _registered(database) == 0
        finally:
            hook.join(_BOUND)
            sqlite_module._FORK_GATE.after_in_parent()

        def child():
            audit.append(_event(), ["logins"])
            assert audit.counters() == {"logins": 2}
            assert len(audit.entries(10)) == 2

        assert _forked(child) == 0
        assert _within(audit.counters) == {"logins": 2}

    @pytest.mark.parametrize(
        "operation",
        [
            lambda audit: audit.append(_event(), ["n"]),
            lambda audit: audit.entries(10),
            lambda audit: audit.client_ids(),
            lambda audit: audit.counters(),
            lambda audit: audit.clear(),
        ],
        ids=["append", "entries", "client_ids", "counters", "clear"],
    )
    def test_every_operation_of_the_audit_is_waited_for(self, tmp_path, monkeypatch, operation):
        store = _store(tmp_path / "runtime.db")
        database = store.audit._database
        inside, release = threading.Event(), threading.Event()
        real_connection = database.connection

        def slow_connection():
            inside.set()
            release.wait(_BOUND)
            return real_connection()

        monkeypatch.setattr(database, "connection", slow_connection)
        caller = _thread(operation, store.audit)
        assert inside.wait(_BOUND)
        forked = threading.Event()

        def fork_hook():
            sqlite_module._FORK_GATE.before_fork()
            forked.set()

        hook = _thread(fork_hook)
        try:
            assert not forked.wait(0.3)
            release.set()
            caller.join(_BOUND)
            assert forked.wait(_BOUND)
        finally:
            hook.join(_BOUND)
            sqlite_module._FORK_GATE.after_in_parent()

    def test_a_close_that_fails_does_not_stop_the_hook(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        store.users.list()
        opened = store._database.connection()

        class Failing:
            def close(self):
                raise sqlite3.ProgrammingError("cannot close")

        store._database._connections[threading.Thread()] = Failing()

        _within(sqlite_module._FORK_GATE.before_fork)
        try:
            assert _registered(store._database) == 0
            with pytest.raises(sqlite3.ProgrammingError):
                opened.execute("SELECT 1")
        finally:
            sqlite_module._FORK_GATE.after_in_parent()

    def test_a_repository_being_lent_is_waited_for(self, tmp_path, monkeypatch):
        """Nothing a store locks is held by another thread at the fork: the
        child would inherit that lock taken, by a thread it does not have."""
        store = _store(tmp_path / "runtime.db")
        lending, release = threading.Event(), threading.Event()
        real_init = sqlite_module.SqliteRuntimeRepository.__init__

        def slow_init(repository, *args):
            lending.set()
            release.wait(_BOUND)
            real_init(repository, *args)

        monkeypatch.setattr(sqlite_module.SqliteRuntimeRepository, "__init__", slow_init)
        lender = _thread(store.repository, "codes", lambda user: user.username, PydanticCodec(User))
        assert lending.wait(_BOUND)
        forked = threading.Event()

        def fork_hook():
            sqlite_module._FORK_GATE.before_fork()
            forked.set()

        hook = _thread(fork_hook)
        try:
            assert not forked.wait(0.3)
            release.set()
            lender.join(_BOUND)
            assert forked.wait(_BOUND)
            assert not store._lock.locked()
        finally:
            hook.join(_BOUND)
            sqlite_module._FORK_GATE.after_in_parent()


class TestTheAudit:
    """The audit of the SQLite store: a file of its own, since a file has
    one writer and the audit must not wait for the repositories (#354, third
    step). Its contract runs in ``tests/test_audit_store.py`` over both
    backends; what is here is what only a file has."""

    @pytest.mark.parametrize(
        "store, audit",
        [
            ("/state/runtime.db", "/state/runtime-audit.db"),
            ("/state/runtime.sqlite3", "/state/runtime-audit.sqlite3"),
            ("/state/runtime", "/state/runtime-audit"),
        ],
    )
    def test_the_audits_file_is_named_after_the_stores(self, store, audit):
        from pathlib import Path

        assert sqlite_module.audit_path_of(Path(store)) == Path(audit)

    @pytest.mark.skipif(not _POSIX, reason="POSIX file modes")
    def test_the_store_is_a_pair_of_private_files(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "umask", os.umask)
        previous = os.umask(0o022)
        try:
            # Kept open while the sidecars are looked at.
            store = _store(tmp_path / "runtime.db")
            store.users.create(_user("alice"))
            store.audit.append(_event(), ["n"])
        finally:
            os.umask(previous)

        assert store.audit.path == tmp_path / "runtime-audit.db"
        for name in ("runtime-audit.db", "runtime-audit.db-wal", "runtime-audit.db-shm"):
            assert _mode(tmp_path / name) == 0o600, name

    def test_the_two_files_are_not_interchangeable(self, tmp_path):
        store = _store(tmp_path / "runtime.db")
        store.users.create(_user("alice"))
        store.audit.append(_event(), ["n"])

        with pytest.raises(RuntimeStoreFileRefused, match="not a NanoIDP runtime audit"):
            SqliteAuditStore(tmp_path / "runtime.db")
        with pytest.raises(RuntimeStoreFileRefused, match="not a NanoIDP runtime store"):
            # A store at the audit's file: its own audit would be elsewhere,
            # the store's file is the audit's.
            SqliteRuntimeStore(tmp_path / "runtime-audit.db")
        assert [user.username for user in store.users.list()] == ["alice"]
        assert store.audit.counters() == {"n": 1}

    def test_an_audit_of_another_schema_version_is_refused(self, tmp_path):
        _store(tmp_path / "runtime.db").audit.append(_event(), ["n"])
        connection = sqlite3.connect(tmp_path / "runtime-audit.db")
        connection.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        connection.commit()
        connection.close()

        with pytest.raises(RuntimeStoreFileRefused, match="schema version 99"):
            _store(tmp_path / "runtime.db")

    def test_a_sqlite_without_upsert_is_refused_before_any_file_is_made(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 23, 1))
        monkeypatch.setattr(sqlite3, "sqlite_version", "3.23.1")

        with pytest.raises(sqlite_module.RuntimeStoreUnsupported, match=r"SQLite >= 3\.24; running 3\.23\.1"):
            _store(tmp_path / "state" / "runtime.db")
        assert not (tmp_path / "state").exists() or list((tmp_path / "state").iterdir()) == []
        assert not issubclass(sqlite_module.RuntimeStoreUnsupported, RuntimeStoreFileRefused)

    @pytest.mark.parametrize(
        "details",
        [
            {"a set": {1}},
            {"a tuple": (1, 2)},
            {1: "a key that is no text"},
            {"nan": float("nan")},
            {"infinity": float("-inf")},
            {"deep": [{"when": dt.datetime(2026, 1, 1)}]},
        ],
        ids=["set", "tuple", "int-key", "nan", "infinity", "deep-datetime"],
    )
    def test_details_that_are_no_json_object_are_refused_before_the_write_lock(self, tmp_path, monkeypatch, details):
        """Outside the audit's domain, whatever the stress mode says: the
        details are a JSON object, and what JSON would change (a tuple into
        a list, a key into text) is no more by value than what it cannot
        write. Refused before BEGIN, so it never holds the file's lock."""
        monkeypatch.setattr(RepositorySwitches, "verify_codecs", False)
        audit = _store(tmp_path / "runtime.db").audit
        audit.append(_event(), ["n"])
        statements = []
        audit._database.connection().set_trace_callback(statements.append)

        with pytest.raises(ValueError, match="JSON object"):
            audit.append(_event(details=details), ["n"])

        assert not any(statement.startswith("BEGIN") for statement in statements)
        assert audit.counters() == {"n": 1}
        assert len(audit.entries(10)) == 1

    def test_in_the_stress_mode_a_codec_that_loses_a_field_is_refused(self, tmp_path, monkeypatch):
        """This backend always writes the event down; the switch adds the
        reading back, which is what catches a codec that is wrong."""
        from nanoidp.services.audit_store import AuditEntryCodec

        audit = _store(tmp_path / "runtime.db").audit
        dump = AuditEntryCodec.dump
        monkeypatch.setattr(AuditEntryCodec, "dump", lambda codec, value: {**dump(codec, value), "details": {}})

        with pytest.raises(ValueError, match="comes back changed"):
            audit.append(_event(details={"kept": "no"}), ["n"])
        assert audit.counters() == {}

        monkeypatch.setattr(RepositorySwitches, "verify_codecs", False)
        audit.append(_event(details={"kept": "no"}), ["n"])
        assert audit.entries(1)[0].details == {}

    def test_the_bound_is_the_files_and_a_process_with_another_is_refused(self, tmp_path):
        """The audit is one for every process that opens its file, and so is
        its bound: one process keeping ten would cut the history of one
        keeping a thousand, and read it cut."""
        audit = SqliteAuditStore(tmp_path / "audit.db", max_entries=1000)
        for number in range(20):
            audit.append(_event(f"e{number}"), ["n"])

        with pytest.raises(RuntimeStoreFileRefused, match="a bound of 1000") as refused:
            SqliteAuditStore(tmp_path / "audit.db", max_entries=10)
        # The one way out: nobody gives a bound to the store's own audit.
        assert "disposable: delete the file (and its -wal and -shm)" in str(refused.value)
        assert len(SqliteAuditStore(tmp_path / "audit.db", max_entries=1000).entries(10**6)) == 20
        assert len(audit.entries(10**6)) == 20

    @pytest.mark.parametrize(
        "refused",
        ["audit is a directory", "audit is somebody else's", "store is somebody else's"],
    )
    def test_a_file_that_is_refused_leaves_no_new_file_behind(self, tmp_path, refused):
        """What exists is opened first and what is missing made after, so a
        refusal of either file makes neither."""
        store_path, audit_path = tmp_path / "runtime.db", tmp_path / "runtime-audit.db"
        if refused == "audit is a directory":
            audit_path.mkdir()
        foreign = audit_path if refused == "audit is somebody else's" else store_path
        if refused != "audit is a directory":
            connection = sqlite3.connect(foreign)
            connection.execute("CREATE TABLE theirs (x)")
            connection.commit()
            connection.close()
        before = sorted(path.name for path in tmp_path.iterdir())

        with pytest.raises(RuntimeStoreFileRefused):
            _store(store_path)

        assert sorted(path.name for path in tmp_path.iterdir()) == before

    def test_a_bound_that_is_refused_makes_no_file(self, tmp_path):
        with pytest.raises(ValueError, match="bound"):
            SqliteAuditStore(tmp_path / "audit.db", max_entries=-1)

        assert list(tmp_path.iterdir()) == []

    def test_an_append_is_one_transaction(self, tmp_path):
        """The event, the bound and the counters, or nothing: a counter that
        cannot be written takes the event back with it."""
        audit = _store(tmp_path / "runtime.db").audit
        audit.append(_event("before"), ["n"])
        audit._database.connection().execute("DROP TABLE counters")

        with pytest.raises(sqlite3.OperationalError):
            audit.append(_event("lost"), ["n"])

        assert [entry.event_type for entry in audit.entries(10)] == ["before"]

    def test_the_bound_is_kept_in_the_append(self, tmp_path):
        audit = SqliteAuditStore(tmp_path / "audit.db", max_entries=3)
        for number in range(10):
            audit.append(_event(f"e{number}"), ["n"])

        rows = sqlite3.connect(tmp_path / "audit.db").execute("SELECT count(*) FROM events").fetchone()[0]
        assert rows == 3
        assert [entry.event_type for entry in audit.entries(10)] == ["e9", "e8", "e7"]
        assert audit.counters() == {"n": 10}

    def test_the_audit_is_held_past_the_wait_is_unavailable(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sqlite_module, "_BUSY_TIMEOUT_MS", 100)
        audit = _store(tmp_path / "runtime.db").audit
        audit.append(_event("kept"), ["n"])
        holder = sqlite3.connect(tmp_path / "runtime-audit.db", isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        try:
            with pytest.raises(RuntimeStoreUnavailable, match="held by another process"):
                audit.append(_event("waited"), ["n"])
            with pytest.raises(RuntimeStoreUnavailable):
                audit.clear()
            # Readers are not held up by a writer in WAL.
            assert [entry.event_type for entry in audit.entries(10)] == ["kept"]
            assert audit.counters() == {"n": 1}
        finally:
            holder.execute("ROLLBACK")
            holder.close()

    def test_an_error_of_the_audit_that_is_not_contention_is_not_called_one(self, tmp_path):
        audit = _store(tmp_path / "runtime.db").audit
        audit._database.connection().execute("DROP TABLE events")

        for operation in (lambda: audit.append(_event(), ["n"]), lambda: audit.entries(10), audit.client_ids):
            with pytest.raises(sqlite3.OperationalError) as raised:
                operation()
            assert not isinstance(raised.value, RuntimeStoreUnavailable)

    def test_the_audit_is_one_across_processes(self, tmp_path):
        """Four processes append at once: every event counted once, the
        bound kept for all of them, and each process's events in the order
        it appended them."""
        path = str(tmp_path / "runtime.db")
        # The audit exists, with the bound the contenders are given, before
        # they open it.
        SqliteAuditStore(tmp_path / "runtime-audit.db", max_entries=500)
        results = _in_processes(_append_many, [(path, index) for index in range(4)])

        assert results == [("ok", 150)] * 4
        audit = SqliteAuditStore(tmp_path / "runtime-audit.db", max_entries=500)
        assert audit.counters() == {"n": 600}
        kept = audit.entries(1000)
        assert len(kept) == 500
        for index in range(4):
            mine = [int(entry.details["i"]) for entry in kept if entry.username == f"p{index}"]
            assert mine == sorted(mine, reverse=True)


def _event(event_type="login", **more):
    from nanoidp.services.audit_store import AuditEntry

    fields = {
        "timestamp": dt.datetime(2026, 9, 21, tzinfo=dt.timezone.utc),
        "event_type": event_type,
        "username": "alice",
        "client_id": None,
        "ip_address": "127.0.0.1",
        "user_agent": "test",
        "endpoint": "/login",
        "method": "POST",
        "status": "success",
    }
    return AuditEntry(**{**fields, **more})


def _append_many(path, index, barrier, out):
    import logging

    logging.disable(logging.CRITICAL)
    from nanoidp.services.sqlite_runtime_store import SqliteAuditStore

    barrier.wait()
    try:
        audit = SqliteAuditStore(__import__("pathlib").Path(path).with_name("runtime-audit.db"), max_entries=500)
        for number in range(150):
            audit.append(_event(username=f"p{index}", details={"i": number}), ["n"])
        out.put(("ok", 150))
    except BaseException as failure:  # noqa: BLE001 - said to the parent
        out.put(("raised", repr(failure)))


def _open_and_create(path, name, barrier, out):
    import logging

    logging.disable(logging.CRITICAL)
    from nanoidp.config import User
    from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

    barrier.wait()
    try:
        SqliteRuntimeStore(path).users.create(User(username=name, password="pw"))
        out.put(("ok", name))
    except BaseException as failure:  # noqa: BLE001 - said to the parent
        out.put(("raised", repr(failure)))


def _in_processes(target, argument_lists):
    barrier, out = _SPAWN.Barrier(len(argument_lists)), _SPAWN.Queue()
    processes = [
        _SPAWN.Process(target=target, args=(*arguments, barrier, out), daemon=True) for arguments in argument_lists
    ]
    for process in processes:
        process.start()
    try:
        return [out.get(timeout=120) for _ in processes]
    finally:
        for process in processes:
            process.join(10)
            if process.is_alive():
                process.terminate()


def _race(path, operation, barrier, out):
    """One contender in another process: the store published as the
    process's, then the operation of a service, as a request would run it."""
    import logging

    logging.disable(logging.CRITICAL)
    from nanoidp.services import runtime_store
    from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

    runtime_store.publish_runtime_store(SqliteRuntimeStore(path), ("sqlite", path))
    barrier.wait()
    try:
        out.put(("ok", _OPERATIONS[operation]()))
    except BaseException as failure:  # noqa: BLE001
        out.put(("raised", repr(failure)))


def _redeem():
    from nanoidp.services.auth_code import get_auth_code_store

    code = open(os.environ["NANOIDP_RACE_CODE"]).read()
    return get_auth_code_store().consume_code(code, "demo-client", "http://localhost:3000/callback") is not None


def _claim_refresh():
    from nanoidp.services.revocation import get_revocation_store

    return get_revocation_store().check_and_claim_refresh("jti-1", "family-1", rotate=True)


def _create_within_the_cap():
    from nanoidp.config import User
    from nanoidp.services.runtime_repository import PydanticCodec, RepositoryFull
    from nanoidp.services.runtime_store import get_runtime_store

    capped = get_runtime_store().repository("capped", lambda user: user.username, PydanticCodec(User))
    made = 0
    for number in range(10):
        try:
            create_within(capped, User(username=f"{os.getpid()}-{number}", password="pw"), 5, full=RepositoryFull("full"))
            made += 1
        except RepositoryFull:
            pass
    return made


def _hold():
    from nanoidp.services.runtime_store import get_runtime_store

    try:
        get_runtime_store().users.transact(lambda view: view.hold("contended", {"by": os.getpid()}))
        return True
    except EntryHeld:
        return False


def _consume():
    from nanoidp.services.runtime_store import get_runtime_store

    return consume(get_runtime_store().users, "once") is not None


_OPERATIONS = {
    "redeem": _redeem,
    "claim_refresh": _claim_refresh,
    "create_within": _create_within_the_cap,
    "hold": _hold,
    "consume": _consume,
}


class TestAtomicAcrossProcesses:
    """The compositions #410 to #416 pinned within one process, with the
    contenders in different processes over one file."""

    CONTENDERS = 4

    def _race(self, path, operation):
        results = _in_processes(_race, [(str(path), operation)] * self.CONTENDERS)
        assert all(kind == "ok" for kind, _ in results), results
        return [value for _, value in results]

    def test_an_authorization_code_is_redeemed_once(self, tmp_path, monkeypatch):
        from nanoidp.services import runtime_store
        from nanoidp.services.auth_code import get_auth_code_store

        path = tmp_path / "runtime.db"
        runtime_store.publish_runtime_store(_store(path), ("sqlite", str(path)))
        code = get_auth_code_store().create_code(
            client_id="demo-client", redirect_uri="http://localhost:3000/callback", username="alice"
        )
        (tmp_path / "code").write_text(code)
        monkeypatch.setenv("NANOIDP_RACE_CODE", str(tmp_path / "code"))

        assert sorted(self._race(path, "redeem")) == [False, False, False, True]

    def test_a_refresh_token_is_claimed_once(self, tmp_path):
        results = self._race(tmp_path / "runtime.db", "claim_refresh")

        assert sorted(results) == [False, True, True, True], "one claims it, the others see its reuse"

    def test_a_cap_is_never_exceeded(self, tmp_path):
        path = tmp_path / "runtime.db"

        made = self._race(path, "create_within")

        assert sum(made) == 5
        assert len(_store(path).repository("capped", lambda user: user.username, PydanticCodec(User)).list()) == 5

    def test_an_entry_is_held_by_one(self, tmp_path):
        path = tmp_path / "runtime.db"
        _store(path).users.create(_user("contended"))

        assert sorted(self._race(path, "hold")) == [False, False, False, True]
        hold = _store(path).users.entry("contended").hold
        assert hold is not None and json.dumps(hold.payload)

    def test_an_entry_is_consumed_once(self, tmp_path):
        path = tmp_path / "runtime.db"
        _store(path).users.create(_user("once"))

        assert sorted(self._race(path, "consume")) == [False, False, False, True]
        assert _store(path).users.list() == []
