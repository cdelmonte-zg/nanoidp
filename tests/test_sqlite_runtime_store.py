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

import json
import multiprocessing
import os
import sqlite3
import stat
import threading

import pytest

from nanoidp.config import User
from nanoidp.services import sqlite_runtime_store as sqlite_module
from nanoidp.services.audit_store import MemoryAuditStore
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
from nanoidp.services.sqlite_runtime_store import RuntimeStoreFileRefused, SqliteRuntimeStore

_SPAWN = multiprocessing.get_context("spawn")
_POSIX = os.name == "posix"


def _store(path):
    return SqliteRuntimeStore(path, MemoryAuditStore())


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
            _store(path).users.create(_user("alice"))
        finally:
            os.umask(previous)

        for name in ("runtime.db", "runtime.db-wal", "runtime.db-shm"):
            assert _mode(tmp_path / name) == 0o600, name

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

        assert seen == [0o600]

    @pytest.mark.skipif(not _POSIX, reason="POSIX file modes")
    def test_a_store_that_is_there_already_is_made_private(self, tmp_path):
        path = tmp_path / "runtime.db"
        _store(path).users.create(_user("alice"))
        for name in ("runtime.db", "runtime.db-wal", "runtime.db-shm"):
            if (tmp_path / name).exists():
                (tmp_path / name).chmod(0o644)

        _store(path)

        for name in ("runtime.db", "runtime.db-wal", "runtime.db-shm"):
            if (tmp_path / name).exists():
                assert _mode(tmp_path / name) == 0o600, name

    def test_wal_is_the_journal(self, tmp_path):
        path = tmp_path / "runtime.db"
        _store(path)

        assert sqlite3.connect(path).execute("PRAGMA journal_mode").fetchone()[0] == "wal"

    def test_processes_opening_a_new_file_together_all_get_one_store(self, tmp_path):
        path = str(tmp_path / "runtime.db")
        results = _in_processes(_open_and_create, [(path, f"u{index}") for index in range(4)])

        assert [kind for kind, _ in results] == ["ok"] * 4, results
        assert sorted(user.username for user in _store(path).users.list()) == ["u0", "u1", "u2", "u3"]


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

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
    def test_a_forked_child_uses_a_connection_of_its_own(self, tmp_path):
        path = tmp_path / "runtime.db"
        store = _store(path)
        store.users.create(_user("parent"))
        parent_connection = store._database.connection()

        pid = os.fork()
        if pid == 0:  # pragma: no cover - the child
            code = 0
            try:
                if store._database.connection() is parent_connection:
                    code = 2
                store.users.create(_user("child"))
            except BaseException:
                code = 3
            os._exit(code)
        _, status = os.waitpid(pid, 0)

        assert os.waitstatus_to_exitcode(status) == 0
        assert sorted(user.username for user in store.users.list()) == ["child", "parent"]


def _open_and_create(path, name, barrier, out):
    import logging

    logging.disable(logging.CRITICAL)
    from nanoidp.config import User
    from nanoidp.services.audit_store import MemoryAuditStore
    from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

    barrier.wait()
    try:
        SqliteRuntimeStore(path, MemoryAuditStore()).users.create(User(username=name, password="pw"))
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
    from nanoidp.services.audit_store import MemoryAuditStore
    from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

    runtime_store.publish_runtime_store(SqliteRuntimeStore(path, MemoryAuditStore()), ("sqlite", path))
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
