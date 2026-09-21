"""The audit behind the runtime boundary (#363, step 5).

``AuditLog`` is a facade with no state; the events and their counters are the
runtime store's, in an ``AuditStore``: a contract of its own, not a
``RuntimeRepository``. The first class is about what a caller of the facade
sees, and most of it fails on the ``AuditLog`` that kept a deque: the order of
the appends, a negative limit, state that is by value. The second is the
contract of the store, over every backend: in memory, and in a SQLite file
of its own (#354, third step), whose file, contention and fork are pinned in
``tests/test_sqlite_runtime_store.py``.
"""

import datetime as dt
import threading

import pytest

from nanoidp.config import init_config
from nanoidp.hooks import HOOK_API_VERSION, SOURCE_SETTINGS
from nanoidp.services import audit as audit_module
from nanoidp.services.audit import AuditLog, get_audit_log

NOON = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.timezone.utc)


def _log(name, log=None, **more):
    (log or get_audit_log()).log(name, "/e", "GET", more.pop("status", "success"), **more)


def _names(entries):
    return [entry["event_type"] for entry in entries]


@pytest.fixture
def clock(monkeypatch):
    """The timestamps the next events get, in order."""

    def set_to(*moments):
        remaining = list(moments)

        class _Clock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return remaining.pop(0) if len(remaining) > 1 else remaining[0]

        monkeypatch.setattr(audit_module, "datetime", _Clock)

    return set_to


class TestTheFacade:
    def test_two_views_are_one_log(self):
        _log("e0", AuditLog())

        assert _names(AuditLog().get_entries()) == ["e0"]
        assert get_audit_log().get_stats()["total_requests"] == 1

    def test_the_log_is_the_runtime_stores(self):
        from nanoidp.services import runtime_store

        _log("e0")
        runtime_store._runtime_store = None

        assert get_audit_log().get_entries() == []
        assert get_audit_log().get_stats()["total_requests"] == 0

    def test_events_of_one_timestamp_come_newest_first(self, clock):
        clock(NOON)
        for name in ("e0", "e1", "e2"):
            _log(name)

        assert _names(get_audit_log().get_entries()) == ["e2", "e1", "e0"]

    def test_a_clock_that_steps_back_does_not_reorder(self, clock):
        clock(NOON, NOON - dt.timedelta(minutes=1), NOON + dt.timedelta(minutes=1))
        for name in ("e0", "e1", "e2"):
            _log(name)

        entries = get_audit_log().get_entries()
        assert _names(entries) == ["e2", "e1", "e0"]
        assert [entry["timestamp"][11:16] for entry in entries] == ["12:01", "11:59", "12:00"]

    def test_the_limit_and_the_filters_are_of_that_order(self):
        _log("a", username="alice", client_id="c1")
        _log("b", username="bob", client_id="c1")
        _log("a", username="bob", client_id="c2")
        _log("a", username="alice", client_id="c2")
        log = get_audit_log()

        assert [e["username"] for e in log.get_entries(event_type="a", limit=2)] == ["alice", "bob"]
        # The limit is of what matches, not of what is looked at: the one "b"
        # is the third newest.
        assert [e["username"] for e in log.get_entries(event_type="b", limit=1)] == ["bob"]
        assert _names(log.get_entries(username="bob")) == ["a", "b"]
        assert [e["username"] for e in log.get_entries(client_id="c1")] == ["bob", "alice"]
        assert len(log.get_entries(event_type="a", username="alice", client_id="c2")) == 1
        # Nothing to filter by is no filter, as it always was.
        assert len(log.get_entries(event_type="", username="", client_id="")) == 4

    @pytest.mark.parametrize("limit, kept", [(-1, 0), (-100, 0), (0, 0), (2, 2), (100, 3)])
    def test_a_negative_limit_is_none_at_all(self, limit, kept):
        """It was a slice: -1 meant "all but the last", and means "no limit"
        to SQLite."""
        for name in ("e0", "e1", "e2"):
            _log(name)

        assert len(get_audit_log().get_entries(limit=limit)) == kept

    def test_what_the_caller_does_with_its_details_afterwards_is_its_own(self):
        details = {"k": ["v"]}
        _log("e", details=details)
        details["k"].append("later")
        details["more"] = True

        assert get_audit_log().get_entries()[0]["details"] == {"k": ["v"]}

    def test_what_a_reader_does_with_an_entry_is_its_own(self):
        _log("e", details={"k": ["v"]})
        read = get_audit_log().get_entries()[0]
        read["details"]["k"].append("tampered")
        read["event_type"] = "other"

        assert get_audit_log().get_entries()[0] == {**read, "event_type": "e", "details": {"k": ["v"]}}

    def test_what_a_hook_does_with_its_event_is_its_own(self, tmp_path):
        seen = []

        class Meddling:
            hook_api_version = HOOK_API_VERSION

            def on_audit_event(self, event):
                seen.append(event["event_type"])
                event["details"]["k"].append("from the hook")
                event["details"]["more"] = True

        (tmp_path / "settings.yaml").write_text("{}")
        (tmp_path / "users.yaml").write_text("users: {}")
        config = init_config(str(tmp_path))
        config.hooks.register_plugin_object("meddling", Meddling(), SOURCE_SETTINGS)

        details = {"k": ["v"]}
        _log("e", details=details)

        assert seen == ["e"]
        assert get_audit_log().get_entries(event_type="e")[0]["details"] == {"k": ["v"]}
        # Nor the caller's: the event a hook gets is nobody else's.
        assert details == {"k": ["v"]}

    def test_a_plugin_that_cannot_even_be_asked_does_not_fail_the_event(self, tmp_path):
        """Asking who listens touches the plugins. One that raises there is
        one more hook that is unavailable: the event is kept, and logging it
        raises nothing."""

        class Unaskable:
            hook_api_version = HOOK_API_VERSION

            def __getattr__(self, name):
                if name == "on_audit_event":
                    raise RuntimeError("cannot even be asked")
                raise AttributeError(name)

        (tmp_path / "settings.yaml").write_text("{}")
        (tmp_path / "users.yaml").write_text("users: {}")
        config = init_config(str(tmp_path))
        config.hooks.register_plugin_object("unaskable", Unaskable(), SOURCE_SETTINGS)

        _log("e")

        assert _names(get_audit_log().get_entries(event_type="e")) == ["e"]

    def test_the_counters_outlive_the_events_they_counted(self, monkeypatch):
        from nanoidp.services import audit_store

        monkeypatch.setattr(audit_store, "MAX_AUDIT_ENTRIES", 2)
        for name in ("e0", "e1", "e2"):
            _log(name)

        assert _names(get_audit_log().get_entries()) == ["e2", "e1"]
        assert get_audit_log().get_stats()["total_requests"] == 3

    def test_the_stats_have_their_shape_before_the_first_event(self):
        assert get_audit_log().get_stats() == {
            "total_requests": 0,
            "token_requests": 0,
            "saml_sso_requests": 0,
            "saml_attribute_queries": 0,
            "login_attempts": 0,
            "successful_logins": 0,
            "failed_logins": 0,
        }

    def test_which_event_counts_as_what(self):
        _log("token_request")
        _log("saml_request")
        _log("saml_attribute_query")
        _log("login")
        _log("login", status="failed")
        _log("login", status="anything but success")
        _log("something else")

        assert get_audit_log().get_stats() == {
            "total_requests": 7,
            "token_requests": 1,
            "saml_sso_requests": 1,
            "saml_attribute_queries": 1,
            "login_attempts": 3,
            "successful_logins": 1,
            "failed_logins": 2,
        }

    def test_the_stats_are_the_readers_own(self):
        _log("login")
        get_audit_log().get_stats()["login_attempts"] = 99

        assert get_audit_log().get_stats()["login_attempts"] == 1

    def test_the_client_ids_are_of_the_events_kept(self, monkeypatch):
        from nanoidp.services import audit_store

        monkeypatch.setattr(audit_store, "MAX_AUDIT_ENTRIES", 4)
        _log("e", client_id="evicted")
        _log("e", client_id="alpha")
        _log("e")
        _log("e", client_id="zeta")
        _log("e", client_id="alpha")

        assert get_audit_log().get_unique_client_ids() == ["alpha", "zeta"]

    def test_clear_forgets_the_events_and_the_counters(self):
        _log("login", client_id="c")
        get_audit_log().clear()

        assert get_audit_log().get_entries() == []
        assert get_audit_log().get_unique_client_ids() == []
        assert get_audit_log().get_stats()["total_requests"] == 0
        _log("after")
        assert _names(get_audit_log().get_entries()) == ["after"]

    def test_a_runtime_reset_leaves_the_audit(self, client):
        _log("before")

        assert client.delete("/api/runtime").status_code == 200

        assert "before" in _names(get_audit_log().get_entries())

    def test_nothing_is_lost_or_counted_twice_under_a_race(self):
        def many():
            for _ in range(200):
                _log("login")

        threads = [threading.Thread(target=many) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        stats = get_audit_log().get_stats()
        assert (stats["total_requests"], stats["login_attempts"], stats["successful_logins"]) == (1600, 1600, 1600)
        assert len(get_audit_log().get_entries(limit=5000)) == 1000


def _memory_audit(tmp_path, **kwargs):
    from nanoidp.services.audit_store import MemoryAuditStore

    return MemoryAuditStore(**kwargs)


def _sqlite_audit(tmp_path, **kwargs):
    from nanoidp.services.sqlite_runtime_store import SqliteAuditStore

    return SqliteAuditStore(tmp_path / f"audit-{len(list(tmp_path.iterdir()))}.db", **kwargs)


class TestTheStore:
    """The contract, on every backend."""

    @pytest.fixture(autouse=True, params=[_memory_audit, _sqlite_audit], ids=["memory", "sqlite"])
    def _backend(self, request, tmp_path):
        self.backend = request.param.__name__
        self._make = lambda **kwargs: request.param(tmp_path, **kwargs)

    def _store(self, **kwargs):
        return self._make(**kwargs)

    def _memory_only(self, why):
        if self.backend != "_memory_audit":
            pytest.skip(why)

    @staticmethod
    def _entry(name="e", **more):
        from nanoidp.services.audit_store import AuditEntry

        fields = {
            "timestamp": NOON,
            "event_type": name,
            "username": None,
            "client_id": None,
            "ip_address": "unknown",
            "user_agent": "unknown",
            "endpoint": "/e",
            "method": "GET",
            "status": "success",
        }
        return AuditEntry(**{**fields, **more})

    def test_the_event_and_its_counters_are_one_step(self):
        store = self._store()
        seen = []
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                seen.append((len(store.entries(5000)), store.counters().get("n", 0)))

        watching = threading.Thread(target=reader, daemon=True)
        watching.start()
        try:
            for _ in range(300):
                store.append(self._entry(), ["n"])
        finally:
            # A failing append must not leave the reader running.
            stop.set()
            watching.join(5)

        # Read one after the other, so the count may be ahead of the events
        # it was read after, never behind them.
        assert all(counted >= events for events, counted in seen)
        assert store.counters() == {"n": 300}

    def test_only_what_was_incremented_is_a_counter(self):
        store = self._store()
        store.append(self._entry(), ["a", "b"])
        store.append(self._entry(), ["a"])
        store.append(self._entry(), [])

        assert store.counters() == {"a": 2, "b": 1}
        assert len(store.entries(10)) == 3
        store.counters()["a"] = 99  # the reader's own
        assert store.counters() == {"a": 2, "b": 1}

    def test_a_name_given_twice_counts_twice(self):
        store = self._store()
        store.append(self._entry(), ["a", "a", "b"])

        assert store.counters() == {"a": 2, "b": 1}

    def test_the_order_is_the_order_of_the_appends_not_of_the_timestamps(self):
        store = self._store()
        later, earlier = NOON + dt.timedelta(hours=1), NOON - dt.timedelta(hours=1)
        store.append(self._entry("first", timestamp=later), [])
        store.append(self._entry("second", timestamp=earlier), [])
        store.append(self._entry("third", timestamp=later), [])

        assert [entry.event_type for entry in store.entries(10)] == ["third", "second", "first"]
        assert [entry.event_type for entry in store.entries(2)] == ["third", "second"]
        assert store.entries(0) == []

    def test_the_filters_are_all_applied_and_the_limit_counts_what_matches(self):
        store = self._store()
        store.append(self._entry("login", username="alice", client_id="a"), [])
        store.append(self._entry("token", username="bob", client_id="b"), [])
        store.append(self._entry("token", username="alice", client_id="b"), [])
        store.append(self._entry("token", username="alice", client_id="a"), [])

        def seen(limit=10, **filters):
            return [(entry.event_type, entry.username, entry.client_id) for entry in store.entries(limit, **filters)]

        assert seen(event_type="login") == [("login", "alice", "a")]
        assert seen(username="bob") == [("token", "bob", "b")]
        assert seen(client_id="a") == [("token", "alice", "a"), ("login", "alice", "a")]
        assert seen(event_type="token", username="alice", client_id="b") == [("token", "alice", "b")]
        assert seen(1, username="alice") == [("token", "alice", "a")]
        assert seen(event_type="nothing") == []

    def test_client_ids_are_the_distinct_ones_kept_sorted(self):
        # Kept, in the order of the appends: None, "zeta", "", "alpha".
        store = self._store(max_entries=4)
        for client_id in ("gone", "alpha", None, "zeta", "", "alpha"):
            store.append(self._entry(client_id=client_id), [])

        assert store.client_ids() == ["alpha", "zeta"]

    def test_clear_forgets_the_events_and_the_counters(self):
        store = self._store()
        store.append(self._entry(), ["n"])
        store.clear()

        assert (store.entries(10), store.counters(), store.client_ids()) == ([], {}, [])
        store.append(self._entry("after"), ["n"])
        assert [entry.event_type for entry in store.entries(10)] == ["after"]
        assert store.counters() == {"n": 1}

    def test_an_append_that_is_refused_counts_nothing(self):
        store = self._store()

        with pytest.raises(TypeError):
            store.append(self._entry(), ["fine", 5])
        with pytest.raises(TypeError):
            store.append(self._entry(), "a-string-is-not-a-list-of-names")
        with pytest.raises(TypeError):
            store.append({"event_type": "not an entry"}, [])

        assert store.counters() == {}
        assert store.entries(10) == []

    @pytest.fixture
    def runtime_of_the_backend(self, tmp_path):
        """The runtime store the facade reaches, of this backend."""
        if self.backend == "_memory_audit":
            return
        from nanoidp.services import runtime_store
        from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("sqlite", str(tmp_path)))

    @pytest.mark.parametrize("limit", [-1, 1.5, "3", None, True])
    def test_a_limit_is_a_whole_number_not_below_zero(self, limit):
        with pytest.raises(ValueError):
            self._store().entries(limit)

    def test_a_limit_beyond_anything_kept_gives_everything_kept(self):
        store = self._store()
        store.append(self._entry("e0"), [])
        store.append(self._entry("e1"), [])

        assert [entry.event_type for entry in store.entries(10**20)] == ["e1", "e0"]
        assert [entry.event_type for entry in store.entries(10**20, event_type="e0")] == ["e0"]

    @pytest.mark.parametrize("bound", [-1, True, 1.5, "3", 10**20])
    def test_a_bound_is_a_whole_number_not_below_zero_and_one_that_can_be_kept(self, bound):
        with pytest.raises(ValueError, match="bound"):
            self._store(max_entries=bound)

    def test_a_bound_of_zero_keeps_nothing_and_counts_all(self):
        store = self._store(max_entries=0)
        store.append(self._entry(), ["n"])

        assert (store.entries(10), store.counters()) == ([], {"n": 1})

    def test_the_bound_is_the_backends_and_drops_the_oldest(self):
        store = self._store(max_entries=2)
        for name in ("e0", "e1", "e2"):
            store.append(self._entry(name), ["n"])

        assert [entry.event_type for entry in store.entries(10)] == ["e2", "e1"]
        assert store.counters() == {"n": 3}

    def test_entries_are_kept_and_given_by_value(self):
        store = self._store()
        entry = self._entry(details={"k": ["v"], "deep": [{"a": ["x"]}]})
        store.append(entry, [])
        entry.details["k"].append("later")
        entry.details["deep"][0]["a"].append("later")
        entry.event_type = "changed"
        read = store.entries(1)[0]
        read.details["k"].append("tampered")
        read.details["deep"][0]["a"].append("tampered")

        assert store.entries(1)[0] == self._entry(details={"k": ["v"], "deep": [{"a": ["x"]}]})

    def test_the_memory_backend_also_copies_what_json_cannot_hold(self, monkeypatch):
        """Not the contract: the details of an event are a JSON object, and a
        backend that writes them down refuses anything else. That the
        in-memory backend, outside the stress mode, copies a set or a tuple
        all the same is its own extra behaviour, which no caller may ask of
        another backend."""
        from nanoidp.services.runtime_repository import RepositorySwitches

        self._memory_only("the in-memory backend's own behaviour, not the contract")
        monkeypatch.setattr(RepositorySwitches, "verify_codecs", False)
        store = self._store()
        scopes, nested = {"openid"}, ({"k": ["v"]},)
        store.append(self._entry(details={"scopes": scopes, "nested": nested}), [])
        scopes.add("later")
        nested[0]["k"].append("later")
        store.entries(1)[0].details["scopes"].add("tampered")

        assert store.entries(1)[0].details == {"scopes": {"openid"}, "nested": ({"k": ["v"]},)}

    def test_a_reader_does_not_hold_the_lock_while_it_looks(self):
        """Every request appends. A read takes the lock for a snapshot and
        filters outside it."""
        self._memory_only("the lock of the in-memory backend; SQLite reads without one")
        store = self._store()
        held = []

        class Watching(str):
            def __ne__(self, other):
                held.append(store._lock.locked())
                return str.__ne__(self, other)

        for _ in range(3):
            store.append(self._entry(Watching("e")), [])

        assert len(store.entries(10, event_type="e")) == 3
        assert held == [False, False, False]
        assert store.client_ids() == []

    def test_an_entry_that_does_not_survive_its_codec_is_refused_in_the_stress_mode(self):
        from nanoidp.services.runtime_repository import RepositorySwitches

        store = self._store()
        assert RepositorySwitches.verify_codecs, "the suite runs with it on, one switch for every store"

        unwritable_details = (
            {"when": NOON},
            {"a set": {1}},
            {"nan": float("nan")},
            {"infinity": float("inf")},
            {1: "a key that is no text"},
        )
        for unwritable in unwritable_details:
            with pytest.raises(ValueError, match="does not survive its codec"):
                store.append(self._entry(details=unwritable), ["n"])

        assert store.counters() == {} and store.entries(10) == []

    def test_the_codec_writes_plain_json_and_reads_it_back(self):
        import json

        from nanoidp.services.audit_store import AuditEntryCodec

        entry = self._entry(username="alice", details={"nested": {"list": [1, "two", None, True]}})
        written = json.loads(json.dumps(AuditEntryCodec().dump(entry), allow_nan=False))

        assert written["timestamp"] == "2026-01-01T12:00:00+00:00"
        assert AuditEntryCodec().load(written) == entry

    def test_no_operation_from_inside_a_decision(self, tmp_path):
        from nanoidp.services.runtime_repository import NestedRepositoryUse
        from nanoidp.services.runtime_store import get_runtime_store
        from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

        runtime = get_runtime_store() if self.backend == "_memory_audit" else SqliteRuntimeStore(tmp_path / "runtime.db")
        store = runtime.audit
        clients = runtime.clients
        operations = {
            "append": lambda: store.append(self._entry(), ["n"]),
            "entries": lambda: store.entries(10),
            "client_ids": store.client_ids,
            "counters": store.counters,
            "clear": store.clear,
        }

        for name, operation in operations.items():
            with pytest.raises(NestedRepositoryUse):
                clients.transact(lambda view, operation=operation: operation())
            assert store.counters() == {}, name

    def test_the_facade_refuses_there_too(self, runtime_of_the_backend):
        from nanoidp.services.runtime_repository import NestedRepositoryUse
        from nanoidp.services.runtime_store import get_runtime_store

        with pytest.raises(NestedRepositoryUse):
            get_runtime_store().clients.transact(lambda view: _log("inside"))

        assert get_audit_log().get_entries() == []

    def test_the_audit_does_not_wait_for_the_repositories(self, runtime_of_the_backend):
        """One runtime boundary is not one mutex: an event is appended while
        a decision holds the repositories' lock. With SQLite, the reason the
        audit is a file of its own: a file has one writer, and an append on
        the store's file would wait for the decision (#354, third step)."""
        from nanoidp.services.runtime_store import get_runtime_store

        deciding, appended = threading.Event(), threading.Event()
        in_time = {}

        def decide(view):
            deciding.set()
            in_time["it was"] = appended.wait(2)  # set, not added to: a decision may be run again

        holder = threading.Thread(target=lambda: get_runtime_store().clients.transact(decide))
        holder.start()
        assert deciding.wait(5)
        _log("meanwhile")
        appended.set()
        holder.join()

        assert in_time == {"it was": True}, "the append waited for the repositories' lock"
        assert _names(get_audit_log().get_entries()) == ["meanwhile"]
