"""The declared configuration across processes (#354, step 4a).

Several processes share a SQLite runtime store and one configuration
directory. The files are the truth: a process notices that they changed at
the start of its next operation, and the creation of a runtime user or client
checks the name against the disk, not against what this process last loaded,
in the same critical section as the insert. With the in-memory store nothing
changes: the store is this process's alone.
"""

import multiprocessing
import os
import shutil
import threading
import time
from pathlib import Path

import pytest
import yaml

from nanoidp.config import ConfigManager, User
from nanoidp.config_writer import LockUnavailableError
from nanoidp.services import runtime_store
from nanoidp.services.identities import DeclaredNameCollision, IdentityResolver
from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

_REPO_CONFIG = Path(__file__).resolve().parent.parent / "config"
_SPAWN = multiprocessing.get_context("spawn")
_BOUND = 30


def _config_dir(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO_CONFIG / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    settings.write_text(yaml.safe_dump(document))
    _age(config_dir)
    return config_dir


def _age(config_dir, seconds=60):
    """The files as an operator's are: written a while before they are read,
    so that their stat is trusted (see the racily clean tests)."""
    for name in ("settings.yaml", "users.yaml"):
        path = config_dir / name
        if path.exists():
            then = time.time() - seconds
            os.utime(path, (then, then))


def _declare_user(config_dir, username):
    """What another process's writer (or an editor) does: the file replaced
    whole, as every nanoidp writer does."""
    users = config_dir / "users.yaml"
    document = yaml.safe_load(users.read_text())
    document["users"][username] = {"password": "declared", "email": f"{username}@example.org"}
    replacement = users.with_name("users.yaml.next")
    replacement.write_text(yaml.safe_dump(document))
    os.replace(replacement, users)


def _set_setting(config_dir, section, key, value):
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document.setdefault(section, {})[key] = value
    replacement = settings.with_name("settings.yaml.next")
    replacement.write_text(yaml.safe_dump(document))
    os.replace(replacement, settings)


@pytest.fixture
def shared(tmp_path):
    """A process's configuration over a directory, and a shared store
    published as the process's (not selectable from YAML before 4c, so
    published with the inputs the activation adopts)."""
    config_dir = _config_dir(tmp_path)
    store = SqliteRuntimeStore(tmp_path / "state" / "runtime.db")
    runtime_store.publish_runtime_store(store, ("memory",))
    config = ConfigManager(str(config_dir))
    return config_dir, config, store


class TestTheFingerprintIsOfTheBytesRead:
    def test_a_snapshot_carries_the_fingerprint_of_the_file_it_was_read_from(self, tmp_path, monkeypatch):
        """Taken from the handle the bytes came from: a file replaced right
        after the read must not lend its fingerprint to the older bytes."""
        from nanoidp import config_store

        config_dir = _config_dir(tmp_path)
        users = config_dir / "users.yaml"
        before = os.stat(users)
        real_open = open

        def replacing_open(path, *args, **kwargs):
            handle = real_open(path, *args, **kwargs)
            if Path(path) == users:
                # Replaced the moment it is open, before anything else is
                # asked of it: the path now names another file.
                replacement = users.with_name("users.yaml.next")
                replacement.write_text("users: {}\n")
                os.replace(replacement, users)
            return handle

        monkeypatch.setattr(config_store, "open", replacing_open, raising=False)
        snapshot = config_store.ConfigFileStore(config_dir).read("users.yaml")

        assert snapshot.data != b"users: {}\n"
        assert snapshot.fingerprint[0] == before.st_ino
        assert snapshot.fingerprint != config_store.ConfigFileStore(config_dir).fingerprint_of("users.yaml")

    def test_a_missing_file_has_no_fingerprint(self, tmp_path):
        from nanoidp.config_store import ConfigFileStore

        store = ConfigFileStore(tmp_path)

        assert store.read("users.yaml").fingerprint is None
        assert store.fingerprint_of("users.yaml") is None


class TestTheCheck:
    def test_nothing_changed_is_seen_without_reading_the_files(self, shared, monkeypatch):
        config_dir, config, store = shared
        reads = []
        real = config._store.read_snapshot
        monkeypatch.setattr(config._store, "read_snapshot", lambda names: reads.append(names) or real(names))

        assert config.refresh_if_changed() is False
        assert reads == []

    def test_another_writer_is_seen_at_the_next_check(self, shared):
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        assert config.get_user("carol") is None

        assert config.refresh_if_changed() is True
        assert config.get_user("carol") is not None
        assert config.refresh_if_changed() is False

    def test_the_same_bytes_under_a_new_fingerprint_are_no_reload(self, shared, monkeypatch):
        config_dir, config, store = shared
        users = config_dir / "users.yaml"
        replacement = users.with_name("users.yaml.next")
        replacement.write_bytes(users.read_bytes())
        os.replace(replacement, users)
        _age(config_dir)
        loads = []
        monkeypatch.setattr(config, "_load_config", lambda *a, **k: loads.append(1))

        assert config.refresh_if_changed() is False
        assert loads == []
        # And the fingerprint of those same bytes is kept: the next check is
        # the fast one again.
        reads = []
        real = config._store.read_snapshot
        monkeypatch.setattr(config._store, "read_snapshot", lambda names: reads.append(names) or real(names))
        assert config.refresh_if_changed() is False
        assert reads == []

    def test_an_invalid_configuration_keeps_the_loaded_one_and_is_tried_once(self, shared, monkeypatch, caplog):
        config_dir, config, store = shared
        (config_dir / "users.yaml").write_text("users: [this is not a mapping\n")
        loads = []
        real_load = config._load_config

        def counting(*args, **kwargs):
            loads.append(1)
            return real_load(*args, **kwargs)

        monkeypatch.setattr(config, "_load_config", counting)
        with caplog.at_level("WARNING"):
            assert config.refresh_if_changed() is False
            assert config.refresh_if_changed() is False
            assert config.refresh_if_changed() is False

        assert loads == [1]
        assert config.get_user("admin") is not None
        assert sum("could not be loaded" in record.getMessage() for record in caplog.records) == 1
        # Bytes that change again are tried again: valid ones, new.
        shutil.copy(_REPO_CONFIG / "users.yaml", config_dir / "users.yaml")
        _declare_user(config_dir, "dave")
        assert config.refresh_if_changed() is True
        assert loads == [1, 1]
        assert config.get_user("dave") is not None

    def test_after_a_refusal_the_check_is_the_fast_one_again(self, shared, monkeypatch):
        config_dir, config, store = shared
        (config_dir / "users.yaml").write_text("users: [this is not a mapping\n")
        _age(config_dir)
        assert config.refresh_if_changed() is False
        reads = []
        real = config._store.read_snapshot
        monkeypatch.setattr(config._store, "read_snapshot", lambda names: reads.append(names) or real(names))

        assert config.refresh_if_changed() is False
        assert reads == []

    def test_the_refused_bytes_under_a_new_fingerprint_are_not_tried_again(self, shared, monkeypatch):
        config_dir, config, store = shared
        users = config_dir / "users.yaml"
        users.write_text("users: [this is not a mapping\n")
        assert config.refresh_if_changed() is False
        replacement = users.with_name("users.yaml.next")
        replacement.write_bytes(users.read_bytes())
        os.replace(replacement, users)
        loads = []
        monkeypatch.setattr(config, "_load_config", lambda *a, **k: loads.append(1))

        assert config.refresh_if_changed() is False
        assert loads == []

    def test_a_lock_the_reload_cannot_take_is_not_an_invalid_configuration_either(self, shared, monkeypatch):
        """At the lock itself: the check's own look succeeds, the reload's
        does not, and a load reports that as a ConfigurationRejected of the
        lock's kind. It is still the lock, and it is not remembered."""
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        _lock_fails_after(monkeypatch, 1)

        with pytest.raises(LockUnavailableError):
            config.refresh_if_changed()
        monkeypatch.undo()

        assert config.refresh_if_changed() is True
        assert config.get_user("carol") is not None

    def test_a_keys_lock_the_activation_cannot_take_is_the_lock_too(self, shared, monkeypatch):
        """Every load activates the signing service, which takes the keys
        directory's lock; a peer holding it is reported two wrappings down
        (a ValueError of the activation, then a ConfigurationRejected). It is
        the lock, and it is not remembered."""
        from nanoidp.services import activate_services

        config_dir, config, store = shared
        config._activate = activate_services
        keys_dir = Path(config.settings.keys_dir).resolve()
        _declare_user(config_dir, "carol")
        _lock_fails_for(monkeypatch, keys_dir)

        with pytest.raises(LockUnavailableError):
            config.refresh_if_changed()
        monkeypatch.undo()

        assert config.refresh_if_changed() is True
        assert config.get_user("carol") is not None

    def test_a_failure_after_the_load_is_not_files_that_do_not_load(self, tmp_path, monkeypatch, caplog):
        """What runs after the configuration is committed (the reconciliation
        of the runtime store) can fail on its own: the files did load, and
        saying they did not would be false, and would stop the check."""
        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        failing = {"on": False}

        def after_load(manager):
            if failing["on"]:
                raise RuntimeError("the store was busy")

        config = ConfigManager(str(config_dir), after_load=after_load)
        _declare_user(config_dir, "carol")
        failing["on"] = True

        with caplog.at_level("WARNING"), pytest.raises(RuntimeError, match="busy"):
            config.refresh_if_changed()

        assert config.get_user("carol") is not None
        assert not any("could not be loaded" in record.getMessage() for record in caplog.records)
        # Nothing remembered: the files are the loaded ones, the check is quiet.
        assert config._refused is None
        failing["on"] = False
        assert config.refresh_if_changed() is False


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    from nanoidp import config as config_module

    fake = _Clock()
    monkeypatch.setattr(config_module, "_now", fake)
    return fake


def _counting_loads(monkeypatch, config):
    loads = []
    real = config._load_config

    def counting(*args, **kwargs):
        loads.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(config, "_load_config", counting)
    return loads


def _failing_activation(config, times):
    """The activation of the next ``times`` loads fails, as a resource
    outside the two files would (an external key not there yet)."""
    left = {"n": times}

    def activate(settings):
        if left["n"] > 0:
            left["n"] -= 1
            raise ValueError("the external key is not there yet")
        return lambda: None

    config._activate = activate


class TestWhatIsRememberedAndWhatIsTriedAgain:
    """Only a refusal the bytes decide is remembered until they change.
    One that depends on what is outside them leaves the loaded configuration
    in force and is tried again, not before a while, and at once when the
    bytes change. A lock that cannot be taken is neither (#354, step 4a)."""

    def test_bytes_that_do_not_parse_are_tried_once_however_long(self, shared, monkeypatch, clock):
        config_dir, config, store = shared
        (config_dir / "users.yaml").write_text("users: [this is not a mapping\n")
        loads = _counting_loads(monkeypatch, config)

        assert config.refresh_if_changed() is False
        clock.now += 60
        assert config.refresh_if_changed() is False

        assert loads == [1]

    def test_an_activation_that_fails_is_tried_again_after_a_while_and_adopted(self, shared, monkeypatch, clock, caplog):
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        _failing_activation(config, 2)
        loads = _counting_loads(monkeypatch, config)

        with caplog.at_level("WARNING"):
            assert config.refresh_if_changed() is False
            clock.now += 4
            assert config.refresh_if_changed() is False
            assert loads == [1]
            clock.now += 2
            assert config.refresh_if_changed() is False  # tried, and still failing
            assert loads == [1, 1]
            clock.now += 6
            assert config.refresh_if_changed() is True  # the same files, adopted

        assert config.get_user("carol") is not None
        assert sum("could not be loaded" in record.getMessage() for record in caplog.records) == 1

    def test_while_waiting_a_check_reads_nothing(self, shared, monkeypatch, clock):
        """The wait is kept by the stat, as the fast negative is: a failure
        pending is not a reason to read the files at every request."""
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        _failing_activation(config, 1)
        assert config.refresh_if_changed() is False
        reads = []
        real = config._store.read_snapshot
        monkeypatch.setattr(config._store, "read_snapshot", lambda names: reads.append(names) or real(names))
        clock.now += 1

        assert config.refresh_if_changed() is False
        assert reads == []

    def test_the_same_bytes_rewritten_while_waiting_wait_on(self, shared, monkeypatch, clock):
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        _failing_activation(config, 1)
        assert config.refresh_if_changed() is False
        users = config_dir / "users.yaml"
        replacement = users.with_name("users.yaml.next")
        replacement.write_bytes(users.read_bytes())
        os.replace(replacement, users)
        loads = _counting_loads(monkeypatch, config)
        clock.now += 1

        assert config.refresh_if_changed() is False
        assert loads == []

    def test_bytes_that_change_while_waiting_are_tried_at_once(self, shared, monkeypatch, clock):
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        _failing_activation(config, 1)
        assert config.refresh_if_changed() is False
        loads = _counting_loads(monkeypatch, config)

        _declare_user(config_dir, "dave")
        assert config.refresh_if_changed() is True

        assert loads == [1]
        assert config.get_user("dave") is not None

    def test_a_read_that_fails_is_tried_again_after_a_while(self, shared, monkeypatch, clock):
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        real_read = config._store.read_snapshot
        reads = []

        def failing_second_read(names):
            reads.append(1)
            if len(reads) == 2:
                raise OSError(5, "Input/output error")
            return real_read(names)

        monkeypatch.setattr(config._store, "read_snapshot", failing_second_read)
        assert config.refresh_if_changed() is False
        clock.now += 6

        assert config.refresh_if_changed() is True
        assert config.get_user("carol") is not None

    def test_a_creation_that_loads_the_files_ends_the_wait_for_the_reads_too(self, shared, monkeypatch, clock):
        """Reads and the critical creation are never in two configurations:
        the creation reloads the same files the check could not, and the
        check, once its wait is over, finds them loaded."""
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        _failing_activation(config, 1)
        assert config.refresh_if_changed() is False

        IdentityResolver(config, store).create_runtime_user(User(username="fresh", password="pw"))
        assert config.get_user("carol") is not None
        loads = _counting_loads(monkeypatch, config)
        clock.now += 6

        assert config.refresh_if_changed() is False
        assert loads == []
        assert config._pending is None


class TestTheFourthReview:
    """#354, step 4a, fourth review: what a failure was about, and what it
    is recorded under."""

    def test_a_creation_against_a_transient_failure_may_come_back(self, shared, monkeypatch):
        from nanoidp.config import DeclaredConfigurationUnloadable

        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        _failing_activation(config, 1)

        with pytest.raises(DeclaredConfigurationUnloadable) as refused:
            IdentityResolver(config, store).create_runtime_user(User(username="x", password="pw"))

        assert refused.value.temporary is True
        assert store.users.get("x") is None

    def test_a_creation_against_bytes_that_do_not_parse_may_not(self, shared):
        from nanoidp.config import DeclaredConfigurationUnloadable

        config_dir, config, store = shared
        (config_dir / "users.yaml").write_text("users: [this is not a mapping\n")

        with pytest.raises(DeclaredConfigurationUnloadable) as refused:
            IdentityResolver(config, store).create_runtime_user(User(username="x", password="pw"))

        assert refused.value.temporary is False

    def test_a_plugin_that_fails_during_a_creation_is_temporary_too(self, shared, monkeypatch):
        from nanoidp.config import DeclaredConfigurationUnloadable
        from nanoidp.hooks import HookError

        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        real_reload = config.reload_local

        def plugin_fails():
            raise HookError("a strict plugin failed", kind="plugin_load")

        monkeypatch.setattr(config, "reload_local", plugin_fails)
        with pytest.raises(DeclaredConfigurationUnloadable) as refused:
            IdentityResolver(config, store).create_runtime_user(User(username="x", password="pw"))
        monkeypatch.setattr(config, "reload_local", real_reload)

        assert refused.value.temporary is True

    def test_the_endpoint_says_come_back_to_a_transient_failure(self, tmp_path):
        from nanoidp.app import create_app
        from nanoidp.config import get_config

        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        application = create_app(str(config_dir))
        application.config["TESTING"] = True
        client = application.test_client()
        config = get_config()
        real_activate = config._activate
        _declare_user(config_dir, "carol")
        # The request's check fails transiently, then the creation's reload.
        left = {"n": 2}

        def activate(settings):
            if left["n"] > 0:
                left["n"] -= 1
                raise ValueError("the external key is not there yet")
            return real_activate(settings)

        config._activate = activate
        response = client.post("/api/runtime/users", json={"username": "x", "password": "pw"})

        assert response.status_code == 503
        assert response.get_json()["error"] == "configuration_unavailable"
        assert response.headers["Retry-After"]

    @pytest.mark.parametrize("where", ["stat", "read"])
    def test_files_that_cannot_be_read_keep_the_configuration_and_wait(self, shared, monkeypatch, clock, caplog, where):
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        real_stat, real_read = config._store.fingerprint_of, config._store.read_snapshot
        broken = {"on": True}

        def stat(name):
            if broken["on"] and where == "stat":
                raise PermissionError(13, "Permission denied")
            return real_stat(name)

        def read(names):
            if broken["on"] and where == "read":
                raise PermissionError(13, "Permission denied")
            return real_read(names)

        monkeypatch.setattr(config._store, "fingerprint_of", stat)
        monkeypatch.setattr(config._store, "read_snapshot", read)
        with caplog.at_level("WARNING"):
            assert config.refresh_if_changed() is False
            assert config.refresh_if_changed() is False
        assert config.get_user("admin") is not None
        assert sum("could not be read" in record.getMessage() for record in caplog.records) == 1

        # Still broken when looked at again: said once for as long as it lasts.
        clock.now += 6
        with caplog.at_level("WARNING"):
            assert config.refresh_if_changed() is False
        assert sum("could not be read" in record.getMessage() for record in caplog.records) == 1

        broken["on"] = False
        assert config.refresh_if_changed() is False  # still waiting
        clock.now += 6
        assert config.refresh_if_changed() is True
        assert config.get_user("carol") is not None

    def test_a_refusal_is_of_the_bytes_the_load_read(self, shared, monkeypatch):
        """The check looks at valid bytes A; a peer writes invalid B before
        the reload reads; B is refused, not A, and A when it comes back is
        adopted."""
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        a_bytes = (config_dir / "users.yaml").read_bytes()
        real_reload = config.reload_local

        def peer_breaks_then_reload():
            (config_dir / "users.yaml").write_text("users: [this is not a mapping\n")
            real_reload()

        monkeypatch.setattr(config, "reload_local", peer_breaks_then_reload)
        assert config.refresh_if_changed() is False
        monkeypatch.setattr(config, "reload_local", real_reload)
        replacement = config_dir / "users.yaml.next"
        replacement.write_bytes(a_bytes)
        os.replace(replacement, config_dir / "users.yaml")

        assert config.refresh_if_changed() is True
        assert config.get_user("carol") is not None

    def test_a_refused_pair_ends_a_wait_that_came_after_it(self, shared, monkeypatch, clock):
        config_dir, config, store = shared
        users = config_dir / "users.yaml"
        users.write_text("users: [this is not a mapping\n")
        refused_bytes = users.read_bytes()
        assert config.refresh_if_changed() is False
        shutil.copy(_REPO_CONFIG / "users.yaml", users)
        _declare_user(config_dir, "carol")
        _failing_activation(config, 1)
        assert config.refresh_if_changed() is False
        assert config._pending is not None
        replacement = config_dir / "users.yaml.next"
        replacement.write_bytes(refused_bytes)
        os.replace(replacement, users)
        _age(config_dir)
        assert config.refresh_if_changed() is False
        reads = []
        real = config._store.read_snapshot
        monkeypatch.setattr(config._store, "read_snapshot", lambda names: reads.append(names) or real(names))

        assert config.refresh_if_changed() is False
        assert reads == []
        assert config._pending is None

    def test_a_change_in_place_after_the_read_is_seen(self, tmp_path, monkeypatch):
        """The fingerprint is taken before the read: a write in place that
        lands after it makes the next stat differ, never the other way."""
        from nanoidp import config_store

        config_dir = _config_dir(tmp_path)
        users = config_dir / "users.yaml"
        real_open = open

        def writing_in_place_after_the_read(path, *args, **kwargs):
            handle = real_open(path, *args, **kwargs)
            if Path(path) == users:
                real_read = handle.read

                def read(*a, **k):
                    data = real_read(*a, **k)
                    with real_open(users, "a") as appending:
                        appending.write("# edited in place\n")
                    return data

                handle.read = read
            return handle

        monkeypatch.setattr(config_store, "open", writing_in_place_after_the_read, raising=False)
        store = config_store.ConfigFileStore(config_dir)
        snapshot = store.read("users.yaml")

        assert snapshot.fingerprint != store.fingerprint_of("users.yaml")


class TestTheFifthReview:
    """#354, step 4a, fifth review."""

    def test_a_creation_that_cannot_read_the_files_may_come_back(self, shared, monkeypatch):
        from nanoidp.config import DeclaredConfigurationUnloadable

        config_dir, config, store = shared

        def unreadable(names):
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(config._store, "read_snapshot_within_lock", unreadable)
        with pytest.raises(DeclaredConfigurationUnloadable) as refused:
            IdentityResolver(config, store).create_runtime_user(User(username="x", password="pw"))

        assert refused.value.temporary is True
        assert isinstance(refused.value.__cause__, PermissionError)
        assert store.users.get("x") is None

    def test_the_endpoint_says_come_back_to_files_it_cannot_read(self, tmp_path, monkeypatch):
        from nanoidp.app import create_app
        from nanoidp.config import get_config

        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        application = create_app(str(config_dir))
        application.config["TESTING"] = True
        client = application.test_client()

        def unreadable(names):
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(get_config()._store, "read_snapshot_within_lock", unreadable)
        response = client.post("/api/runtime/users", json={"username": "x", "password": "pw"})

        assert response.status_code == 503
        assert response.get_json()["error"] == "configuration_unavailable"
        assert response.headers["Retry-After"]

    def test_an_empty_file_where_there_was_none_is_a_change(self, tmp_path):
        """No users.yaml loads the default user; an empty one loads none.
        The same revision, the hash of no bytes, and not the same files."""
        config_dir = _config_dir(tmp_path)
        (config_dir / "users.yaml").unlink()
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        config = ConfigManager(str(config_dir))
        assert config.get_user("admin") is not None

        (config_dir / "users.yaml").write_text("")

        assert config.refresh_if_changed() is True
        assert config.get_user("admin") is None

    def test_a_creation_sees_an_empty_file_where_there_was_none(self, tmp_path):
        config_dir = _config_dir(tmp_path)
        (config_dir / "users.yaml").unlink()
        store = SqliteRuntimeStore(tmp_path / "runtime.db")
        runtime_store.publish_runtime_store(store, ("memory",))
        config = ConfigManager(str(config_dir))
        (config_dir / "users.yaml").write_text("")

        IdentityResolver(config, store).create_runtime_user(User(username="admin", password="pw"))

        assert store.users.get("admin") is not None

    def test_the_others_wait_briefly_but_never_queue_behind_the_lock_timeout(self, shared, monkeypatch):
        """While one request waits for the directory lock to look at files
        that changed, the others wait for it only briefly, and are then told
        that the configuration cannot be established now, instead of queueing
        behind it for the lock's timeout."""
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        entered, release = threading.Event(), threading.Event()
        real = config._store.read_snapshot
        looks = []

        def slow_look(names):
            looks.append(1)
            entered.set()
            release.wait(10)
            return real(names)

        monkeypatch.setattr(config._store, "read_snapshot", slow_look)
        first = threading.Thread(target=config.refresh_if_changed, daemon=True)
        first.start()
        assert entered.wait(10)
        outcomes, started = [], time.monotonic()

        def follower():
            try:
                config.refresh_if_changed()
                outcomes.append("proceeded")
            except LockUnavailableError as refused:
                outcomes.append(refused.kind)

        followers = [threading.Thread(target=follower, daemon=True) for _ in range(5)]
        for thread in followers:
            thread.start()
        for thread in followers:
            thread.join(5)
        elapsed = time.monotonic() - started
        # Only the first looked while the others came and went (its reload
        # looks again after, to load).
        looks_meanwhile = list(looks)
        release.set()
        first.join(10)

        assert outcomes == ["freshness_in_progress"] * 5
        assert elapsed < 3
        assert looks_meanwhile == [1]
        assert config.get_user("carol") is not None


class TestTheSixthReview:
    """#354, step 4a, sixth review: the check's cost to the requests around
    it, and what its fast negative may conclude."""

    def test_the_others_wait_a_moment_for_a_check_that_is_quick(self, shared, monkeypatch):
        """An ordinary reload after a peer's save: the others wait for it,
        briefly, find the files loaded, and go on; none reloads again."""
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        # An operator's file, whose stat is trusted once it is loaded: the
        # others then answer from the stat alone and look at nothing.
        _age(config_dir)
        entered, release = threading.Event(), threading.Event()
        real = config._store.read_snapshot
        looks = []

        def slow_look(names):
            looks.append(1)
            if len(looks) == 1:
                entered.set()
                release.wait(10)
            return real(names)

        monkeypatch.setattr(config._store, "read_snapshot", slow_look)
        first = threading.Thread(target=config.refresh_if_changed, daemon=True)
        first.start()
        assert entered.wait(10)
        outcomes = []

        def follower():
            try:
                outcomes.append(config.refresh_if_changed())
            except LockUnavailableError as refused:
                outcomes.append(refused.kind)

        loads = _counting_loads(monkeypatch, config)
        followers = [threading.Thread(target=follower, daemon=True) for _ in range(5)]
        for thread in followers:
            thread.start()
        time.sleep(0.1)
        release.set()
        for thread in followers:
            thread.join(5)
        first.join(10)

        assert outcomes == [False] * 5
        # The first looked and reloaded; the others found the files loaded
        # and did neither.
        assert loads == [1]
        assert looks == [1, 1]
        assert config.get_user("carol") is not None

    def test_the_others_take_a_check_made_after_they_came_though_the_stat_is_racy(self, shared, monkeypatch):
        """A peer's save leaves files freshly written, whose stat is not
        trusted for a while. The requests that waited for the check made
        after they arrived take its result: none looks again."""
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        entered, release = threading.Event(), threading.Event()
        real = config._store.read_snapshot
        looks = []

        def slow_look(names):
            looks.append(1)
            if len(looks) == 1:
                entered.set()
                release.wait(10)
            return real(names)

        monkeypatch.setattr(config._store, "read_snapshot", slow_look)
        first = threading.Thread(target=config.refresh_if_changed, daemon=True)
        first.start()
        assert entered.wait(10)
        outcomes = []
        followers = [threading.Thread(target=lambda: outcomes.append(config.refresh_if_changed()), daemon=True) for _ in range(5)]
        for thread in followers:
            thread.start()
        time.sleep(0.1)
        release.set()
        for thread in followers:
            thread.join(5)
        first.join(10)

        assert config._loaded_racy
        assert outcomes == [False] * 5
        assert looks == [1, 1]

    @pytest.mark.parametrize("seen_before", [False, True], ids=["refused-now", "refused-again"])
    def test_the_others_take_a_refusal_the_check_made_after_they_came(self, shared, monkeypatch, seen_before):
        """A refusal the bytes decided is an established state too: the
        others take it, and neither look nor try to load."""
        config_dir, config, store = shared
        users = config_dir / "users.yaml"
        users.write_text("users: [this is not a mapping\n")
        if seen_before:
            assert config.refresh_if_changed() is False
            replacement = config_dir / "users.yaml.next"
            replacement.write_bytes(users.read_bytes())
            os.replace(replacement, users)
        entered, release = threading.Event(), threading.Event()
        real = config._store.read_snapshot
        looks = []

        def slow_look(names):
            looks.append(1)
            if len(looks) == 1:
                entered.set()
                release.wait(10)
            return real(names)

        monkeypatch.setattr(config._store, "read_snapshot", slow_look)
        first = threading.Thread(target=config.refresh_if_changed, daemon=True)
        first.start()
        assert entered.wait(10)
        outcomes = []
        followers = [threading.Thread(target=lambda: outcomes.append(config.refresh_if_changed()), daemon=True) for _ in range(4)]
        for thread in followers:
            thread.start()
        time.sleep(0.1)
        release.set()
        for thread in followers:
            thread.join(5)
        first.join(10)

        assert outcomes == [False] * 4
        # The first's look, and its reload's when the refusal is new.
        assert looks == ([1] if seen_before else [1, 1])

    @pytest.mark.parametrize("what", ["the same bytes rewritten", "a failure outside the bytes"])
    def test_the_others_answer_from_what_the_check_left_without_reading(self, shared, monkeypatch, clock, what):
        """The same bytes rewritten: the check establishes them, and the
        others take it. A failure outside the bytes: nothing established, and
        the others answer from the wait it left, by the stat."""
        config_dir, config, store = shared
        users = config_dir / "users.yaml"
        if what == "the same bytes rewritten":
            replacement = config_dir / "users.yaml.next"
            replacement.write_bytes(users.read_bytes())
            os.replace(replacement, users)
        else:
            _declare_user(config_dir, "carol")
            _failing_activation(config, 1)
        entered, release = threading.Event(), threading.Event()
        real = config._store.read_snapshot
        looks = []

        def slow_look(names):
            looks.append(1)
            if len(looks) == 1:
                entered.set()
                release.wait(10)
            return real(names)

        monkeypatch.setattr(config._store, "read_snapshot", slow_look)
        first = threading.Thread(target=config.refresh_if_changed, daemon=True)
        first.start()
        assert entered.wait(10)
        outcomes = []
        followers = [threading.Thread(target=lambda: outcomes.append(config.refresh_if_changed()), daemon=True) for _ in range(4)]
        for thread in followers:
            thread.start()
        time.sleep(0.1)
        release.set()
        for thread in followers:
            thread.join(5)
        first.join(10)

        assert outcomes == [False] * 4
        # The first's look, and its reload's when it tried one.
        assert looks == ([1] if what == "the same bytes rewritten" else [1, 1])

    def test_a_check_that_failed_is_not_taken_by_the_others(self, shared, monkeypatch):
        """Only a check that established the files is shared: when the one in
        flight fails (the lock), the others look for themselves."""
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")
        entered, release = threading.Event(), threading.Event()
        real = config._store.read_snapshot
        looks = []

        def failing_first_look(names):
            looks.append(1)
            if len(looks) == 1:
                entered.set()
                release.wait(10)
                raise LockUnavailableError("held by a peer", kind="lock_timeout")
            return real(names)

        monkeypatch.setattr(config._store, "read_snapshot", failing_first_look)
        first = threading.Thread(target=lambda: pytest.raises(LockUnavailableError, config.refresh_if_changed), daemon=True)
        first.start()
        assert entered.wait(10)
        outcomes = []
        followers = [threading.Thread(target=lambda: outcomes.append(config.refresh_if_changed()), daemon=True) for _ in range(3)]
        for thread in followers:
            thread.start()
        time.sleep(0.1)
        release.set()
        for thread in followers:
            thread.join(5)
        first.join(10)

        assert sorted(outcomes) == [False, False, True]
        assert config.get_user("carol") is not None

    def test_a_request_that_cannot_wait_is_told_to_come_back_in_a_second(self, tmp_path, monkeypatch):
        from nanoidp.app import create_app

        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        application = create_app(str(config_dir))
        application.config["TESTING"] = True
        client = application.test_client()
        from nanoidp.config import get_config

        def busy():
            raise LockUnavailableError("another request is looking", kind="freshness_in_progress")

        monkeypatch.setattr(get_config(), "refresh_if_changed", busy)
        token = client.post("/token", data={"grant_type": "client_credentials"})
        page = client.get("/", headers={"Accept": "text/html"})

        assert token.status_code == 503
        assert token.get_json() == {"error": "configuration_unavailable", "kind": "freshness_in_progress"}
        assert token.headers["Retry-After"] == "1"
        assert page.status_code == 503
        assert page.headers["Retry-After"] == "1"
        assert "text/html" in page.headers["Content-Type"]

    def test_a_lock_that_will_never_be_had_has_no_retry_after(self, tmp_path, monkeypatch):
        from nanoidp.app import create_app
        from nanoidp.config import get_config

        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        application = create_app(str(config_dir))
        application.config["TESTING"] = True

        def unsupported():
            raise LockUnavailableError("no advisory locking here", kind="lock_unsupported")

        monkeypatch.setattr(get_config(), "refresh_if_changed", unsupported)
        response = application.test_client().post("/token", data={"grant_type": "client_credentials"})

        assert response.status_code == 503
        assert "Retry-After" not in response.headers

    @pytest.mark.parametrize("path", ["/health", "/api/health", "/static/does-not-matter.css"])
    def test_health_and_static_do_not_look_at_the_files(self, tmp_path, monkeypatch, path):
        """They say the process is alive, not that it can establish its
        configuration right now: a probe must not restart a healthy pod
        because a peer holds the directory lock."""
        from nanoidp.app import create_app
        from nanoidp.config import get_config

        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        application = create_app(str(config_dir))
        application.config["TESTING"] = True
        looked = []

        def looking():
            looked.append(path)
            raise LockUnavailableError("held by a peer", kind="lock_timeout")

        monkeypatch.setattr(get_config(), "refresh_if_changed", looking)
        response = application.test_client().get(path)

        assert looked == []
        assert response.status_code in (200, 404)

    def test_a_stat_as_recent_as_the_read_is_not_trusted(self, shared, monkeypatch):
        """Racily clean, as git calls it: a write in place of the same size
        within the timestamp's tick leaves the stat as it was. A fingerprint
        whose times are not older than the read, by a margin, does not
        conclude; the bytes are hashed."""
        config_dir, config, store = shared
        # Files written just before they are read: the load happens now.
        for name in ("settings.yaml", "users.yaml"):
            os.utime(config_dir / name)
        config.reload_local()
        loaded = config._loaded_fingerprints
        assert config._loaded_racy
        _declare_user(config_dir, "carol")
        monkeypatch.setattr(config._store, "fingerprint_of", lambda name: loaded[["settings.yaml", "users.yaml"].index(name)])

        assert config.refresh_if_changed() is True
        assert config.get_user("carol") is not None

    def test_a_refused_file_as_recent_as_the_read_is_not_trusted_either(self, shared, monkeypatch):
        config_dir, config, store = shared
        (config_dir / "users.yaml").write_text("users: [this is not a mapping\n")
        assert config.refresh_if_changed() is False
        assert config._refused[2]
        refused = config._refused[1]
        shutil.copy(_REPO_CONFIG / "users.yaml", config_dir / "users.yaml")
        _declare_user(config_dir, "carol")
        monkeypatch.setattr(config._store, "fingerprint_of", lambda name: refused[["settings.yaml", "users.yaml"].index(name)])

        assert config.refresh_if_changed() is True
        assert config.get_user("carol") is not None

    def test_a_stat_well_older_than_the_read_is_trusted(self, shared, monkeypatch):
        from nanoidp import config as config_module

        config_dir, config, store = shared
        real_wall = config_module._wall_ns
        monkeypatch.setattr(config_module, "_wall_ns", lambda: real_wall() + 10 * 10**9)
        config.reload_local()
        assert not config._loaded_racy
        reads = []
        real = config._store.read_snapshot
        monkeypatch.setattr(config._store, "read_snapshot", lambda names: reads.append(names) or real(names))

        assert config.refresh_if_changed() is False
        assert reads == []

    def test_a_racy_stat_becomes_trusted_once_the_same_bytes_are_seen_later(self, shared, monkeypatch):
        from nanoidp import config as config_module

        config_dir, config, store = shared
        for name in ("settings.yaml", "users.yaml"):
            os.utime(config_dir / name)
        config.reload_local()
        assert config._loaded_racy
        real_wall = config_module._wall_ns
        monkeypatch.setattr(config_module, "_wall_ns", lambda: real_wall() + 10 * 10**9)

        assert config.refresh_if_changed() is False  # hashed: the same bytes
        assert not config._loaded_racy
        reads = []
        real = config._store.read_snapshot
        monkeypatch.setattr(config._store, "read_snapshot", lambda names: reads.append(names) or real(names))
        assert config.refresh_if_changed() is False
        assert reads == []


class TestAFailureAfterAPeersWrite:
    def test_a_failure_after_a_load_of_newer_files_is_still_not_the_files(self, tmp_path, monkeypatch, caplog):
        """A peer writes again between the check's look and its reload: the
        reload loads the newer files and commits them, then its after_load
        fails. What was committed is not the pair the check looked at, and
        the failure is still not theirs."""
        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        failing = {"on": False}

        def after_load(manager):
            if failing["on"]:
                raise RuntimeError("the store was busy")

        config = ConfigManager(str(config_dir), after_load=after_load)
        _declare_user(config_dir, "carol")
        real_reload = config.reload_local

        def peer_writes_then_reload():
            _declare_user(config_dir, "dave")
            failing["on"] = True
            real_reload()

        monkeypatch.setattr(config, "reload_local", peer_writes_then_reload)
        with caplog.at_level("WARNING"), pytest.raises(RuntimeError, match="busy"):
            config.refresh_if_changed()

        assert config.get_user("dave") is not None
        assert config._refused is None
        assert not any("could not be loaded" in record.getMessage() for record in caplog.records)


class TestTheLockedSection:
    def test_what_the_section_raises_is_what_the_caller_gets(self, tmp_path):
        from nanoidp.config_store import ConfigFileStore
        from nanoidp.services.key_directory import KeysDirectoryNotWritable

        store = ConfigFileStore(_config_dir(tmp_path))
        raised = KeysDirectoryNotWritable(Path("/keys"), OSError(30, "Read-only file system"))

        with pytest.raises(KeysDirectoryNotWritable) as seen:
            with store.locked():
                raise raised
        assert seen.value is raised


class TestTheLockBehindAFailedLoad:
    @pytest.mark.parametrize("depth", [0, 1, 2, 3])
    def test_a_lock_is_found_however_deep_it_was_wrapped(self, depth):
        from nanoidp.config import ConfigurationRejected, _lock_behind

        lock = LockUnavailableError("held by a peer", kind="lock_timeout")
        failure: BaseException = lock
        for level in range(depth):
            try:
                raise (ValueError("activation") if level % 2 == 0 else ConfigurationRejected("x", kind="activation")) from failure
            except BaseException as wrapped:  # noqa: BLE001
                failure = wrapped

        assert _lock_behind(failure) is lock

    def test_a_directory_with_no_lock_namespace_is_no_lock_held(self):
        from nanoidp.config import ConfigurationRejected, _lock_behind
        from nanoidp.services.key_directory import KeysDirectoryNotWritable

        try:
            raise ConfigurationRejected("x", kind="activation") from KeysDirectoryNotWritable(
                Path("/keys"), OSError(30, "Read-only file system")
            )
        except ConfigurationRejected as failure:
            assert _lock_behind(failure) is None

    def test_a_chain_that_comes_back_on_itself_ends(self):
        from nanoidp.config import _lock_behind

        first, second = ValueError("a"), ValueError("b")
        first.__cause__, second.__cause__ = second, first

        assert _within(lambda: _lock_behind(first)) is None

    def test_an_io_error_anywhere_behind_a_rejection_is_not_the_bytes(self):
        from nanoidp.config import ConfigurationRejected, _decided_by_the_bytes

        def raised_while(error):
            try:
                try:
                    raise error
                except OSError:
                    raise ValueError("while reading")  # noqa: B904 - a context, on purpose
            except ValueError as middle:
                try:
                    raise ConfigurationRejected("x", kind="invalid") from middle
                except ConfigurationRejected as rejected:
                    return rejected

        assert _decided_by_the_bytes(raised_while(OSError(5, "Input/output error"))) is False
        try:
            raise ConfigurationRejected("x", kind="invalid") from ValueError("not a mapping")
        except ConfigurationRejected as rejected:
            assert _decided_by_the_bytes(rejected) is True
        assert _decided_by_the_bytes(ConfigurationRejected("x", kind="activation")) is False

    def test_a_failure_that_is_no_lock_is_none(self):
        from nanoidp.config import ConfigurationRejected, _lock_behind

        try:
            raise ConfigurationRejected("x", kind="invalid") from ValueError("not a mapping")
        except ConfigurationRejected as failure:
            assert _lock_behind(failure) is None

    def test_the_bytes_that_were_loaded_back_again_are_no_reload(self, shared, monkeypatch):
        """An editor's mistake undone: the files are the loaded ones again."""
        config_dir, config, store = shared
        original = (config_dir / "users.yaml").read_bytes()
        (config_dir / "users.yaml").write_text("users: [this is not a mapping\n")
        assert config.refresh_if_changed() is False
        (config_dir / "users.yaml").write_bytes(original)
        loads = []
        monkeypatch.setattr(config, "_load_config", lambda *a, **k: loads.append(1))

        assert config.refresh_if_changed() is False
        assert loads == []

    def test_a_lock_that_cannot_be_taken_is_not_an_invalid_configuration(self, shared, monkeypatch):
        config_dir, config, store = shared
        _declare_user(config_dir, "carol")

        def unavailable(names):
            raise LockUnavailableError("held by a peer", kind="lock_timeout")

        monkeypatch.setattr(config._store, "read_snapshot", unavailable)
        with pytest.raises(LockUnavailableError):
            config.refresh_if_changed()
        monkeypatch.undo()

        # Nothing was remembered as refused: the next check reloads.
        assert config.refresh_if_changed() is True
        assert config.get_user("carol") is not None


class TestWhereTheCheckRuns:
    def test_only_a_shared_store_asks_for_it(self, tmp_path, monkeypatch):
        from nanoidp.services.runtime_store import MemoryRuntimeStore, fresh_configuration

        config = ConfigManager(str(_config_dir(tmp_path)))
        monkeypatch.setattr("nanoidp.services.runtime_store.get_config_if_loaded", lambda: config)
        checks = []
        monkeypatch.setattr(config, "refresh_if_changed", lambda: checks.append(1) or False)

        runtime_store.publish_runtime_store(MemoryRuntimeStore(), ("memory",))
        fresh_configuration()
        assert checks == []

        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        fresh_configuration()
        assert checks == [1]

    def test_a_request_sees_the_files_before_the_blueprints_guards(self, tmp_path):
        from nanoidp.app import create_app

        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        application = create_app(str(config_dir))
        application.config["TESTING"] = True
        client = application.test_client()
        assert client.get("/").status_code == 200

        _set_setting(config_dir, "session", "require_ui_login", True)
        response = client.get("/")

        assert response.status_code == 302
        assert "/login" in response.headers["Location"]

    def test_a_request_with_the_memory_store_does_not_look(self, tmp_path):
        from nanoidp.app import create_app

        config_dir = _config_dir(tmp_path)
        application = create_app(str(config_dir))
        application.config["TESTING"] = True
        client = application.test_client()
        _set_setting(config_dir, "session", "require_ui_login", True)

        assert client.get("/").status_code == 200

    async def test_an_mcp_tool_sees_the_files_before_the_admin_check(self, tmp_path, mcp_call_tool):
        from nanoidp.config import init_config

        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        init_config(str(config_dir))
        _set_setting(config_dir, "session", "management_secret", "s" * 32)

        result = _payload(await mcp_call_tool("create_user", {"username": "eve", "password": "pw"}))

        assert result["code"] == "MCP_ADMIN_SECRET_REQUIRED"

    @pytest.mark.parametrize("kind, retryable", [("freshness_in_progress", True), ("lock_unsupported", False)])
    async def test_an_mcp_tool_says_whether_coming_back_helps(self, tmp_path, monkeypatch, mcp_call_tool, kind, retryable):
        from nanoidp.config import init_config

        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        config = init_config(str(config_dir))

        def unavailable():
            raise LockUnavailableError("not now", kind=kind)

        monkeypatch.setattr(config, "refresh_if_changed", unavailable)
        result = _payload(await mcp_call_tool("list_users", {}))

        assert result["code"] == "MCP_CONFIGURATION_UNAVAILABLE"
        assert result["retryable"] is retryable

    async def test_an_mcp_tool_that_cannot_observe_the_files_may_retry(self, tmp_path, monkeypatch, mcp_call_tool):
        from nanoidp.config import init_config

        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        config = init_config(str(config_dir))

        def unavailable():
            raise LockUnavailableError("held by a peer", kind="lock_timeout")

        monkeypatch.setattr(config, "refresh_if_changed", unavailable)
        result = _payload(await mcp_call_tool("list_users", {}))

        assert result["code"] == "MCP_CONFIGURATION_UNAVAILABLE"
        assert result["retryable"] is True


def _payload(result):
    import json

    return json.loads(result.content[0].text)


class TestTheCriticalCreation:
    def test_a_name_another_process_declared_is_refused_though_this_one_never_reloaded(self, shared):
        """The census scenario: B's loaded configuration is stale, and B
        checks the name against the disk, under the lock the writers take."""
        config_dir, config, store = shared
        b = IdentityResolver(config, store)
        _declare_user(config_dir, "x")
        assert config.get_user("x") is None

        with pytest.raises(DeclaredNameCollision):
            b.create_runtime_user(User(username="x", password="pw"))

        assert store.users.get("x") is None
        # And B now resolves x as the declared configuration says.
        assert config.get_user("x") is not None

    def test_the_insert_is_made_with_the_directory_lock_held(self, shared, monkeypatch):
        import fcntl

        config_dir, config, store = shared
        b = IdentityResolver(config, store)
        held = []
        real_create = store.users.create

        def create(user, *args, **kwargs):
            probe = os.open(config_dir / ".nanoidp-write.lock", os.O_RDWR)
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held.append(False)
                fcntl.flock(probe, fcntl.LOCK_UN)
            except BlockingIOError:
                held.append(True)
            finally:
                os.close(probe)
            return real_create(user, *args, **kwargs)

        monkeypatch.setattr(store.users, "create", create)
        b.create_runtime_user(User(username="fresh", password="pw"))

        assert held == [True]

    def test_a_disk_that_moves_again_after_the_reload_is_looked_at_again(self, shared, monkeypatch):
        config_dir, config, store = shared
        b = IdentityResolver(config, store)
        _declare_user(config_dir, "first")
        reloads = []
        real_reload = config.reload_local

        def reload_then_declare():
            real_reload()
            reloads.append(1)
            if len(reloads) == 1:
                # Another writer, between this reload and the next lock.
                _declare_user(config_dir, "x")

        monkeypatch.setattr(config, "reload_local", reload_then_declare)

        with pytest.raises(DeclaredNameCollision):
            b.create_runtime_user(User(username="x", password="pw"))
        assert reloads == [1, 1]
        assert store.users.get("x") is None

    def test_a_disk_that_cannot_be_loaded_refuses_the_creation(self, shared):
        """The name cannot be checked against a declaration that does not
        load: refused, and said as that, not as a collision."""
        from nanoidp.config import DeclaredConfigurationUnloadable

        config_dir, config, store = shared
        b = IdentityResolver(config, store)
        (config_dir / "users.yaml").write_text("users: [this is not a mapping\n")

        with pytest.raises(DeclaredConfigurationUnloadable):
            b.create_runtime_user(User(username="x", password="pw"))

        assert store.users.get("x") is None
        assert config.get_user("admin") is not None

    @pytest.mark.parametrize(
        "path, body",
        [
            ("/api/runtime/users", {"username": "x", "password": "pw"}),
            ("/api/runtime/clients", {"client_id": "x", "client_secret": "s" * 20}),
            ("/register", {"redirect_uris": ["http://localhost:3000/callback"], "token_endpoint_auth_method": "none"}),
        ],
    )
    def test_the_endpoints_say_the_declaration_does_not_load(self, tmp_path, path, body):
        from nanoidp.app import create_app

        config_dir = _config_dir(tmp_path)
        _set_setting(config_dir, "oauth", "dynamic_registration", {"enabled": True})
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        application = create_app(str(config_dir))
        application.config["TESTING"] = True
        client = application.test_client()
        (config_dir / "users.yaml").write_text("users: [this is not a mapping\n")

        response = client.post(path, json=body)

        assert response.status_code == 503
        assert response.get_json()["error"] == "configuration_unloadable"

    def test_a_lock_that_cannot_be_taken_creates_nothing(self, shared, monkeypatch):
        from nanoidp import config_writer

        config_dir, config, store = shared
        b = IdentityResolver(config, store)

        def unavailable(*args, **kwargs):
            raise LockUnavailableError("held by a peer", kind="lock_timeout")

        monkeypatch.setattr(config_writer, "_cross_process_lock", unavailable)
        with pytest.raises(LockUnavailableError):
            b.create_runtime_user(User(username="x", password="pw"))
        monkeypatch.undo()

        assert store.users.get("x") is None

    def test_a_lock_the_reload_cannot_take_is_not_a_declaration_that_does_not_load(self, shared, monkeypatch):
        """The files moved, the creation releases the lock to reload, and the
        reload cannot take it: temporary, said as the lock, not as files that
        do not load (which would say nothing helps until they are fixed)."""
        from nanoidp.config import DeclaredConfigurationUnloadable

        config_dir, config, store = shared
        b = IdentityResolver(config, store)
        _declare_user(config_dir, "someone")
        _lock_fails_after(monkeypatch, 1)

        with pytest.raises(LockUnavailableError) as refused:
            b.create_runtime_user(User(username="x", password="pw"))

        assert not isinstance(refused.value, DeclaredConfigurationUnloadable)
        assert store.users.get("x") is None

    def test_the_endpoint_says_a_lock_held_by_a_peer_is_temporary(self, tmp_path, monkeypatch):
        from nanoidp.app import create_app

        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        application = create_app(str(config_dir))
        application.config["TESTING"] = True
        client = application.test_client()
        _declare_user(config_dir, "someone")
        # The request's check looks (1) and its reload is refused the lock
        # (2). Remembered as files that do not load, the check would let the
        # request through to a creation whose look succeeds (3) and whose
        # reload is refused (4), and which would then say the files do not
        # load; the lock is what it is, at the check.
        _lock_fails_on(monkeypatch, {2, 4})

        response = client.post("/api/runtime/users", json={"username": "x", "password": "pw"})

        assert response.status_code == 503
        assert response.get_json()["error"] == "configuration_unavailable"

    def test_the_memory_store_does_not_take_the_directory_lock(self, tmp_path, monkeypatch):
        from nanoidp import config_writer
        from nanoidp.services.runtime_store import MemoryRuntimeStore

        config = ConfigManager(str(_config_dir(tmp_path)))
        store = MemoryRuntimeStore()
        taken = []
        real = config_writer._cross_process_lock

        def recording(*args, **kwargs):
            taken.append(1)
            return real(*args, **kwargs)

        monkeypatch.setattr(config_writer, "_cross_process_lock", recording)
        IdentityResolver(config, store).create_runtime_user(User(username="fresh", password="pw"))

        assert taken == []

    def test_a_client_is_checked_against_the_disk_too(self, shared):
        from nanoidp.config import OAuthClient

        config_dir, config, store = shared
        b = IdentityResolver(config, store)
        settings = config_dir / "settings.yaml"
        document = yaml.safe_load(settings.read_text())
        document["oauth"]["clients"].append({"client_id": "x", "client_secret": "s" * 20})
        settings.write_text(yaml.safe_dump(document))

        with pytest.raises(DeclaredNameCollision):
            b.create_runtime_client_entry(OAuthClient(client_id="x", client_secret="t" * 20))
        assert store.clients.get("x") is None


class TestAcrossProcesses:
    def test_a_name_declared_by_one_process_is_refused_to_the_other(self, tmp_path):
        """Real processes: B loads, A declares x and says so, B creates a
        runtime x and is refused; then B resolves x as declared."""
        config_dir = _config_dir(tmp_path)
        store_path = tmp_path / "state" / "runtime.db"
        SqliteRuntimeStore(store_path)
        loaded, declared, out = _SPAWN.Event(), _SPAWN.Event(), _SPAWN.Queue()
        b = _SPAWN.Process(target=_b_process, args=(str(config_dir), str(store_path), loaded, declared, out), daemon=True)
        b.start()
        try:
            assert loaded.wait(_BOUND)
            _declare_user(config_dir, "x")
            declared.set()
            result = out.get(timeout=_BOUND)
        finally:
            b.join(_BOUND)
            if b.is_alive():
                b.terminate()

        assert result == {"create": "DeclaredNameCollision", "stored": False, "resolves_declared": True}


def _b_process(config_dir, store_path, loaded, declared, out):
    import logging

    logging.disable(logging.CRITICAL)
    from nanoidp.config import ConfigManager, User
    from nanoidp.services import runtime_store
    from nanoidp.services.identities import IdentityResolver
    from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

    store = SqliteRuntimeStore(store_path)
    runtime_store.publish_runtime_store(store, ("memory",))
    config = ConfigManager(config_dir)
    loaded.set()
    declared.wait(60)
    try:
        IdentityResolver(config, store).create_runtime_user(User(username="x", password="pw"))
        outcome = "created"
    except Exception as failure:  # noqa: BLE001 - said to the parent
        outcome = type(failure).__name__
    user = config.get_user("x")
    out.put({"create": outcome, "stored": store.users.get("x") is not None, "resolves_declared": user is not None})


def _lock_fails_after(monkeypatch, successes):
    """The directory's cross-process lock is taken ``successes`` times, then
    held by a peer past the timeout."""
    _lock_fails_on(monkeypatch, None, successes)


def _lock_fails_on(monkeypatch, attempts, successes=None):
    """The directory's cross-process lock held by a peer past the timeout at
    the numbered attempts (from 1), or at every attempt after ``successes``."""
    from nanoidp import config_writer

    real = config_writer._cross_process_lock
    taken = []

    def lock(*args, **kwargs):
        taken.append(1)
        refused = len(taken) in attempts if attempts is not None else len(taken) > successes
        if refused:
            raise LockUnavailableError("held by a peer", kind="lock_timeout")
        return real(*args, **kwargs)

    monkeypatch.setattr(config_writer, "_cross_process_lock", lock)


def _lock_fails_for(monkeypatch, directory):
    """The cross-process lock of one directory held by a peer past the
    timeout; every other directory's lock as it is."""
    from nanoidp import config_writer

    real = config_writer._cross_process_lock

    def lock(target, *args, **kwargs):
        if Path(target).resolve() == directory:
            raise LockUnavailableError("held by a peer", kind="lock_timeout")
        return real(target, *args, **kwargs)

    monkeypatch.setattr(config_writer, "_cross_process_lock", lock)


def _within(action, seconds=5):
    import threading

    done = []
    worker = threading.Thread(target=lambda: done.append(action()), daemon=True)
    worker.start()
    worker.join(seconds)
    assert done, "stuck"
    return done[0]
