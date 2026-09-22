"""The claim of a promotion whose writer died (#354, step 4b).

A promotion claims its runtime object with a ``writing`` hold on the entry,
which only the thread writing it resolves. With a store several processes
share, that thread can die with its process, and the claim would stay for
ever, refusing every delete, reset and promotion of the object. The claim
now names its owner, a process that holds an OS lock on a lease file for as
long as it lives; a peer that can take the lock has proved the owner dead,
and recovers the claim as the declared configuration says. No timeout is a
proof: a claim whose owner is alive is never recovered, however old.
"""

import multiprocessing
import os
import shutil
import signal
import time
from pathlib import Path

import pytest
import yaml

from nanoidp.config import ConfigManager, User
from nanoidp.services import runtime_store
from nanoidp.services.identities import (
    IdentityResolver,
    PromotionInProgress,
    RuntimeObjectNotFound,
    reconcile_runtime_identities,
)
from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

_REPO_CONFIG = Path(__file__).resolve().parent.parent / "config"
_SPAWN = multiprocessing.get_context("spawn")
_BOUND = 60
_POSIX = pytest.mark.skipif(os.name != "posix", reason="kills a process with SIGKILL")
_RECOVERED = "runtime_identity_promotion_recovered"


def _config_dir(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO_CONFIG / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    settings.write_text(yaml.safe_dump(document))
    for name in ("settings.yaml", "users.yaml"):
        then = time.time() - 60
        os.utime(config_dir / name, (then, then))
    return config_dir


def _declare(config_dir, username):
    users = config_dir / "users.yaml"
    document = yaml.safe_load(users.read_text())
    document["users"][username] = {"password": "declared", "email": f"{username}@example.org"}
    replacement = users.with_name("users.yaml.next")
    replacement.write_text(yaml.safe_dump(document))
    os.replace(replacement, users)


def _peer(config_dir, store, reconciling=True):
    """This process, as a peer of the one that died: its own configuration
    over the directory, reconciling after its loads unless told not to (so
    that what an operation recovers is the operation's), and the store."""
    runtime_store.publish_runtime_store(store, ("memory",))
    config = ConfigManager(str(config_dir), after_load=reconcile_runtime_identities if reconciling else None)
    return config, IdentityResolver(config, store)


def _recovered(store):
    return [(entry.username or entry.client_id, entry.details) for entry in store.audit.entries(100, event_type=_RECOVERED)]


# ---- the process that dies ------------------------------------------------------


def _promoter(config_dir, store_path, names, when, ready, out):
    """Creates the runtime users ``names`` and claims each for a promotion,
    as a promotion does before it writes: then, ``when`` is "after", writes
    their entries into the file (no reload follows), says it has stopped,
    and waits to be killed."""
    import logging
    import threading

    logging.disable(logging.CRITICAL)
    from nanoidp.config import User, init_config
    from nanoidp.services import identities as identities_module
    from nanoidp.services import runtime_store
    from nanoidp.services.identities import IdentityResolver
    from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

    store = SqliteRuntimeStore(store_path)
    runtime_store.publish_runtime_store(store, ("memory",))
    config = init_config(config_dir)
    identities = IdentityResolver(config, store)
    for name in names:
        identities.create_runtime_user(User(username=name, password="pw"))
    for name in names:
        identities_module._claim(store.users, "user", name, {"endpoint": "/promote"}, store.claim_owner())
    if when == "after":
        for name in names:
            _declare(Path(config_dir), name)
    out.put(store.claim_owner())
    ready.set()
    threading.Event().wait()  # until killed


def _promoting(config_dir, store_path, ready, out):
    """A promotion of runtime x through IdentityResolver's own promotion,
    whose write stops before it writes anything: then waits to be killed."""
    import logging
    import threading

    logging.disable(logging.CRITICAL)
    from nanoidp.config import User, init_config
    from nanoidp.services import runtime_store
    from nanoidp.services.identities import IdentityResolver
    from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

    store = SqliteRuntimeStore(store_path)
    runtime_store.publish_runtime_store(store, ("memory",))
    identities = IdentityResolver(init_config(config_dir), store)
    identities.create_runtime_user(User(username="x", password="pw"))
    stopped = threading.Event()

    def stop(user):
        stopped.set()
        threading.Event().wait()

    threading.Thread(target=identities._promote, args=("user", "x", stop, {"endpoint": "/promote"}), daemon=True).start()
    stopped.wait()
    out.put(store.claim_owner())
    ready.set()
    threading.Event().wait()


def _promotion_stopped(tmp_path, names=("x",), when="after"):
    """The config directory, the store's path, the owner id, and the process,
    stopped in the middle of its promotions."""
    config_dir = _config_dir(tmp_path)
    store_path = tmp_path / "state" / "runtime.db"
    SqliteRuntimeStore(store_path)
    ready, out = _SPAWN.Event(), _SPAWN.Queue()
    process = _SPAWN.Process(
        target=_promoter, args=(str(config_dir), str(store_path), list(names), when, ready, out), daemon=True
    )
    process.start()
    assert ready.wait(_BOUND), "the promoter did not stop where it was meant to"
    return config_dir, store_path, out.get(timeout=_BOUND), process


def _kill(process):
    os.kill(process.pid, signal.SIGKILL)
    process.join(_BOUND)
    assert process.exitcode == -signal.SIGKILL


# ---- the tests ------------------------------------------------------------------


@_POSIX
class TestADeadWriter:
    def test_an_entry_it_wrote_is_declared_and_the_claim_goes_as_recovered(self, tmp_path):
        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="after")
        _kill(process)
        store = SqliteRuntimeStore(store_path)
        config, identities = _peer(config_dir, store, reconciling=False)

        with pytest.raises(RuntimeObjectNotFound):
            identities.delete_runtime_user("x")

        assert store.users.get("x") is None
        assert config.get_user("x") is not None
        assert [(name, details["outcome"]) for name, details in _recovered(store)] == [("x", "declared")]
        # Proved dead and decided: its lease goes.
        assert not (store_path.parent / "runtime-owners" / f"{owner}.lock").exists()

    def test_a_promotion_killed_in_its_write_names_its_owner_and_is_recovered(self, tmp_path):
        """Through the promotion itself, not a claim made by hand: the owner
        it names is the process's, and its death frees the object."""
        config_dir = _config_dir(tmp_path)
        store_path = tmp_path / "state" / "runtime.db"
        SqliteRuntimeStore(store_path)
        ready, out = _SPAWN.Event(), _SPAWN.Queue()
        process = _SPAWN.Process(target=_promoting, args=(str(config_dir), str(store_path), ready, out), daemon=True)
        process.start()
        assert ready.wait(_BOUND)
        owner = out.get(timeout=_BOUND)
        store = SqliteRuntimeStore(store_path)
        assert store.users.entry("x").hold.payload["promotion"]["owner"] == owner
        _kill(process)
        config, identities = _peer(config_dir, store, reconciling=False)

        identities.delete_runtime_user("x")

        assert [(name, details["outcome"]) for name, details in _recovered(store)] == [("x", "runtime")]

    def test_the_recovery_decides_on_the_files_as_they_are(self, tmp_path):
        """A peer loaded before the entry reached the file: its recovery
        looks at the files, not at what it loaded, and finds x declared."""
        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="before")
        store = SqliteRuntimeStore(store_path)
        config, identities = _peer(config_dir, store)
        _declare(config_dir, "x")
        _kill(process)
        assert config.get_user("x") is None

        with pytest.raises(RuntimeObjectNotFound):
            identities.delete_runtime_user("x")

        assert [(name, details["outcome"]) for name, details in _recovered(store)] == [("x", "declared")]

    def test_an_entry_it_never_wrote_stays_runtime_and_the_operation_goes_on(self, tmp_path):
        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="before")
        _kill(process)
        store = SqliteRuntimeStore(store_path)
        config, identities = _peer(config_dir, store, reconciling=False)

        identities.delete_runtime_user("x")

        assert store.users.get("x") is None
        assert config.get_user("x") is None
        assert [(name, details["outcome"]) for name, details in _recovered(store)] == [("x", "runtime")]

    def test_a_promotion_of_it_goes_on_once_recovered(self, tmp_path, monkeypatch):
        from nanoidp.services import identities as identities_module

        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="before")
        _kill(process)
        store = SqliteRuntimeStore(store_path)
        config, identities = _peer(config_dir, store, reconciling=False)
        written = []
        monkeypatch.setattr(
            identities_module, "get_yaml_writer", lambda: type("W", (), {"save_user": lambda self, user, is_new: written.append(user.username)})()
        )

        identities.promote_runtime_user("x", {"endpoint": "/promote"})

        assert written == ["x"]

    def test_a_load_recovers_it_too_and_once(self, tmp_path):
        """No operation needed: the peer's own load reconciles, and a claim
        of a dead writer is recovered there, once."""
        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="after")
        _kill(process)
        store = SqliteRuntimeStore(store_path)

        config, identities = _peer(config_dir, store)

        assert store.users.get("x") is None
        assert [(name, details["outcome"]) for name, details in _recovered(store)] == [("x", "declared")]
        config.reload_local()
        assert len(_recovered(store)) == 1

    def test_a_load_whose_files_moved_leaves_the_recovery_to_the_next(self, tmp_path, monkeypatch):
        """Inside a load, files that moved since it read them are not decided
        on: nothing is recovered, and nothing is loaded again from there."""
        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="after")
        _kill(process)
        store = SqliteRuntimeStore(store_path)
        runtime_store.publish_runtime_store(store, ("memory",))
        moved = {"once": False}
        real = ConfigManager.act_if_files_are_loaded

        def files_moved_first(self, act):
            if not moved["once"]:
                moved["once"] = True
                return False, None
            return real(self, act)

        monkeypatch.setattr(ConfigManager, "act_if_files_are_loaded", files_moved_first)
        config = ConfigManager(str(config_dir), after_load=reconcile_runtime_identities)

        assert store.users.entry("x").hold is not None
        assert _recovered(store) == []
        config.reload_local()
        assert store.users.get("x") is None
        assert len(_recovered(store)) == 1

    def test_two_claims_of_one_dead_owner_are_both_recovered(self, tmp_path):
        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, names=("x", "y"), when="before")
        _kill(process)
        store = SqliteRuntimeStore(store_path)
        config, identities = _peer(config_dir, store, reconciling=False)

        identities.delete_runtime_user("x")
        identities.delete_runtime_user("y")

        assert (store.users.get("x"), store.users.get("y")) == (None, None)
        assert sorted(name for name, details in _recovered(store)) == ["x", "y"]

    def test_two_peers_recovering_together_decide_once(self, tmp_path):
        """One outcome and one audit event, and neither peer is told the
        object is still being promoted once it is not."""
        import threading

        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="before")
        _kill(process)
        store = SqliteRuntimeStore(store_path)
        runtime_store.publish_runtime_store(store, ("memory",))
        peers = [IdentityResolver(ConfigManager(str(config_dir)), store) for _ in range(2)]
        start, outcomes = threading.Barrier(2), []

        def delete(identities):
            start.wait()
            try:
                identities.delete_runtime_user("x")
                outcomes.append("deleted")
            except RuntimeObjectNotFound:
                outcomes.append("not found")
            except PromotionInProgress:
                outcomes.append("in progress")

        threads = [threading.Thread(target=delete, args=(peer,)) for peer in peers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(_BOUND)

        assert sorted(outcomes) == ["deleted", "not found"]
        assert [(name, details["outcome"]) for name, details in _recovered(store)] == [("x", "runtime")]
        assert store.users.get("x") is None

    def test_reset_counts_what_it_removed_not_what_recovery_did(self, tmp_path):
        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, names=("x", "y"), when="before")
        # x reaches the file after all (a peer declared it), y does not.
        _declare(config_dir, "x")
        _kill(process)
        store = SqliteRuntimeStore(store_path)
        config, identities = _peer(config_dir, store, reconciling=False)
        store.users.create(User(username="z", password="pw"))

        users_deleted, clients_deleted = identities.reset_runtime_identities()

        # z, and y once released; x went by the recovery, declared.
        assert users_deleted == 2
        assert store.users.list() == []
        assert sorted((name, details["outcome"]) for name, details in _recovered(store)) == [
            ("x", "declared"),
            ("y", "runtime"),
        ]


@_POSIX
class TestALiveWriter:
    def test_a_claim_whose_owner_is_alive_is_never_recovered(self, tmp_path):
        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="before")
        try:
            store = SqliteRuntimeStore(store_path)
            config, identities = _peer(config_dir, store)

            with pytest.raises(PromotionInProgress):
                identities.delete_runtime_user("x")
            assert identities.reset_runtime_identities() == (0, 0)
            config.reload_local()

            assert store.users.entry("x").hold is not None
            assert _recovered(store) == []
            with store.prove_owner_dead(owner) as dead:
                assert dead is False
        finally:
            _kill(process)


@_POSIX
class TestWhatIsNoDeadWritersClaim:
    def test_a_written_claim_of_a_dead_owner_is_the_loads_to_resolve_as_a_promotion(self, tmp_path):
        """Written: its entry reached the file, and a load says how it ended,
        as a promotion. Its owner being dead changes nothing of that."""
        from nanoidp.services import identities as identities_module

        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="after")
        store = SqliteRuntimeStore(store_path)
        identities_module._mark_written(store.users, store.users.entry("x"))
        _kill(process)

        _peer(config_dir, store)

        assert store.users.get("x") is None
        assert _recovered(store) == []
        assert [entry.username for entry in store.audit.entries(10, event_type="runtime_identity_promoted")] == ["x"]

    def test_the_decision_is_on_the_claim_proved_and_no_other(self, tmp_path):
        from nanoidp.services import identities as identities_module

        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="before")
        _kill(process)
        store = SqliteRuntimeStore(store_path)
        config, identities = _peer(config_dir, store, reconciling=False)
        held = store.users.entry("x").hold

        outcome = identities_module._recover_under_lock(store, config, store.users, "user", "x", "another-claim", owner)

        assert outcome is None
        assert store.users.entry("x").hold == held


class TestTheLeases:
    def test_a_store_in_memory_has_no_owner_and_proves_nobody_dead(self):
        from nanoidp.services.runtime_store import MemoryRuntimeStore

        store = MemoryRuntimeStore()

        assert store.claim_owner() is None
        with store.prove_owner_dead("0" * 32) as dead:
            assert dead is False

    def test_an_owner_is_made_once_and_is_not_its_own_dead(self, tmp_path):
        store = SqliteRuntimeStore(tmp_path / "runtime.db")
        owner = store.claim_owner()

        assert owner == store.claim_owner()
        assert len(owner) == 32 and int(owner, 16) >= 0
        with store.prove_owner_dead(owner) as dead:
            assert dead is False
        with store.prove_owner_dead(None) as dead:
            assert dead is False

    @pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
    def test_the_leases_are_private(self, tmp_path):
        import stat

        store = SqliteRuntimeStore(tmp_path / "runtime.db")
        owner = store.claim_owner()
        owners = tmp_path / "runtime-owners"

        assert stat.S_IMODE(os.stat(owners).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(owners / f"{owner}.lock").st_mode) == 0o600

    @pytest.mark.parametrize("owner", ["../../etc/passwd", "x" * 32, "", "0" * 31, "0" * 32 + "/"])
    def test_an_owner_that_is_no_owner_id_proves_nothing(self, tmp_path, owner):
        store = SqliteRuntimeStore(tmp_path / "runtime.db")

        with store.prove_owner_dead(owner) as dead:
            assert dead is False

    def test_an_owner_whose_lease_is_gone_is_dead(self, tmp_path):
        store = SqliteRuntimeStore(tmp_path / "runtime.db")
        store.claim_owner()

        with store.prove_owner_dead("f" * 32) as dead:
            assert dead is True

    @_POSIX
    def test_a_stale_lease_is_removed_and_a_held_one_is_kept(self, tmp_path):
        config_dir, store_path, alive, process = _promotion_stopped(tmp_path, when="before")
        try:
            owners = store_path.parent / "runtime-owners"
            stale = owners / f"{'a' * 32}.lock"
            stale.write_text("")
            store = SqliteRuntimeStore(store_path)
            store.claim_owner()

            assert not stale.exists()
            assert (owners / f"{alive}.lock").exists()
        finally:
            _kill(process)

    @_POSIX
    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    def test_a_forked_child_is_an_owner_of_its_own_and_its_death_is_not_the_parents(self, tmp_path):
        store_path = tmp_path / "runtime.db"
        store = SqliteRuntimeStore(store_path)
        parent = store.claim_owner()
        read_end, write_end = os.pipe()
        pid = os.fork()
        if pid == 0:  # pragma: no cover - the child
            code = 0
            try:
                os.close(read_end)
                os.write(write_end, store.claim_owner().encode())
            except BaseException:
                code = 3
            os._exit(code)
        os.close(write_end)
        child = os.read(read_end, 64).decode()
        os.close(read_end)
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0

        assert child != parent and len(child) == 32
        result = _SPAWN.Queue()
        peer = _SPAWN.Process(target=_proves, args=(str(store_path), [parent, child], result), daemon=True)
        peer.start()
        peer.join(_BOUND)
        assert result.get(timeout=_BOUND) == [False, True]


def _fork_then_die(store_path, out):
    """An owner that forks a child which lives on, and dies itself."""
    import time as _time

    from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

    store = SqliteRuntimeStore(store_path)
    owner = store.claim_owner()
    pid = os.fork()
    if pid == 0:  # the child lives on, and makes no claim
        _time.sleep(120)
        os._exit(0)
    out.put((owner, pid))
    # Sent before this process goes: a queue's put is its feeder thread's.
    out.close()
    out.join_thread()
    os._exit(0)


def _proves(store_path, owners, out):
    from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

    store = SqliteRuntimeStore(store_path)
    answers = []
    for owner in owners:
        with store.prove_owner_dead(owner) as dead:
            answers.append(dead)
    out.put(answers)


@_POSIX
def test_a_child_that_lives_on_does_not_keep_its_dead_parents_lease(tmp_path):
    """The child closes its copy of the parent's lease descriptor: the lock is
    the open file's, and a child holding it would keep a dead parent alive
    for as long as the child lives."""
    store_path = tmp_path / "runtime.db"
    SqliteRuntimeStore(store_path)
    out = _SPAWN.Queue()
    parent = _SPAWN.Process(target=_fork_then_die, args=(str(store_path), out), daemon=True)
    parent.start()
    owner, child = out.get(timeout=_BOUND)
    # Not join(): the child inherited the descriptor join waits on, and
    # holds it for as long as it lives; exitcode asks waitpid.
    deadline = time.monotonic() + _BOUND
    while parent.exitcode is None and time.monotonic() < deadline:
        time.sleep(0.05)
    assert parent.exitcode == 0
    try:
        store = SqliteRuntimeStore(store_path)
        store.claim_owner()
        with store.prove_owner_dead(owner) as dead:
            assert dead is True
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


class TestTheReviewOf4b:
    def test_a_lease_being_made_is_never_swept_away(self, tmp_path):
        """A peer's sweep of dead leases runs while this process is making
        its own: the lease it is making is not a dead one, and this process
        is never proved dead while it lives."""
        from unittest import mock

        from nanoidp.services import sqlite_runtime_store as module

        owners = tmp_path / "runtime-owners"
        owners.mkdir(mode=0o700)
        first, second = module._OwnerLeases(owners), module._OwnerLeases(owners)
        real_lock = module._try_lock
        calls = []

        def a_peer_sweeps_in_between(fd):
            calls.append(fd)
            if len(calls) == 1:
                with mock.patch.object(module, "_try_lock", real_lock):
                    first.owner()
            return real_lock(fd)

        with mock.patch.object(module, "_try_lock", a_peer_sweeps_in_between):
            alive = second.owner()

        assert (owners / f"{alive}.lock").exists()
        with first.prove_dead(alive) as dead:
            assert dead is False

    @_POSIX
    def test_a_live_peers_claim_does_not_make_the_files_matter(self, tmp_path):
        """Nothing is recoverable while its owner lives: a delete answers
        PromotionInProgress and a reset removes the rest, whatever the files
        say, broken ones included, and no load asks for the directory lock
        for it."""
        from nanoidp import config_writer

        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="before")
        try:
            store = SqliteRuntimeStore(store_path)
            config, identities = _peer(config_dir, store, reconciling=False)
            store.users.create(User(username="z", password="pw"))
            (config_dir / "users.yaml").write_text("users: [this is not a mapping\n")

            with pytest.raises(PromotionInProgress):
                identities.delete_runtime_user("x")
            assert identities.reset_runtime_identities() == (1, 0)

            (config_dir / "users.yaml").unlink()
            shutil.copy(_REPO_CONFIG / "users.yaml", config_dir / "users.yaml")
            loading = ConfigManager(str(config_dir), after_load=reconcile_runtime_identities)
            taken = []
            real = config_writer._cross_process_lock

            def counting(*args, **kwargs):
                taken.append(1)
                return real(*args, **kwargs)

            config_writer._cross_process_lock = counting
            try:
                loading.reload_local()
            finally:
                config_writer._cross_process_lock = real
            # The load's own look at the files, and nothing for the claim.
            assert len(taken) == 1
            assert store.users.entry("x").hold is not None
        finally:
            _kill(process)


@_POSIX
class TestTheProofThatDecides:
    def test_a_wrong_first_look_does_not_recover_a_live_owners_claim(self, tmp_path, monkeypatch):
        """The quick look only spares the files; what decides is the proof
        under the lock, whatever the look said."""
        config_dir, store_path, owner, process = _promotion_stopped(tmp_path, when="before")
        try:
            store = SqliteRuntimeStore(store_path)
            config, identities = _peer(config_dir, store, reconciling=False)
            monkeypatch.setattr(store, "owner_may_be_dead", lambda owner: True)

            with pytest.raises(PromotionInProgress):
                identities.delete_runtime_user("x")
            assert store.users.entry("x").hold is not None
            assert _recovered(store) == []
        finally:
            _kill(process)

    def test_a_claim_naming_no_owner_id_is_left_without_the_files(self, tmp_path):
        from nanoidp.services import identities as identities_module

        config_dir = _config_dir(tmp_path)
        store = SqliteRuntimeStore(tmp_path / "runtime.db")
        config, identities = _peer(config_dir, store, reconciling=False)
        store.users.create(User(username="x", password="pw"))
        store.users.create(User(username="z", password="pw"))
        identities_module._claim(store.users, "user", "x", {}, "../../not-an-owner")
        (config_dir / "users.yaml").write_text("users: [this is not a mapping\n")

        assert identities.reset_runtime_identities() == (1, 0)
        assert store.users.entry("x").hold is not None


class TestTheCurrentFilesWithoutAReload:
    def test_an_action_runs_when_the_files_are_the_loaded_ones(self, tmp_path):
        config = ConfigManager(str(_config_dir(tmp_path)))

        assert config.act_if_files_are_loaded(lambda: "acted") == (True, "acted")

    def test_files_that_moved_skip_the_action_and_load_nothing(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path)
        config = ConfigManager(str(config_dir))
        _declare(config_dir, "carol")
        loads = []
        monkeypatch.setattr(config, "_load_config", lambda *a, **k: loads.append(1))

        assert config.act_if_files_are_loaded(lambda: "acted") == (False, None)
        assert loads == []
