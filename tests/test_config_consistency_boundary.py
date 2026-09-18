"""One observation of a configuration directory, not several (#246).

The defect this file pins is architectural, not platform-specific. A reader
opens ``settings.yaml`` and ``users.yaml`` with two separate, unlocked
reads, so a write landing between them is observed as a pair that never
existed on disk:

```text
reader                           writer
------                           ------
reads settings OLD
                                 writes settings NEW
                                 writes users NEW
reads users NEW

=> the runtime is built from OLD settings and NEW users
```

The Windows ``PermissionError`` that #234 chased is a manifestation of the
same missing boundary, on the one platform whose ``replace`` refuses a file
another handle has open. Closing the mixed snapshot closes that race by
construction, because a reader inside the lock cannot be holding a file open
while a writer replaces it. So this is the red test, and the platform
symptom is the corollary.

The interleaving is forced with events, never with sleeps or with a
thousand probabilistic iterations: the reader is stopped at the exact seam
between its two acquisitions, which is the only moment the defect needs.
"""

import contextlib
import errno
import fcntl
import os
import shutil
import threading
from pathlib import Path

import pytest

from nanoidp import config_writer
from nanoidp.config import ConfigManager
from nanoidp.config_store import ConfigFileStore
from nanoidp.config_validation import validate_config_result
from nanoidp.config_writer import (
    LockNamespaceUnavailable,
    LockUnavailableError,
    revision_of_bytes,
)

_REPO_CONFIG = Path(__file__).resolve().parent.parent / "config"

_OLD_ISSUER = "http://old.example"
_NEW_ISSUER = "http://new.example"


def _settings(issuer: str) -> str:
    return f"oauth:\n  issuer: '{issuer}'\n  audience: 'default'\n"


def _users(name: str) -> str:
    return f"users:\n  {name}:\n    password: 'pw'\n    roles: ['USER']\n"


@pytest.fixture
def directory(tmp_path):
    (tmp_path / "settings.yaml").write_text(_settings(_OLD_ISSUER))
    (tmp_path / "users.yaml").write_text(_users("old_user"))
    return tmp_path


class TestADirectoryIsObservedOnce:
    def test_a_write_between_the_two_reads_is_never_observed_as_a_pair(
        self, directory, monkeypatch
    ):
        """The invariant: whatever a reader ends up with, both files come
        from the same moment. (OLD, OLD) and (NEW, NEW) are both correct
        answers; (OLD, NEW) is the one that must be impossible.

        Without the boundary this fails with the mixed pair, deterministically
        rather than occasionally.
        """
        # The writer gives up quickly once the reader holds the directory,
        # so the test states its own bound instead of waiting out the
        # production timeout.
        monkeypatch.setattr("nanoidp.config_writer._LOCK_TIMEOUT_SECONDS", 0.3)

        reader_thread = threading.current_thread()
        settings_read = threading.Event()
        writer_finished = threading.Event()
        real_open = open

        def seam(file, *args, **kwargs):
            # The seam sits between the reader's two acquisitions: it fires
            # when the reader is about to take users.yaml, having already
            # taken settings.yaml.
            if (
                threading.current_thread() is reader_thread
                and str(file).endswith("users.yaml")
                and settings_read.is_set() is False
            ):
                settings_read.set()
                # Bounded, and expected to time out once the reader holds
                # the lock: the writer is then blocked rather than finished.
                writer_finished.wait(timeout=5)
            return real_open(file, *args, **kwargs)

        def write_both_files():
            try:
                settings_read.wait(timeout=5)
                manager = ConfigManager(config_dir=str(directory))
                manager.settings.issuer = _NEW_ISSUER
                manager.users.clear()
                manager.save()
            except Exception:  # noqa: BLE001 - the reader must never hang on it
                pass
            finally:
                writer_finished.set()

        writer = threading.Thread(target=write_both_files)
        writer.start()
        monkeypatch.setattr("builtins.open", seam)
        try:
            observed = ConfigManager(config_dir=str(directory))
        finally:
            monkeypatch.undo()
            writer.join(timeout=10)

        # Without this the test could pass vacuously: if the reader ever
        # stops going through the builtin open, the seam never fires, the
        # writer is never provoked into racing, and every pair looks
        # consistent for the wrong reason.
        assert settings_read.is_set(), (
            "the seam never fired: the reader no longer opens users.yaml "
            "through builtins.open, so this test proves nothing as written"
        )

        observed_settings = observed.settings.issuer
        observed_users = set(observed.users)
        pair = (observed_settings, observed_users)

        assert pair in (
            (_OLD_ISSUER, {"old_user"}),
            (_NEW_ISSUER, set()),
        ), (
            f"observed a pair that never existed on disk: settings from "
            f"{observed_settings!r} with users {sorted(observed_users)!r}"
        )


class TestOneObservationMeansOne:
    """The seam in the test above cannot see this, and it took a surviving
    mutation to notice.

    Its seam fires while the reader is opening ``users.yaml``, which is
    inside whatever critical section the reader is in at that moment. A
    reader that took the lock twice, once per file, would therefore look
    exactly the same to it, while leaving the directory unguarded in
    between - and that gap is the whole defect.

    The invariant is not "each read is locked", it is "the pair is ONE
    observation", so what these tests count is observations: one lock
    acquisition for the pair, and one open per file. In a boundary whose
    purpose is to collapse several looks into one, counting the looks is the
    property, not an implementation detail.
    """

    def test_loading_the_directory_acquires_the_lock_once(self, directory, monkeypatch):
        import nanoidp.config_store as config_store

        acquisitions = []
        real_lock = config_store.directory_lock

        @contextlib.contextmanager
        def counting_lock(path):
            acquisitions.append(path)
            with real_lock(path):
                yield

        monkeypatch.setattr(config_store, "directory_lock", counting_lock)

        ConfigManager(config_dir=str(directory))

        # One for the whole pre-load phase - settings.yaml for the
        # strictness and bootstrap.yaml for the registry, together - which
        # is a different moment on purpose, since it runs before the
        # on_before_load hooks that may render settings.yaml. And one for
        # the load's own pair.
        assert len(acquisitions) == 2, (
            f"the loader observed the directory {len(acquisitions)} times; "
            "settings.yaml and users.yaml must come from one acquisition"
        )

    def test_a_file_is_opened_once_per_observation(self, directory, monkeypatch):
        """Reading the bytes and then reading them again for the revision
        would be two looks at one file, which is what FileSnapshot exists to
        prevent."""
        from nanoidp.config_store import ConfigFileStore

        opens = []
        real_open = open

        def counting_open(file, *args, **kwargs):
            if str(file).endswith(".yaml"):
                opens.append(str(file))
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr("builtins.open", counting_open)
        store = ConfigFileStore(directory)

        store.read("settings.yaml")

        monkeypatch.undo()
        assert opens.count(str(directory / "settings.yaml")) == 1


class TestContentAndRevisionAreOneObservation:
    """A revision describes the bytes it was computed from, or it describes
    nothing. The pattern this forbids is

    ```python
    data = read(path)
    revision = current_revision(path)   # a second observation
    ```

    which can hand back a revision for content the caller never saw.
    """

    def test_a_read_carries_the_revision_of_what_it_returned(self, directory):
        from nanoidp.config_store import ConfigFileStore

        store = ConfigFileStore(directory)

        snapshot = store.read("settings.yaml")

        assert snapshot.revision == revision_of_bytes(snapshot.data)

    def test_a_snapshot_carries_one_revision_per_file_from_the_same_moment(
        self, directory
    ):
        from nanoidp.config_store import ConfigFileStore

        store = ConfigFileStore(directory)

        snapshot = store.read_snapshot(("settings.yaml", "users.yaml"))

        assert set(snapshot) == {"settings.yaml", "users.yaml"}
        for name, observed in snapshot.items():
            assert observed.revision == revision_of_bytes(observed.data), name

    def test_a_missing_file_is_observed_as_empty_with_the_matching_revision(
        self, directory
    ):
        """``current_revision`` already gives a missing file the hash of
        empty bytes, so "create this only if it still does not exist" keeps
        working through the store (#229 phase 5)."""
        from nanoidp.config_store import ConfigFileStore

        store = ConfigFileStore(directory)

        snapshot = store.read("bootstrap.yaml")

        assert snapshot.data == b""
        assert snapshot.revision == revision_of_bytes(b"")
        assert snapshot.exists is False

    def test_an_empty_file_is_not_a_missing_one(self, directory):
        """Same bytes, different observation: a loader treats an absent
        settings.yaml as "use the defaults" and an empty one as a document
        that parsed to nothing, so existence belongs in the snapshot rather
        than in a second look at the directory."""
        from nanoidp.config_store import ConfigFileStore

        (directory / "bootstrap.yaml").write_text("")
        store = ConfigFileStore(directory)

        snapshot = store.read("bootstrap.yaml")

        assert snapshot.data == b""
        assert snapshot.exists is True


class TestWhenTheProtocolCannotExistVersusWhenItCannotBeJoined:
    """The line the #246 review drew, and the reason it is not "consistency
    always" (#246).

    A read never abandons an available protocol: contention fails, and a
    filesystem without advisory locking fails, because both mean the
    protocol is there and this process could not join it. What a read does
    keep is its historical behaviour on a view where the protocol cannot
    exist at all - a read-only mount, which this project supports and
    documents in both docker-compose.yml and the Helm chart, or a directory
    that is not there. Such a view has no writer to be inconsistent with:
    writing configuration needs the same directory-entry capability the lock
    file needs.
    """

    def test_a_read_only_directory_that_has_a_lock_file_still_coordinates(
        self, directory, monkeypatch
    ):
        """The case the first fix missed, and the common one: a read-only
        mount usually CARRIES a lock file, because it is part of whatever
        content was mounted - this repository's own config/ has one after
        any local save. flock works on a descriptor opened read-only, so
        the protocol is still there and this process still joins it rather
        than conceding (#246 review round 2)."""
        if os.geteuid() == 0:
            pytest.skip("root ignores the modes this test relies on")
        lock_file = directory / ".nanoidp-write.lock"
        lock_file.write_bytes(b"")
        os.chmod(lock_file, 0o444)
        os.chmod(directory, 0o555)

        attempts = []
        real_attempt = config_writer._try_lock_exclusive
        monkeypatch.setattr(
            "nanoidp.config_writer._try_lock_exclusive",
            lambda fd: (attempts.append(fd), real_attempt(fd))[1],
        )
        try:
            manager = ConfigManager(config_dir=str(directory))
        finally:
            os.chmod(directory, 0o755)
            os.chmod(lock_file, 0o644)

        assert set(manager.users) == {"old_user"}
        assert attempts, "the read gave up the protocol instead of joining it read-only"

    def test_a_read_only_directory_still_loads(self, directory):
        """The regression the review caught: the chart mounts the config
        read-only and its README says SAVES fail while reads work. Taking
        the write lock for reads made the pod fail at startup instead."""
        if os.geteuid() == 0:
            pytest.skip("root ignores the directory mode this test relies on")
        os.chmod(directory, 0o555)
        try:
            manager = ConfigManager(config_dir=str(directory))
        finally:
            os.chmod(directory, 0o755)

        assert set(manager.users) == {"old_user"}
        assert manager.settings.issuer == _OLD_ISSUER
        assert not (directory / ".nanoidp-write.lock").exists()

    def test_a_missing_directory_still_falls_back_to_the_defaults(self, tmp_path):
        manager = ConfigManager(config_dir=str(tmp_path / "not-there"))

        assert set(manager.users) == {"admin"}

    def test_contention_is_not_a_reason_to_read_unlocked(self, directory, monkeypatch):
        """The half of the principle that did not move: a peer holding the
        lock makes a read fail, it does not make it read anyway."""
        monkeypatch.setattr("nanoidp.config_writer._LOCK_TIMEOUT_SECONDS", 0.3)
        store = ConfigFileStore(directory)
        held = os.open(str(directory / ".nanoidp-write.lock"), os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with pytest.raises(LockUnavailableError) as refused:
                store.read_snapshot(("settings.yaml", "users.yaml"))
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)

        assert refused.value.kind == "lock_timeout"
        assert not isinstance(refused.value, LockNamespaceUnavailable)

    def test_a_filesystem_without_advisory_locks_fails_rather_than_degrading(
        self, directory, monkeypatch
    ):
        """"I cannot coordinate" must never be mistaken for "there is
        nothing to coordinate with"."""
        def unsupported(fd):
            raise OSError(errno.ENOLCK, "No locks available")

        monkeypatch.setattr("nanoidp.config_writer._try_lock_exclusive", unsupported)
        store = ConfigFileStore(directory)

        with pytest.raises(LockUnavailableError) as refused:
            store.read_snapshot(("settings.yaml", "users.yaml"))

        assert refused.value.kind == "lock_unsupported"

    def test_windows_does_not_take_the_read_only_fallback(self, directory, monkeypatch):
        """``msvcrt.locking`` needs a writable descriptor and answers EACCES
        on a read-only one, which the attempt helper reads as "someone else
        holds it" - so the POSIX fallback would poll out the whole timeout
        there and then blame a peer that does not exist (#246 review round
        3). Windows reaches the same conclusion without the wait.

        Driven by forcing the platform branch, since the suite runs on
        POSIX: what is asserted is that no lock attempt is made at all.
        """
        monkeypatch.setattr("nanoidp.config_writer.sys.platform", "win32")

        def refuse_to_open_for_writing(path, flags, *args):
            if str(path).endswith(".nanoidp-write.lock") and flags & os.O_RDWR:
                raise PermissionError(errno.EACCES, "Permission denied")
            return real_os_open(path, flags, *args)

        real_os_open = os.open
        monkeypatch.setattr("nanoidp.config_writer.os.open", refuse_to_open_for_writing)
        attempts = []
        monkeypatch.setattr(
            "nanoidp.config_writer._try_lock_exclusive",
            lambda fd: attempts.append(fd) or True,
        )

        observed = ConfigFileStore(directory).read_snapshot(("settings.yaml",))

        assert observed["settings.yaml"].data
        assert attempts == [], (
            "Windows tried to lock a descriptor it could not open for "
            "writing, which polls out the timeout and blames a peer"
        )

    def test_an_existing_but_unopenable_lock_file_fails_closed(self, directory):
        """The namespace exists and something is wrong with it, which is not
        the read-only case: widening the catch to every OSError would turn
        this into a silent unlocked read."""
        if os.geteuid() == 0:
            pytest.skip("root ignores the file mode this test relies on")
        lock_file = directory / ".nanoidp-write.lock"
        lock_file.write_bytes(b"")
        os.chmod(lock_file, 0o000)
        store = ConfigFileStore(directory)
        try:
            with pytest.raises(OSError) as refused:
                store.read_snapshot(("settings.yaml", "users.yaml"))
        finally:
            os.chmod(lock_file, 0o644)

        assert not isinstance(refused.value, LockNamespaceUnavailable)


class TestWaitingForAnotherProcessDoesNotOwnThisOne:
    """The lock ORDER, which #246's review found by measuring (#246).

    ``directory_lock`` used to take the process-global ``_write_lock``
    first and then poll the directory's file lock while holding it, so one
    stuck peer process stalled every thread here, including readers of an
    unrelated directory. That was tolerable while only writers took the
    lock; PR A puts every read on that path, which turns it into a stall of
    ordinary page renders.

    The order is now the file lock first, the thread lock second. Both are
    still held for the whole critical section, so nothing about mutual
    exclusion changed - only that waiting on another process no longer
    monopolizes this one.
    """

    def _directory(self, root, name):
        made = root / name
        made.mkdir()
        (made / "settings.yaml").write_text(_settings(_OLD_ISSUER))
        (made / "users.yaml").write_text(_users("old_user"))
        return made

    def test_a_stuck_peer_on_one_directory_leaves_another_readable(
        self, tmp_path, monkeypatch
    ):
        contended = self._directory(tmp_path, "contended")
        unrelated = self._directory(tmp_path, "unrelated")
        monkeypatch.setattr("nanoidp.config_writer._LOCK_TIMEOUT_SECONDS", 5.0)

        # Knowing the first reader is REALLY polling, rather than assuming
        # it from elapsed time: the seam fires on its first failed attempt.
        polling = threading.Event()
        real_attempt = config_writer._try_lock_exclusive

        def watched(fd):
            acquired = real_attempt(fd)
            if not acquired:
                polling.set()
            return acquired

        monkeypatch.setattr("nanoidp.config_writer._try_lock_exclusive", watched)

        held = os.open(
            str(contended / ".nanoidp-write.lock"), os.O_CREAT | os.O_RDWR, 0o644
        )
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        first_reader_done = threading.Event()

        def read_the_contended_one():
            try:
                ConfigFileStore(contended).read_snapshot(("settings.yaml", "users.yaml"))
            except LockUnavailableError:
                pass
            finally:
                first_reader_done.set()

        blocked = threading.Thread(target=read_the_contended_one)
        blocked.start()
        try:
            assert polling.wait(timeout=5), "the first reader never reached the lock"

            observed = ConfigFileStore(unrelated).read_snapshot(
                ("settings.yaml", "users.yaml")
            )

            # The property, stated as a fact about ordering rather than as a
            # stopwatch reading: the unrelated read COMPLETED while the
            # contended one was still waiting.
            assert not first_reader_done.is_set(), (
                "the unrelated directory was only readable after the "
                "contended one gave up, so waiting on a peer still owns "
                "this whole process"
            )
            assert observed["settings.yaml"].data
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)
            blocked.join(timeout=10)

    def test_the_batch_write_path_has_the_same_ordering(self, tmp_path, monkeypatch):
        """The same invariant on the other path, because a surviving
        mutation showed it was unguarded there: reversing the order inside
        compare_and_replace_many alone broke no test.

        One ordering for the whole codebase, or none: the batch takes every
        directory's file lock, in sorted order so two batches over the same
        set cannot deadlock, and the thread lock last.
        """
        contended = self._directory(tmp_path, "contended")
        unrelated = self._directory(tmp_path, "unrelated")
        monkeypatch.setattr("nanoidp.config_writer._LOCK_TIMEOUT_SECONDS", 5.0)

        polling = threading.Event()
        real_attempt = config_writer._try_lock_exclusive

        def watched(fd):
            acquired = real_attempt(fd)
            if not acquired:
                polling.set()
            return acquired

        monkeypatch.setattr("nanoidp.config_writer._try_lock_exclusive", watched)

        held = os.open(
            str(contended / ".nanoidp-write.lock"), os.O_CREAT | os.O_RDWR, 0o644
        )
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        writer_done = threading.Event()

        def write_the_contended_one():
            try:
                config_writer.compare_and_replace_many(
                    [(contended / "settings.yaml", None, lambda doc: doc.update({"x": 1}))]
                )
            except LockUnavailableError:
                pass
            finally:
                writer_done.set()

        blocked = threading.Thread(target=write_the_contended_one)
        blocked.start()
        try:
            assert polling.wait(timeout=5), "the blocked writer never reached the lock"

            ConfigFileStore(unrelated).read_snapshot(("settings.yaml", "users.yaml"))

            assert not writer_done.is_set(), (
                "an unrelated directory was only readable after the blocked "
                "batch gave up: the batch still takes the thread lock first"
            )
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)
            blocked.join(timeout=10)


class TestAnUnobservableDirectoryAnswers503:
    """A read can fail now, so an HTTP surface has to say so (#246 review).

    Before PR A a plain GET could not fail because a peer process held
    `.nanoidp-write.lock`; joining reads to the protocol made that possible.
    Without a handler it reaches the catch-all and answers 500 with a
    traceback, which is untrue: the service is fine, it could not observe
    the configuration at that moment.

    What each surface says about it is PR B's question. What belongs here is
    that none of them answers with a stack trace.
    """

    def test_a_held_lock_turns_a_page_render_into_503(self, tmp_path, monkeypatch):
        from nanoidp.app import create_app

        config_dir = tmp_path / "cfg"
        config_dir.mkdir()
        shutil.copy(_REPO_CONFIG / "settings.yaml", config_dir / "settings.yaml")
        shutil.copy(_REPO_CONFIG / "users.yaml", config_dir / "users.yaml")
        app = create_app(config_dir=str(config_dir))
        app.config["TESTING"] = False
        client = app.test_client()

        monkeypatch.setattr("nanoidp.config_writer._LOCK_TIMEOUT_SECONDS", 0.3)
        held = os.open(
            str(config_dir / ".nanoidp-write.lock"), os.O_CREAT | os.O_RDWR, 0o644
        )
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            response = client.get("/clients")
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)

        assert response.status_code == 503
        body = response.data.decode()
        assert "Traceback" not in body
        assert "nanoidp-write.lock" not in body

    def test_a_json_client_gets_the_reason_in_json(self, tmp_path, monkeypatch):
        from nanoidp.app import create_app

        config_dir = tmp_path / "cfg"
        config_dir.mkdir()
        shutil.copy(_REPO_CONFIG / "settings.yaml", config_dir / "settings.yaml")
        shutil.copy(_REPO_CONFIG / "users.yaml", config_dir / "users.yaml")
        app = create_app(config_dir=str(config_dir))
        app.config["TESTING"] = False

        monkeypatch.setattr("nanoidp.config_writer._LOCK_TIMEOUT_SECONDS", 0.3)
        held = os.open(
            str(config_dir / ".nanoidp-write.lock"), os.O_CREAT | os.O_RDWR, 0o644
        )
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            response = app.test_client().get(
                "/clients", headers={"Accept": "application/json"}
            )
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)

        assert response.status_code == 503
        assert response.get_json() == {
            "error": "configuration_unavailable",
            "kind": "lock_timeout",
        }


class TestAMissingDirectoryIsOneDecision:
    """The directory's absence is decided once, and then not re-observed
    (#246 review round 4).

    Reading each file after the check would be a fresh observation each,
    so a directory appearing in between would hand back a snapshot composed
    of different moments - the very class of bug this module removes,
    reintroduced on the path meant to be the simple case.
    """

    def test_a_directory_that_appears_mid_call_does_not_leak_into_the_snapshot(
        self, tmp_path, monkeypatch
    ):
        absent = tmp_path / "not-there"
        store = ConfigFileStore(absent)

        real_is_dir = Path.is_dir

        def create_it_right_after_the_check(self):
            answer = real_is_dir(self)
            if self == absent and not answer:
                # Exactly the race: another process gets there between the
                # decision and whatever would come next.
                absent.mkdir()
                (absent / "settings.yaml").write_text(_settings(_NEW_ISSUER))
                (absent / "users.yaml").write_text(_users("new_user"))
            return answer

        monkeypatch.setattr(Path, "is_dir", create_it_right_after_the_check)

        observed = store.read_snapshot(("settings.yaml", "users.yaml"))

        assert absent.is_dir(), "the race never happened, so this proves nothing"
        for name, snapshot in observed.items():
            assert snapshot.exists is False, name
            assert snapshot.data == b"", name


class TestValidateConfigObservesTheDirectoryOnce:
    """The reason PR B is not cleanup (#246, second part).

    A validation run used to read settings.yaml three times - once for the
    findings, once for the strictness and once for the report header - and
    each file on its own besides. So while a save was in progress it could
    pair the pre-save settings with the post-save users file and report a
    cross-file version disagreement for a state that never existed on disk:
    a false failure in the tool operators use to gate a deploy.
    """

    def test_each_file_is_opened_once_for_a_whole_run(self, directory, monkeypatch):
        from nanoidp.config_validation import validate_config_result

        opens: list = []
        real_open = open

        def counting_open(file, *args, **kwargs):
            name = Path(str(file)).name
            if name.endswith(".yaml"):
                opens.append(name)
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr("builtins.open", counting_open)
        validate_config_result(directory)
        monkeypatch.undo()

        assert opens.count("settings.yaml") == 1, opens
        assert opens.count("users.yaml") == 1, opens

    def test_a_save_between_the_files_cannot_produce_a_cross_file_finding(
        self, directory, monkeypatch
    ):
        """The false positive itself: both files are rewritten together, so
        a run that observed them at one moment can never see one of each."""
        from nanoidp.config_validation import validate_config_result

        monkeypatch.setattr("nanoidp.config_writer._LOCK_TIMEOUT_SECONDS", 0.3)
        reader_thread = threading.current_thread()
        settings_read = threading.Event()
        writer_finished = threading.Event()
        real_open = open

        def seam(file, *args, **kwargs):
            if (
                threading.current_thread() is reader_thread
                and str(file).endswith("users.yaml")
                and not settings_read.is_set()
            ):
                settings_read.set()
                writer_finished.wait(timeout=5)
            return real_open(file, *args, **kwargs)

        def rewrite_both_files():
            try:
                settings_read.wait(timeout=5)
                manager = ConfigManager(config_dir=str(directory))
                manager.settings.issuer = _NEW_ISSUER
                manager.users.clear()
                manager.save()
            except Exception:  # noqa: BLE001 - the reader must never hang on it
                pass
            finally:
                writer_finished.set()

        writer = threading.Thread(target=rewrite_both_files)
        writer.start()
        monkeypatch.setattr("builtins.open", seam)
        try:
            result = validate_config_result(directory)
        finally:
            monkeypatch.undo()
            writer.join(timeout=10)

        assert settings_read.is_set(), "the seam never fired, so this proves nothing"
        for finding in result["findings"]:
            assert "config_version" not in finding["message"], finding

    def test_a_directory_that_cannot_be_observed_is_an_error_finding(
        self, directory, monkeypatch
    ):
        """Consistency is not degraded to get a report out: the refusal is
        reported, it does not become an unlocked read (#246)."""
        from nanoidp.config_validation import validate_config_result

        monkeypatch.setattr("nanoidp.config_writer._LOCK_TIMEOUT_SECONDS", 0.3)
        held = os.open(
            str(directory / ".nanoidp-write.lock"), os.O_CREAT | os.O_RDWR, 0o644
        )
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            result = validate_config_result(directory)
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)

        assert result["valid"] is False
        assert any(
            finding["level"] == "error" and "consistent configuration snapshot" in finding["message"]
            for finding in result["findings"]
        ), result["findings"]

    def test_the_bootstrap_read_joins_the_protocol(self, directory, monkeypatch):
        """NANOIDP_BOOTSTRAP_HOOK exists so something else can render this
        file, so an exists()-then-open() pair here was a check against
        exactly the writer it was written for."""
        import nanoidp.config_store as config_store
        from nanoidp.hooks import bootstrap_registry

        (directory / "bootstrap.yaml").write_text("hooks: {}\n")
        acquisitions = []
        real_lock = config_store.directory_lock

        @contextlib.contextmanager
        def counting_lock(path):
            acquisitions.append(path)
            with real_lock(path):
                yield

        monkeypatch.setattr(config_store, "directory_lock", counting_lock)

        bootstrap_registry(directory)

        assert acquisitions == [directory]


class TestALintToolAnswersWithAReport:
    """A lint tool answers with findings, never with a traceback (#246 PR B
    review).

    Acquiring the bytes moved into the store, so the OSError ``_read_yaml``
    used to catch per file surfaces at the acquisition instead. It has to
    come back out as a finding: the CLI prints lines and the MCP tool
    returns ``{valid, findings}``, and neither is built for an exception.
    """

    def _unreadable(self, directory):
        os.chmod(directory / "settings.yaml", 0o000)

    def test_an_unreadable_file_is_a_finding_not_an_exception(self, directory):
        if os.geteuid() == 0:
            pytest.skip("root ignores the file mode this test relies on")
        from nanoidp.config_validation import validate_config_dir

        self._unreadable(directory)
        try:
            findings = validate_config_dir(directory)
        finally:
            os.chmod(directory / "settings.yaml", 0o644)

        assert any(
            finding.level == "error" and "cannot be read" in finding.message
            for finding in findings
        ), findings

    def test_the_mcp_result_stays_a_result(self, directory):
        if os.geteuid() == 0:
            pytest.skip("root ignores the file mode this test relies on")
        from nanoidp.config_validation import validate_config_result

        self._unreadable(directory)
        try:
            result = validate_config_result(directory)
        finally:
            os.chmod(directory / "settings.yaml", 0o644)

        assert result["valid"] is False
        assert any("cannot be read" in f["message"] for f in result["findings"])

    def test_the_report_header_falls_back_instead_of_raising(self, directory):
        if os.geteuid() == 0:
            pytest.skip("root ignores the file mode this test relies on")
        from nanoidp.config_validation import declared_mode, effective_strict

        self._unreadable(directory)
        try:
            assert declared_mode(directory) == "warn"
            assert effective_strict(directory, False) is False
        finally:
            os.chmod(directory / "settings.yaml", 0o644)


class TestTheCliAndTheToolShareOneObservation:
    """The gate this work is about is the CLI, and it was the one path left
    reaching its strictness separately (#246 PR B review).

    A deploy rewriting `config_validation` between the two reads made the
    run apply strict rules while printing a header for a directory that no
    longer declared them: the same false failure, in the same tool.
    """

    def test_one_acquisition_for_findings_and_strictness(self, directory, monkeypatch):
        import nanoidp.config_store as config_store
        from nanoidp.config_validation import validate_once

        acquisitions = []
        real_lock = config_store.directory_lock

        @contextlib.contextmanager
        def counting_lock(path):
            acquisitions.append(path)
            with real_lock(path):
                yield

        monkeypatch.setattr(config_store, "directory_lock", counting_lock)

        result = validate_once(directory)

        assert acquisitions == [directory], (
            "the findings and the declared mode came from different "
            "observations of the directory"
        )
        assert result.declared_mode in ("warn", "strict")

    def test_the_command_line_goes_through_it(self, directory, monkeypatch):
        """Pinned at the entry point, because fixing only the MCP path is
        exactly the mistake the review caught."""
        import nanoidp.config_validation as config_validation
        from nanoidp.__main__ import validate_config_command

        calls = []
        real = config_validation.validate_once
        monkeypatch.setattr(
            config_validation,
            "validate_once",
            lambda d: (calls.append(d), real(d))[1],
        )

        validate_config_command(str(directory), strict=False)

        assert calls == [str(directory)]


class TestARunThatDidNotHappenIsNotAVerdict:
    """Three outcomes, not two (#246 PR B review).

    This work exists because a mixed snapshot made the deploy gate report
    INVALID for a state that never existed. Answering INVALID because the
    directory could not be observed would have moved that defect rather
    than removed it: there is no failed validation, there is no validation.
    """

    def _with_the_lock_held(self, directory, run):
        held = os.open(
            str(directory / ".nanoidp-write.lock"), os.O_CREAT | os.O_RDWR, 0o644
        )
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            return run()
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)

    def test_contention_is_unavailable_not_invalid(self, directory, monkeypatch):
        from nanoidp.config_validation import UNAVAILABLE, validate_once

        monkeypatch.setattr("nanoidp.config_writer._LOCK_TIMEOUT_SECONDS", 0.3)

        result = self._with_the_lock_held(directory, lambda: validate_once(directory))

        assert result.status == UNAVAILABLE

    def test_an_unreadable_file_stays_a_verdict(self, directory):
        """Only the acquisition is UNAVAILABLE. A file the run could not
        read is still something it found out about the configuration, with
        the attribution it has always had."""
        if os.geteuid() == 0:
            pytest.skip("root ignores the file mode this test relies on")
        from nanoidp.config_validation import OBSERVED, validate_once

        os.chmod(directory / "settings.yaml", 0o000)
        try:
            result = validate_once(directory)
        finally:
            os.chmod(directory / "settings.yaml", 0o644)

        assert result.status == OBSERVED
        assert any("cannot be read" in f.message for f in result.findings)

    def test_the_command_line_exits_two_and_does_not_say_invalid(
        self, directory, monkeypatch, capsys
    ):
        from nanoidp.__main__ import validate_config_command

        monkeypatch.setattr("nanoidp.config_writer._LOCK_TIMEOUT_SECONDS", 0.3)

        code = self._with_the_lock_held(
            directory, lambda: validate_config_command(str(directory), strict=False)
        )

        assert code == 2
        printed = capsys.readouterr().out
        assert "UNAVAILABLE" in printed
        assert "invalid" not in printed.lower()

    def test_the_mcp_tool_answers_structured(self, directory, monkeypatch):
        from nanoidp.config_validation import UNAVAILABLE, validate_config_result

        monkeypatch.setattr("nanoidp.config_writer._LOCK_TIMEOUT_SECONDS", 0.3)

        result = self._with_the_lock_held(
            directory, lambda: validate_config_result(directory)
        )

        assert result["status"] == UNAVAILABLE
        assert result["valid"] is False


class TestTheMcpToolTakesItsStrictnessFromTheSameObservation:
    """The last place findings and strictness came from two moments (#246
    PR B review).

    `config.strict_config` is not an override: it is the `config_validation`
    this runtime read when IT loaded. Using it meant a settings.yaml that
    had since been relaxed was validated under the strictness of a file the
    run never saw - the defect this work closes, surviving on the one path
    the earlier fix did not touch.
    """

    def _write(self, directory, mode, with_warning=False):
        extra = "  unknown_key: 1\n" if with_warning else ""
        (directory / "settings.yaml").write_text(
            f"config_validation: {mode}\noauth:\n  issuer: '{_OLD_ISSUER}'\n"
            f"  audience: 'default'\n{extra}"
        )

    def test_the_tool_itself_follows_the_file_not_the_runtime(self, directory):
        """Pinned at the HANDLER, not at the library call underneath it: a
        mutation showed that testing validate_config_result directly left
        the entry point free to keep reading config.strict_config, which is
        exactly the mistake this fixes (#246 PR B review)."""
        from nanoidp.mcp_server.handlers_config import _tool_validate_config

        self._write(directory, "strict")
        manager = ConfigManager(config_dir=str(directory))
        assert manager.strict_config is True

        self._write(directory, "warn", with_warning=True)
        result = _tool_validate_config({}, manager)

        assert result["strict"] is False
        assert result["valid"] is True, result["findings"]

    def test_the_tool_keeps_a_real_override(self, directory):
        from nanoidp.mcp_server.handlers_config import _tool_validate_config

        self._write(directory, "warn")
        manager = ConfigManager(config_dir=str(directory), strict_config=True)
        self._write(directory, "warn", with_warning=True)

        result = _tool_validate_config({}, manager)

        assert result["strict"] is True
        assert result["valid"] is False

    def test_a_relaxed_file_is_validated_as_relaxed(self, directory):
        """The runtime loaded a strict directory; the file says warn now,
        and carries something that is only a warning. The run must follow
        the file it actually read."""
        self._write(directory, "strict")
        manager = ConfigManager(config_dir=str(directory))
        assert manager.strict_config is True

        self._write(directory, "warn", with_warning=True)
        result = validate_config_result(directory, manager.strict_config_override)

        assert result["strict"] is False
        assert result["valid"] is True, result["findings"]

    def test_a_real_override_still_wins(self, directory):
        """`--strict-config` is a decision about the process, not an
        observation of the file, so it survives the file being relaxed."""
        self._write(directory, "warn")
        manager = ConfigManager(config_dir=str(directory), strict_config=True)
        self._write(directory, "warn", with_warning=True)

        result = validate_config_result(directory, manager.strict_config_override)

        assert result["strict"] is True
        assert result["valid"] is False

    def test_an_override_of_false_is_a_decision_too(self, directory):
        """Collapsing False into "no override" would turn an explicit
        "not strict" into "whatever the file says"."""
        self._write(directory, "strict", with_warning=True)

        result = validate_config_result(directory, False)

        assert result["strict"] is False
        assert result["valid"] is True, result["findings"]
