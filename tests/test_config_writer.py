"""
Tests for the shared compare-and-replace write primitive (issue #229, phase 1).

These exercise ``config_writer.py`` in isolation, against plain files on
disk - no ``ConfigManager``/``YamlWriter`` involved yet (phase 3 migrates
``YamlWriter`` onto this primitive).
"""

import itertools
import logging
import multiprocessing
import sys
import threading
import time
from pathlib import Path

import pytest

from nanoidp import config_writer
from nanoidp.config_writer import (
    ConflictError,
    LockUnavailableError,
    compare_and_replace,
    compare_and_replace_many,
    current_revision,
    directory_lock,
)
from nanoidp.serialization import load_yaml_document


def _mp_worker(file_path_str, base_revision, barrier, value, result_queue):
    """Module-level so it can be used as a multiprocessing target regardless
    of start method. Sleeps inside mutate to widen the check-to-replace
    window (#229 review round 2's probe).

    barrier.wait() is bounded (#229 review, non-blocking - applied): a
    plain wait() with no timeout means a sibling that dies (or never
    gets scheduled) before reaching the barrier leaves this process
    blocked forever. A timeout turns that into a clean, reported failure
    instead of a hung test process."""

    def mutate(doc):
        time.sleep(0.05)
        doc.update({"counter": value})

    try:
        barrier.wait(timeout=10)
    except Exception:
        result_queue.put(("barrier_timeout", value))
        return
    try:
        compare_and_replace(Path(file_path_str), base_revision, mutate)
        result_queue.put(("ok", value))
    except ConflictError:
        result_queue.put(("conflict", value))


class TestCurrentRevision:
    def test_missing_file_has_a_well_defined_revision(self, tmp_path):
        missing = tmp_path / "settings.yaml"
        assert current_revision(missing) == current_revision(missing)

    def test_revision_changes_when_bytes_change(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("a: 1\n")
        before = current_revision(f)
        f.write_text("a: 2\n")
        after = current_revision(f)
        assert before != after

    def test_revision_stable_across_reads(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("a: 1\n")
        assert current_revision(f) == current_revision(f)


class TestCompareAndReplaceUnconditional:
    """expected_revision=None: today's last-write-wins, no error ever."""

    def test_no_precondition_always_succeeds(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("a: 1\n")

        new_rev = compare_and_replace(f, None, lambda doc: doc.update({"a": 2}))

        assert f.read_text().strip() == "a: 2"
        assert new_rev == current_revision(f)

    def test_no_precondition_creates_a_missing_file(self, tmp_path):
        f = tmp_path / "settings.yaml"

        compare_and_replace(f, None, lambda doc: doc.update({"a": 1}))

        assert f.exists()
        assert f.read_text().strip() == "a: 1"


class TestCompareAndReplaceConflict:
    def test_matching_revision_succeeds(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("a: 1\n")
        base = current_revision(f)

        compare_and_replace(f, base, lambda doc: doc.update({"a": 2}))

        assert f.read_text().strip() == "a: 2"

    def test_stale_revision_raises_conflict_error(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("a: 1\n")
        base = current_revision(f)
        f.write_text("a: 999\n")  # someone else wrote it first

        with pytest.raises(ConflictError) as exc_info:
            compare_and_replace(f, base, lambda doc: doc.update({"a": 2}))

        assert exc_info.value.kind == "conflict"
        assert f.name in exc_info.value.message

    def test_conflict_leaves_the_file_untouched(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("a: 1\n")
        base = current_revision(f)
        f.write_text("a: 999\n")

        with pytest.raises(ConflictError):
            compare_and_replace(f, base, lambda doc: doc.update({"a": 2}))

        assert f.read_text().strip() == "a: 999"

    def test_conflict_does_not_run_mutate(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("a: 1\n")
        base = current_revision(f)
        f.write_text("a: 999\n")

        calls = []
        with pytest.raises(ConflictError):
            compare_and_replace(f, base, lambda doc: calls.append(doc))

        assert calls == []

    def test_missing_file_has_a_conflict_precondition_too(self, tmp_path):
        f = tmp_path / "settings.yaml"
        missing_revision = current_revision(f)
        f.write_text("a: 1\n")  # someone else created it first

        with pytest.raises(ConflictError):
            compare_and_replace(f, missing_revision, lambda doc: doc.update({"a": 2}))


class TestCompareAndReplaceConcurrency:
    """Two threads racing the same file: exactly one must win, the other
    must see ConflictError, and the file must never end up partially
    written or applying only one of the two mutations (#204 lesson)."""

    def test_one_writer_wins_the_other_conflicts(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("counter: 0\n")
        base = current_revision(f)

        results = []
        barrier = threading.Barrier(2)

        def attempt(value):
            barrier.wait()
            try:
                compare_and_replace(f, base, lambda doc: doc.update({"counter": value}))
                results.append(("ok", value))
            except ConflictError:
                results.append(("conflict", value))

        threads = [threading.Thread(target=attempt, args=(v,)) for v in (1, 2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        outcomes = [r[0] for r in results]
        assert outcomes.count("ok") == 1
        assert outcomes.count("conflict") == 1

        winner_value = next(v for outcome, v in results if outcome == "ok")
        assert f.read_text().strip() == f"counter: {winner_value}"


class TestConcurrentReadsOutsideTheLock:
    """Regression pin for the #229 review finding: reads never take
    compare_and_replace's write lock (reload_local(), YamlWriter's
    loaders and every other read path call
    serialization.load_yaml_document directly), so the lock alone cannot
    make a concurrent load_yaml_document safe against a racing write -
    that has to hold at the loader/dumper level (a fresh ruamel YAML
    instance per call, not one shared at module scope). Without that fix,
    this probe reliably raised errors of six different kinds, including
    one inside compare_and_replace's own load_yaml_document call, corrupted
    by a reader that was never inside the lock to begin with.

    xfail on Windows only (#229 review round 11): concurrent readers are
    not yet part of the config-file coordination protocol at all -
    load_yaml_document is only one of several direct readers
    (_stage_directory, config_validation.py, hooks.py read settings.yaml/
    users.yaml on their own), so a retry or a handle-close fix scoped to
    this one function cannot make the property this test wants
    (errors == []) actually true system-wide. Whether readers join the
    protocol at all is a real design question for #246, not a write-path
    bug - kept here, non-strict, active and required on POSIX, so the
    property stays visible instead of being loosened or deleted."""

    @pytest.mark.xfail(
        sys.platform == "win32",
        reason="Concurrent readers are not yet part of the config-file "
        "coordination protocol; see #246",
    )
    def test_readers_outside_the_lock_do_not_corrupt_a_racing_write(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("oauth:\n  issuer: 'http://localhost:8000'\n  audience: 'default'\n")

        errors = []
        stop = threading.Event()

        def read_loop():
            while not stop.is_set():
                try:
                    load_yaml_document(f)
                except Exception as exc:
                    errors.append(exc)

        readers = [threading.Thread(target=read_loop) for _ in range(4)]
        for t in readers:
            t.start()

        try:
            for i in range(300):
                compare_and_replace(f, None, lambda doc, i=i: doc.update({"counter": i}))
        finally:
            stop.set()
            for t in readers:
                t.join()

        assert errors == []


class TestReadersInsideTheProtocol:
    """The counterpart to the class above, for readers that DO join the
    protocol (#246).

    That one keeps its reader deliberately outside the lock, because the
    property it pins is the loader's own thread safety - a fresh ruamel
    instance per call - which must hold whoever calls it. This one pins what
    the boundary buys: a reader going through ``ConfigFileStore`` observes
    the directory under the same lock the writer takes, so it is never
    holding a file open while a replace happens.

    That is also why the Windows failure disappears here rather than being
    retried around: on the one platform whose replace refuses a file another
    handle has open, no reader in the protocol has one open at that moment.
    """

    def test_readers_through_the_store_see_no_errors_during_a_racing_write(self, tmp_path):
        from nanoidp.config_store import ConfigFileStore

        settings = tmp_path / "settings.yaml"
        settings.write_text("oauth:\n  issuer: 'http://localhost:8000'\n")
        users = tmp_path / "users.yaml"
        users.write_text("users: {}\n")
        store = ConfigFileStore(tmp_path)

        errors = []
        mixed = []
        stop = threading.Event()

        def read_loop():
            while not stop.is_set():
                try:
                    observed = store.read_snapshot(("settings.yaml", "users.yaml"))
                except Exception as exc:  # noqa: BLE001 - recorded, not raised
                    errors.append(exc)
                    continue
                # Both files carry the same counter, written together, so a
                # pair that disagrees is a snapshot that never existed.
                pair = (observed["settings.yaml"].data, observed["users.yaml"].data)
                if _counter_of(pair[0]) != _counter_of(pair[1]):
                    mixed.append(pair)

        readers = [threading.Thread(target=read_loop) for _ in range(4)]
        for reader in readers:
            reader.start()
        try:
            for i in range(50):
                compare_and_replace_many(
                    [
                        (settings, None, lambda doc, i=i: doc.update({"counter": i})),
                        (users, None, lambda doc, i=i: doc.update({"counter": i})),
                    ]
                )
        finally:
            stop.set()
            for reader in readers:
                reader.join()

        assert errors == []
        assert mixed == []


def _counter_of(raw: bytes) -> object:
    for line in raw.decode().splitlines():
        if line.startswith("counter:"):
            return line.split(":", 1)[1].strip()
    return None


class TestCrossProcessConflictDetection:
    """Regression pin for the #229 review round-2 finding: compare_and_replace's
    thread lock only serializes threads within one process, so two separate
    OS processes each get their own _write_lock and can both pass the
    revision check before either has written - the reviewer's
    multiprocessing probe (Barrier + a sleep inside mutate to widen the
    check-to-replace window) lost an update 10/10 trials without a
    cross-process lock. The advisory lock on a file in the config
    directory (_cross_process_lock) closes it.

    "spawn", not "fork" (#229 review round 8): fork does not exist on
    Windows at all, and CPython warns about it on 3.12+ when the parent
    process is multi-threaded, which pytest often is. spawn re-imports
    _mp_worker in the child by module + qualname rather than inheriting
    the parent's memory, which is why that worker is a plain top-level
    function taking only picklable arguments.
    """

    def test_two_processes_racing_the_same_file_one_wins_one_conflicts(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("counter: 0\n")
        base = current_revision(f)

        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(2)
        result_queue = ctx.Queue()

        procs = [
            ctx.Process(target=_mp_worker, args=(str(f), base, barrier, value, result_queue))
            for value in (1, 2)
        ]
        try:
            for p in procs:
                p.start()
            for p in procs:
                p.join(timeout=15)
            # A worker that didn't finish in time is a test failure, not a
            # leaked process (#229 review, non-blocking - applied): kill
            # and reap anything still alive before asserting.
            for p in procs:
                if p.is_alive():
                    p.kill()
                    p.join()

            results = [result_queue.get(timeout=5) for _ in procs]
        finally:
            for p in procs:
                if p.is_alive():
                    p.kill()
                    p.join()

        outcomes = [outcome for outcome, _ in results]
        assert outcomes.count("ok") == 1
        assert outcomes.count("conflict") == 1

        winner_value = next(value for outcome, value in results if outcome == "ok")
        assert f.read_text().strip() == f"counter: {winner_value}"


class TestCompareAndReplaceMany:
    def test_repeated_path_raises_value_error(self, tmp_path):
        """#229 review round 8, non-blocking: two items on the same path
        would each mutate their own independently loaded copy of that
        document, and whichever writes second silently discards the
        first's mutation - refuse the call outright instead."""
        a = tmp_path / "a.yaml"
        a.write_text("x: 1\n")

        with pytest.raises(ValueError, match="repeated path"):
            compare_and_replace_many(
                [
                    (a, None, lambda doc: doc.update({"x": 2})),
                    (a, None, lambda doc: doc.update({"x": 3})),
                ]
            )

    def test_all_items_written_when_every_revision_matches(self, tmp_path):
        a = tmp_path / "a.yaml"
        b = tmp_path / "b.yaml"
        a.write_text("x: 1\n")
        b.write_text("y: 1\n")
        base_a, base_b = current_revision(a), current_revision(b)

        compare_and_replace_many(
            [
                (a, base_a, lambda doc: doc.update({"x": 2})),
                (b, base_b, lambda doc: doc.update({"y": 2})),
            ]
        )

        assert a.read_text().strip() == "x: 2"
        assert b.read_text().strip() == "y: 2"

    def test_conflict_on_second_item_leaves_first_item_untouched(self, tmp_path):
        a = tmp_path / "a.yaml"
        b = tmp_path / "b.yaml"
        a.write_text("x: 1\n")
        b.write_text("y: 1\n")
        base_a, base_b = current_revision(a), current_revision(b)
        b.write_text("y: 999\n")  # someone else writes b first

        with pytest.raises(ConflictError):
            compare_and_replace_many(
                [
                    (a, base_a, lambda doc: doc.update({"x": 2})),
                    (b, base_b, lambda doc: doc.update({"y": 2})),
                ]
            )

        assert a.read_text().strip() == "x: 1"
        assert b.read_text().strip() == "y: 999"

    def test_a_raising_mutate_leaves_every_item_in_the_batch_untouched(self, tmp_path):
        """#229 review, non-blocking tightening: mutate is run for every
        item before any item is written, so a mutate that raises on the
        second item cannot leave the first one already on disk."""
        a = tmp_path / "a.yaml"
        b = tmp_path / "b.yaml"
        a.write_text("x: 1\n")
        b.write_text("y: 1\n")

        def boom(doc):
            raise ValueError("mutate blew up")

        with pytest.raises(ValueError, match="mutate blew up"):
            compare_and_replace_many(
                [
                    (a, None, lambda doc: doc.update({"x": 2})),
                    (b, None, boom),
                ]
            )

        assert a.read_text().strip() == "x: 1"
        assert b.read_text().strip() == "y: 1"


class TestLockPolling:
    """The pause between two tries of the file lock doubles from 1 ms to
    50 ms (#426 point 3): a collision with a short section costs about the
    section, and a long one is polled as before. The deadline is untouched."""

    def test_the_pauses_double_from_one_millisecond_to_the_cap(self):
        assert list(itertools.islice(config_writer._poll_pauses(), 9)) == [
            0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.05, 0.05, 0.05,
        ]

    def test_an_acquisition_pauses_by_the_schedule_until_the_lock_is_free(self, tmp_path, monkeypatch):
        tries = iter([False] * 8 + [True])
        monkeypatch.setattr(config_writer, "_try_lock_exclusive", lambda fd: next(tries))
        # The stub takes no lock, so there is none to release: on Windows
        # unlocking a region that was never locked raises.
        monkeypatch.setattr(config_writer, "_unlock", lambda fd: None)
        slept = []
        monkeypatch.setattr(time, "sleep", slept.append)

        entered = False
        with directory_lock(tmp_path):
            entered = True

        assert entered
        assert slept == [0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.05, 0.05]

    @pytest.mark.parametrize("misses, warnings", [(6, 0), (7, 1), (12, 1)])
    def test_the_wait_is_logged_once_the_pauses_have_reached_the_cap(
        self, tmp_path, monkeypatch, caplog, misses, warnings
    ):
        """A collision with a read or a write is absorbed by the short
        pauses in silence; a peer that holds the lock past them is said
        once."""
        tries = iter([False] * misses + [True])
        monkeypatch.setattr(config_writer, "_try_lock_exclusive", lambda fd: next(tries))
        monkeypatch.setattr(config_writer, "_unlock", lambda fd: None)
        monkeypatch.setattr(time, "sleep", lambda seconds: None)

        with caplog.at_level(logging.WARNING, logger="nanoidp.config_writer"):
            with directory_lock(tmp_path):
                pass

        assert [r.getMessage() for r in caplog.records if "Waiting for the write lock" in r.getMessage()] == [
            f"Waiting for the write lock on {tmp_path}..."
        ] * warnings

    def test_the_clock_is_read_once_per_try_so_a_pause_is_never_negative(self, tmp_path, monkeypatch):
        """The deadline check and the pause share one reading of the clock:
        read twice, a clock that crossed the deadline in between gave
        time.sleep a negative length, a ValueError where the callers
        classify only LockUnavailableError."""
        monkeypatch.setattr(config_writer, "_try_lock_exclusive", lambda fd: False)
        monkeypatch.setattr(config_writer, "_LOCK_TIMEOUT_SECONDS", 0.2)
        # The deadline is set at 1000.2; the check passes at 1000.19 and
        # every later reading is past it.
        readings = iter([1000.0, 1000.19] + [1000.25] * 10)
        monkeypatch.setattr(time, "monotonic", lambda: next(readings))
        slept = []
        monkeypatch.setattr(time, "sleep", slept.append)

        with pytest.raises(LockUnavailableError) as caught:
            with directory_lock(tmp_path):
                pass

        assert caught.value.kind == "lock_timeout"
        assert slept == [pytest.approx(0.001)]
        assert all(seconds >= 0 for seconds in slept)

    def test_the_deadline_ends_the_wait_and_the_last_pause_is_what_is_left(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config_writer, "_try_lock_exclusive", lambda fd: False)
        monkeypatch.setattr(config_writer, "_LOCK_TIMEOUT_SECONDS", 0.2)
        clock = [1000.0]
        slept = []

        def sleep(seconds):
            slept.append(seconds)
            clock[0] += seconds

        monkeypatch.setattr(time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(time, "sleep", sleep)

        with pytest.raises(LockUnavailableError) as caught:
            with directory_lock(tmp_path):
                pass

        assert caught.value.kind == "lock_timeout"
        assert slept == pytest.approx([0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.05, 0.05, 0.037])
        assert abs(sum(slept) - 0.2) < 1e-9
