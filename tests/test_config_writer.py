"""
Tests for the shared compare-and-replace write primitive (issue #229, phase 1).

These exercise ``config_writer.py`` in isolation, against plain files on
disk - no ``ConfigManager``/``YamlWriter`` involved yet (phase 3 migrates
``YamlWriter`` onto this primitive).
"""

import multiprocessing
import threading
import time
from pathlib import Path

import pytest

from nanoidp.config_writer import (
    ConflictError,
    compare_and_replace,
    compare_and_replace_many,
    current_revision,
)
from nanoidp.serialization import load_yaml_document


def _mp_worker(file_path_str, base_revision, barrier, value, result_queue):
    """Module-level so it can be used as a multiprocessing target regardless
    of start method. Sleeps inside mutate to widen the check-to-replace
    window (#229 review round 2's probe)."""

    def mutate(doc):
        time.sleep(0.05)
        doc.update({"counter": value})

    barrier.wait()
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
    by a reader that was never inside the lock to begin with."""

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


class TestCrossProcessConflictDetection:
    """Regression pin for the #229 review round-2 finding: compare_and_replace's
    thread lock only serializes threads within one process, so two separate
    OS processes each get their own _write_lock and can both pass the
    revision check before either has written - the reviewer's
    multiprocessing probe (Barrier + a sleep inside mutate to widen the
    check-to-replace window) lost an update 10/10 trials without a
    cross-process lock. fcntl.flock on a lock file in the config directory
    (_cross_process_lock) closes it."""

    def test_two_processes_racing_the_same_file_one_wins_one_conflicts(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("counter: 0\n")
        base = current_revision(f)

        ctx = multiprocessing.get_context("fork")
        barrier = ctx.Barrier(2)
        result_queue = ctx.Queue()

        procs = [
            ctx.Process(target=_mp_worker, args=(str(f), base, barrier, value, result_queue))
            for value in (1, 2)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=10)

        results = [result_queue.get(timeout=5) for _ in procs]
        outcomes = [outcome for outcome, _ in results]
        assert outcomes.count("ok") == 1
        assert outcomes.count("conflict") == 1

        winner_value = next(value for outcome, value in results if outcome == "ok")
        assert f.read_text().strip() == f"counter: {winner_value}"


class TestCompareAndReplaceMany:
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
