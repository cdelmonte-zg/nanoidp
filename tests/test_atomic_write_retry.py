"""
Tests for atomic_write_yaml's retry around os.replace() (#229 Windows CI).

Windows CI failed TestConcurrentReadsOutsideTheLock (a reader thread
briefly holding the file open for a load_yaml_document() call, while
another thread's atomic_write_yaml() tried to replace it) with
PermissionError: [WinError 5] Access is denied - Windows can refuse to
replace a file that another handle currently has open even just for
reading, unlike POSIX rename(2), which never cares. These tests pin the
retry directly, without needing an actual concurrent reader to reproduce
the race.
"""

import os
import threading

import pytest

from nanoidp.serialization import atomic_write_yaml, load_yaml_document


class TestAtomicWriteRetriesATransientPermissionError:
    def test_succeeds_after_a_few_transient_permission_errors(self, tmp_path, monkeypatch):
        f = tmp_path / "settings.yaml"
        f.write_text("a: 1\n")

        real_replace = os.replace
        calls = {"count": 0}

        def flaky_replace(src, dst):
            calls["count"] += 1
            if calls["count"] < 3:
                raise PermissionError("[WinError 5] Access is denied")
            real_replace(src, dst)

        monkeypatch.setattr(os, "replace", flaky_replace)

        atomic_write_yaml(f, {"a": 2})

        assert calls["count"] == 3
        assert load_yaml_document(f)["a"] == 2

    def test_still_raises_once_retries_are_exhausted(self, tmp_path, monkeypatch):
        f = tmp_path / "settings.yaml"
        f.write_text("a: 1\n")

        def always_denied(src, dst):
            raise PermissionError("[WinError 5] Access is denied")

        monkeypatch.setattr(os, "replace", always_denied)

        with pytest.raises(RuntimeError, match="Access is denied"):
            atomic_write_yaml(f, {"a": 2})

        # the original file is untouched - the failed write never landed
        assert load_yaml_document(f)["a"] == 1


class TestFailedReplaceDoesNotCorruptTheLiveFile:
    """Regression pin for #229 review round 10: atomic_write_yaml used to
    "restore" from the .bak backup via shutil.copy2 on ANY failure,
    including a failed os.replace() that never touched the target at
    all - there was nothing to restore. copy2() is not atomic, so that
    unconditional restore performed a non-atomic in-place overwrite of a
    live, still-correct file. A concurrent reader can observe that copy
    mid-flight: reproduced by forcing os.replace() to fail on POSIX and
    running four readers against a large settings.yaml - 43 of 983
    reads came back with fewer clients than the file has, silently, no
    exception raised at all. Fixed by restoring from backup only when
    the target actually disappeared."""

    def test_a_failed_replace_never_lets_a_reader_see_a_partial_document(
        self, tmp_path, monkeypatch
    ):
        f = tmp_path / "settings.yaml"
        num_clients = 400
        clients = "\n".join(
            f"  - client_id: 'client-{i}'\n"
            f"    client_secret: 'secret-{i}'\n"
            f"    description: 'Client number {i}'"
            for i in range(num_clients)
        )
        original = f"oauth:\n  issuer: 'http://localhost:8000'\n  clients:\n{clients}\n"
        f.write_text(original)
        assert len(original) > 20_000  # comparable to the review's 21KB repro

        def always_denied(src, dst):
            raise PermissionError("denied")

        monkeypatch.setattr(os, "replace", always_denied)

        errors = []
        truncated = []
        stop = threading.Event()

        def read_loop():
            while not stop.is_set():
                try:
                    doc = load_yaml_document(f)
                    if len(doc.get("oauth", {}).get("clients", [])) != num_clients:
                        truncated.append(doc)
                except Exception as exc:
                    errors.append(exc)

        readers = [threading.Thread(target=read_loop) for _ in range(4)]
        for t in readers:
            t.start()

        try:
            for _ in range(50):
                with pytest.raises(RuntimeError):
                    atomic_write_yaml(f, {"oauth": {"issuer": "changed"}})
        finally:
            stop.set()
            for t in readers:
                t.join()

        assert errors == []
        assert truncated == []
        # never partially overwritten by the old unconditional restore
        assert f.read_text() == original
