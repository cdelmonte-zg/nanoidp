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

import pytest

from nanoidp.serialization import atomic_write_yaml, load_yaml_document


class TestAtomicWriteRetriesATransientPermissionError:
    def test_succeeds_after_a_few_transient_permission_errors(self, tmp_path, monkeypatch):
        f = tmp_path / "settings.yaml"
        f.write_text("a: 1\n")

        import os

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

        import os

        def always_denied(src, dst):
            raise PermissionError("[WinError 5] Access is denied")

        monkeypatch.setattr(os, "replace", always_denied)

        with pytest.raises(RuntimeError, match="Access is denied"):
            atomic_write_yaml(f, {"a": 2})

        # the original file is untouched - the failed write never landed
        assert load_yaml_document(f)["a"] == 1
