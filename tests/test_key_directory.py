"""Generated signing keys as state several processes share (#420, first part:
the directory).

Measured on main before this: two processes cold-starting on one empty keys
directory ended with different signing keys, twelve times out of twelve, and a
rotation wrote its files one after the other over fixed names, so that a
process killed after the first of them left a marker that said OLD over a
private key that was NEW.

What is pinned here: one winner of a cold start, with real processes; a
rotation that can die at every one of its steps, and during its own recovery,
and still leaves a bundle that is whole, the old one before the commit and the
new one after it; and rotations from several processes that come one after the
other. The peers' noticing a rotation, and verification by ``kid``, are the
second part.
"""

import json
import multiprocessing
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from nanoidp.services import key_directory
from nanoidp.services.crypto import CryptoService

_REPO = Path(__file__).resolve().parent.parent
_SPAWN = multiprocessing.get_context("spawn")


class Killed(BaseException):
    """The process dies here. Not an Exception: nothing may catch it and tidy
    up, because a process that is killed runs no handler."""


def _die_at(monkeypatch, step, times=1):
    """From now on, the ``times``-th arrival at ``step`` is a death."""
    arrivals = []

    def checkpoint(name):
        if name == step:
            arrivals.append(name)
            if len(arrivals) == times:
                raise Killed(step)

    monkeypatch.setattr(key_directory, "_checkpoint", checkpoint)


def _whole(keys_dir):
    """The directory holds one bundle, all of it, and says what it is."""
    service = CryptoService(keys_dir=str(keys_dir))
    private = serialization.load_pem_private_key(service.priv_pem, password=None)
    public = serialization.load_pem_public_key(service.pub_pem)
    assert private.public_key().public_numbers() == public.public_numbers()
    assert service._certificate_matches(service.cert_pem)
    assert service.kid == (keys_dir / "kid.txt").read_text().strip()
    metadata = json.loads((keys_dir / "keys.json").read_text())
    assert metadata["active_kid"] == service.kid
    listed = [entry["kid"] for entry in metadata["previous_keys"]]
    on_disk = sorted(file.name for file in (keys_dir / "previous").glob("*_public.pem")) if (keys_dir / "previous").is_dir() else []
    assert on_disk == sorted(f"{kid}_public.pem" for kid in listed)
    assert not (keys_dir / ".rotation").exists()
    assert [file.name for file in keys_dir.iterdir() if file.name.startswith(".rsa") or file.name.startswith(".kid")] == []
    return service


def _snapshot(keys_dir):
    return {name: (keys_dir / name).read_bytes() for name in ("rsa_private.pem", "rsa_public.pem", "idp-cert.pem", "keys.json", "kid.txt")}


def _cold_start(keys_dir, barrier, out):
    import logging

    logging.disable(logging.CRITICAL)
    from nanoidp.services.crypto import CryptoService

    barrier.wait()
    try:
        service = CryptoService(keys_dir=keys_dir)
        out.put(("ok", service.kid, service.priv_pem))
    except BaseException as failure:  # noqa: BLE001 - reported to the parent, whatever it is
        out.put(("raised", repr(failure), b""))


def _rotate(keys_dir, barrier, out):
    import logging

    logging.disable(logging.CRITICAL)
    from nanoidp.services.crypto import CryptoService

    service = CryptoService(keys_dir=keys_dir)
    barrier.wait()
    try:
        out.put(("ok", service.rotate_keys()["new_kid"], b""))
    except BaseException as failure:  # noqa: BLE001
        out.put(("raised", repr(failure), b""))


def _in_processes(target, keys_dir, how_many):
    barrier, out = _SPAWN.Barrier(how_many), _SPAWN.Queue()
    processes = [_SPAWN.Process(target=target, args=(str(keys_dir), barrier, out)) for _ in range(how_many)]
    for process in processes:
        process.start()
    results = [out.get(timeout=120) for _ in processes]
    for process in processes:
        process.join(30)
    return results


class TestAColdStartHasOneWinner:
    @pytest.mark.parametrize("round_", range(4))
    def test_processes_starting_together_on_an_empty_directory_sign_with_one_key(self, tmp_path, round_):
        results = _in_processes(_cold_start, tmp_path / "keys", 4)

        assert [kind for kind, _, _ in results] == ["ok"] * 4, results
        assert len({kid for _, kid, _ in results}) == 1
        assert len({private for _, _, private in results}) == 1
        service = _whole(tmp_path / "keys")
        assert service.kid == results[0][1] and service.priv_pem == results[0][2]

    def test_files_that_were_never_published_are_not_a_bundle(self, tmp_path):
        """No marker, so whatever is there was never published: a start that
        died half way, or somebody's leftovers."""
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "rsa_private.pem").write_bytes(b"half a key")
        (keys_dir / "keys.json").write_text("{not json")

        service = _whole(keys_dir)

        assert b"half a key" not in service.priv_pem

    @pytest.mark.parametrize("step", ["first:rsa_private.pem", "first:rsa_public.pem", "first:idp-cert.pem", "first:keys.json", "first:marker"])
    def test_a_cold_start_that_dies_on_the_way_is_started_again(self, tmp_path, monkeypatch, step):
        keys_dir = tmp_path / "keys"
        _die_at(monkeypatch, step)
        with pytest.raises(Killed):
            CryptoService(keys_dir=str(keys_dir))
        monkeypatch.undo()

        assert key_directory.active_kid(keys_dir) is None
        _whole(keys_dir)

    def test_a_marker_with_no_key_behind_it_is_not_a_bundle(self, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "kid.txt").write_text("orphan")

        assert _whole(keys_dir).kid != "orphan"

    @pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
    def test_the_private_key_is_its_owners_alone(self, tmp_path):
        keys_dir = tmp_path / "keys"
        CryptoService(keys_dir=str(keys_dir)).rotate_keys()

        assert stat.S_IMODE((keys_dir / "rsa_private.pem").stat().st_mode) == 0o600
        assert stat.S_IMODE((keys_dir / "rsa_public.pem").stat().st_mode) == 0o644
        assert stat.S_IMODE((keys_dir / "idp-cert.pem").stat().st_mode) == 0o644


_BEFORE_THE_COMMIT = [
    "rollback:written",
    "journal:published",
    "previous:added",
    "live:rsa_private.pem",  # the case the journal exists for: the marker says OLD over a private key that is NEW
    "live:rsa_public.pem",
    "live:idp-cert.pem",
    "live:keys.json",
]
_AFTER_THE_COMMIT = ["marker:committed", "finish:pruned"]


class TestARotationCanDieAnywhere:
    @pytest.mark.parametrize("step", _BEFORE_THE_COMMIT)
    def test_before_the_commit_the_old_bundle_is_restored_whole(self, tmp_path, monkeypatch, step):
        keys_dir = tmp_path / "keys"
        # One previous key kept, and one there already: the rotation that
        # dies would have dropped it, and must not have done so yet.
        service = CryptoService(keys_dir=str(keys_dir), max_previous_keys=1)
        service.rotate_keys()
        before = _snapshot(keys_dir)
        previous_before = sorted(file.name for file in (keys_dir / "previous").iterdir())

        _die_at(monkeypatch, step)
        with pytest.raises(Killed):
            service.rotate_keys()
        monkeypatch.undo()

        assert _whole(keys_dir).kid == before["kid.txt"].decode()
        assert _snapshot(keys_dir) == before
        assert sorted(file.name for file in (keys_dir / "previous").iterdir()) == previous_before

    @pytest.mark.parametrize("step", _AFTER_THE_COMMIT)
    def test_after_the_commit_the_new_bundle_is_the_one(self, tmp_path, monkeypatch, step):
        keys_dir = tmp_path / "keys"
        service = CryptoService(keys_dir=str(keys_dir), max_previous_keys=1)
        first = service.kid
        service.rotate_keys()
        second = service.kid

        _die_at(monkeypatch, step)
        with pytest.raises(Killed):
            service.rotate_keys()
        monkeypatch.undo()

        loaded = _whole(keys_dir)
        assert loaded.kid not in (first, second)
        # One previous key is kept: the second. The first was rotated out, and
        # its file went with the recovery, not only with a rotation that ends.
        assert [key.kid for key in loaded.previous_keys] == [second]
        assert not (keys_dir / "previous" / f"{first}_public.pem").exists()

    @pytest.mark.parametrize("restore_step", ["restore:rsa_private.pem", "restore:rsa_public.pem", "restore:idp-cert.pem", "restore:keys.json", "restore:done"])
    def test_a_recovery_that_dies_is_recovered_again(self, tmp_path, monkeypatch, restore_step):
        """The rollback is copied from, never moved: it is as whole for the
        second recovery as it was for the first."""
        keys_dir = tmp_path / "keys"
        service = CryptoService(keys_dir=str(keys_dir))
        before = _snapshot(keys_dir)
        _die_at(monkeypatch, "live:rsa_public.pem")
        with pytest.raises(Killed):
            service.rotate_keys()
        monkeypatch.undo()

        _die_at(monkeypatch, restore_step)
        with pytest.raises(Killed):
            CryptoService(keys_dir=str(keys_dir))
        monkeypatch.undo()

        assert _whole(keys_dir).kid == before["kid.txt"].decode()
        assert _snapshot(keys_dir) == before

    def test_a_file_that_was_not_there_is_not_there_after_a_restore(self, tmp_path, monkeypatch):
        """A directory from before the metadata existed. What is restored is
        what was there, not an empty file under the name of what was not."""
        keys_dir = tmp_path / "keys"
        service = CryptoService(keys_dir=str(keys_dir))
        (keys_dir / "keys.json").unlink()

        _die_at(monkeypatch, "live:keys.json")
        with pytest.raises(Killed):
            service.rotate_keys()
        monkeypatch.undo()
        with key_directory.locked(keys_dir):
            pass

        assert not (keys_dir / "keys.json").exists()
        assert CryptoService(keys_dir=str(keys_dir)).kid == service.kid

    def test_the_service_that_died_rotating_did_not_change_what_it_signs_with(self, tmp_path, monkeypatch):
        keys_dir = tmp_path / "keys"
        service = CryptoService(keys_dir=str(keys_dir))
        kid, private = service.kid, service.priv_pem

        _die_at(monkeypatch, "live:keys.json")
        with pytest.raises(Killed):
            service.rotate_keys()

        assert (service.kid, service.priv_pem) == (kid, private)

    @pytest.mark.parametrize("step, expected", [("live:rsa_private.pem", "old"), ("marker:committed", "new")])
    def test_a_process_that_is_really_killed(self, tmp_path, step, expected):
        """Not an exception in this process: another one, gone with
        ``os._exit`` in the middle of its rotation, its lock released by the
        operating system and nothing else done."""
        keys_dir = tmp_path / "keys"
        before = CryptoService(keys_dir=str(keys_dir)).kid
        script = textwrap.dedent(
            f"""
            import logging, os, sys
            logging.disable(logging.CRITICAL)
            from nanoidp.services import key_directory
            from nanoidp.services.crypto import CryptoService
            service = CryptoService(keys_dir={str(keys_dir)!r})
            key_directory._checkpoint = lambda name: os._exit(9) if name == {step!r} else None
            service.rotate_keys()
            """
        )
        env = {**os.environ, "PYTHONPATH": str(_REPO / "src")}
        died = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, timeout=120)
        assert died.returncode == 9, died.stderr.decode()[-500:]

        loaded = _whole(keys_dir)

        assert (loaded.kid == before) == (expected == "old")


class TestRotationsComeOneAfterTheOther:
    def test_two_processes_rotating_together_both_succeed_and_the_directory_is_whole(self, tmp_path):
        keys_dir = tmp_path / "keys"
        original = CryptoService(keys_dir=str(keys_dir)).kid

        results = _in_processes(_rotate, keys_dir, 2)

        assert [kind for kind, _, _ in results] == ["ok", "ok"], results
        loaded = _whole(keys_dir)
        new_kids = {kid for _, kid, _ in results}
        assert loaded.kid in new_kids
        # The one that came second retired the first one's key, not the key
        # it had loaded before waiting: nothing signed in between is orphaned.
        assert [key.kid for key in loaded.previous_keys] == [(new_kids - {loaded.kid}).pop(), original]

    def test_a_rotation_retires_what_is_published_not_what_the_service_remembers(self, tmp_path):
        keys_dir = tmp_path / "keys"
        stale = CryptoService(keys_dir=str(keys_dir))
        original = stale.kid
        peer = CryptoService(keys_dir=str(keys_dir))
        by_the_peer = peer.rotate_keys()["new_kid"]

        result = stale.rotate_keys()

        assert result["old_kid"] == by_the_peer
        assert [key.kid for key in stale.previous_keys] == [by_the_peer, original]
        _whole(keys_dir)

    def test_rotating_keeps_as_many_previous_keys_as_it_is_told(self, tmp_path):
        keys_dir = tmp_path / "keys"
        service = CryptoService(keys_dir=str(keys_dir), max_previous_keys=2)
        kids = [service.kid]
        for _ in range(4):
            kids.append(service.rotate_keys()["new_kid"])

        loaded = _whole(keys_dir)

        assert [key.kid for key in loaded.previous_keys] == [kids[3], kids[2]]
        assert sorted(file.name for file in (keys_dir / "previous").iterdir()) == sorted(f"{kid}_public.pem" for kid in kids[2:4])
