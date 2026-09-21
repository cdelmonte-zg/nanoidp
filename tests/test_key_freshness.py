"""Generated signing keys as state several processes share (#420, second
part: the service).

Measured on main before the two parts: after one process rotated, it and a
running peer refused each other's tokens for as long as the peer ran, and the
peer's JWKS never showed the new key; and in a single process a token minted
before a rotation was refused after it, because ``verify_jwt`` decoded against
the active key whatever ``kid`` the token named, while the documentation said
"old key stays valid for verification".

What is pinned here. Verification is by ``kid``, among the active key and the
previous ones kept, and no wider than ``max_previous_keys``. A process notices
that a peer rotated, in ONE place, ``get_crypto_service()``, so that JWT, JWKS,
SAML and the key information cannot each have a freshness of their own; it
looks at the marker without the lock and takes the lock only when the marker
moved. The directory itself is the first part (``test_key_directory``).
"""

import base64
import multiprocessing

import jwt as pyjwt
import pytest

from nanoidp.services import crypto as crypto_module
from nanoidp.services import key_directory
from nanoidp.services.crypto import CryptoService, get_crypto_service, publish_crypto_service

_SPAWN = multiprocessing.get_context("spawn")
_BASIC = {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}


def _mint(service, **claims):
    return service.create_jwt("u", "http://idp", "x", **claims)


def _signed_by_hand(private_pem, header):
    import json

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")

    signed = part(header) + b"." + part({"sub": "u", "aud": "x", "exp": 4102444800})
    key = serialization.load_pem_private_key(private_pem, password=None)
    signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    return (signed + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()


def _verifies(service, token):
    try:
        service.verify_jwt(token, audience="x")
        return True
    except ValueError:
        return False


class TestVerificationIsByKid:
    def test_a_token_minted_before_a_rotation_verifies_after_it(self, tmp_path):
        service = CryptoService(keys_dir=str(tmp_path / "keys"))
        before = _mint(service)

        service.rotate_keys()

        assert _verifies(service, before)
        assert _verifies(service, _mint(service))

    def test_until_its_key_is_rotated_out(self, tmp_path):
        """No wider than ``max_previous_keys``: the JWKS and the verifier
        agree about which keys there are."""
        service = CryptoService(keys_dir=str(tmp_path / "keys"), max_previous_keys=1)
        first = _mint(service)
        service.rotate_keys()
        second = _mint(service)
        service.rotate_keys()

        assert not _verifies(service, first)
        assert _verifies(service, second)
        assert {key["kid"] for key in service.get_jwks()["keys"]} == {service.kid, pyjwt.get_unverified_header(second)["kid"]}

    def test_the_verifier_keeps_as_many_keys_as_the_jwks_shows_from_the_start(self, tmp_path):
        """``max_previous_keys`` applies as soon as a service is built (#358),
        not only at its next rotation: the directory may hold more."""
        keys_dir = tmp_path / "keys"
        generous = CryptoService(keys_dir=str(keys_dir), max_previous_keys=2)
        oldest = _mint(generous)
        generous.rotate_keys()
        older = _mint(generous)
        generous.rotate_keys()

        strict = CryptoService(keys_dir=str(keys_dir), max_previous_keys=1)

        assert len(strict.get_jwks()["keys"]) == 2
        assert _verifies(strict, older) and not _verifies(strict, oldest)
        assert _verifies(generous, oldest)

    def test_a_kid_nobody_knows_is_refused(self, tmp_path):
        service = CryptoService(keys_dir=str(tmp_path / "keys"))
        stranger = CryptoService(keys_dir=str(tmp_path / "another"))

        assert not _verifies(service, _mint(stranger))

    def test_the_active_key_under_a_kid_that_is_not_its_own_is_refused(self, tmp_path):
        """What a resource server that looks the kid up in the JWKS does:
        a kid the issuer does not publish names no key, whoever signed. Only
        the key holder could make such a token, and nanoidp refuses it as its
        relying parties would (external keys excepted, see below)."""
        service = CryptoService(keys_dir=str(tmp_path / "keys"))

        token = _signed_by_hand(service.priv_pem, {"alg": "RS256", "typ": "JWT", "kid": "not-one-of-its-kids"})

        assert not _verifies(service, token)

    def test_a_kid_that_is_known_does_not_vouch_for_another_key(self, tmp_path):
        """The kid chooses which key to check against, and nothing else: a
        token signed by a stranger under a kid this service keeps is checked
        against that key, and fails."""
        service = CryptoService(keys_dir=str(tmp_path / "keys"))
        kept = service.kid
        service.rotate_keys()
        stranger = CryptoService(keys_dir=str(tmp_path / "another"))
        for kid in (kept, service.kid):
            forged = pyjwt.encode(
                {"sub": "u", "aud": "x", "exp": 4102444800}, stranger.priv_pem, algorithm="RS256", headers={"kid": kid}
            )
            assert not _verifies(service, forged)

    def test_a_token_with_no_kid_is_checked_against_the_active_key_as_it_always_was(self, tmp_path):
        service = CryptoService(keys_dir=str(tmp_path / "keys"))
        old_private = service.priv_pem
        claims = {"sub": "u", "aud": "x", "exp": 4102444800}
        by_the_active_key = pyjwt.encode(claims, service.priv_pem, algorithm="RS256")
        assert _verifies(service, by_the_active_key)

        service.rotate_keys()

        assert not _verifies(service, pyjwt.encode(claims, old_private, algorithm="RS256"))

    @pytest.mark.parametrize("kid", [5, ["a"], {"a": 1}, None, True])
    def test_a_kid_that_is_no_text_is_no_key(self, tmp_path, kid):
        """Signed by the active key, and well formed but for its kid. PyJWT
        will not write such a header, so it is written by hand."""
        service = CryptoService(keys_dir=str(tmp_path / "keys"))
        service.rotate_keys()

        assert not _verifies(service, _signed_by_hand(service.priv_pem, {"alg": "RS256", "typ": "JWT", "kid": kid}))

    def test_an_empty_kid_names_no_key_and_the_active_one_is_asked(self, tmp_path):
        service = CryptoService(keys_dir=str(tmp_path / "keys"))
        old_private = service.priv_pem
        service.rotate_keys()
        header = {"alg": "RS256", "typ": "JWT", "kid": ""}

        assert _verifies(service, _signed_by_hand(service.priv_pem, header))
        assert not _verifies(service, _signed_by_hand(old_private, header))

    def test_what_is_not_a_token_is_an_invalid_token(self, tmp_path):
        service = CryptoService(keys_dir=str(tmp_path / "keys"))

        for garbage in ("", "not.a.jwt", "a.b", "e30.e30.e30"):
            with pytest.raises(ValueError, match="Invalid token"):
                service.verify_jwt(garbage, audience="x")

    def test_external_keys_verify_as_they_always_did_whatever_the_kid(self, tmp_path):
        """External keys have no history: one key, whatever kid it has been
        published under. Here the same pair under the kid the generated
        service gave it, and after ``external_key_id`` is changed."""
        source = CryptoService(keys_dir=str(tmp_path / "source"))
        external = {
            "external_private_key": str(tmp_path / "source" / "rsa_private.pem"),
            "external_public_key": str(tmp_path / "source" / "rsa_public.pem"),
        }
        service = CryptoService(keys_dir=str(tmp_path / "keys"), external_key_id="one", **external)
        before = _mint(service)

        renamed = CryptoService(keys_dir=str(tmp_path / "keys"), external_key_id="two", **external)

        assert renamed.kid == "two"
        assert _verifies(renamed, before) and _verifies(renamed, _mint(renamed))
        assert _verifies(renamed, _mint(source)), "the same key, under the kid of the generated service"
        stranger = CryptoService(keys_dir=str(tmp_path / "another"))
        assert not _verifies(renamed, _mint(stranger)), "and the signature is still what decides"


class TestTheKeysAreTakenOnce:
    """A rotation between two readings of the service would pair one key's
    kid with the other's private key. The service's keys are one value,
    replaced whole; minting, verifying and the JWKS each take it once. The
    trap below makes any reading of a single field rotate the service
    right after it has answered, so that a second reading answers for the
    other key."""

    @pytest.fixture
    def trapped(self, tmp_path, monkeypatch):
        service = CryptoService(keys_dir=str(tmp_path / "keys"), max_previous_keys=5)
        armed = []

        def trap(field):
            def read(self):
                value = getattr(self._keys, field)
                if armed and armed.pop():
                    self.rotate_keys()
                return value

            return property(read)

        for field in ("kid", "priv_pem", "pub_pem", "cert_pem", "previous_keys"):
            monkeypatch.setattr(CryptoService, field, trap(field))
        return service, lambda: armed.append(True)

    def test_a_rotation_replaces_the_keys_and_changes_none_in_place(self, tmp_path):
        import dataclasses

        service = CryptoService(keys_dir=str(tmp_path / "keys"))
        before = service.keys
        snapshot = (before.kid, before.priv_pem, before.pub_pem, before.cert_pem, before.previous_keys)

        service.rotate_keys()

        assert service.keys is not before
        assert (before.kid, before.priv_pem, before.pub_pem, before.cert_pem, before.previous_keys) == snapshot
        with pytest.raises(dataclasses.FrozenInstanceError):
            before.kid = "changed"  # type: ignore[misc]

    def test_minting(self, trapped):
        service, arm = trapped
        arm()
        token = _mint(service)

        assert _verifies(service, token)

    def test_verifying(self, trapped):
        service, arm = trapped
        token = _mint(service)
        arm()

        assert _verifies(service, token)

    def test_the_jwks(self, trapped):
        service, arm = trapped
        arm()
        published = service.get_jwks()["keys"]
        arm()
        active = service.get_jwk()

        by_kid = {service.kid: service.pub_pem, **{key.kid: key.pub_pem for key in service.previous_keys}}
        for jwk in published + [active]:
            assert jwk == service._pem_to_jwk(by_kid[jwk["kid"]], jwk["kid"])


class TestTheEndpointsKeepTheirOwnEarlierTokens:
    """Through HTTP, because that is where it was measured: /userinfo went
    from 200 to 401, /introspect to active false, the refresh grant to
    invalid_grant."""

    @pytest.fixture
    def tokens(self, client):
        response = client.post(
            "/token",
            data={"grant_type": "password", "username": "user1", "password": "password", "scope": "openid offline_access"},
            headers=_BASIC,
        )
        assert response.status_code == 200
        return response.get_json()

    def test_after_a_rotation(self, client, tokens):
        assert client.post("/api/keys/rotate").status_code == 200

        bearer = {"Authorization": "Bearer " + tokens["access_token"]}
        assert client.get("/userinfo", headers=bearer).status_code == 200
        assert client.post("/introspect", data={"token": tokens["access_token"]}, headers=_BASIC).get_json()["active"] is True
        refreshed = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}, headers=_BASIC)
        assert refreshed.status_code == 200
        assert pyjwt.get_unverified_header(refreshed.get_json()["access_token"])["kid"] == get_crypto_service().kid

    def test_until_the_key_is_rotated_out(self, client, tokens):
        for _ in range(get_crypto_service().max_previous_keys + 1):
            assert client.post("/api/keys/rotate").status_code == 200

        bearer = {"Authorization": "Bearer " + tokens["access_token"]}
        assert client.get("/userinfo", headers=bearer).status_code == 401
        assert client.post("/introspect", data={"token": tokens["access_token"]}, headers=_BASIC).get_json()["active"] is False
        refreshed = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}, headers=_BASIC)
        assert (refreshed.status_code, refreshed.get_json()["error"]) == (400, "invalid_grant")


class TestAPeerNoticesARotation:
    """``get_crypto_service()`` is the one place. A second CryptoService over
    the same directory is all a second process is, as far as the keys go."""

    @pytest.fixture
    def published(self, tmp_path):
        keys_dir = tmp_path / "keys"
        service = CryptoService(keys_dir=str(keys_dir))
        publish_crypto_service(service)
        return keys_dir, service

    def test_nothing_is_reloaded_while_the_marker_stays(self, published, monkeypatch):
        """Not loaded, and not even the refresh's lock asked for: a look that
        finds the marker as it was is a stat and nothing more."""
        _, service = published
        loads, refreshes = [], []
        monkeypatch.setattr(key_directory, "load_published", lambda keys_dir: loads.append(keys_dir))
        lock = crypto_module._refresh_lock

        class Counting:
            def acquire(self, *args, **kwargs):
                refreshes.append(1)
                return lock.acquire(*args, **kwargs)

            def release(self):
                lock.release()

        monkeypatch.setattr(crypto_module, "_refresh_lock", Counting())

        assert all(get_crypto_service() is service for _ in range(5))
        assert loads == [] and refreshes == []

    def test_the_lock_is_not_taken_to_look(self, published):
        """Every signature comes through here. The marker is one small file
        replaced atomically, and reading it needs no lock."""
        import threading

        from nanoidp.services import crypto as crypto_module

        _, service = published
        got = []

        # Not the directory's lock, not the one services are published
        # under, not the refresh's: all three are held here, and a look from
        # another thread returns.
        with key_directory._thread_lock, crypto_module._crypto_service_lock, crypto_module._refresh_lock:
            looking = threading.Thread(target=lambda: got.append(get_crypto_service()))
            looking.start()
            looking.join(5)

        assert got == [service]

    def test_a_peers_rotation_is_adopted_whole(self, published):
        keys_dir, service = published
        before = _mint(service)
        peer = CryptoService(keys_dir=str(keys_dir))
        new_kid = peer.rotate_keys()["new_kid"]

        fresh = get_crypto_service()

        assert fresh is not service, "a new service is published, not the old one changed under its readers"
        assert (fresh.kid, fresh.priv_pem, fresh.pub_pem, fresh.cert_pem) == (new_kid, peer.priv_pem, peer.pub_pem, peer.cert_pem)
        assert [key.kid for key in fresh.previous_keys] == [service.kid]
        assert fresh.get_jwks() == peer.get_jwks()
        assert _verifies(fresh, before) and _verifies(peer, _mint(fresh)) and _verifies(fresh, _mint(peer))
        assert get_crypto_service() is fresh

    def test_a_reader_that_got_the_old_service_keeps_a_whole_one(self, published):
        """A request that took the service before the peer's commit signs
        with OLD, which is correct: OLD becomes a previous key and stays
        verifiable. What it must never hold is half of each."""
        keys_dir, service = published
        held = get_crypto_service()
        snapshot = (held.kid, held.priv_pem, held.pub_pem, held.cert_pem)
        CryptoService(keys_dir=str(keys_dir)).rotate_keys()

        fresh = get_crypto_service()

        assert (held.kid, held.priv_pem, held.pub_pem, held.cert_pem) == snapshot
        assert _verifies(fresh, _mint(held))

    def test_the_settings_the_service_was_built_from_are_kept(self, tmp_path):
        keys_dir = tmp_path / "keys"
        service = CryptoService(keys_dir=str(keys_dir), max_previous_keys=1)
        publish_crypto_service(service)
        peer = CryptoService(keys_dir=str(keys_dir), max_previous_keys=1)
        peer.rotate_keys()
        peer.rotate_keys()

        fresh = get_crypto_service()

        assert fresh.inputs == service.inputs
        assert fresh.max_previous_keys == 1 and len(fresh.previous_keys) == 1

    def test_this_processes_own_rotation_needs_no_reload(self, published, monkeypatch):
        _, service = published
        service.rotate_keys()
        monkeypatch.setattr(key_directory, "load_published", lambda keys_dir: pytest.fail("reloaded its own rotation"))

        assert get_crypto_service() is service

    def test_a_rotation_has_its_new_keys_before_it_lets_the_directory_go(self, published, monkeypatch):
        """A thread of this process that sees the new marker waits for the
        directory's lock to load it; by then the rotating service must have
        the new keys, or that thread publishes a second service for one
        rotation."""
        keys_dir, service = published
        at_release = []
        lock = key_directory._thread_lock

        class Watching:
            def acquire(self, *args, **kwargs):
                return lock.acquire(*args, **kwargs)

            def release(self):
                at_release.append(service.kid)
                lock.release()

            def locked(self):
                return lock.locked()

        monkeypatch.setattr(key_directory, "_thread_lock", Watching())
        new_kid = service.rotate_keys()["new_kid"]

        assert at_release[-1] == new_kid

    def test_a_refresh_that_finds_the_service_caught_up_publishes_nothing(self, published):
        keys_dir, service = published
        service.rotate_keys()
        refreshed = service.reloaded()

        assert refreshed is not None and refreshed.kid == service.kid
        assert crypto_module._publish_refreshed(service, refreshed) is service
        assert get_crypto_service() is service

    def test_threads_that_look_during_this_processes_own_rotation_end_with_it(self, published, monkeypatch):
        import threading

        keys_dir, service = published
        got = []

        def look_while_committed(step):
            if step == "marker:committed":
                looker = threading.Thread(target=lambda: got.append(get_crypto_service()))
                looker.start()
                got.append(looker)

        monkeypatch.setattr(key_directory, "_checkpoint", look_while_committed)
        service.rotate_keys()
        got[0].join(10)

        assert got[1:] == [service]
        assert get_crypto_service() is service

    def test_a_directory_emptied_under_a_running_service_is_not_a_rotation(self, published, monkeypatch):
        """No marker says nothing was published, not that something else
        was. The service goes on as it always did, and does not even try to
        load anything; its next rotation puts the directory right (first
        part)."""
        keys_dir, service = published
        for file in list(keys_dir.iterdir()):
            if file.is_file():
                file.unlink()
        monkeypatch.setattr(CryptoService, "reloaded", lambda self: pytest.fail("tried to load an emptied directory"))

        assert get_crypto_service() is service
        assert not (keys_dir / "kid.txt").exists(), "and looking did not start cold over it"

    def test_a_marker_with_no_key_behind_it_makes_no_new_key(self, published, caplog):
        """A running process that follows the marker loads, and does nothing
        else: the constructor would have generated a key pair here, and
        replaced the signing key and every previous one with it."""
        keys_dir, service = published
        peer = CryptoService(keys_dir=str(keys_dir))
        peer.rotate_keys()
        (keys_dir / "rsa_private.pem").unlink()
        marker = (keys_dir / "kid.txt").read_bytes()

        with caplog.at_level("WARNING", logger="nanoidp.services.crypto"):
            assert get_crypto_service() is service

        assert (keys_dir / "kid.txt").read_bytes() == marker
        assert not (keys_dir / "rsa_private.pem").exists()
        assert "no key is there" in caplog.text

    def test_the_marker_is_read_only_when_the_file_is_another(self, published, monkeypatch):
        """A stat first: every signature comes through here, and on a shared
        mount a read costs more than a stat."""
        keys_dir, service = published
        reads = []
        active_kid = key_directory.active_kid
        monkeypatch.setattr(key_directory, "active_kid", lambda directory: reads.append(1) or active_kid(directory))

        for _ in range(20):
            assert get_crypto_service() is service
        assert len(reads) <= 1

        new_kid = CryptoService(keys_dir=str(keys_dir)).rotate_keys()["new_kid"]
        reads.clear()
        assert get_crypto_service().kid == new_kid
        assert reads, "a new file is read"

    def test_a_marker_that_cannot_be_read_is_said_and_is_not_no_rotation(self, published, monkeypatch, caplog):
        import errno

        keys_dir, service = published
        CryptoService(keys_dir=str(keys_dir)).rotate_keys()

        def out_of_descriptors(directory):
            raise OSError(errno.EMFILE, "Too many open files")

        monkeypatch.setattr(key_directory, "active_kid", out_of_descriptors)
        with caplog.at_level("WARNING", logger="nanoidp.services.crypto"):
            assert get_crypto_service() is service

        assert "cannot be read" in caplog.text

    def test_only_a_marker_that_is_not_there_means_nothing_is_published(self, tmp_path):
        import os

        if os.name != "posix" or os.geteuid() == 0:
            pytest.skip("needs a file this user cannot read")
        keys_dir = tmp_path / "keys"
        CryptoService(keys_dir=str(keys_dir))
        (keys_dir / "kid.txt").chmod(0o000)
        try:
            with pytest.raises(PermissionError):
                key_directory.active_kid(keys_dir)
        finally:
            (keys_dir / "kid.txt").chmod(0o644)
        (keys_dir / "kid.txt").unlink()
        assert key_directory.active_kid(keys_dir) is None

    def test_external_keys_are_not_looked_for_in_the_directory(self, tmp_path, monkeypatch):
        CryptoService(keys_dir=str(tmp_path / "source"))
        keys_dir = tmp_path / "keys"
        CryptoService(keys_dir=str(keys_dir))  # generated keys are there too, and are somebody else's
        service = CryptoService(
            keys_dir=str(keys_dir),
            external_private_key=str(tmp_path / "source" / "rsa_private.pem"),
            external_public_key=str(tmp_path / "source" / "rsa_public.pem"),
        )
        publish_crypto_service(service)
        monkeypatch.setattr(key_directory, "active_kid", lambda keys_dir: pytest.fail("looked at the generated keys' marker"))

        assert get_crypto_service() is service

    def test_a_refresh_that_fails_leaves_the_service_there_is(self, published, monkeypatch):
        """The peer rotated and the bundle cannot be loaded just now (the
        lock is busy past its time). Signing with the key this process has
        is correct, as it was a moment ago; failing every request is not."""
        from nanoidp import config_writer

        keys_dir, service = published
        CryptoService(keys_dir=str(keys_dir)).rotate_keys()
        monkeypatch.setattr(config_writer, "_LOCK_TIMEOUT_SECONDS", 0.2)
        monkeypatch.setattr(crypto_module, "_REFRESH_RETRY_SECONDS", 0.0)

        with key_directory._thread_lock:
            assert get_crypto_service() is service
        assert get_crypto_service() is not service, "and the next look finds it"

    def test_a_refresh_that_failed_is_not_tried_again_at_every_look(self, published, monkeypatch):
        """Every request looks. A refresh that fails because the directory's
        lock is stuck would otherwise wait for it again at each one."""
        import time

        from nanoidp import config_writer

        keys_dir, service = published
        CryptoService(keys_dir=str(keys_dir)).rotate_keys()
        monkeypatch.setattr(config_writer, "_LOCK_TIMEOUT_SECONDS", 0.2)
        tries = []
        reloaded = CryptoService.reloaded
        monkeypatch.setattr(CryptoService, "reloaded", lambda self: tries.append(1) or reloaded(self))

        with key_directory._thread_lock:
            assert get_crypto_service() is service
            began = time.monotonic()
            for _ in range(20):
                assert get_crypto_service() is service
            assert time.monotonic() - began < 0.2

        assert tries == [1]

    def test_nobody_waits_for_a_refresh_that_is_stuck_nor_for_the_publication_lock(self, published, monkeypatch, tmp_path):
        """One request refreshes and is stuck on the directory's lock. The
        others wait for it at most a moment, and not at all once it has been
        stuck longer than that; and a configuration that publishes a service
        meanwhile is not held up either (the refresh has a lock of its own)."""
        import threading
        import time

        from nanoidp import config_writer

        keys_dir, service = published
        CryptoService(keys_dir=str(keys_dir)).rotate_keys()
        monkeypatch.setattr(config_writer, "_LOCK_TIMEOUT_SECONDS", 3.0)
        monkeypatch.setattr(crypto_module, "_REFRESH_WAIT_SECONDS", 0.2)
        entered = threading.Event()
        reloaded = CryptoService.reloaded

        def announced(self):
            entered.set()
            return reloaded(self)

        monkeypatch.setattr(CryptoService, "reloaded", announced)
        other = CryptoService(keys_dir=str(tmp_path / "another"))

        with key_directory._thread_lock:
            refresher = threading.Thread(target=get_crypto_service)
            refresher.start()
            assert entered.wait(5)
            began = time.monotonic()
            assert get_crypto_service() is service
            waited = time.monotonic() - began
            time.sleep(0.25)
            began = time.monotonic()
            assert get_crypto_service() is service
            not_waited = time.monotonic() - began
            began = time.monotonic()
            publish_crypto_service(other)
            published_in = time.monotonic() - began
        refresher.join(10)

        assert waited < 0.5 and not_waited < 0.05 and published_in < 0.05
        assert crypto_module._crypto_service is other, "a refresh does not undo a newer publication"

    def test_threads_that_notice_together_publish_one_service(self, published, monkeypatch):
        import threading

        keys_dir, _ = published
        CryptoService(keys_dir=str(keys_dir)).rotate_keys()
        got, start, reloads = [], threading.Barrier(8), []
        reloaded = CryptoService.reloaded

        def counted(self):
            reloads.append(self.kid)
            return reloaded(self)

        monkeypatch.setattr(CryptoService, "reloaded", counted)

        def look():
            start.wait()
            got.append(get_crypto_service())

        threads = [threading.Thread(target=look) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len({id(service) for service in got}) == 1
        assert len(reloads) == 1, "the first to notice loads the bundle; the others find it done"


def _peer(keys_dir, commands, answers):
    """A NanoIDP process as far as the keys go: a published service, and
    everything asked of it through ``get_crypto_service()``."""
    import logging

    logging.disable(logging.CRITICAL)
    from nanoidp.services.crypto import CryptoService, get_crypto_service, publish_crypto_service

    try:
        publish_crypto_service(CryptoService(keys_dir=keys_dir))
        answers.put(("ready", get_crypto_service().kid))
    except BaseException as failure:  # noqa: BLE001 - said to the parent, not swallowed
        answers.put(("raised", repr(failure)))
        return
    while True:
        command, argument = commands.get()
        if command == "stop":
            return
        try:
            _answer(command, argument, get_crypto_service(), answers)
        except BaseException as failure:  # noqa: BLE001
            answers.put(("raised", repr(failure)))


def _answer(command, argument, service, answers):
    if command == "mint":
        answers.put(service.create_jwt("u", "http://idp", "x"))
    elif command == "verify":
        try:
            service.verify_jwt(argument, audience="x")
            answers.put(True)
        except ValueError:
            answers.put(False)
    elif command == "jwks":
        answers.put(sorted(key["kid"] for key in service.get_jwks()["keys"]))
    elif command == "certificate":
        answers.put(service.cert_pem)
    elif command == "rotate":
        answers.put(service.rotate_keys()["new_kid"])


class TestWithARealPeer:
    @pytest.fixture
    def peer(self, tmp_path):
        keys_dir = tmp_path / "keys"
        mine = CryptoService(keys_dir=str(keys_dir))
        publish_crypto_service(mine)
        commands, answers = _SPAWN.Queue(), _SPAWN.Queue()
        # A daemon, and stopped whatever happens: a peer left waiting on its
        # queue would hold the test run open at exit.
        process = _SPAWN.Process(target=_peer, args=(str(keys_dir), commands, answers), daemon=True)
        process.start()

        def ask(command, argument=None):
            commands.put((command, argument))
            answer = answers.get(timeout=60)
            if isinstance(answer, tuple) and answer[:1] == ("raised",):
                raise AssertionError(f"the peer raised: {answer[1]}")
            return answer

        try:
            ready = answers.get(timeout=120)
            assert ready == ("ready", mine.kid), ready
            yield keys_dir, ask
        finally:
            commands.put(("stop", None))
            process.join(10)
            if process.is_alive():
                process.terminate()
                process.join(5)

    def test_after_this_process_rotates_the_peer_signs_verifies_and_publishes_as_it_does(self, peer):
        keys_dir, ask = peer
        mine_before = _mint(get_crypto_service())
        theirs_before = ask("mint")

        new_kid = get_crypto_service().rotate_keys()["new_kid"]
        mine = get_crypto_service()

        theirs = ask("mint")
        assert pyjwt.get_unverified_header(theirs)["kid"] == new_kid
        assert _verifies(mine, theirs) and _verifies(mine, theirs_before)
        assert ask("verify", _mint(mine)) and ask("verify", mine_before)
        assert ask("jwks") == sorted(key["kid"] for key in mine.get_jwks()["keys"])
        assert ask("certificate") == mine.cert_pem == (keys_dir / "idp-cert.pem").read_bytes(), "SAML signs with the same key"

    def test_after_the_peer_rotates_this_process_does(self, peer):
        _, ask = peer
        before = get_crypto_service()
        mine_before = _mint(before)

        new_kid = ask("rotate")

        mine = get_crypto_service()
        assert mine.kid == new_kid and mine is not before
        assert ask("verify", _mint(mine)) and ask("verify", mine_before)
        assert _verifies(mine, ask("mint"))

    def test_rotations_from_both_sides_orphan_nothing(self, peer):
        _, ask = peer
        tokens = [_mint(get_crypto_service())]
        ask("rotate")
        tokens.append(ask("mint"))
        get_crypto_service().rotate_keys()
        tokens.append(_mint(get_crypto_service()))

        # max_previous_keys is 2: all three keys are still kept, on both sides.
        assert all(_verifies(get_crypto_service(), token) for token in tokens)
        assert all(ask("verify", token) for token in tokens)

