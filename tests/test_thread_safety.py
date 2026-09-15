"""
Concurrency tests for shared in-memory state (issue #43).

Flask serves requests on multiple threads, so the authorization code store,
the lazily-created service singletons and the device code dict must tolerate
concurrent access. These tests use barriers to force the racy interleavings:
without the locks they fail reliably, with them they must always pass.
"""

import threading
from pathlib import Path

import nanoidp.config as config_module
import nanoidp.services.crypto as crypto_module
from nanoidp.services.auth_code import AuthCodeStore


def _run_threads(n, target):
    threads = [threading.Thread(target=target) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


class TestAuthCodeStoreConcurrency:
    """One-time use must hold under concurrent redemption (RFC 6749 §4.1.2)."""

    def test_concurrent_consume_succeeds_exactly_once(self):
        store = AuthCodeStore()
        code = store.create_code(
            client_id="demo-client",
            redirect_uri="http://localhost:9000/callback",
            username="admin",
        )

        n = 8
        barrier = threading.Barrier(n)
        results = []
        results_lock = threading.Lock()

        def consume():
            barrier.wait()  # maximize the overlap between redemptions
            outcome = store.consume_code(
                code=code,
                client_id="demo-client",
                redirect_uri="http://localhost:9000/callback",
            )
            with results_lock:
                results.append(outcome)

        _run_threads(n, consume)

        successes = [r for r in results if r is not None]
        assert len(results) == n
        assert len(successes) == 1, (
            f"{len(successes)} concurrent redemptions of the same code succeeded; "
            "one-time use requires exactly 1"
        )

    def test_concurrent_create_does_not_lose_codes(self):
        store = AuthCodeStore()
        n = 16
        barrier = threading.Barrier(n)
        codes = []
        codes_lock = threading.Lock()

        def create():
            barrier.wait()
            code = store.create_code(
                client_id="demo-client",
                redirect_uri="http://localhost:9000/callback",
                username="admin",
            )
            with codes_lock:
                codes.append(code)

        _run_threads(n, create)

        assert len(set(codes)) == n
        for code in codes:
            assert store.get_code_info(code) is not None


class TestSingletonConcurrency:
    """Lazy singletons must be constructed exactly once under concurrent
    first access. A slow __init__ forces the check-then-set race window."""

    def _assert_single_instance(self, module, attr, getter, monkeypatch, stub_attrs=None):
        """Race ``n`` threads through ``getter`` with the service class
        replaced by a slow stub, and assert one construction, seen by all.

        ``stub_attrs`` is a callable ``(stub, *args, **kwargs) -> None`` that
        gives the stub the attributes the getter reads on a published
        instance; a getter that inspects the instance (get_crypto_service
        since #281 reads ``keys_dir`` and ``uses_external_keys``) raises
        AttributeError on a bare stub in every thread that observes it, and
        those threads never reach ``seen`` (#320).
        """
        instances = []

        class SlowInit:
            def __init__(self, *args, **kwargs):
                import time
                time.sleep(0.05)  # widen the race window
                if stub_attrs is not None:
                    stub_attrs(self, *args, **kwargs)
                instances.append(self)

        monkeypatch.setattr(module, attr, SlowInit)
        n = 8
        barrier = threading.Barrier(n)
        seen = []
        seen_lock = threading.Lock()

        def get():
            barrier.wait()
            obj = getter()
            with seen_lock:
                seen.append(obj)

        _run_threads(n, get)

        assert len(instances) == 1, f"{attr} was constructed {len(instances)} times"
        # Every thread must get here: a getter that raises on the stub would
        # otherwise leave ``seen`` short and the next assertion vacuous (#320).
        assert len(seen) == n, f"{len(seen)} of {n} threads returned an instance"
        assert all(obj is seen[0] for obj in seen)

    def test_get_config_creates_one_instance(self, monkeypatch):
        config_module._config = None
        self._assert_single_instance(
            config_module, "ConfigManager", config_module.get_config, monkeypatch
        )

    def test_get_crypto_service_creates_one_instance(self, monkeypatch):
        crypto_module._crypto_service = None

        def crypto_stub(stub, keys_dir, *args, **kwargs):
            # What get_crypto_service reads on a published instance (#281):
            # the keys_dir it was built for, and whether it hosts external
            # keys. CryptoService sets both before the getter can publish it.
            stub.keys_dir = Path(keys_dir)
            stub.uses_external_keys = False

        self._assert_single_instance(
            crypto_module,
            "CryptoService",
            crypto_module.get_crypto_service,
            monkeypatch,
            stub_attrs=crypto_stub,
        )
