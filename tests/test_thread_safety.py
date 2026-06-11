"""
Concurrency tests for shared in-memory state (issue #43).

Flask serves requests on multiple threads, so the authorization code store,
the lazily-created service singletons and the device code dict must tolerate
concurrent access. These tests use barriers to force the racy interleavings:
without the locks they fail reliably, with them they must always pass.
"""

import threading

import nanoidp.config as config_module
import nanoidp.services.crypto as crypto_module
import nanoidp.services.token as token_module
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

    def _assert_single_instance(self, module, attr, getter, monkeypatch):
        instances = []

        class SlowInit:
            def __init__(self, *args, **kwargs):
                import time
                time.sleep(0.05)  # widen the race window
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
        assert all(obj is seen[0] for obj in seen)

    def test_get_config_creates_one_instance(self, monkeypatch):
        config_module._config = None
        self._assert_single_instance(
            config_module, "ConfigManager", config_module.get_config, monkeypatch
        )

    def test_get_token_service_creates_one_instance(self, monkeypatch):
        token_module._token_service = None
        self._assert_single_instance(
            token_module, "TokenService", token_module.get_token_service, monkeypatch
        )

    def test_get_crypto_service_creates_one_instance(self, monkeypatch):
        crypto_module._crypto_service = None
        self._assert_single_instance(
            crypto_module, "CryptoService", crypto_module.get_crypto_service, monkeypatch
        )
