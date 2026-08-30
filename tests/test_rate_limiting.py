"""
The /token rate limit is actually enforced when enabled (#304).

Until 3.0 the limiter was constructed with default_limits=[] and no view
was ever decorated: with rate_limit_enabled: true the app logged
"Rate limiting: enabled (10/minute on /token)" while enforcing nothing -
a "metadata never lies" violation (VISION principle 2). These tests pin
both directions: enabled -> the configured limit answers 429 JSON with
Retry-After; disabled (the default) -> no limit.
"""

import base64

import pytest

from nanoidp.app import create_app
from nanoidp.config import get_config


def _basic(client_id: str, secret: str) -> dict:
    credentials = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


AUTH = _basic("demo-client", "demo-secret")
DATA = {"grant_type": "client_credentials"}


@pytest.fixture
def limited_app(app):
    """A second app built with the limit ON and tight (3/minute).

    The plain `app` fixture already initialized the config; flipping the
    settings before another create_app() call gives an app whose limiter
    is real. Restored afterwards.
    """
    with app.app_context():
        config = get_config()
        config.settings.rate_limit_enabled = True
        config.settings.rate_limit_token_endpoint = "3/minute"
        # create_app() reloads from disk, so the flip must be persisted -
        # the conftest gives every test an isolated config copy.
        config.save()
    limited = create_app()
    limited.config["TESTING"] = True
    limited.config["SECRET_KEY"] = "test-secret-key"
    yield limited
    with app.app_context():
        config = get_config()
        config.settings.rate_limit_enabled = False
        config.settings.rate_limit_token_endpoint = "10/minute"
        config.save()


class TestRateLimitEnforced:
    def test_configured_limit_answers_429_json(self, limited_app):
        client = limited_app.test_client()
        for _ in range(3):
            assert client.post("/token", data=DATA, headers=AUTH).status_code == 200

        throttled = client.post("/token", data=DATA, headers=AUTH)
        assert throttled.status_code == 429
        body = throttled.get_json()
        assert body is not None, f"non-JSON 429 body: {throttled.data[:120]!r}"
        assert body["error"] == "rate_limit_exceeded"
        assert throttled.headers.get("Retry-After") is not None

    def test_other_endpoints_are_not_limited(self, limited_app):
        client = limited_app.test_client()
        for _ in range(6):
            assert client.get("/health").status_code == 200

    def test_limit_is_per_client_address_bucketed_on_token_only(self, limited_app):
        """Exhaust /token, then confirm discovery still answers - the limit
        is scoped to the token endpoint, exactly as documented."""
        client = limited_app.test_client()
        for _ in range(4):
            client.post("/token", data=DATA, headers=AUTH)
        assert client.get("/.well-known/openid-configuration").status_code == 200


class TestRateLimitDisabledByDefault:
    def test_default_app_never_throttles_token(self, client):
        for _ in range(12):
            resp = client.post("/token", data=DATA, headers=AUTH)
            assert resp.status_code == 200


class TestStricterDevProfilePromise:
    """stricter-dev has always FORCED rate_limit_enabled: true
    (_STRICTER_DEV_HARDENING) - and until #304 that promise was a no-op.
    The profile's hardening is real now."""

    def test_stricter_dev_actually_limits_token(self, app):
        from nanoidp.app import create_app
        from nanoidp.config import get_config

        with app.app_context():
            config = get_config()
            config.settings.rate_limit_token_endpoint = "2/minute"
            config.save()
        hardened = create_app(profile="stricter-dev")
        hardened.config["TESTING"] = True
        client = hardened.test_client()
        try:
            for _ in range(2):
                assert (
                    client.post("/token", data=DATA, headers=AUTH).status_code == 200
                )
            throttled = client.post("/token", data=DATA, headers=AUTH)
            assert throttled.status_code == 429
            assert throttled.get_json()["error"] == "rate_limit_exceeded"
        finally:
            with app.app_context():
                config = get_config()
                config.settings.rate_limit_token_endpoint = "10/minute"
                config.save()
