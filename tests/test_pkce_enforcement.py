"""
Tests for PKCE enforcement (issue #47).

``require_pkce`` (off by default, enabled by the stricter-dev profile)
rejects /authorize requests without a ``code_challenge``. The stricter-dev
profile also rejects ``code_challenge_method=plain`` (RFC 7636 §4.2 reserves
it for when S256 is unavailable) and stops advertising it in discovery.
"""

import json

import pytest

from nanoidp.config import get_config
from tests.conftest import authorize_error

AUTHORIZE_PARAMS = {
    "response_type": "code",
    "client_id": "demo-client",
    "redirect_uri": "http://localhost:9000/callback",
}


def _authorize(client, **extra):
    return client.get("/authorize", query_string={**AUTHORIZE_PARAMS, **extra})


class TestDefaultBehaviorUnchanged:
    def test_default_require_pkce_is_off(self, app):
        with app.app_context():
            assert get_config().settings.require_pkce is False

    def test_authorize_without_pkce_is_accepted(self, client):
        resp = _authorize(client)
        assert resp.status_code == 200  # login page renders

    def test_plain_method_accepted_in_dev(self, client):
        resp = _authorize(client, code_challenge="x" * 43, code_challenge_method="plain")
        assert resp.status_code == 200

    def test_discovery_advertises_both_methods_in_dev(self, client):
        doc = json.loads(client.get("/.well-known/openid-configuration").data)
        assert doc["code_challenge_methods_supported"] == ["plain", "S256"]


class TestRequirePkce:
    @pytest.fixture(autouse=True)
    def enable(self, app):
        with app.app_context():
            get_config().settings.require_pkce = True
        yield

    def test_authorize_without_code_challenge_rejected(self, client):
        resp = _authorize(client)
        assert resp.status_code == 302
        data = authorize_error(resp)
        assert data["error"] == "invalid_request"
        assert "code_challenge" in data["error_description"]

    def test_authorize_with_code_challenge_accepted(self, client):
        resp = _authorize(client, code_challenge="x" * 43, code_challenge_method="S256")
        assert resp.status_code == 200


class TestStricterDevProfile:
    @pytest.fixture(autouse=True)
    def stricter(self, app):
        with app.app_context():
            settings = get_config().settings
            settings.security_profile = "stricter-dev"
            settings.require_pkce = True
        yield

    def test_plain_method_rejected(self, client):
        resp = _authorize(client, code_challenge="x" * 43, code_challenge_method="plain")
        assert resp.status_code == 302
        assert "plain" in authorize_error(resp)["error_description"]

    def test_s256_method_accepted(self, client):
        resp = _authorize(client, code_challenge="x" * 43, code_challenge_method="S256")
        assert resp.status_code == 200

    def test_discovery_advertises_s256_only(self, client):
        doc = json.loads(client.get("/.well-known/openid-configuration").data)
        assert doc["code_challenge_methods_supported"] == ["S256"]


class TestProfileWiring:
    def test_create_app_stricter_dev_enables_require_pkce(self):
        from nanoidp.app import create_app
        create_app(profile="stricter-dev")
        assert get_config().settings.require_pkce is True
