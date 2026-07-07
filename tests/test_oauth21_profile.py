"""
Tests for the oauth21 security profile (issue #68).

The profile aligns nanoidp's strictest behavior with draft OAuth 2.1:
PKCE required on the authorization code flow (§4.1.1), S256 only (§7.5.2),
refresh token rotation on (§4.3.1), the password grant removed, and
registered redirect URIs mandatory at /authorize. Protocol strictness only:
runtime hardening (bcrypt, CORS, rate limiting) remains stricter-dev's job.

Discovery must reflect every one of these (principle 2: metadata never lies).
"""

import base64
import hashlib
import json
import secrets

import pytest
from pydantic import ValidationError

from nanoidp.config import Settings, get_config
from nanoidp.services.discovery import build_discovery_document


def _s256_challenge() -> str:
    verifier = secrets.token_urlsafe(32)
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )


@pytest.fixture
def oauth21(app):
    """Switch the active config to the oauth21 profile for one test."""
    with app.app_context():
        settings = get_config().settings
        settings.security_profile = "oauth21"
    yield settings
    settings.security_profile = "dev"


class TestProfileValidation:
    def test_oauth21_is_a_valid_profile(self):
        assert Settings(security_profile="oauth21").security_profile == "oauth21"

    def test_unknown_profile_rejected(self):
        with pytest.raises(ValidationError):
            Settings(security_profile="oauth3")


class TestDerivedBehavior:
    """The Settings properties routes and discovery consume."""

    def test_dev_stays_permissive(self):
        s = Settings(security_profile="dev")
        assert not s.pkce_required
        assert s.pkce_plain_allowed
        assert not s.rotation_enabled
        assert s.password_grant_enabled

    def test_oauth21_is_strict(self):
        s = Settings(security_profile="oauth21")
        assert s.pkce_required
        assert not s.pkce_plain_allowed
        assert s.rotation_enabled
        assert not s.password_grant_enabled

    def test_explicit_settings_still_apply_in_dev(self):
        s = Settings(security_profile="dev", require_pkce=True, refresh_token_rotation=True)
        assert s.pkce_required
        assert s.rotation_enabled

    def test_stricter_dev_unchanged(self):
        """stricter-dev keeps its behavior: S256-only, but PKCE requirement
        still comes from the require_pkce setting (set by the CLI profile)."""
        s = Settings(security_profile="stricter-dev")
        assert not s.pkce_plain_allowed
        assert not s.pkce_required  # the CLI sets require_pkce=True separately
        assert s.password_grant_enabled


class TestDiscoveryNeverLies:
    def test_dev_advertises_password_and_plain(self):
        doc = build_discovery_document(Settings(security_profile="dev"))
        assert "password" in doc["grant_types_supported"]
        assert doc["code_challenge_methods_supported"] == ["plain", "S256"]

    def test_oauth21_hides_password_and_plain(self):
        doc = build_discovery_document(Settings(security_profile="oauth21"))
        assert "password" not in doc["grant_types_supported"]
        assert doc["code_challenge_methods_supported"] == ["S256"]
        # the other grants stay
        assert "authorization_code" in doc["grant_types_supported"]
        assert "refresh_token" in doc["grant_types_supported"]


class TestTokenEndpoint:
    def test_password_grant_rejected_under_oauth21(self, client, oauth21):
        response = client.post(
            "/token",
            data={"grant_type": "password", "username": "admin", "password": "admin"},
            headers={
                "Authorization": "Basic "
                + base64.b64encode(b"demo-client:demo-secret").decode()
            },
        )
        assert response.status_code == 400
        assert b"disabled by the oauth21 profile" in response.data

    def test_client_credentials_still_works_under_oauth21(self, client, oauth21):
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials"},
            headers={
                "Authorization": "Basic "
                + base64.b64encode(b"demo-client:demo-secret").decode()
            },
        )
        assert response.status_code == 200
        assert "access_token" in json.loads(response.data)


class TestAuthorizeEndpoint:
    REGISTERED_URI = "http://localhost:3000/callback"

    def _authorize(self, client, client_id, **extra):
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": self.REGISTERED_URI,
            "scope": "openid",
            **extra,
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return client.get(f"/authorize?{query}")

    def test_registered_client_with_s256_gets_login_page(self, client, oauth21):
        response = self._authorize(
            client,
            "registered-client",
            code_challenge=_s256_challenge(),
            code_challenge_method="S256",
        )
        assert response.status_code == 200
        assert b"username" in response.data

    def test_missing_pkce_rejected(self, client, oauth21):
        response = self._authorize(client, "registered-client")
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "invalid_request"
        assert "code_challenge" in data["error_description"]

    def test_plain_pkce_rejected(self, client, oauth21):
        response = self._authorize(
            client,
            "registered-client",
            code_challenge="plain-verifier-value",
            code_challenge_method="plain",
        )
        assert response.status_code == 400

    def test_client_without_registered_uris_rejected(self, client, oauth21):
        response = self._authorize(
            client,
            "demo-client",
            code_challenge=_s256_challenge(),
            code_challenge_method="S256",
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "registered redirect_uris" in data["error_description"]

    def test_dev_profile_unaffected(self, client):
        """Without the profile, demo-client + no PKCE still gets the login page."""
        response = self._authorize(client, "demo-client")
        assert response.status_code == 200


class TestMCPParity:
    async def test_get_settings_reports_profile(self, app):
        from nanoidp.mcp_server import _execute_tool

        with app.app_context():
            config = get_config()
        result = await _execute_tool("get_settings", {}, config)
        assert result["security_profile"] == "dev"

    async def test_mcp_discovery_reflects_profile(self, app):
        from nanoidp.mcp_server import _execute_tool

        with app.app_context():
            config = get_config()
        config.settings.security_profile = "oauth21"
        try:
            result = await _execute_tool("get_oidc_discovery", {}, config)
            assert "password" not in result["grant_types_supported"]
            assert result["code_challenge_methods_supported"] == ["S256"]
        finally:
            config.settings.security_profile = "dev"
