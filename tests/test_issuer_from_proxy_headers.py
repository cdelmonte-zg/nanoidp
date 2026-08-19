"""
Tests for ``oauth.issuer_from_proxy_headers`` - trust a single reverse-proxy hop's
``X-Forwarded-Proto``/``X-Forwarded-Host``/``X-Forwarded-For`` headers (via
werkzeug's ProxyFix).

Off by default, so ``request.scheme``/``host_url`` (and therefore
``issuer_from_request``, which depends on them) reflect the connection
NanoIDP itself sees, not the client-supplied forwarding headers - which are
otherwise trivially spoofable. Opted in, they're combined with
``issuer_from_request`` here since that's the only user-visible signal that
observes ``request.host_url``.
"""

import json

import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import get_config
from nanoidp.mcp_server import _execute_tool


def _write_settings(tmp_path, oauth_overrides=None):
    data = {
        "server": {"host": "0.0.0.0", "port": 8000},
        "oauth": {
            "issuer": "http://localhost:8000",
            "audience": "my-app",
            "token_expiry_minutes": 60,
            "clients": [],
            **(oauth_overrides or {}),
        },
    }
    (tmp_path / "settings.yaml").write_text(yaml.safe_dump(data))


class TestIssuerFromProxyHeadersOff:
    def test_default_is_off(self, tmp_path):
        _write_settings(tmp_path)
        app = create_app(config_dir=str(tmp_path))
        with app.app_context():
            assert get_config().settings.issuer_from_proxy_headers is False

    def test_discovery_ignores_forwarded_headers_by_default(self, tmp_path):
        _write_settings(tmp_path, oauth_overrides={"issuer_from_request": True})
        app = create_app(config_dir=str(tmp_path))
        client = app.test_client()

        resp = client.get(
            "/.well-known/openid-configuration",
            headers={
                "Host": "internal:8000",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "idp.example.com",
            },
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == "http://internal:8000"


class TestIssuerFromProxyHeadersOn:
    def test_forwarded_headers_flip_discovery_issuer(self, tmp_path):
        _write_settings(
            tmp_path,
            oauth_overrides={"issuer_from_proxy_headers": True, "issuer_from_request": True},
        )
        app = create_app(config_dir=str(tmp_path))
        client = app.test_client()

        resp = client.get(
            "/.well-known/openid-configuration",
            headers={
                "Host": "internal:8000",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "idp.example.com",
            },
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == "https://idp.example.com"
        assert doc["jwks_uri"] == "https://idp.example.com/.well-known/jwks.json"

    def test_without_forwarded_headers_falls_back_to_actual_connection(self, tmp_path):
        _write_settings(
            tmp_path,
            oauth_overrides={"issuer_from_proxy_headers": True, "issuer_from_request": True},
        )
        app = create_app(config_dir=str(tmp_path))
        client = app.test_client()

        resp = client.get(
            "/.well-known/openid-configuration",
            headers={"Host": "internal:8000"},
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == "http://internal:8000"

    def test_health_endpoint_unaffected(self, tmp_path):
        """Sanity check that enabling the middleware doesn't break plain requests."""
        _write_settings(tmp_path, oauth_overrides={"issuer_from_proxy_headers": True})
        app = create_app(config_dir=str(tmp_path))
        client = app.test_client()

        resp = client.get("/health")
        assert resp.status_code == 200


class TestIssuerFromProxyHeadersWithIssuerAllowlist:
    """issuer_allowlist is checked against the proxy-derived origin, not the
    raw (untrusted) Host header the request actually arrived with."""

    def test_allowlist_matches_the_forwarded_origin(self, tmp_path):
        _write_settings(
            tmp_path,
            oauth_overrides={
                "issuer_from_proxy_headers": True,
                "issuer_from_request": True,
                "issuer_allowlist": ["https://idp.example.com"],
            },
        )
        app = create_app(config_dir=str(tmp_path))
        client = app.test_client()

        resp = client.get(
            "/.well-known/openid-configuration",
            headers={
                "Host": "internal:8000",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "idp.example.com",
            },
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == "https://idp.example.com"

    def test_allowlist_rejects_a_forwarded_origin_not_listed(self, tmp_path):
        _write_settings(
            tmp_path,
            oauth_overrides={
                "issuer_from_proxy_headers": True,
                "issuer_from_request": True,
                "issuer_allowlist": ["https://idp.example.com"],
            },
        )
        app = create_app(config_dir=str(tmp_path))
        client = app.test_client()

        resp = client.get(
            "/.well-known/openid-configuration",
            headers={
                "Host": "internal:8000",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "evil.example.com",
            },
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == "http://localhost:8000"


class TestIssuerFromProxyHeadersMcp:
    """MCP get_settings/update_settings mirror the toggle, like every other
    oauth.* setting. Since ProxyFix is wired at Flask app construction, a
    value flipped at runtime here only takes effect after the process
    restarts - update_settings still records the change for save_config."""

    @pytest.mark.asyncio
    async def test_mcp_get_settings_reports_it(self, app):
        with app.app_context():
            assert get_config().settings.issuer_from_proxy_headers is False
        result = await _execute_tool("get_settings", {}, get_config())
        assert result["issuer_from_proxy_headers"] is False

    @pytest.mark.asyncio
    async def test_mcp_update_settings_sets_it(self, app):
        result = await _execute_tool(
            "update_settings", {"issuer_from_proxy_headers": True}, get_config()
        )
        assert result["success"] is True
        assert result["current_settings"]["issuer_from_proxy_headers"] is True
        assert get_config().settings.issuer_from_proxy_headers is True
