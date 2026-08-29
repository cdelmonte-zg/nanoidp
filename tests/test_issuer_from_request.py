"""
Tests for ``oauth.issuer_from_request`` - reflect the issuer with respect to
how NanoIDP was actually reached, rather than always the fixed configured
value.

Off by default, so discovery, tokens, and the device flow all keep reporting
the fixed ``settings.issuer`` unchanged. Opted in, all three follow the
incoming request's own Host header instead, so the same NanoIDP can be
reachable at more than one hostname (e.g. a Docker Compose service name from
other containers, ``localhost`` from the host browser) without ending up
with a discovery ``issuer`` that disagrees with a token's ``iss`` - both OIDC
Discovery and ID Token validation require an exact match.

The MCP tools have no HTTP request of their own to derive a host from, so
they always report the fixed ``settings.issuer`` regardless of this setting
- a deliberate, narrow exception to the discovery-parity guarantee asserted
in ``test_discovery_parity.py`` (which only exercises the default, off,
case).
"""

import json

import jwt as pyjwt
import pytest

from nanoidp.config import get_config
from nanoidp.mcp_server import _execute_tool


class TestDefaultBehaviorUnchanged:
    def test_default_is_off(self, app):
        with app.app_context():
            assert get_config().settings.issuer_from_request is False

    def test_discovery_issuer_ignores_host_header_by_default(self, client):
        resp = client.get(
            "/.well-known/openid-configuration",
            headers={"Host": "nanoidp:9900"},
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == get_config().settings.issuer

    def test_device_verification_uri_ignores_host_header_by_default(
        self, client, auth_header
    ):
        resp = client.post(
            "/device_authorization",
            data={"scope": "openid"},
            headers={**auth_header, "Host": "nanoidp:9900"},
        )
        data = json.loads(resp.data)
        assert data["verification_uri"] == f"{get_config().settings.issuer}/device"


class TestIssuerFromRequest:
    @pytest.fixture(autouse=True)
    def enable(self, app):
        with app.app_context():
            get_config().settings.issuer_from_request = True
        yield

    def test_discovery_issuer_reflects_host_header(self, client):
        resp = client.get(
            "/.well-known/openid-configuration",
            headers={"Host": "nanoidp:9900"},
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == "http://nanoidp:9900"
        assert doc["jwks_uri"] == "http://nanoidp:9900/.well-known/jwks.json"
        assert doc["token_endpoint"] == "http://nanoidp:9900/token"

    def test_discovery_issuer_reflects_a_different_host_header(self, client):
        resp = client.get(
            "/.well-known/openid-configuration",
            headers={"Host": "localhost:9900"},
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == "http://localhost:9900"

    def test_token_iss_matches_discovery_for_the_same_host(self, client, auth_header):
        host = "nanoidp:9900"
        discovery = json.loads(
            client.get(
                "/.well-known/openid-configuration", headers={"Host": host}
            ).data
        )

        response = client.post(
            "/token",
            data={"grant_type": "client_credentials"},
            headers={**auth_header, "Host": host},
        )
        tokens = json.loads(response.data)
        payload = pyjwt.decode(
            tokens["access_token"], options={"verify_signature": False}
        )

        assert payload["iss"] == discovery["issuer"] == f"http://{host}"

    def test_device_verification_uri_reflects_host_header(self, client, auth_header):
        host = "nanoidp:9900"
        resp = client.post(
            "/device_authorization",
            data={"scope": "openid"},
            headers={**auth_header, "Host": host},
        )
        data = json.loads(resp.data)
        assert data["verification_uri"] == f"http://{host}/device"
        assert data["verification_uri_complete"].startswith(data["verification_uri"])


class TestMcpToolsUnaffected:
    """MCP tools have no request to derive a host from - the fixed issuer is
    the only value they can report, on or off."""

    @pytest.fixture(autouse=True)
    def enable(self, app):
        with app.app_context():
            get_config().settings.issuer_from_request = True
        yield

    @pytest.mark.asyncio
    async def test_mcp_discovery_still_reports_fixed_issuer(self):
        doc = await _execute_tool("get_oidc_discovery", {}, get_config())
        assert doc["issuer"] == get_config().settings.issuer

    @pytest.mark.asyncio
    async def test_mcp_get_settings_reports_the_toggle(self):
        result = await _execute_tool("get_settings", {}, get_config())
        assert result["issuer_from_request"] is True


class TestIssuerAllowlist:
    """``issuer_allowlist`` narrows ``issuer_from_request``: a Host that
    doesn't match an allowed origin falls back to the fixed ``issuer``
    instead of trusting an arbitrary Host header. Empty (the default) keeps
    prior behavior - any Host is reflected.
    """

    @pytest.fixture(autouse=True)
    def enable(self, app):
        with app.app_context():
            get_config().settings.issuer_from_request = True
        yield

    def test_empty_allowlist_allows_any_host(self, client):
        resp = client.get(
            "/.well-known/openid-configuration",
            headers={"Host": "anyhost:9900"},
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == "http://anyhost:9900"

    def test_matching_host_is_reflected(self, app, client):
        with app.app_context():
            get_config().settings.issuer_allowlist = ["http://nanoidp:9900"]
        resp = client.get(
            "/.well-known/openid-configuration",
            headers={"Host": "nanoidp:9900"},
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == "http://nanoidp:9900"

    def test_non_matching_host_falls_back_to_fixed_issuer(self, app, client):
        with app.app_context():
            get_config().settings.issuer_allowlist = ["http://nanoidp:9900"]
        resp = client.get(
            "/.well-known/openid-configuration",
            headers={"Host": "evil.example.com"},
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == get_config().settings.issuer

    def test_token_iss_falls_back_when_host_not_allowlisted(
        self, app, client, auth_header
    ):
        with app.app_context():
            get_config().settings.issuer_allowlist = ["http://nanoidp:9900"]
        resp = client.post(
            "/token",
            data={"grant_type": "client_credentials"},
            headers={**auth_header, "Host": "evil.example.com"},
        )
        tokens = json.loads(resp.data)
        payload = pyjwt.decode(
            tokens["access_token"], options={"verify_signature": False}
        )
        assert payload["iss"] == get_config().settings.issuer

    def test_device_verification_uri_falls_back_when_host_not_allowlisted(
        self, app, client, auth_header
    ):
        with app.app_context():
            get_config().settings.issuer_allowlist = ["http://nanoidp:9900"]
        resp = client.post(
            "/device_authorization",
            data={"scope": "openid"},
            headers={**auth_header, "Host": "evil.example.com"},
        )
        data = json.loads(resp.data)
        assert data["verification_uri"] == f"{get_config().settings.issuer}/device"

    @pytest.mark.asyncio
    async def test_mcp_get_settings_reports_allowlist(self, app):
        with app.app_context():
            get_config().settings.issuer_allowlist = ["http://nanoidp:9900"]
        result = await _execute_tool("get_settings", {}, get_config())
        assert result["issuer_allowlist"] == ["http://nanoidp:9900"]

    @pytest.mark.asyncio
    async def test_mcp_update_settings_normalizes_allowlist(self, app):
        result = await _execute_tool(
            "update_settings",
            {"issuer_allowlist": ["http://nanoidp:9900", ""]},
            get_config(),
        )
        assert result["success"] is True
        assert get_config().settings.issuer_allowlist == ["http://nanoidp:9900"]


class TestDeviceVerificationBaseUrl:
    """``device_verification_base_url`` pins the device flow's
    verification_uri to a human-reachable host, decoupled from whichever
    Host called ``/device_authorization`` (a backend/container caller's Host
    would otherwise leak into a URL the human's own browser can't open).
    """

    def test_default_is_none(self, app):
        with app.app_context():
            assert get_config().settings.device_verification_base_url is None

    def test_overrides_verification_uri_regardless_of_calling_host(
        self, app, client, auth_header
    ):
        with app.app_context():
            get_config().settings.issuer_from_request = True
            get_config().settings.device_verification_base_url = (
                "https://idp.example.com"
            )
        resp = client.post(
            "/device_authorization",
            data={"scope": "openid"},
            headers={**auth_header, "Host": "nanoidp:9900"},
        )
        data = json.loads(resp.data)
        assert data["verification_uri"] == "https://idp.example.com/device"

    def test_does_not_affect_discovery_issuer_or_token_iss(
        self, app, client, auth_header
    ):
        """Only the device flow's verification_uri is overridden - discovery
        and tokens must still match the request that fetched/requested them."""
        with app.app_context():
            get_config().settings.issuer_from_request = True
            get_config().settings.device_verification_base_url = (
                "https://idp.example.com"
            )
        resp = client.get(
            "/.well-known/openid-configuration",
            headers={"Host": "nanoidp:9900"},
        )
        doc = json.loads(resp.data)
        assert doc["issuer"] == "http://nanoidp:9900"

    def test_ignored_when_issuer_from_request_is_off(
        self, app, client, auth_header
    ):
        with app.app_context():
            get_config().settings.device_verification_base_url = (
                "https://idp.example.com"
            )
        resp = client.post(
            "/device_authorization",
            data={"scope": "openid"},
            headers={**auth_header, "Host": "nanoidp:9900"},
        )
        data = json.loads(resp.data)
        assert data["verification_uri"] == f"{get_config().settings.issuer}/device"

    @pytest.mark.asyncio
    async def test_mcp_get_settings_reports_it(self, app):
        with app.app_context():
            get_config().settings.device_verification_base_url = (
                "https://idp.example.com"
            )
        result = await _execute_tool("get_settings", {}, get_config())
        assert result["device_verification_base_url"] == "https://idp.example.com"

    @pytest.mark.asyncio
    async def test_mcp_update_settings_sets_and_clears_it(self, app):
        result = await _execute_tool(
            "update_settings",
            {"device_verification_base_url": "https://idp.example.com"},
            get_config(),
        )
        assert result["success"] is True
        assert (
            get_config().settings.device_verification_base_url
            == "https://idp.example.com"
        )

        result = await _execute_tool(
            "update_settings",
            {"device_verification_base_url": ""},
            get_config(),
        )
        assert result["success"] is True
        assert get_config().settings.device_verification_base_url is None




class TestApiGenerateTokenIssuer:
    """``/api/users/<username>/token`` mints real JWTs too, so its ``iss``
    must follow the same effective-issuer resolution as ``/token`` and
    discovery (#133): reflected when ``issuer_from_request`` is on (allowlist
    honoured), fixed otherwise. Before the shared helper it silently kept the
    fixed issuer, contradicting the discovery its own hostname advertised."""

    def _minted_iss(self, client, host):
        resp = client.post("/api/users/admin/token", headers={"Host": host})
        token = json.loads(resp.data)["access_token"]
        return pyjwt.decode(token, options={"verify_signature": False})["iss"]

    def test_fixed_issuer_when_flag_off(self, client):
        assert self._minted_iss(client, "nanoidp:9900") == get_config().settings.issuer

    def test_reflects_host_when_enabled(self, app, client):
        with app.app_context():
            get_config().settings.issuer_from_request = True
        assert self._minted_iss(client, "nanoidp:9900") == "http://nanoidp:9900"

    def test_matches_discovery_for_the_same_host(self, app, client):
        with app.app_context():
            get_config().settings.issuer_from_request = True
        doc = json.loads(
            client.get(
                "/.well-known/openid-configuration", headers={"Host": "nanoidp:9900"}
            ).data
        )
        assert self._minted_iss(client, "nanoidp:9900") == doc["issuer"]

    def test_allowlist_fallback_applies(self, app, client):
        with app.app_context():
            get_config().settings.issuer_from_request = True
            get_config().settings.issuer_allowlist = ["http://nanoidp:9900"]
        assert (
            self._minted_iss(client, "evil.example.com")
            == get_config().settings.issuer
        )


class TestApiGenerateTokenBinding:
    """/api/users/<u>/token mirrors the MCP generate_token tool for #73: an
    unbound token (no client_id) gets no refresh token, since a refresh token
    with no client_id binding is refused; a client_id (which must be a real
    client) binds it so the refresh token is actually spendable."""

    def test_unbound_token_has_no_refresh_token(self, client):
        resp = client.post("/api/users/admin/token")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "access_token" in data
        assert "refresh_token" not in data

    def test_bound_token_refresh_is_spendable(self, client):
        import base64

        resp = client.post("/api/users/admin/token", json={"client_id": "demo-client"})
        assert resp.status_code == 200
        rt = json.loads(resp.data)["refresh_token"]
        header = {
            "Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()
        }
        refreshed = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": rt},
            headers=header,
        )
        assert refreshed.status_code == 200, refreshed.data

    def test_unknown_client_id_is_rejected(self, client):
        resp = client.post("/api/users/admin/token", json={"client_id": "does-not-exist"})
        assert resp.status_code == 400
        assert "does-not-exist" in json.loads(resp.data)["error"]
