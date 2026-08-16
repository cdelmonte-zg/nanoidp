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
