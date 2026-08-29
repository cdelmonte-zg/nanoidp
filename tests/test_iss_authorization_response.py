"""
Tests for issue #189: RFC 9207 - iss on the authorization response.

/authorize returns iss (the effective issuer of the request) on the success
redirect, so a client can detect an authorization-server mix-up. The value
follows issuer_from_request (#126). RFC 9207 requires an https issuer with
no query/fragment, so
authorization_response_iss_parameter_supported is advertised only when the
effective issuer qualifies - with an http dev issuer the parameter is still
sent but not advertised.
"""

import base64
import hashlib
import json
from urllib.parse import parse_qs, urlparse

from nanoidp.config import get_config
from nanoidp.services.discovery import issuer_qualifies_for_iss_parameter

VERIFIER = "a-code-verifier-that-is-long-enough-for-rfc-7636"
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest())
    .decode()
    .rstrip("=")
)
REDIRECT = "http://localhost:3000/callback"


def _authorize_redirect(client, **headers):
    params = {
        "response_type": "code",
        "client_id": "demo-client",
        "redirect_uri": REDIRECT,
        "scope": "openid",
        "state": "xyz",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    client.get("/authorize?" + query, headers=headers)
    resp = client.post(
        "/authorize", data={**params, "username": "admin", "password": "admin"},
        follow_redirects=False, headers=headers,
    )
    return resp


class TestIssOnAuthorizationResponse:
    def test_success_redirect_carries_iss(self, client, app):
        resp = _authorize_redirect(client)
        assert resp.status_code == 302
        params = parse_qs(urlparse(resp.headers["Location"]).query)
        with app.app_context():
            issuer = get_config().settings.issuer
        assert params["iss"] == [issuer]
        assert params["code"]  # still there
        assert params["state"] == ["xyz"]

    def test_iss_reflects_issuer_from_request(self, client, app):
        with app.app_context():
            settings = get_config().settings
            settings.issuer_from_request = True
            settings.issuer_allowlist = []
        resp = _authorize_redirect(client, Host="idp.internal:9900")
        params = parse_qs(urlparse(resp.headers["Location"]).query)
        assert params["iss"] == ["http://idp.internal:9900"]

    def test_iss_falls_back_to_fixed_issuer_outside_the_allowlist(self, client, app):
        with app.app_context():
            settings = get_config().settings
            settings.issuer_from_request = True
            settings.issuer_allowlist = ["http://allowed.example"]
            fixed = settings.issuer
        resp = _authorize_redirect(client, Host="evil.example")
        params = parse_qs(urlparse(resp.headers["Location"]).query)
        assert params["iss"] == [fixed]


class TestDiscoveryAdvertisement:
    def test_http_issuer_appends_but_does_not_advertise(self, client, app):
        with app.app_context():
            assert get_config().settings.issuer.startswith("http://")
        doc = json.loads(client.get("/.well-known/openid-configuration").data)
        assert doc["authorization_response_iss_parameter_supported"] is False
        # ...yet the parameter is still delivered (useful for testing).
        resp = _authorize_redirect(client)
        assert "iss" in parse_qs(urlparse(resp.headers["Location"]).query)

    def test_https_issuer_advertises(self, client, app):
        with app.app_context():
            get_config().settings.issuer = "https://idp.example"
        doc = json.loads(client.get("/.well-known/openid-configuration").data)
        assert doc["authorization_response_iss_parameter_supported"] is True

    def test_https_issuer_with_query_does_not_qualify(self):
        assert issuer_qualifies_for_iss_parameter("https://idp.example?x=1") is False
        assert issuer_qualifies_for_iss_parameter("https://idp.example#f") is False
        assert issuer_qualifies_for_iss_parameter("http://idp.example") is False
        assert issuer_qualifies_for_iss_parameter("https://idp.example/") is True

    def test_mcp_discovery_carries_the_metadata(self, app):
        """The MCP get_oidc_discovery tool builds the same document (#40), so
        it advertises the same value - here False for the http dev issuer."""
        import asyncio

        import nanoidp.mcp_server as mcp
        from nanoidp.config import ConfigManager
        from tests.conftest import call_mcp_tool

        with app.app_context():
            mcp._config = ConfigManager(get_config().config_dir)

        async def _call():
            result = await call_mcp_tool("get_oidc_discovery", {})
            return json.loads(result.content[0].text)

        doc = asyncio.run(_call())
        assert "authorization_response_iss_parameter_supported" in doc
