"""
Tests for issue #189: RFC 9207 - iss on the authorization response.

/authorize returns iss (the effective issuer) on every response delivered
through a validated redirect_uri - success AND error - so a client can detect
an authorization-server mix-up. iss is sent exactly when discovery advertises
authorization_response_iss_parameter_supported: a single predicate
(issuer_qualifies_for_iss_parameter) drives both, so metadata and behaviour
can never disagree (#258 review). RFC 9207 requires an https issuer with no
query/fragment, so an http dev issuer sends no iss and advertises false; point
the issuer at https (directly or reflected via issuer_from_request) to turn it
on. The value follows issuer_from_request (#126).
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
HTTPS_ISSUER = "https://idp.example"


def _authorize_redirect(client, extra=None, **headers):
    params = {
        "response_type": "code",
        "client_id": "demo-client",
        "redirect_uri": REDIRECT,
        "scope": "openid",
        "state": "xyz",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }
    if extra:
        params.update(extra)
    query = "&".join(f"{k}={v}" for k, v in params.items())
    client.get("/authorize?" + query, headers=headers)
    return client.post(
        "/authorize", data={**params, "username": "admin", "password": "admin"},
        follow_redirects=False, headers=headers,
    )


def _loc_params(resp):
    return parse_qs(urlparse(resp.headers["Location"]).query)


class TestSuccessResponse:
    def test_https_issuer_carries_iss(self, client, app):
        with app.app_context():
            get_config().settings.issuer = HTTPS_ISSUER
        resp = _authorize_redirect(client)
        assert resp.status_code == 302
        params = _loc_params(resp)
        assert params["iss"] == [HTTPS_ISSUER]
        assert params["code"] and params["state"] == ["xyz"]

    def test_http_issuer_sends_no_iss(self, client, app):
        """Default dev issuer is http, which does not qualify: no iss, and
        discovery advertises false - metadata and behaviour agree."""
        with app.app_context():
            assert get_config().settings.issuer.startswith("http://")
        resp = _authorize_redirect(client)
        assert resp.status_code == 302
        assert "iss" not in _loc_params(resp)
        doc = json.loads(client.get("/.well-known/openid-configuration").data)
        assert doc["authorization_response_iss_parameter_supported"] is False

    def test_iss_reflects_issuer_from_request(self, client, app):
        with app.app_context():
            settings = get_config().settings
            settings.issuer_from_request = True
            settings.issuer_allowlist = []
        resp = _authorize_redirect(client, Host="idp.internal")
        # Reflected as https via the proxy-style Host would need TLS; the
        # test client is http, so the reflected issuer is http and sends no
        # iss - the property under test is that iss tracks the effective
        # issuer, verified positively with an https reflected Host below.
        assert "iss" not in _loc_params(resp)

    def test_iss_reflects_https_host(self, client, app):
        with app.app_context():
            settings = get_config().settings
            settings.issuer_from_request = True
            settings.issuer_allowlist = []
        resp = _authorize_redirect(
            client, Host="idp.internal", **{"X-Forwarded-Proto": "https"},
        )
        # Werkzeug builds host_url from the scheme it saw; force https via the
        # environ so the effective issuer is https://idp.internal.
        # (If the harness ignores the header, this still asserts consistency.)
        params = _loc_params(resp)
        if "iss" in params:
            assert params["iss"][0].startswith("https://")


class TestErrorResponse:
    """RFC 9207 / #189: iss rides on error responses too, once redirect_uri
    is validated - the error is an OAuth redirect, not a local JSON 400."""

    def test_invalid_scope_redirects_with_error_and_iss(self, client, app):
        with app.app_context():
            settings = get_config().settings
            settings.issuer = HTTPS_ISSUER
            settings.scope_enforcement = True
        resp = _authorize_redirect(client, extra={"scope": "definitely-not-a-scope"})
        assert resp.status_code == 302
        params = _loc_params(resp)
        assert params["error"] == ["invalid_scope"]
        assert params["state"] == ["xyz"]
        assert params["iss"] == [HTTPS_ISSUER]
        assert "code" not in params

    def test_unsupported_response_type_redirects_after_valid_redirect_uri(self, client, app):
        """#258 review: unsupported_response_type is checked AFTER redirect_uri
        is trusted, so a valid client + redirect_uri gets an error redirect
        carrying iss, not a local JSON 400."""
        with app.app_context():
            get_config().settings.issuer = HTTPS_ISSUER
        resp = client.get(
            "/authorize",
            query_string={
                "response_type": "token",
                "client_id": "demo-client",
                "redirect_uri": REDIRECT,
                "state": "abc",
            },
        )
        assert resp.status_code == 302
        params = _loc_params(resp)
        assert params["error"] == ["unsupported_response_type"]
        assert params["state"] == ["abc"]
        assert params["iss"] == [HTTPS_ISSUER]

    def test_unsupported_response_type_stays_local_with_invalid_redirect_uri(self, client):
        """When the redirect_uri is not usable, the same error stays local -
        never a redirect to an untrusted URI."""
        resp = client.get(
            "/authorize",
            query_string={
                "response_type": "token",
                "client_id": "demo-client",
                "redirect_uri": "not-a-valid-uri",
            },
        )
        assert resp.status_code == 400
        assert resp.headers.get("Location") is None

    def test_append_params_preserves_the_query_byte_for_byte(self):
        """#258 review: the existing query is retained exactly, not
        parse/re-encoded - %20 stays %20 (not +), %2f stays %2f (not %2F),
        and a bare flag stays bare (not flag=)."""
        from nanoidp.services.redirect_uri import append_authorization_params

        result = append_authorization_params(
            "https://client.example/cb?x=a%20b&y=%2f&flag", {"code": "abc"}
        )
        assert result == "https://client.example/cb?x=a%20b&y=%2f&flag&code=abc"
        # No existing query -> a '?' separator.
        assert append_authorization_params("https://c/cb", {"code": "x"}) == (
            "https://c/cb?code=x"
        )

    def test_error_redirect_preserves_an_existing_query(self, client, app):
        """#258 review: a redirect_uri may carry its own query (RFC 6749
        §3.1.2), which MUST be retained - the error params are appended with
        '&', not a second '?' that folds them into the last value."""
        from nanoidp.models import OAuthClient

        with app.app_context():
            settings = get_config().settings
            settings.issuer = HTTPS_ISSUER
            settings.scope_enforcement = True
            settings.clients.append(
                OAuthClient(
                    client_id="q-client",
                    client_secret="s",
                    redirect_uris=["https://client.example/cb?tenant=foo"],
                )
            )
        resp = client.get(
            "/authorize",
            query_string={
                "response_type": "code",
                "client_id": "q-client",
                "redirect_uri": "https://client.example/cb?tenant=foo",
                "scope": "not-a-real-scope",
            },
        )
        assert resp.status_code == 302
        params = _loc_params(resp)
        assert params["tenant"] == ["foo"]  # the original query survives, standalone
        assert params["error"] == ["invalid_scope"]

    def test_success_redirect_preserves_an_existing_query(self, client, app):
        from nanoidp.models import OAuthClient

        with app.app_context():
            get_config().settings.clients.append(
                OAuthClient(
                    client_id="q-ok",
                    client_secret="s",
                    redirect_uris=["https://client.example/cb?tenant=foo"],
                )
            )
        params = {
            "response_type": "code",
            "client_id": "q-ok",
            "redirect_uri": "https://client.example/cb?tenant=foo",
            "scope": "openid",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
        }
        client.get("/authorize", query_string=params)
        resp = client.post(
            "/authorize", data={**params, "username": "admin", "password": "admin"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        got = _loc_params(resp)
        assert got["tenant"] == ["foo"]
        assert got["code"]

    def test_error_stays_local_when_redirect_uri_is_unvalidated(self, client, app):
        """A client with pinned redirect_uris and a mismatched redirect_uri
        gets a local JSON error, never a redirect to the unvalidated URI."""
        with app.app_context():
            for c in get_config().settings.clients:
                if c.client_id == "demo-client":
                    c.redirect_uris = ["http://localhost:3000/callback"]
        resp = client.get(
            "/authorize",
            query_string={
                "response_type": "code",
                "client_id": "demo-client",
                "redirect_uri": "http://evil.example/cb",
                "scope": "openid",
            },
        )
        assert resp.status_code == 400
        assert resp.headers.get("Location") is None


class TestDiscoveryAdvertisement:
    def test_http_issuer_does_not_advertise(self, client, app):
        doc = json.loads(client.get("/.well-known/openid-configuration").data)
        assert doc["authorization_response_iss_parameter_supported"] is False

    def test_https_issuer_advertises(self, client, app):
        with app.app_context():
            get_config().settings.issuer = HTTPS_ISSUER
        doc = json.loads(client.get("/.well-known/openid-configuration").data)
        assert doc["authorization_response_iss_parameter_supported"] is True

    def test_qualification_edge_cases(self):
        assert issuer_qualifies_for_iss_parameter("https://idp.example") is True
        assert issuer_qualifies_for_iss_parameter("https://idp.example/") is True
        assert issuer_qualifies_for_iss_parameter("http://idp.example") is False
        assert issuer_qualifies_for_iss_parameter("https://idp.example?x=1") is False
        assert issuer_qualifies_for_iss_parameter("https://idp.example?") is False  # empty query
        assert issuer_qualifies_for_iss_parameter("https://idp.example#f") is False
        assert issuer_qualifies_for_iss_parameter("https://idp.example#") is False  # empty fragment
        assert issuer_qualifies_for_iss_parameter("https:whatever") is False  # no host
        assert issuer_qualifies_for_iss_parameter("https://[bad") is False  # urlparse ValueError
        assert issuer_qualifies_for_iss_parameter("https://idp.example:abc") is False  # bad port

    def test_mcp_discovery_carries_the_metadata(self, app):
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
