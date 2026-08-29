"""
Tests for issue #187: RFC 8707 Resource Indicators.

A ``resource`` on /authorize, /token or /device_authorization binds the
access token ``aud`` to that resource, so a token minted for MCP server A is
useless at server B. Per-client ``allowed_resources`` gates which resources a
client may target; a /token request may narrow the resources a prior step
bound, never widen them; sending no resource leaves ``aud`` at
``oauth.audience`` (no change for existing clients).
"""

import base64
import hashlib
import json

import pytest

from nanoidp.config import get_config
from nanoidp.models import OAuthClient
from nanoidp.services.resource import is_valid_resource_indicator, resolve_resources

RES_A = "https://mcp-a.example/server"
RES_B = "https://mcp-b.example/server"
REDIRECT = "http://localhost:3000/callback"
VERIFIER = "a-code-verifier-that-is-long-enough-for-rfc-7636"
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest())
    .decode()
    .rstrip("=")
)


def _basic(client_id="demo-client", secret="demo-secret"):
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


def _aud(access_token):
    payload = access_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))["aud"]


class TestResourceValidation:
    @pytest.mark.parametrize(
        "value,valid",
        [
            ("https://mcp.example/server", True),
            ("https://mcp.example/server?v=1", True),
            ("urn:example:resource", True),
            ("https://mcp.example/server#frag", False),  # fragment
            ("https://example.com/#", False),  # empty fragment component (#254 review)
            ("https://[bad", False),  # urlparse ValueError, not a crash (#254 review)
            ("https://exa mple/resource", False),  # raw space, not RFC 3986 (#254 review)
            ("/relative/path", False),  # no scheme
            ("", False),
        ],
    )
    def test_indicator_syntax(self, value, valid):
        assert is_valid_resource_indicator(value) is valid

    def test_allowed_resources_gate(self):
        client = OAuthClient(client_id="c", client_secret="s", allowed_resources=[RES_A])
        assert resolve_resources([RES_A], client).ok is True
        assert resolve_resources([RES_B], client).ok is False

    def test_empty_allow_list_accepts_any_valid_resource(self):
        client = OAuthClient(client_id="c", client_secret="s")
        assert resolve_resources([RES_A, RES_B], client).granted == [RES_A, RES_B]

    def test_narrowing_subset(self):
        client = OAuthClient(client_id="c", client_secret="s")
        assert resolve_resources([RES_A], client, allowed_subset=[RES_A, RES_B]).ok is True
        assert resolve_resources([RES_B], client, allowed_subset=[RES_A]).ok is False


class TestClientCredentials:
    def test_resource_becomes_the_access_token_aud(self, client):
        resp = client.post(
            "/token", data={"grant_type": "client_credentials", "resource": RES_A},
            headers=_basic(),
        )
        assert resp.status_code == 200
        assert _aud(json.loads(resp.data)["access_token"]) == RES_A

    def test_two_resources_make_aud_an_array(self, client):
        resp = client.post(
            "/token",
            data={"grant_type": "client_credentials", "resource": [RES_A, RES_B]},
            headers=_basic(),
        )
        assert resp.status_code == 200
        assert _aud(json.loads(resp.data)["access_token"]) == [RES_A, RES_B]

    def test_no_resource_keeps_the_default_audience(self, client, app):
        resp = client.post(
            "/token", data={"grant_type": "client_credentials"}, headers=_basic()
        )
        with app.app_context():
            default_aud = get_config().settings.audience
        assert _aud(json.loads(resp.data)["access_token"]) == default_aud

    def test_invalid_resource_is_invalid_target(self, client):
        resp = client.post(
            "/token",
            data={"grant_type": "client_credentials", "resource": "https://x/#frag"},
            headers=_basic(),
        )
        assert resp.status_code == 400
        assert json.loads(resp.data)["error"] == "invalid_target"

    def test_disallowed_resource_is_invalid_target(self, client, app):
        with app.app_context():
            get_config().settings.clients.append(
                OAuthClient(client_id="rc", client_secret="s", allowed_resources=[RES_A])
            )
        resp = client.post(
            "/token",
            data={"grant_type": "client_credentials", "resource": RES_B},
            headers=_basic("rc", "s"),
        )
        assert resp.status_code == 400
        assert json.loads(resp.data)["error"] == "invalid_target"


class TestAuthorizationCodeFlow:
    def _code(self, client, resources):
        params = {
            "response_type": "code",
            "client_id": "demo-client",
            "redirect_uri": REDIRECT,
            "scope": "openid",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
        }
        query = "&".join([f"{k}={v}" for k, v in params.items()] + [f"resource={r}" for r in resources])
        client.get("/authorize?" + query)
        resp = client.post(
            "/authorize", data={**params, "username": "admin", "password": "admin"},
            follow_redirects=False,
        )
        return resp.headers["Location"].split("code=")[1].split("&")[0]

    def _exchange(self, client, code, resources):
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER,
            "resource": resources,
        }
        return client.post("/token", data=data, headers=_basic())

    def test_resource_from_authorize_binds_the_token(self, client):
        code = self._code(client, [RES_A])
        resp = self._exchange(client, code, [])  # inherit
        assert resp.status_code == 200
        assert _aud(json.loads(resp.data)["access_token"]) == RES_A

    def test_token_narrows_to_a_subset(self, client):
        code = self._code(client, [RES_A, RES_B])
        resp = self._exchange(client, code, [RES_A])
        assert resp.status_code == 200
        assert _aud(json.loads(resp.data)["access_token"]) == RES_A

    def test_token_cannot_widen_beyond_the_code(self, client):
        code = self._code(client, [RES_A])
        resp = self._exchange(client, code, [RES_B])
        assert resp.status_code == 400
        assert json.loads(resp.data)["error"] == "invalid_target"

    def test_duplicate_resource_at_authorize_is_deduplicated(self, client):
        """#254 review, finding 3: a repeated resource at /authorize must not
        become a duplicate entry in the token aud - the authorization code
        stores the de-duplicated list, like the device flow already did."""
        code = self._code(client, [RES_A, RES_A])
        resp = self._exchange(client, code, [])
        assert resp.status_code == 200
        assert _aud(json.loads(resp.data)["access_token"]) == RES_A

    def test_refresh_keeps_the_full_grant_not_the_narrowed_subset(self, client):
        """#254 review, finding 1 (RFC 8707 §2.2): narrowing the access token
        to a subset must NOT narrow the refresh token - a later refresh can
        still request any resource the original authorization covered."""
        code = self._code(client, [RES_A, RES_B])
        # scope offline_access so a refresh token is issued for the code flow.
        first = json.loads(self._exchange(client, code, [RES_A]).data)
        assert _aud(first["access_token"]) == RES_A
        assert "refresh_token" in first
        refreshed = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"],
                  "resource": RES_B},
            headers=_basic(),
        )
        assert refreshed.status_code == 200
        assert _aud(json.loads(refreshed.data)["access_token"]) == RES_B

    def test_token_cannot_introduce_a_resource_the_code_never_bound(self, client):
        """#254 review, finding 1: a code that bound no resource cannot have
        one introduced at /token - that would bind the token to a resource
        /authorize never authorized (widening from nothing)."""
        code = self._code(client, [])  # no resource at /authorize
        resp = self._exchange(client, code, [RES_A])
        assert resp.status_code == 400
        assert json.loads(resp.data)["error"] == "invalid_target"


class TestRefreshToken:
    def test_refresh_keeps_the_resource_aud(self, client):
        first = json.loads(
            client.post(
                "/token", data={"grant_type": "client_credentials", "resource": RES_A},
                headers=_basic(),
            ).data
        )
        # client_credentials issues no refresh token (#239); use the password
        # grant, which does, to exercise the refresh path.
        first = json.loads(
            client.post(
                "/token",
                data={"grant_type": "password", "username": "admin", "password": "admin",
                      "scope": "openid", "resource": RES_A},
                headers=_basic(),
            ).data
        )
        assert _aud(first["access_token"]) == RES_A
        refreshed = json.loads(
            client.post(
                "/token",
                data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
                headers=_basic(),
            ).data
        )
        assert _aud(refreshed["access_token"]) == RES_A

    def test_refresh_cannot_widen(self, client):
        first = json.loads(
            client.post(
                "/token",
                data={"grant_type": "password", "username": "admin", "password": "admin",
                      "scope": "openid", "resource": RES_A},
                headers=_basic(),
            ).data
        )
        resp = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"],
                  "resource": RES_B},
            headers=_basic(),
        )
        assert resp.status_code == 400
        assert json.loads(resp.data)["error"] == "invalid_target"


class TestIntrospection:
    def test_introspect_reports_the_resource_aud(self, client):
        token = json.loads(
            client.post(
                "/token", data={"grant_type": "client_credentials", "resource": RES_A},
                headers=_basic(),
            ).data
        )["access_token"]
        resp = client.post("/introspect", data={"token": token}, headers=_basic())
        payload = json.loads(resp.data)
        assert payload["active"] is True
        assert payload["aud"] == RES_A

    def test_introspect_client_id_is_the_token_owner(self, client, app):
        """#254 review, finding 4 (RFC 7662 §2.2): the response client_id is
        the client the token was issued to, not the caller introspecting."""
        with app.app_context():
            get_config().settings.clients.append(
                OAuthClient(client_id="rs", client_secret="rs-secret")
            )
        token = json.loads(
            client.post(
                "/token", data={"grant_type": "client_credentials"}, headers=_basic()
            ).data
        )["access_token"]
        # A different client (a resource server) introspects the token.
        resp = client.post("/introspect", data={"token": token}, headers=_basic("rs", "rs-secret"))
        assert json.loads(resp.data)["client_id"] == "demo-client"


class TestDeviceFlow:
    def test_resource_binds_the_device_token(self, client, app):
        start = json.loads(
            client.post(
                "/device_authorization",
                data={"scope": "openid", "resource": RES_A},
                headers=_basic(),
            ).data
        )
        # Approve the user code directly through the store, then poll.
        from nanoidp.services import get_device_code_store

        with app.app_context():
            store = get_device_code_store()
            store.verify(
                start["user_code"], "approve", "admin", "admin",
                get_config().interactive_authenticate,
            )
        resp = client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": start["device_code"],
            },
            headers=_basic(),
        )
        assert resp.status_code == 200
        assert _aud(json.loads(resp.data)["access_token"]) == RES_A

    def test_duplicate_device_resource_is_deduplicated(self, client, app):
        """#254 review, finding 2: a repeated resource must not become a
        duplicate entry in the token aud."""
        start = json.loads(
            client.post(
                "/device_authorization",
                data={"scope": "openid", "resource": [RES_A, RES_A]},
                headers=_basic(),
            ).data
        )
        from nanoidp.services import get_device_code_store

        with app.app_context():
            get_device_code_store().verify(
                start["user_code"], "approve", "admin", "admin",
                get_config().interactive_authenticate,
            )
        resp = client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": start["device_code"],
            },
            headers=_basic(),
        )
        assert resp.status_code == 200
        # A single resource collapses to a plain string, not a 1- or 2-item array.
        assert _aud(json.loads(resp.data)["access_token"]) == RES_A

    def test_invalid_device_resource_is_invalid_target(self, client):
        resp = client.post(
            "/device_authorization",
            data={"scope": "openid", "resource": "https://x/#frag"},
            headers=_basic(),
        )
        assert resp.status_code == 400
        assert json.loads(resp.data)["error"] == "invalid_target"
