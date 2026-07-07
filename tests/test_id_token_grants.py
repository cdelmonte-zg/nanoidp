"""
Tests for which OAuth grants emit an ID Token when ``openid`` scope is requested
(issue #36).

Spec rationale: an ID Token represents an authenticated end-user, so it is emitted
for grants that authenticate one — ``authorization_code`` (covered elsewhere),
``password`` and the device flow (RFC 8628). ``client_credentials`` has no
end-user, so it never emits an ID Token even if ``openid`` is requested.
"""

import json

import jwt as pyjwt
import pytest


def _decode(token: str) -> dict:
    return pyjwt.decode(token, options={"verify_signature": False})


@pytest.fixture(autouse=True)
def cleanup_device_codes():
    yield
    from nanoidp.services.device_code import get_device_code_store
    get_device_code_store().clear()


class TestPasswordGrantIdToken:
    """The password grant authenticates an end-user → emits an ID Token."""

    def test_password_grant_with_openid_returns_id_token(self, client, auth_header):
        resp = client.post(
            "/token",
            data={
                "grant_type": "password",
                "username": "admin",
                "password": "admin",
                "scope": "openid",
            },
            headers=auth_header,
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "id_token" in data
        claims = _decode(data["id_token"])
        # aud is the requesting client_id (issue #32 contract carries over).
        assert claims["aud"] == "demo-client"
        assert claims["token_use"] == "id"

    def test_password_grant_without_openid_has_no_id_token(self, client, auth_header):
        resp = client.post(
            "/token",
            data={
                "grant_type": "password",
                "username": "admin",
                "password": "admin",
                "scope": "profile email",
            },
            headers=auth_header,
        )
        assert resp.status_code == 200
        assert "id_token" not in json.loads(resp.data)

    def test_password_grant_no_scope_has_no_id_token(self, client, auth_header):
        resp = client.post(
            "/token",
            data={"grant_type": "password", "username": "admin", "password": "admin"},
            headers=auth_header,
        )
        assert resp.status_code == 200
        assert "id_token" not in json.loads(resp.data)

    def test_password_grant_empty_nonce_omits_nonce_claim(self, client, auth_header):
        """An empty nonce form field must not produce an empty `nonce` claim."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "password",
                "username": "admin",
                "password": "admin",
                "scope": "openid",
                "nonce": "",
            },
            headers=auth_header,
        )
        assert resp.status_code == 200
        claims = _decode(json.loads(resp.data)["id_token"])
        assert "nonce" not in claims

    def test_password_grant_passes_nonce_when_provided(self, client, auth_header):
        resp = client.post(
            "/token",
            data={
                "grant_type": "password",
                "username": "admin",
                "password": "admin",
                "scope": "openid",
                "nonce": "n-xyz",
            },
            headers=auth_header,
        )
        assert resp.status_code == 200
        claims = _decode(json.loads(resp.data)["id_token"])
        assert claims["nonce"] == "n-xyz"


class TestDeviceFlowIdToken:
    """The device flow authenticates an end-user → emits an ID Token."""

    def _run(self, client, auth_header, scope):
        data = {"scope": scope} if scope else {}
        resp = client.post("/device_authorization", data=data, headers=auth_header)
        assert resp.status_code == 200
        info = json.loads(resp.data)
        client.post(
            "/device",
            data={
                "user_code": info["user_code"],
                "username": "admin",
                "password": "admin",
                "action": "authorize",
            },
        )
        resp = client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": info["device_code"],
            },
            headers=auth_header,
        )
        assert resp.status_code == 200
        return json.loads(resp.data)

    def test_device_flow_with_openid_returns_id_token(self, client, auth_header):
        data = self._run(client, auth_header, "openid")
        assert "id_token" in data
        claims = _decode(data["id_token"])
        assert claims["aud"] == "demo-client"
        assert claims["token_use"] == "id"

    def test_device_flow_without_openid_has_no_id_token(self, client, auth_header):
        data = self._run(client, auth_header, "profile")
        assert "id_token" not in data


class TestClientCredentialsNoIdToken:
    """client_credentials has no end-user → never emits an ID Token."""

    def test_client_credentials_with_openid_has_no_id_token(self, client, auth_header):
        resp = client.post(
            "/token",
            data={"grant_type": "client_credentials", "scope": "openid"},
            headers=auth_header,
        )
        assert resp.status_code == 200
        assert "id_token" not in json.loads(resp.data)


class TestRefreshGrantIdToken:
    """The refresh_token grant re-issues an ID Token when the original scope
    included ``openid`` (OIDC Core §12.2, issue #39).

    The granted scope is persisted in the refresh token claims at issuance and
    recovered on refresh; a ``scope`` form parameter may narrow, but never
    broaden, the original grant (RFC 6749 §6).
    """

    def _password_grant(self, client, auth_header, scope=None):
        data = {
            "grant_type": "password",
            "username": "admin",
            "password": "admin",
        }
        if scope is not None:
            data["scope"] = scope
        resp = client.post("/token", data=data, headers=auth_header)
        assert resp.status_code == 200
        return json.loads(resp.data)

    def _refresh(self, client, auth_header, refresh_token, scope=None):
        data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        if scope is not None:
            data["scope"] = scope
        return client.post("/token", data=data, headers=auth_header)

    def test_refresh_reissues_id_token_when_openid_granted(self, client, auth_header):
        tokens = self._password_grant(client, auth_header, "openid profile")
        resp = self._refresh(client, auth_header, tokens["refresh_token"])
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "id_token" in data
        claims = _decode(data["id_token"])
        # Same contract as the original ID Token (issue #32): aud = client_id.
        assert claims["aud"] == "demo-client"
        assert claims["token_use"] == "id"
        # The nonce binds the original authentication request, not refreshes.
        assert "nonce" not in claims

    def test_refresh_without_openid_has_no_id_token(self, client, auth_header):
        tokens = self._password_grant(client, auth_header, "profile email")
        resp = self._refresh(client, auth_header, tokens["refresh_token"])
        assert resp.status_code == 200
        assert "id_token" not in json.loads(resp.data)

    def test_refresh_of_scopeless_grant_has_no_id_token(self, client, auth_header):
        """Refresh tokens without a persisted scope (e.g. minted before #39)
        keep the old behavior: tokens refresh fine, no ID Token."""
        tokens = self._password_grant(client, auth_header)
        resp = self._refresh(client, auth_header, tokens["refresh_token"])
        assert resp.status_code == 200
        assert "id_token" not in json.loads(resp.data)

    def test_refresh_can_narrow_scope_dropping_openid(self, client, auth_header):
        tokens = self._password_grant(client, auth_header, "openid profile")
        resp = self._refresh(client, auth_header, tokens["refresh_token"], "profile")
        assert resp.status_code == 200
        assert "id_token" not in json.loads(resp.data)

    def test_refresh_can_narrow_scope_keeping_openid(self, client, auth_header):
        tokens = self._password_grant(client, auth_header, "openid profile")
        resp = self._refresh(client, auth_header, tokens["refresh_token"], "openid")
        assert resp.status_code == 200
        assert "id_token" in json.loads(resp.data)

    def test_refresh_cannot_broaden_scope(self, client, auth_header):
        tokens = self._password_grant(client, auth_header, "profile")
        resp = self._refresh(client, auth_header, tokens["refresh_token"], "openid profile")
        assert resp.status_code == 400

    def test_scope_survives_refresh_chains(self, client, auth_header):
        """The refresh token returned by a refresh carries the scope forward,
        so ID Tokens keep being re-issued across consecutive refreshes."""
        tokens = self._password_grant(client, auth_header, "openid")
        first = self._refresh(client, auth_header, tokens["refresh_token"])
        assert first.status_code == 200
        rotated = json.loads(first.data)["refresh_token"]
        second = self._refresh(client, auth_header, rotated)
        assert second.status_code == 200
        assert "id_token" in json.loads(second.data)
