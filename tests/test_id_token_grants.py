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
    try:
        from nanoidp.routes.oauth import _device_codes
        _device_codes.clear()
    except (ImportError, AttributeError):
        pass


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
