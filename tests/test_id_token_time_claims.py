"""
Tests for the ``auth_time`` and ``at_hash`` ID Token claims (issue #42).

``auth_time`` must reflect when the end-user actually authenticated:
- password grant: the token request itself;
- authorization_code: when the code was created (the login page);
- refresh_token: preserved unchanged from the original authentication
  (OIDC Core §12.2), carried in the refresh token claims like scope (#39).

``at_hash`` binds the ID Token to the access token issued alongside it:
base64url(left half of SHA-256(access_token)), per OIDC Core §3.1.3.6.
Both claims belong to the ID Token only — never to the access token.
"""

import base64
import hashlib
import json
import time

import jwt as pyjwt


def _decode(token: str) -> dict:
    return pyjwt.decode(token, options={"verify_signature": False})


def _password_grant(client, auth_header, scope="openid"):
    resp = client.post(
        "/token",
        data={
            "grant_type": "password",
            "username": "admin",
            "password": "admin",
            "scope": scope,
        },
        headers=auth_header,
    )
    assert resp.status_code == 200
    return json.loads(resp.data)


def _expected_at_hash(access_token: str) -> str:
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode("ascii")


class TestAuthTime:
    def test_password_grant_auth_time_is_now(self, client, auth_header):
        before = int(time.time())
        data = _password_grant(client, auth_header)
        after = int(time.time())
        claims = _decode(data["id_token"])
        assert before <= claims["auth_time"] <= after

    def test_refresh_preserves_original_auth_time(self, client, auth_header):
        data = _password_grant(client, auth_header)
        original = _decode(data["id_token"])["auth_time"]

        time.sleep(1.1)  # ensure "now" has moved past the original auth_time
        resp = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": data["refresh_token"],
            },
            headers=auth_header,
        )
        assert resp.status_code == 200
        refreshed = _decode(json.loads(resp.data)["id_token"])
        assert refreshed["auth_time"] == original
        assert refreshed["iat"] > original

    def test_access_token_has_no_auth_time(self, client, auth_header):
        data = _password_grant(client, auth_header)
        assert "auth_time" not in _decode(data["access_token"])


class TestAtHash:
    def test_at_hash_binds_id_token_to_access_token(self, client, auth_header):
        data = _password_grant(client, auth_header)
        claims = _decode(data["id_token"])
        assert claims["at_hash"] == _expected_at_hash(data["access_token"])

    def test_at_hash_changes_with_the_access_token(self, client, auth_header):
        first = _password_grant(client, auth_header)
        second = _password_grant(client, auth_header)
        assert _decode(first["id_token"])["at_hash"] != _decode(second["id_token"])["at_hash"]

    def test_access_token_has_no_at_hash(self, client, auth_header):
        data = _password_grant(client, auth_header)
        assert "at_hash" not in _decode(data["access_token"])


class TestDiscoveryAdvertisesTimeClaims:
    def test_claims_supported_lists_new_claims(self, client):
        doc = json.loads(client.get("/.well-known/openid-configuration").data)
        for claim in ("auth_time", "nonce", "at_hash"):
            assert claim in doc["claims_supported"]
