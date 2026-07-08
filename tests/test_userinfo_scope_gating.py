"""
Tests for scope-to-claim gating on /userinfo and the access-token scope claim.

Issue #102: the standard OIDC claims (email/profile) must only be returned from
/userinfo when the matching scope was granted (OIDC Core §5.4). Enforcement is
gated on the security profile: the permissive ``dev`` default keeps returning
them unconditionally (backward compatible), while ``stricter-dev``/``oauth21``
enforce the scope check. The granted scope is read from the access token's
``scope`` claim (RFC 9068 §2.2.3).
"""

import base64
import json

import jwt as pyjwt

from nanoidp.app import create_app


def _client(profile):
    app = create_app(profile=profile)
    app.config["TESTING"] = True
    return app.test_client()


def _auth_header():
    creds = base64.b64encode(b"demo-client:demo-secret").decode()
    return {"Authorization": f"Basic {creds}"}


def _get_token(client, scope=None):
    data = {"grant_type": "password", "username": "admin", "password": "admin"}
    if scope is not None:
        data["scope"] = scope
    resp = client.post("/token", data=data, headers=_auth_header())
    assert resp.status_code == 200, resp.data
    return json.loads(resp.data)["access_token"]


def _userinfo(client, token):
    return client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})


class TestAccessTokenScopeClaim:
    """The access token advertises its granted scope (RFC 9068 §2.2.3)."""

    def test_access_token_carries_scope_when_requested(self):
        client = _client("dev")
        token = _get_token(client, scope="openid email")
        payload = pyjwt.decode(token, options={"verify_signature": False})
        assert payload.get("scope") == "openid email"

    def test_access_token_has_no_scope_claim_when_absent(self):
        client = _client("dev")
        token = _get_token(client)  # no scope form parameter
        payload = pyjwt.decode(token, options={"verify_signature": False})
        assert "scope" not in payload


class TestUserinfoDevProfilePermissive:
    """The default ``dev`` profile keeps returning claims unconditionally."""

    def test_email_returned_without_email_scope(self):
        client = _client("dev")
        token = _get_token(client, scope="openid")
        data = json.loads(_userinfo(client, token).data)
        assert "email" in data
        assert "email_verified" in data

    def test_preferred_username_returned_without_profile_scope(self):
        client = _client("dev")
        token = _get_token(client, scope="openid")
        data = json.loads(_userinfo(client, token).data)
        assert "preferred_username" in data


class TestUserinfoStrictProfileGated:
    """``stricter-dev`` enforces the OIDC scope-to-claim mapping (§5.4)."""

    def test_email_omitted_without_email_scope(self):
        client = _client("stricter-dev")
        token = _get_token(client, scope="openid")
        data = json.loads(_userinfo(client, token).data)
        assert "email" not in data
        assert "email_verified" not in data

    def test_email_returned_with_email_scope(self):
        client = _client("stricter-dev")
        token = _get_token(client, scope="openid email")
        data = json.loads(_userinfo(client, token).data)
        assert data.get("email") == "admin@example.org"
        assert data.get("email_verified") is True

    def test_preferred_username_omitted_without_profile_scope(self):
        client = _client("stricter-dev")
        token = _get_token(client, scope="openid")
        data = json.loads(_userinfo(client, token).data)
        assert "preferred_username" not in data

    def test_preferred_username_returned_with_profile_scope(self):
        client = _client("stricter-dev")
        token = _get_token(client, scope="openid profile")
        data = json.loads(_userinfo(client, token).data)
        assert data.get("preferred_username") == "admin"

    def test_custom_claims_always_returned(self):
        """nanoidp-specific claims have no standard scope, so they are never gated."""
        client = _client("stricter-dev")
        token = _get_token(client, scope="openid")  # minimal scope
        data = json.loads(_userinfo(client, token).data)
        assert "roles" in data
        assert "tenant" in data
        assert data["sub"] == "admin"
