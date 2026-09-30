"""
A response that carries a token, a credential or other sensitive information
is never stored by a cache (#462).

RFC 6749 section 5.1 asks for ``Cache-Control: no-store`` and
``Pragma: no-cache`` on every such response of the authorization server;
OpenID Connect Core 3.1.3.3 asks for the first on every token response.
nanoidp applies the same pair to the two views that answer with personal
data and token state (``/userinfo``, ``/introspect``), a policy of its own:
an ``active: true`` served by a cache after a revocation would mislead a
test. The rule is declared on the view, so these tests read the headers off
real responses of each view, per grant, and keep the public documents
without it: the change must not become a server-wide rule by accident.
"""

import base64
import hashlib
import json
import secrets

import pytest

from nanoidp.routes._auth import no_store

REDIRECT = "http://localhost:3000/callback"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def assert_never_stored(response):
    assert response.headers.get("Cache-Control") == "no-store", dict(response.headers)
    assert response.headers.get("Pragma") == "no-cache", dict(response.headers)


def assert_storable(response):
    assert "Cache-Control" not in response.headers, dict(response.headers)
    assert "Pragma" not in response.headers, dict(response.headers)


def _obtain_code(client):
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    page = client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "demo-client",
            "redirect_uri": REDIRECT,
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert page.status_code == 200
    redirect = client.post(
        "/authorize", data={"username": "admin", "password": "admin"}, follow_redirects=False
    )
    assert redirect.status_code == 302
    code = redirect.headers["Location"].split("code=")[1].split("&")[0]
    return code, verifier


def _obtain_refresh_token(client, auth_header):
    response = client.post(
        "/token",
        data={"grant_type": "password", "username": "admin", "password": "admin"},
        headers=auth_header,
    )
    assert response.status_code == 200
    return json.loads(response.data)["refresh_token"]


def _obtain_approved_device_code(client, auth_header):
    response = client.post("/device_authorization", headers=auth_header)
    assert response.status_code == 200
    data = json.loads(response.data)
    approved = client.post(
        "/device",
        data={
            "user_code": data["user_code"],
            "username": "admin",
            "password": "admin",
            "action": "authorize",
        },
    )
    assert approved.status_code == 200
    return data["device_code"]


class TestTokenEndpointResponsesAreNeverStored:
    """Every response of /token, success and error, for every grant."""

    def test_client_credentials_success(self, client, auth_header):
        response = client.post(
            "/token", data={"grant_type": "client_credentials"}, headers=auth_header
        )
        assert response.status_code == 200
        assert_never_stored(response)

    def test_password_success(self, client, auth_header):
        response = client.post(
            "/token",
            data={"grant_type": "password", "username": "admin", "password": "admin"},
            headers=auth_header,
        )
        assert response.status_code == 200
        assert_never_stored(response)

    def test_authorization_code_success(self, client, auth_header):
        code, verifier = _obtain_code(client)
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": verifier,
            },
            headers=auth_header,
        )
        assert response.status_code == 200, response.data
        assert_never_stored(response)

    def test_refresh_token_success(self, client, auth_header):
        refresh_token = _obtain_refresh_token(client, auth_header)
        response = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            headers=auth_header,
        )
        assert response.status_code == 200, response.data
        assert_never_stored(response)

    def test_device_code_success(self, client, auth_header):
        device_code = _obtain_approved_device_code(client, auth_header)
        response = client.post(
            "/token",
            data={"grant_type": DEVICE_GRANT, "device_code": device_code},
            headers=auth_header,
        )
        assert response.status_code == 200, response.data
        assert_never_stored(response)

    def test_device_code_pending(self, client, auth_header):
        pending = json.loads(client.post("/device_authorization", headers=auth_header).data)
        response = client.post(
            "/token",
            data={"grant_type": DEVICE_GRANT, "device_code": pending["device_code"]},
            headers=auth_header,
        )
        assert response.status_code == 400
        assert json.loads(response.data)["error"] == "authorization_pending"
        assert_never_stored(response)

    def test_invalid_grant(self, client, auth_header):
        response = client.post(
            "/token",
            data={"grant_type": "authorization_code", "code": "nope", "redirect_uri": REDIRECT},
            headers=auth_header,
        )
        assert response.status_code == 400
        assert json.loads(response.data)["error"] == "invalid_grant"
        assert_never_stored(response)

    def test_wrong_password(self, client, auth_header):
        response = client.post(
            "/token",
            data={"grant_type": "password", "username": "admin", "password": "wrong"},
            headers=auth_header,
        )
        assert response.status_code == 400
        assert_never_stored(response)

    def test_invalid_client_with_a_basic_challenge(self, client):
        wrong = base64.b64encode(b"demo-client:wrong").decode()
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials"},
            headers={"Authorization": f"Basic {wrong}"},
        )
        assert response.status_code == 401
        assert "WWW-Authenticate" in response.headers
        assert_never_stored(response)

    def test_invalid_client_without_authentication(self, client):
        response = client.post("/token", data={"grant_type": "client_credentials"})
        assert response.status_code == 400
        assert json.loads(response.data)["error"] == "invalid_client"
        assert_never_stored(response)

    def test_unsupported_grant_type(self, client, auth_header):
        response = client.post("/token", data={"grant_type": "nope"}, headers=auth_header)
        assert response.status_code == 400
        assert json.loads(response.data)["error"] == "unsupported_grant_type"
        assert_never_stored(response)

    def test_invalid_request(self, client, auth_header):
        response = client.post(
            "/token", data={"grant_type": "client_credentials", "exp": "x"}, headers=auth_header
        )
        assert response.status_code == 400
        assert json.loads(response.data)["error"] == "invalid_request"
        assert_never_stored(response)


class TestDeviceAuthorizationResponsesAreNeverStored:
    """The response carries credentials: device_code and user_code."""

    @pytest.mark.parametrize("path", ["/device_authorization", "/device/code"])
    def test_success(self, client, auth_header, path):
        response = client.post(path, headers=auth_header)
        assert response.status_code == 200
        assert "device_code" in json.loads(response.data)
        assert_never_stored(response)

    def test_error(self, client):
        response = client.post("/device_authorization")
        assert response.status_code == 401
        assert_never_stored(response)


class TestUserinfoResponsesAreNeverStored:
    """Personal data, by nanoidp policy rather than by a MUST."""

    @pytest.mark.parametrize("method", ["get", "post"])
    def test_success(self, client, bearer_header, method):
        response = getattr(client, method)("/userinfo", headers=bearer_header)
        assert response.status_code == 200
        assert json.loads(response.data)["sub"] == "admin"
        assert_never_stored(response)

    def test_error(self, client):
        response = client.get("/userinfo")
        assert response.status_code == 401
        assert_never_stored(response)


class TestIntrospectionResponsesAreNeverStored:
    """Token state, by nanoidp policy rather than by a MUST."""

    def test_active(self, client, auth_header, access_token):
        response = client.post("/introspect", data={"token": access_token}, headers=auth_header)
        assert response.status_code == 200
        assert json.loads(response.data)["active"] is True
        assert_never_stored(response)

    def test_inactive(self, client, auth_header):
        response = client.post("/introspect", data={"token": "nope"}, headers=auth_header)
        assert response.status_code == 200
        assert json.loads(response.data)["active"] is False
        assert_never_stored(response)

    def test_error(self, client, access_token):
        response = client.post("/introspect", data={"token": access_token})
        assert response.status_code == 401
        assert_never_stored(response)


class TestManagementTokenResponsesAreNeverStored:
    """POST /api/users/<username>/token carries tokens like /token does."""

    def test_success(self, client):
        response = client.post("/api/users/admin/token")
        assert response.status_code == 200
        assert "access_token" in json.loads(response.data)
        assert_never_stored(response)

    def test_error(self, client):
        response = client.post("/api/users/nobody/token")
        assert response.status_code == 404
        assert_never_stored(response)


class TestPublicDocumentsStayStorable:
    """The rule is declared per view: the public documents keep no such
    header, so the change cannot silently become a server-wide rule."""

    @pytest.mark.parametrize(
        "path",
        [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/jwks.json",
        ],
    )
    def test_public_document(self, client, path):
        response = client.get(path)
        assert response.status_code == 200
        assert_storable(response)


class TestNoStoreHelper:
    """no_store() is the one home of the pair, for a single response as
    well as for a whole view: its earlier callers (the registration
    responses, the second-factor screens) gain Pragma with it."""

    def test_sets_both_headers_and_keeps_the_status(self, app):
        with app.test_request_context():
            response = no_store(("body", 201))
        assert response.status_code == 201
        assert_never_stored(response)
