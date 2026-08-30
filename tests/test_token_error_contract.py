"""
Every /token error branch answers RFC 6749 §5.2 JSON (#308).

The #287 "Error surfaces" contract said protocol endpoints never answer
HTML - and roughly twenty /token branches still did, via Werkzeug abort().
The pre-existing suite only ever asserted status codes, so the HTML bodies
were invisible (the #307 review's example: a 400 assertion that never
looked at the body). This file is the parametric guard: one table of
(request, expected status, expected error code), each case asserting the
BODY is §5.2 JSON.

Status changes vs the old aborts are deliberate and CHANGELOGed: grant
failures that used to 401 (revoked/foreign refresh token, unknown user,
bad resource-owner credentials) are invalid_grant 400 - §5.2 reserves 401
for CLIENT authentication (invalid_client), not for grant validity.
"""

import base64
import time

import jwt as pyjwt
import pytest

from nanoidp.config import get_config
from nanoidp.services.crypto import get_crypto_service


def _basic(client_id: str, secret: str) -> dict:
    credentials = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


AUTH = _basic("demo-client", "demo-secret")


def _sign(app, claims):
    with app.app_context():
        crypto = get_crypto_service(get_config().settings.keys_dir)
    return pyjwt.encode(claims, crypto.priv_pem, algorithm="RS256")


def _refresh_claims(**over):
    claims = {
        "sub": "admin",
        "jti": f"contract-{time.time()}",
        "token_use": "refresh",
        "token_type": "refresh",
        "client_id": "demo-client",
        "exp": int(time.time()) + 300,
    }
    claims.update(over)
    return claims


# (case id, form data or callable(app)->data, headers, status, error code)
CASES = [
    ("no_client_auth", {"grant_type": "client_credentials"}, {}, 401, "invalid_client"),
    (
        "unsupported_grant_type",
        {"grant_type": "carrier-pigeon"},
        AUTH,
        400,
        "unsupported_grant_type",
    ),
    (
        "exp_not_integer",
        {"grant_type": "client_credentials", "exp": "soon"},
        AUTH,
        400,
        "invalid_request",
    ),
    (
        "exp_out_of_bounds",
        {"grant_type": "client_credentials", "exp": "99999"},
        AUTH,
        400,
        "invalid_request",
    ),
    (
        "extra_invalid_json",
        {"grant_type": "client_credentials", "extra": "{nope"},
        AUTH,
        400,
        "invalid_request",
    ),
    (
        "extra_not_object",
        {"grant_type": "client_credentials", "extra": "[1,2]"},
        AUTH,
        400,
        "invalid_request",
    ),
    (
        "refresh_token_missing",
        {"grant_type": "refresh_token"},
        AUTH,
        400,
        "invalid_request",
    ),
    (
        "refresh_unverifiable",
        {"grant_type": "refresh_token", "refresh_token": "not-a-jwt"},
        AUTH,
        400,
        "invalid_grant",
    ),
    (
        "access_token_used_as_refresh",
        lambda app: {
            "grant_type": "refresh_token",
            "refresh_token": _sign(
                app, _refresh_claims(token_use="access", token_type="access")
            ),
        },
        AUTH,
        400,
        "invalid_grant",
    ),
    (
        "refresh_of_unknown_user",
        lambda app: {
            "grant_type": "refresh_token",
            "refresh_token": _sign(app, _refresh_claims(sub="ghost-user")),
        },
        AUTH,
        400,
        "invalid_grant",
    ),
    (
        "password_missing_credentials",
        {"grant_type": "password"},
        AUTH,
        400,
        "invalid_request",
    ),
    (
        "password_bad_credentials",
        {"grant_type": "password", "username": "admin", "password": "wrong"},
        AUTH,
        400,
        "invalid_grant",
    ),
    (
        "authorization_code_missing_code",
        {"grant_type": "authorization_code", "redirect_uri": "http://localhost/cb"},
        AUTH,
        400,
        "invalid_request",
    ),
    (
        "authorization_code_missing_redirect_uri",
        {"grant_type": "authorization_code", "code": "whatever"},
        AUTH,
        400,
        "invalid_request",
    ),
    (
        "authorization_code_invalid_code",
        {
            "grant_type": "authorization_code",
            "code": "no-such-code",
            "redirect_uri": "http://localhost/cb",
        },
        AUTH,
        400,
        "invalid_grant",
    ),
]


class TestTokenErrorContract:
    @pytest.mark.parametrize(
        "case_id,data,headers,status,error",
        CASES,
        ids=[c[0] for c in CASES],
    )
    def test_error_is_rfc6749_json(self, client, app, case_id, data, headers, status, error):
        if callable(data):
            data = data(app)
        resp = client.post("/token", data=data, headers=headers)
        assert resp.status_code == status, resp.data[:200]
        body = resp.get_json(silent=True)
        assert body is not None, f"non-JSON body: {resp.data[:200]!r}"
        assert body["error"] == error
        assert "error_description" in body

    def test_foreign_client_refresh_is_invalid_grant(self, client, app):
        """A refresh token issued to another client: invalid_grant 400
        (used to be a 401 HTML abort). Minted for scoped-client, spent by
        demo-client."""
        resp = client.post(
            "/token",
            data={"grant_type": "password", "username": "admin", "password": "admin"},
            headers=_basic("scoped-client", "scoped-secret"),
        )
        assert resp.status_code == 200
        stolen = resp.get_json()["refresh_token"]

        spent = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": stolen},
            headers=AUTH,
        )
        assert spent.status_code == 400
        body = spent.get_json()
        assert body["error"] == "invalid_grant"

    def test_revoked_refresh_is_invalid_grant(self, client, app):
        resp = client.post(
            "/token",
            data={"grant_type": "password", "username": "admin", "password": "admin"},
            headers=AUTH,
        )
        rt = resp.get_json()["refresh_token"]
        assert (
            client.post("/revoke", data={"token": rt}, headers=AUTH).status_code == 200
        )
        spent = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": rt},
            headers=AUTH,
        )
        assert spent.status_code == 400
        assert spent.get_json()["error"] == "invalid_grant"
