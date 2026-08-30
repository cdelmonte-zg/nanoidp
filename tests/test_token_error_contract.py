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
    # 400, not 401: no Authorization header was attempted, and RFC 9110
    # forbids a challenge-less 401 (#310 review round 2).
    ("no_client_auth", {"grant_type": "client_credentials"}, {}, 400, "invalid_client"),
    (
        "unsupported_grant_type",
        {"grant_type": "carrier-pigeon"},
        AUTH,
        400,
        "unsupported_grant_type",
    ),
    (
        # #310 review blocker 1: the caller's arbitrary value must NOT be
        # reflected into error_description (§5.2 restricts it to a narrow
        # ASCII subset) - this is the case that distinguishes fixed text
        # from reflection.
        "unsupported_grant_type_non_ascii",
        {"grant_type": 'sp\u00e4ce"\U0001f4a5\ntype'},
        AUTH,
        400,
        "unsupported_grant_type",
    ),
    (
        "refresh_token_without_subject",
        lambda app: {
            "grant_type": "refresh_token",
            "refresh_token": _sign(
                app, {k: v for k, v in _refresh_claims().items() if k != "sub"}
            ),
        },
        AUTH,
        400,
        "invalid_grant",
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

    def test_non_ascii_grant_type_is_not_reflected(self, client):
        """The description is fixed text; the raw value lives in the audit
        event, not the response (#310 review blocker 1)."""
        resp = client.post(
            "/token",
            data={"grant_type": 'sp\u00e4ce"\U0001f4a5\ntype'},
            headers=AUTH,
        )
        body = resp.get_json()
        assert body["error_description"] == "The requested grant_type is not supported"
        assert "\U0001f4a5" not in body["error_description"]

    def test_invalid_client_with_basic_carries_www_authenticate(self, client):
        """§5.2 MUST (#310 review blocker 2): a client that ATTEMPTED
        Authorization-header authentication gets 401 with a
        WWW-Authenticate challenge for the scheme it used."""
        resp = client.post(
            "/token",
            data={"grant_type": "client_credentials"},
            headers=_basic("demo-client", "wrong-secret"),
        )
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_client"
        assert resp.headers.get("WWW-Authenticate", "").startswith("Basic")

    def test_invalid_client_without_auth_header_is_400_no_challenge(self, client):
        """No Authorization header attempted: §5.2's DEFAULT applies -
        invalid_client 400 - because RFC 9110 §11.6.1 forbids a 401 without
        a WWW-Authenticate challenge, and issuing a Basic challenge to a
        client that never tried Basic would be wrong too (#310 round 2)."""
        resp = client.post("/token", data={"grant_type": "client_credentials"})
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_client"
        assert "WWW-Authenticate" not in resp.headers

    def test_client_secret_post_wrong_secret_is_400_no_basic_challenge(self, client, app):
        """A client_secret_post client with a wrong BODY secret never
        touched the Authorization header: 400 invalid_client, and no Basic
        challenge for a client whose registered method is not Basic
        (#310 round 2 - the case that makes the 400/401 split matter)."""
        from nanoidp.config import OAuthClient, get_config

        with app.app_context():
            settings = get_config().settings
            settings.clients.append(
                OAuthClient(
                    client_id="post-client-310",
                    client_secret="post-secret",
                    token_endpoint_auth_method="client_secret_post",
                )
            )
        try:
            resp = client.post(
                "/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "post-client-310",
                    "client_secret": "wrong",
                },
            )
            assert resp.status_code == 400
            assert resp.get_json()["error"] == "invalid_client"
            assert "WWW-Authenticate" not in resp.headers
        finally:
            with app.app_context():
                settings = get_config().settings
                settings.clients = [
                    c for c in settings.clients if c.client_id != "post-client-310"
                ]

    def test_client_id_mismatch_is_json_with_challenge(self, client):
        """Basic for one client plus a contradictory body client_id: 401
        invalid_client JSON (was HTML) WITH the challenge - Basic was
        presented by construction."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "scoped-client",
            },
            headers=AUTH,
        )
        assert resp.status_code == 401
        body = resp.get_json()
        assert body["error"] == "invalid_client"
        assert resp.headers.get("WWW-Authenticate", "").startswith("Basic")

    def test_password_grant_disabled_by_oauth21_is_unsupported_grant_type(
        self, client, app
    ):
        from nanoidp.config import get_config

        with app.app_context():
            settings = get_config().settings
            original = settings.security_profile
            settings.security_profile = "oauth21"
        try:
            resp = client.post(
                "/token",
                data={"grant_type": "password", "username": "admin", "password": "admin"},
                headers=AUTH,
            )
            assert resp.status_code == 400
            body = resp.get_json()
            assert body["error"] == "unsupported_grant_type"
            assert "oauth21" in body["error_description"]
        finally:
            with app.app_context():
                get_config().settings.security_profile = original

    def test_code_for_a_deleted_user_is_invalid_grant(self, client, app):
        """An authorization code whose user vanished between /authorize and
        redemption: invalid_grant JSON (was a 401 HTML abort)."""
        from nanoidp.services.auth_code import get_auth_code_store

        with app.app_context():
            code = get_auth_code_store().create_code(
                client_id="demo-client",
                redirect_uri="http://localhost/cb",
                username="ghost-user-never-existed",
            )
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost/cb",
            },
            headers=AUTH,
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_grant"

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


class TestBrokenBasicHeaderIsStillAnAttempt:
    """#311: werkzeug parses a syntactically broken Basic header to None,
    which used to land in the no-attempt branch (400, no challenge). The
    attempt is now detected from the RAW header: a botched Basic is still
    a Basic attempt - 401 with the challenge."""

    def test_garbage_basic_header_gets_401_with_challenge(self, client):
        resp = client.post(
            "/token",
            data={"grant_type": "client_credentials"},
            headers={"Authorization": "Basic %%%not-base64%%%"},
        )
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_client"
        assert resp.headers.get("WWW-Authenticate", "").startswith("Basic")

    def test_bearer_header_is_not_a_basic_attempt(self, client):
        """A different scheme is not a Basic attempt: no Basic challenge,
        400 per the §5.2 default."""
        resp = client.post(
            "/token",
            data={"grant_type": "client_credentials"},
            headers={"Authorization": "Bearer some-token"},
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_client"
        assert "WWW-Authenticate" not in resp.headers
