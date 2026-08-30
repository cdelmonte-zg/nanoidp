"""
NanoIDP token profile: exp is required (#306).

Policy decision, option (a): a JWT accepted by verify_jwt must have a
finite lifetime. This is nanoidp's token-profile policy, not a JWT-spec
requirement - RFC 7519 leaves exp optional, but OIDC Core requires it on ID
Tokens, RFC 9068 requires it on JWT access tokens, and create_jwt has
always stamped one on everything nanoidp mints. The only tokens this
rejects are hand-crafted ones signed with the nanoidp key and no expiry -
an eternal bearer that would let an integration test pass here and fail
against any real IdP.
"""

import base64
import json
import time

import jwt as pyjwt
import pytest

from nanoidp.config import get_config
from nanoidp.services.crypto import get_crypto_service


def _mint(app, claims):
    with app.app_context():
        crypto = get_crypto_service(get_config().settings.keys_dir)
    return pyjwt.encode(claims, crypto.priv_pem, algorithm="RS256")


def _base_claims(**over):
    claims = {
        "sub": "admin",
        "iss": "http://localhost:8000",
        "aud": "my-app",
        "jti": "no-exp-test",
        "iat": int(time.time()),
        "token_use": "access",
        "token_type": "access",
    }
    claims.update(over)
    return claims


def _basic(client_id, secret):
    credentials = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


class TestVerifyJwtRequiresExp:
    def test_signed_token_without_exp_is_rejected(self, app):
        token = _mint(app, _base_claims())
        with app.app_context():
            crypto = get_crypto_service(get_config().settings.keys_dir)
        with pytest.raises(ValueError):
            crypto.verify_jwt(token, None)

    def test_signed_token_with_future_exp_is_accepted(self, app):
        token = _mint(app, _base_claims(exp=int(time.time()) + 300))
        with app.app_context():
            crypto = get_crypto_service(get_config().settings.keys_dir)
        payload = crypto.verify_jwt(token, None)
        assert payload["sub"] == "admin"


class TestEndpointsRejectNoExpTokens:
    def test_introspect_reports_inactive(self, client, app):
        """The error contract of the surface, not a new shape: an
        unacceptable token introspects as active: false (RFC 7662)."""
        token = _mint(app, _base_claims())
        resp = client.post(
            "/introspect",
            data={"token": token},
            headers=_basic("demo-client", "demo-secret"),
        )
        assert resp.status_code == 200
        assert json.loads(resp.data)["active"] is False

    def test_userinfo_rejects(self, client, app):
        token = _mint(app, _base_claims())
        resp = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_refresh_grant_rejects_a_no_exp_refresh_token(self, client, app):
        """The case that surfaced #306 (#293 round 2): an eternal refresh
        token. It must fail verification, never reach the grant."""
        token = _mint(
            app,
            _base_claims(
                token_use="refresh",
                token_type="refresh",
                client_id="demo-client",
                rt_family="fam-no-exp",
            ),
        )
        resp = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": token},
            headers=_basic("demo-client", "demo-secret"),
        )
        assert resp.status_code == 400
        assert json.loads(resp.data)["error"] == "invalid_grant"
