"""
Tests for issue #188: public clients (token_endpoint_auth_method 'none')
and, with them, real client_secret_post support (advertised in discovery
since forever, silently ignored until now).

A public client is identified by client_id alone: PKCE with S256 is
mandatory on /authorize regardless of profile, client_credentials is
refused (unauthorized_client), refresh tokens always rotate, /revoke
works with an ownership check, and /introspect stays closed (RFC 7662
requires authentication; a public client_id is not authentication).
"""

import base64
import hashlib
import json

import pytest
import yaml
from pydantic import ValidationError

from nanoidp.config import ConfigManager, get_config
from nanoidp.models import OAuthClient
from tests.conftest import authorize_error

PUBLIC_ID = "pub-cli"
REDIRECT = "http://localhost:3000/callback"

VERIFIER = "a-code-verifier-that-is-long-enough-for-rfc-7636"
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest())
    .decode()
    .rstrip("=")
)


@pytest.fixture
def public_client(app):
    """A public client registered next to the confidential demo-client."""
    with app.app_context():
        config = get_config()
        config.settings.clients.append(
            OAuthClient(client_id=PUBLIC_ID, token_endpoint_auth_method="none")
        )
    yield
    with app.app_context():
        config = get_config()
        config.settings.clients = [
            c for c in config.settings.clients if c.client_id != PUBLIC_ID
        ]


def _basic(client_id, secret):
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


@pytest.fixture
def post_client(app):
    """A confidential client registered with client_secret_post."""
    with app.app_context():
        get_config().settings.clients.append(
            OAuthClient(
                client_id="post-cli",
                client_secret="post-secret",
                token_endpoint_auth_method="client_secret_post",
            )
        )
    yield
    with app.app_context():
        config = get_config()
        config.settings.clients = [
            c for c in config.settings.clients if c.client_id != "post-cli"
        ]


def _authorize(client, **extra):
    params = {
        "response_type": "code",
        "client_id": PUBLIC_ID,
        "redirect_uri": REDIRECT,
        "scope": "openid",
        **extra,
    }
    return client.get("/authorize", query_string=params)


def _obtain_code(client):
    resp = _authorize(client, code_challenge=CHALLENGE, code_challenge_method="S256")
    assert resp.status_code == 200
    resp = client.post(
        "/authorize", data={"username": "admin", "password": "admin"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    return resp.headers["Location"].split("code=")[1].split("&")[0]


class TestModel:
    def test_public_client_needs_no_secret(self):
        c = OAuthClient(client_id="x", token_endpoint_auth_method="none")
        assert c.client_secret is None
        assert c.is_public is True

    def test_confidential_client_without_secret_is_rejected(self):
        with pytest.raises(ValidationError, match="client_secret is required"):
            OAuthClient(client_id="x")

    def test_secret_with_none_method_is_allowed_but_never_authenticates(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.yaml").write_text(
            yaml.safe_dump(
                {
                    "oauth": {
                        "issuer": "http://localhost:8000",
                        "clients": [
                            {
                                "client_id": "pub",
                                "client_secret": "stored-but-ignored",
                                "token_endpoint_auth_method": "none",
                            }
                        ],
                    }
                }
            )
        )
        (config_dir / "users.yaml").write_text(
            'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
        )
        config = ConfigManager(str(config_dir))
        assert config.get_client("pub").is_public is True
        # The stored secret must never become a credential (#188).
        assert config.check_client("pub", "stored-but-ignored") is False

    def test_clearing_the_secret_on_a_confidential_client_is_rejected(self):
        c = OAuthClient(client_id="x", client_secret="s")
        with pytest.raises(ValidationError):
            c.client_secret = None

    def test_yaml_public_client_without_secret_loads(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.yaml").write_text(
            yaml.safe_dump(
                {
                    "oauth": {
                        "issuer": "http://localhost:8000",
                        "clients": [
                            {"client_id": "pub", "token_endpoint_auth_method": "none"}
                        ],
                    }
                }
            )
        )
        (config_dir / "users.yaml").write_text(
            'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
        )
        config = ConfigManager(str(config_dir))
        client = config.get_client("pub")
        assert client is not None and client.is_public and client.client_secret is None

    def test_yaml_invalid_auth_method_is_rejected_at_load(self, tmp_path):
        """token_endpoint_auth_method is a closed enum on the document model
        (#254 review), so an invalid value fails at load with a field path,
        not only later in to_client()."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.yaml").write_text(
            yaml.safe_dump(
                {
                    "oauth": {
                        "issuer": "http://localhost:8000",
                        "clients": [
                            {
                                "client_id": "x",
                                "client_secret": "s",
                                "token_endpoint_auth_method": "client_secret_jwt",
                            }
                        ],
                    }
                }
            )
        )
        (config_dir / "users.yaml").write_text(
            'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
        )
        with pytest.raises(ValueError, match="token_endpoint_auth_method"):
            ConfigManager(str(config_dir))


class TestAuthorizePkceMandatory:
    """S256 PKCE is forced for public clients regardless of require_pkce."""

    def test_require_pkce_is_off_in_this_app(self, app, public_client):
        with app.app_context():
            assert get_config().settings.require_pkce is False

    def test_authorize_without_challenge_is_rejected(self, client, public_client):
        resp = _authorize(client)
        assert resp.status_code == 302
        data = authorize_error(resp)
        assert data["error"] == "invalid_request"
        assert "S256" in data["error_description"]

    def test_authorize_with_plain_method_is_rejected(self, client, public_client):
        resp = _authorize(client, code_challenge="x" * 43, code_challenge_method="plain")
        assert resp.status_code == 302
        assert "S256" in authorize_error(resp)["error_description"]

    def test_authorize_with_omitted_method_is_rejected(self, client, public_client):
        """RFC 7636 defaults an omitted method to 'plain' - which is not S256."""
        resp = _authorize(client, code_challenge="x" * 43)
        assert resp.status_code == 302

    def test_authorize_with_s256_renders_login(self, client, public_client):
        resp = _authorize(client, code_challenge=CHALLENGE, code_challenge_method="S256")
        assert resp.status_code == 200

    def test_confidential_client_still_needs_no_pkce(self, client, public_client):
        resp = client.get(
            "/authorize",
            query_string={
                "response_type": "code",
                "client_id": "demo-client",
                "redirect_uri": REDIRECT,
            },
        )
        assert resp.status_code == 200


class TestTokenEndpoint:
    def test_public_client_completes_the_code_flow_with_client_id_alone(
        self, client, public_client
    ):
        code = _obtain_code(client)
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": PUBLIC_ID,
                "code_verifier": VERIFIER,
            },
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["access_token"] and data["id_token"]

    def test_wrong_verifier_is_rejected(self, client, public_client):
        code = _obtain_code(client)
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": PUBLIC_ID,
                "code_verifier": "not-the-right-verifier-at-all-padpadpad",
            },
        )
        assert resp.status_code == 400

    def test_a_presented_secret_is_ignored(self, client, public_client):
        """Basic auth with any password on a public client must not fail
        the request: the secret is ignored, not validated (#188)."""
        code = _obtain_code(client)
        bogus = base64.b64encode(f"{PUBLIC_ID}:whatever".encode()).decode()
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": VERIFIER,
            },
            headers={"Authorization": f"Basic {bogus}"},
        )
        assert resp.status_code == 200

    def test_client_credentials_is_refused_with_unauthorized_client(
        self, client, public_client
    ):
        resp = client.post(
            "/token",
            data={"grant_type": "client_credentials", "client_id": PUBLIC_ID},
        )
        assert resp.status_code == 400
        assert json.loads(resp.data)["error"] == "unauthorized_client"

    def test_refresh_always_rotates_for_a_public_client(self, client, app, public_client):
        """rotation is off in settings, yet a public client's refresh token
        must be single-use (OAuth 2.1 §4.3.1/§6.1)."""
        with app.app_context():
            assert get_config().settings.rotation_enabled is False
        code = _obtain_code(client)
        first = json.loads(
            client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT,
                    "client_id": PUBLIC_ID,
                    "code_verifier": VERIFIER,
                },
            ).data
        )
        refresh = first["refresh_token"]

        used_once = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": PUBLIC_ID,
            },
        )
        assert used_once.status_code == 200

        replayed = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": PUBLIC_ID,
            },
        )
        assert replayed.status_code != 200


class TestMethodEnforcement:
    """token_endpoint_auth_method is ENFORCED, not descriptive (#254 review,
    blocking 2). A basic client must use Basic and a post client must use
    the body; the wrong channel is rejected, and a confidential client
    cannot skip authentication on any grant."""

    def test_basic_client_authenticates_via_basic(self, client):
        resp = client.post(
            "/token", data={"grant_type": "client_credentials"},
            headers=_basic("demo-client", "demo-secret"),
        )
        assert resp.status_code == 200
        assert json.loads(resp.data)["access_token"]

    def test_basic_client_rejects_a_body_secret(self, client):
        """demo-client is client_secret_basic: a body secret is the wrong
        channel and must not authenticate it (previously it silently did)."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "demo-client",
                "client_secret": "demo-secret",
            },
        )
        assert resp.status_code == 401

    def test_basic_client_rejects_valid_basic_plus_a_body_secret(self, client):
        """#254 review round 2: two authentication methods in one request is
        an RFC 6749 §2.3 violation and must be rejected even when the Basic
        credentials are valid - Basic must not silently win over a
        contradictory body secret."""
        for body_secret in ("demo-secret", "wrong"):
            resp = client.post(
                "/token",
                data={"grant_type": "client_credentials", "client_secret": body_secret},
                headers=_basic("demo-client", "demo-secret"),
            )
            assert resp.status_code == 401, body_secret

    def test_post_client_authenticates_via_body(self, client, post_client):
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "post-cli",
                "client_secret": "post-secret",
            },
        )
        assert resp.status_code == 200
        assert json.loads(resp.data)["access_token"]

    def test_post_client_rejects_basic(self, client, post_client):
        resp = client.post(
            "/token", data={"grant_type": "client_credentials"},
            headers=_basic("post-cli", "post-secret"),
        )
        assert resp.status_code == 401

    def test_post_client_with_wrong_body_secret_is_401(self, client, post_client):
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "post-cli",
                "client_secret": "wrong",
            },
        )
        assert resp.status_code == 401

    def test_confidential_authorization_code_requires_client_auth(self, client):
        """A confidential client cannot redeem a code with client_id alone
        (RFC 6749 §3.2.1; #188 contract). This was the authorization_code
        exemption bug (#254 review)."""
        params = {
            "response_type": "code",
            "client_id": "demo-client",
            "redirect_uri": REDIRECT,
            "scope": "openid",
        }
        client.get("/authorize", query_string=params)
        loc = client.post(
            "/authorize", data={**params, "username": "admin", "password": "admin"},
            follow_redirects=False,
        ).headers["Location"]
        code = loc.split("code=")[1].split("&")[0]
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": "demo-client",
            },
        )
        assert resp.status_code == 401

    def test_introspect_with_post_client_body_secret_works(self, client, post_client):
        token = json.loads(
            client.post(
                "/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "post-cli",
                    "client_secret": "post-secret",
                },
            ).data
        )["access_token"]
        resp = client.post(
            "/introspect",
            data={"token": token, "client_id": "post-cli", "client_secret": "post-secret"},
        )
        assert resp.status_code == 200
        assert json.loads(resp.data)["active"] is True

    def test_device_authorization_with_post_client_body_secret_works(
        self, client, post_client
    ):
        resp = client.post(
            "/device_authorization",
            data={"client_id": "post-cli", "client_secret": "post-secret"},
        )
        assert resp.status_code == 200
        assert "device_code" in json.loads(resp.data)


class TestRevocation:
    def _public_token(self, client):
        code = _obtain_code(client)
        return json.loads(
            client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT,
                    "client_id": PUBLIC_ID,
                    "code_verifier": VERIFIER,
                },
            ).data
        )["access_token"]

    def _confidential_token(self, client):
        return json.loads(
            client.post(
                "/token", data={"grant_type": "client_credentials"},
                headers=_basic("demo-client", "demo-secret"),
            ).data
        )["access_token"]

    def _active(self, client, token):
        resp = client.post(
            "/introspect", data={"token": token},
            headers=_basic("demo-client", "demo-secret"),
        )
        return json.loads(resp.data)["active"]

    def test_public_client_revokes_its_own_token_with_client_id_alone(
        self, client, public_client
    ):
        token = self._public_token(client)
        assert self._active(client, token) is True
        resp = client.post("/revoke", data={"token": token, "client_id": PUBLIC_ID})
        assert resp.status_code == 200
        assert self._active(client, token) is False

    def test_public_client_cannot_revoke_another_clients_token(
        self, client, public_client
    ):
        foreign = self._confidential_token(client)
        resp = client.post("/revoke", data={"token": foreign, "client_id": PUBLIC_ID})
        # RFC 7009 privacy guidance: same 200 either way, but nothing revoked.
        assert resp.status_code == 200
        assert self._active(client, foreign) is True

    def test_forged_ownership_claim_cannot_revoke_a_foreign_token(
        self, client, public_client
    ):
        """#254 review, blocking 1: the ownership check must not trust an
        unsigned token. A public client submits a bogus JWT signed with its
        own key, carrying its own client_id but a FOREIGN jti; the real
        token with that jti must stay active."""
        import jwt as pyjwt

        foreign = self._confidential_token(client)
        foreign_jti = pyjwt.decode(foreign, options={"verify_signature": False})["jti"]
        forged = pyjwt.encode(
            {"jti": foreign_jti, "client_id": PUBLIC_ID, "sub": "attacker"},
            "an-attacker-controlled-key-32-bytes-long!!",
            algorithm="HS256",
        )

        resp = client.post("/revoke", data={"token": forged, "client_id": PUBLIC_ID})
        assert resp.status_code == 200  # RFC 7009: 200 regardless
        assert self._active(client, foreign) is True  # but nothing revoked

    def test_confidential_client_revocation_still_works(self, client):
        token = self._confidential_token(client)
        resp = client.post(
            "/revoke", data={"token": token}, headers=_basic("demo-client", "demo-secret")
        )
        assert resp.status_code == 200
        assert self._active(client, token) is False

    def test_unknown_client_id_without_credentials_is_401(self, client):
        resp = client.post("/revoke", data={"token": "x", "client_id": "ghost"})
        assert resp.status_code == 401


class TestIntrospectionStaysClosed:
    def test_public_client_id_alone_is_401(self, client, public_client):
        token = TestRevocation()._public_token(client)
        resp = client.post("/introspect", data={"token": token, "client_id": PUBLIC_ID})
        assert resp.status_code == 401
        assert json.loads(resp.data)["error"] == "invalid_client"


class TestDiscovery:
    def test_none_advertised_for_token_and_revocation_but_not_introspection(
        self, client
    ):
        doc = json.loads(client.get("/.well-known/openid-configuration").data)
        assert "none" in doc["token_endpoint_auth_methods_supported"]
        assert "none" in doc["revocation_endpoint_auth_methods_supported"]
        assert "none" not in doc["introspection_endpoint_auth_methods_supported"]


class TestNonTokenEndpointAuthEnforcement:
    """#262: nanoidp applies the registered token_endpoint_auth_method
    consistently to /introspect, /revoke and /device_authorization - the
    method is enforced and two auth methods in one request are rejected
    (RFC 6749 §2.3). RFC 7009 and RFC 8628 tie /revoke and
    /device_authorization to token-endpoint authentication; RFC 7662 permits
    authentication at introspection but leaves the method open, so reusing it
    there is nanoidp's consistency policy. Behaviour change: a body secret
    from a client_secret_basic client, Basic from a client_secret_post client,
    or Basic+body together used to be accepted and now is not. The
    public-client policy is unchanged: introspect and device refuse public
    clients, revoke keeps its ownership relaxation."""

    def _token(self, client):
        return json.loads(
            client.post(
                "/token", data={"grant_type": "client_credentials"},
                headers=_basic("demo-client", "demo-secret"),
            ).data
        )["access_token"]

    # /introspect
    def test_introspect_basic_via_basic_works(self, client):
        resp = client.post(
            "/introspect", data={"token": self._token(client)},
            headers=_basic("demo-client", "demo-secret"),
        )
        assert resp.status_code == 200
        assert json.loads(resp.data)["active"] is True

    def test_introspect_basic_client_rejects_body_secret(self, client):
        resp = client.post(
            "/introspect",
            data={"token": self._token(client), "client_id": "demo-client", "client_secret": "demo-secret"},
        )
        assert resp.status_code == 401

    def test_introspect_rejects_basic_plus_body_secret(self, client):
        resp = client.post(
            "/introspect",
            data={"token": self._token(client), "client_secret": "demo-secret"},
            headers=_basic("demo-client", "demo-secret"),
        )
        assert resp.status_code == 401

    def test_introspect_post_client_rejects_basic(self, client, post_client):
        resp = client.post(
            "/introspect", data={"token": self._token(client)},
            headers=_basic("post-cli", "post-secret"),
        )
        assert resp.status_code == 401

    def test_introspect_public_client_rejected(self, client, public_client):
        resp = client.post(
            "/introspect", data={"token": self._token(client), "client_id": PUBLIC_ID}
        )
        assert resp.status_code == 401

    # /revoke
    def test_revoke_basic_via_basic_works(self, client):
        resp = client.post(
            "/revoke", data={"token": self._token(client)},
            headers=_basic("demo-client", "demo-secret"),
        )
        assert resp.status_code == 200

    def test_revoke_basic_client_rejects_body_secret(self, client):
        resp = client.post(
            "/revoke",
            data={"token": self._token(client), "client_id": "demo-client", "client_secret": "demo-secret"},
        )
        assert resp.status_code == 401

    def test_revoke_rejects_basic_plus_body_secret(self, client):
        resp = client.post(
            "/revoke",
            data={"token": self._token(client), "client_secret": "demo-secret"},
            headers=_basic("demo-client", "demo-secret"),
        )
        assert resp.status_code == 401

    def test_revoke_public_client_still_relaxed(self, client, public_client):
        # RFC 7009 §2.1 relaxation preserved: client_id alone, no secret, 200.
        resp = client.post("/revoke", data={"token": "whatever", "client_id": PUBLIC_ID})
        assert resp.status_code == 200

    # /device_authorization
    def test_device_basic_via_basic_works(self, client):
        resp = client.post(
            "/device_authorization", data={"scope": "openid"},
            headers=_basic("demo-client", "demo-secret"),
        )
        assert resp.status_code == 200
        assert "device_code" in json.loads(resp.data)

    def test_device_basic_client_rejects_body_secret(self, client):
        resp = client.post(
            "/device_authorization",
            data={"client_id": "demo-client", "client_secret": "demo-secret"},
        )
        assert resp.status_code == 401

    def test_device_rejects_basic_plus_body_secret(self, client):
        resp = client.post(
            "/device_authorization", data={"client_secret": "demo-secret"},
            headers=_basic("demo-client", "demo-secret"),
        )
        assert resp.status_code == 401

    def test_device_post_client_rejects_basic(self, client, post_client):
        resp = client.post(
            "/device_authorization", headers=_basic("post-cli", "post-secret")
        )
        assert resp.status_code == 401

    def test_device_public_client_rejected(self, client, public_client):
        resp = client.post("/device_authorization", data={"client_id": PUBLIC_ID})
        assert resp.status_code == 401

    # positive: a client_secret_post client authenticates over the BODY (the
    # channel its registered method names) at each endpoint.
    def _post_token(self, client):
        return json.loads(
            client.post(
                "/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "post-cli",
                    "client_secret": "post-secret",
                },
            ).data
        )["access_token"]

    def test_introspect_post_client_via_body_works(self, client, post_client):
        resp = client.post(
            "/introspect",
            data={
                "token": self._post_token(client),
                "client_id": "post-cli",
                "client_secret": "post-secret",
            },
        )
        assert resp.status_code == 200
        assert json.loads(resp.data)["active"] is True

    def test_revoke_post_client_via_body_works(self, client, post_client):
        resp = client.post(
            "/revoke",
            data={
                "token": self._post_token(client),
                "client_id": "post-cli",
                "client_secret": "post-secret",
            },
        )
        assert resp.status_code == 200

    def test_device_post_client_via_body_works(self, client, post_client):
        resp = client.post(
            "/device_authorization",
            data={"client_id": "post-cli", "client_secret": "post-secret"},
        )
        assert resp.status_code == 200
        assert "device_code" in json.loads(resp.data)
