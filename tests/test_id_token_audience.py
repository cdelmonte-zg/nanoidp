"""
Tests for the OIDC ID Token ``aud`` (audience) claim contract.

Contract (per the official specifications):

* **OpenID Connect Core 1.0, §2 (ID Token):** the ``aud`` claim MUST contain the
  OAuth 2.0 ``client_id`` of the Relying Party. It MAY contain other audiences.
  In the general case it is an array of strings; with a single audience it MAY be
  a single string (RFC 7519 §4.1.3).
* **OpenID Connect Core 1.0, §2 / §3.1.3.7 (azp):** ``azp`` is optional in Core,
  but if present it must contain the OAuth 2.0 ``client_id`` of the authorized
  party. nanoidp emits it when additional audiences are configured, so clients
  can test authorized-party validation.
* **RFC 9068 §2.2 (JWT access tokens):** the *access token* ``aud`` identifies the
  resource server (``settings.audience``), NOT the client. It is therefore left
  unchanged by this contract — see :class:`TestAccessTokenAudienceUnchanged`.

Additional audiences for a client are configured via the new
``OAuthClient.additional_audiences`` field, which is what makes the ``aud`` an
array (the issue asks to be able to test the array form).
"""

import jwt as pyjwt
import pytest

from nanoidp.config import OAuthClient, User, get_config
from nanoidp.services.token import get_token_service


def _decode(token: str) -> dict:
    """Decode a JWT without signature verification (claims inspection only)."""
    return pyjwt.decode(token, options={"verify_signature": False})


@pytest.fixture
def token_service(app):
    """Token service bound to the active (file-backed) config singleton."""
    with app.app_context():
        get_config()  # ensure the config singleton is initialised first
        return get_token_service()


@pytest.fixture
def basic_user():
    return User(
        username="alice",
        password="x",
        email="alice@example.org",
        roles=["USER"],
        tenant="default",
    )


def _register_client(token_service, client_id, additional_audiences=None):
    """(Re)register a client on the active config, optionally with extra audiences.

    Mutates the very config instance the token service uses so the lookup in
    ``create_token`` observes the change.
    """
    settings = token_service.config.settings
    settings.clients = [c for c in settings.clients if c.client_id != client_id]
    settings.clients.append(
        OAuthClient(
            client_id=client_id,
            client_secret="secret",
            additional_audiences=additional_audiences or [],
        )
    )


class TestIdTokenAudience:
    """The ID Token ``aud`` MUST be the requesting client's ``client_id``."""

    @pytest.mark.parametrize("client_id", ["demo-client", "test-client"])
    def test_aud_is_client_id_single_string(self, token_service, basic_user, app, client_id):
        """Single audience → ``aud`` is the ``client_id`` as a plain string."""
        with app.app_context():
            result = token_service.create_token(
                basic_user, scope="openid", client_id=client_id
            )
        claims = _decode(result["id_token"])
        assert claims["aud"] == client_id
        assert isinstance(claims["aud"], str)

    @pytest.mark.parametrize("client_id", ["demo-client", "test-client"])
    def test_no_azp_when_single_audience(self, token_service, basic_user, app, client_id):
        """``azp`` is omitted when there is exactly one audience."""
        with app.app_context():
            result = token_service.create_token(
                basic_user, scope="openid", client_id=client_id
            )
        claims = _decode(result["id_token"])
        assert "azp" not in claims

    @pytest.mark.parametrize(
        "extras,expected_aud",
        [
            ([], "demo-client"),
            (["https://api.example.com"], ["demo-client", "https://api.example.com"]),
            (
                ["https://api.example.com", "urn:service:billing"],
                ["demo-client", "https://api.example.com", "urn:service:billing"],
            ),
        ],
        ids=["none", "one-extra", "two-extras"],
    )
    def test_aud_composition(self, token_service, basic_user, app, extras, expected_aud):
        """No extras → string; one or more extras → array led by ``client_id``."""
        with app.app_context():
            _register_client(token_service, "demo-client", extras)
            result = token_service.create_token(
                basic_user, scope="openid", client_id="demo-client"
            )
        claims = _decode(result["id_token"])
        assert claims["aud"] == expected_aud

    @pytest.mark.parametrize(
        "extras,is_array",
        [
            ([], False),
            (["https://api.example.com"], True),
            (["a", "b"], True),
        ],
        ids=["single", "array-1", "array-2"],
    )
    def test_azp_present_only_for_array_aud(self, token_service, basic_user, app, extras, is_array):
        """nanoidp emits ``azp`` (== ``client_id``) exactly when ``aud`` is an array."""
        with app.app_context():
            _register_client(token_service, "demo-client", extras)
            result = token_service.create_token(
                basic_user, scope="openid", client_id="demo-client"
            )
        claims = _decode(result["id_token"])
        if is_array:
            assert claims["azp"] == "demo-client"
        else:
            assert "azp" not in claims

    @pytest.mark.parametrize(
        "extras",
        [
            ["demo-client"],
            ["demo-client", "https://api.example.com"],
            ["https://api.example.com", "demo-client"],
        ],
        ids=["only-self", "self-first", "self-last"],
    )
    def test_client_id_not_duplicated(self, token_service, basic_user, app, extras):
        """``client_id`` appears exactly once even if also listed in extras."""
        with app.app_context():
            _register_client(token_service, "demo-client", extras)
            result = token_service.create_token(
                basic_user, scope="openid", client_id="demo-client"
            )
        aud = _decode(result["id_token"])["aud"]
        aud_list = [aud] if isinstance(aud, str) else aud
        assert aud_list.count("demo-client") == 1
        assert aud_list[0] == "demo-client"  # client_id is always listed first

    def test_aud_falls_back_to_settings_audience_without_client_id(
        self, token_service, basic_user, app
    ):
        """Safety: with no client context, ``aud`` falls back to settings.audience."""
        with app.app_context():
            result = token_service.create_token(basic_user, scope="openid", client_id=None)
            expected = token_service.config.settings.audience
        claims = _decode(result["id_token"])
        assert claims["aud"] == expected

    def test_id_token_still_carries_nonce(self, token_service, basic_user, app):
        """Regression: changing ``aud`` must not drop the ``nonce`` claim."""
        with app.app_context():
            result = token_service.create_token(
                basic_user, scope="openid", client_id="demo-client", nonce="n-123"
            )
        assert _decode(result["id_token"])["nonce"] == "n-123"

    @pytest.mark.parametrize("scope", [None, "profile", "email profile"])
    def test_no_id_token_without_openid_scope(self, token_service, basic_user, app, scope):
        """No ``openid`` scope → no ID Token is issued (unchanged behaviour)."""
        with app.app_context():
            result = token_service.create_token(
                basic_user, scope=scope, client_id="demo-client"
            )
        assert "id_token" not in result


class TestAccessTokenAudienceUnchanged:
    """Access/refresh token ``aud`` stays the resource audience (RFC 9068)."""

    @pytest.mark.parametrize("token_key", ["access_token", "refresh_token"])
    @pytest.mark.parametrize("client_id", ["demo-client", "test-client"])
    def test_aud_is_settings_audience_not_client_id(
        self, token_service, basic_user, app, token_key, client_id
    ):
        with app.app_context():
            result = token_service.create_token(
                basic_user, scope="openid", client_id=client_id
            )
            settings_audience = token_service.config.settings.audience
        aud = _decode(result[token_key])["aud"]
        assert aud == settings_audience
        assert aud != client_id


class TestIdTokenAudienceIntegration:
    """End-to-end: client_id threads through the authorization_code flow into aud."""

    def _exchange(self, client, auth_header, client_id):
        client.get(
            f"/authorize?response_type=code&client_id={client_id}"
            "&redirect_uri=http://localhost:3000/callback&scope=openid"
        )
        resp = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )
        code = resp.headers["Location"].split("code=")[1].split("&")[0]
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost:3000/callback",
            },
            headers=auth_header,
        )
        import json

        return json.loads(resp.data)

    def test_auth_code_flow_id_token_aud_is_client_id(self, client, auth_header):
        data = self._exchange(client, auth_header, "demo-client")
        claims = _decode(data["id_token"])
        assert claims["aud"] == "demo-client"
        assert "azp" not in claims
