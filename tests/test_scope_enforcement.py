"""
Tests for per-client allowed scopes and invalid_scope enforcement (issue #186).

Before this, /authorize and /token accepted any scope string unchecked: a
client could obtain 'admin' just by asking. oauth.scopes_supported is the
global vocabulary; OAuthClient.allowed_scopes is an optional per-client
subset of it. A requested scope outside the vocabulary is invalid_scope for
every client; outside a client's own allowed_scopes (when set) it is
invalid_scope for that client specifically. scope_enforcement (dev-only) is
the escape hatch back to the old, unchecked behavior.

The shipped config/settings.yaml carries a 'scoped-client' restricted to
['openid', 'profile'] and the pre-existing 'demo-client' (unrestricted),
used throughout via the `client`/`app` fixtures (isolated_repo_config copies
config/ per test, so mutating either client's YAML entry never touches the
real one).
"""

import base64
import json

import pytest
from pydantic import ValidationError

from nanoidp.config import ConfigManager, OAuthClient, Settings, get_config
from nanoidp.services.discovery import build_discovery_document
from nanoidp.services.scope import resolve_scope
from tests.conftest import authorize_error


def _basic_auth(client_id: str, secret: str) -> dict:
    credentials = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


SCOPED_AUTH = _basic_auth("scoped-client", "scoped-secret")


class TestOAuthClientAllowedScopes:
    def test_default_is_empty_unrestricted(self):
        assert OAuthClient(client_id="c", client_secret="s").allowed_scopes == []

    def test_explicit_list_is_kept(self):
        client = OAuthClient(client_id="c", client_secret="s", allowed_scopes=["openid", "profile"])
        assert client.allowed_scopes == ["openid", "profile"]


class TestSettingsScopeFields:
    def test_scopes_supported_default(self):
        assert Settings().scopes_supported == ["openid", "profile", "email", "offline_access"]

    def test_scope_enforcement_default_on(self):
        assert Settings().scope_enforcement_active is True

    def test_scope_enforcement_off_in_dev(self):
        s = Settings(security_profile="dev", scope_enforcement=False)
        assert s.scope_enforcement_active is False

    def test_scope_enforcement_off_forced_on_under_stricter_dev(self):
        """The raw flag can say off, but stricter-dev/oauth21 always enforce -
        the same 'raw field OR profile decides' shape as pkce_required, just
        force-ENABLING instead of force-relaxing."""
        s = Settings(security_profile="stricter-dev", scope_enforcement=False)
        assert s.scope_enforcement_active is True

    def test_scope_enforcement_off_forced_on_under_oauth21(self):
        s = Settings(security_profile="oauth21", scope_enforcement=False)
        assert s.scope_enforcement_active is True

    def test_unknown_security_profile_still_rejected(self):
        """Sanity: adding scope_enforcement_active didn't disturb the existing validator."""
        with pytest.raises(ValidationError):
            Settings(security_profile="not-a-profile")


class TestResolveScopeHelper:
    """Direct unit tests of services.scope.resolve_scope - the shared logic
    behind every /authorize, /token and /device_authorization check."""

    VOCAB = ["openid", "profile", "email"]

    def _client(self, allowed=None):
        return OAuthClient(client_id="c", client_secret="s", allowed_scopes=allowed or [])

    def test_enforcement_off_passes_anything_through(self):
        result = resolve_scope("admin nonsense", self._client(), self.VOCAB, False)
        assert result.ok
        assert result.granted == "admin nonsense"

    def test_enforcement_off_ignores_allowed_scopes_even_when_set(self):
        result = resolve_scope("admin", self._client(["openid"]), self.VOCAB, False)
        assert result.ok
        assert result.granted == "admin"

    def test_enforcement_off_omitted_uses_default(self):
        result = resolve_scope(None, self._client(), self.VOCAB, False, default_when_omitted="openid")
        assert result.granted == "openid"

    def test_unrestricted_client_any_vocabulary_scope_allowed(self):
        result = resolve_scope("openid email", self._client(), self.VOCAB, True)
        assert result.ok
        assert result.granted == "openid email"

    def test_scope_outside_global_vocabulary_rejected_for_every_client(self):
        result = resolve_scope("admin", self._client(), self.VOCAB, True)
        assert not result.ok
        assert "admin" in result.error_description
        assert result.granted is None

    def test_scope_outside_global_vocabulary_rejected_even_when_client_allows_it(self):
        """A client's own allow-list can never widen the global vocabulary."""
        result = resolve_scope("admin", self._client(["admin"]), self.VOCAB, True)
        assert not result.ok

    def test_scope_outside_client_allowed_scopes_rejected(self):
        result = resolve_scope("email", self._client(["openid"]), self.VOCAB, True)
        assert not result.ok
        assert "email" in result.error_description

    def test_scope_within_client_allowed_scopes_accepted(self):
        result = resolve_scope("openid", self._client(["openid", "profile"]), self.VOCAB, True)
        assert result.ok
        assert result.granted == "openid"

    def test_omitted_scope_restricted_client_defaults_to_full_allowed_set(self):
        result = resolve_scope(None, self._client(["openid", "profile"]), self.VOCAB, True)
        assert result.ok
        assert result.granted == "openid profile"

    def test_omitted_scope_unrestricted_client_uses_default_when_omitted(self):
        result = resolve_scope(None, self._client(), self.VOCAB, True, default_when_omitted="openid")
        assert result.ok
        assert result.granted == "openid"

    def test_omitted_scope_unrestricted_client_no_default_is_none(self):
        result = resolve_scope(None, self._client(), self.VOCAB, True)
        assert result.ok
        assert result.granted is None

    def test_validate_only_does_not_default_omitted_scope_for_restricted_client(self):
        """#186 review B1: at a RE-check (refresh, auth-code redemption), an
        absent original scope must stay absent, never widened to the
        client's current allowed_scopes."""
        result = resolve_scope(None, self._client(["openid", "profile"]), self.VOCAB, True, validate_only=True)
        assert result.ok
        assert result.granted is None

    def test_validate_only_ignores_default_when_omitted_too(self):
        result = resolve_scope(
            None, self._client(), self.VOCAB, True,
            default_when_omitted="openid", validate_only=True,
        )
        assert result.ok
        assert result.granted is None

    def test_validate_only_still_validates_a_present_scope(self):
        result = resolve_scope("email", self._client(["openid"]), self.VOCAB, True, validate_only=True)
        assert not result.ok

    def test_validate_only_accepts_a_present_allowed_scope(self):
        result = resolve_scope("openid", self._client(["openid"]), self.VOCAB, True, validate_only=True)
        assert result.ok
        assert result.granted == "openid"

    def test_validate_only_enforcement_off_passes_through(self):
        result = resolve_scope(None, self._client(["openid"]), self.VOCAB, False, validate_only=True)
        assert result.ok
        assert result.granted is None


class TestDiscoveryScopesSupported:
    def test_reflects_settings(self):
        settings = Settings(scopes_supported=["openid", "custom"])
        doc = build_discovery_document(settings)
        assert doc["scopes_supported"] == ["openid", "custom"]

    def test_default_matches_prior_hardcoded_list(self):
        doc = build_discovery_document(Settings())
        assert doc["scopes_supported"] == ["openid", "profile", "email", "offline_access"]


class TestYamlLoadAllowedScopes:
    def test_scoped_client_loads_from_shipped_config(self, app):
        with app.app_context():
            client = get_config().get_client("scoped-client")
        assert client is not None
        assert client.allowed_scopes == ["openid", "profile"]

    def test_scalar_allowed_scopes_coerced_to_list(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.yaml").write_text(
            'oauth:\n'
            '  issuer: "http://localhost:8000"\n'
            '  audience: "my-app"\n'
            '  clients:\n'
            '    - client_id: "c1"\n'
            '      client_secret: "s1"\n'
            '      allowed_scopes: "openid"\n'
        )
        (config_dir / "users.yaml").write_text(
            'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
        )
        config = ConfigManager(str(config_dir))
        assert config.get_client("c1").allowed_scopes == ["openid"]


class TestAuthorizeScopeEnforcement:
    REGISTERED_URI = "http://localhost:3000/callback"

    def _authorize(self, client, client_id, **extra):
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": self.REGISTERED_URI,
            **extra,
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return client.get(f"/authorize?{query}")

    def test_disallowed_scope_is_invalid_scope(self, client):
        response = self._authorize(client, "scoped-client", scope="email")
        assert response.status_code == 302
        assert authorize_error(response)["error"] == "invalid_scope"

    def test_allowed_scope_gets_login_page(self, client):
        response = self._authorize(client, "scoped-client", scope="openid")
        assert response.status_code == 200

    def test_unrestricted_client_any_vocabulary_scope_allowed(self, client):
        response = self._authorize(client, "demo-client", scope="offline_access")
        assert response.status_code == 200

    def test_scope_outside_global_vocabulary_rejected_for_unrestricted_client(self, client):
        response = self._authorize(client, "demo-client", scope="admin")
        assert response.status_code == 302
        assert authorize_error(response)["error"] == "invalid_scope"

    def test_omitted_scope_on_restricted_client_defaults_to_full_allowed_set(self, client):
        """No 'scope' param at all - a bare login page, not an error."""
        response = client.get(
            f"/authorize?response_type=code&client_id=scoped-client"
            f"&redirect_uri={self.REGISTERED_URI}"
        )
        assert response.status_code == 200


class TestTokenScopeEnforcement:
    def test_client_credentials_disallowed_scope_rejected(self, client):
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials", "scope": "email"},
            headers=SCOPED_AUTH,
        )
        assert response.status_code == 400
        assert json.loads(response.data)["error"] == "invalid_scope"

    def test_client_credentials_allowed_scope_accepted(self, client):
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials", "scope": "profile"},
            headers=SCOPED_AUTH,
        )
        assert response.status_code == 200
        assert json.loads(response.data)["scope"] == "profile"

    def test_client_credentials_unrestricted_client_vocabulary_scope_accepted(self, client, auth_header):
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials", "scope": "email"},
            headers=auth_header,
        )
        assert response.status_code == 200
        assert json.loads(response.data)["scope"] == "email"

    def test_client_credentials_scope_outside_vocabulary_rejected(self, client, auth_header):
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials", "scope": "admin"},
            headers=auth_header,
        )
        assert response.status_code == 400
        assert json.loads(response.data)["error"] == "invalid_scope"

    def test_password_grant_disallowed_scope_rejected(self, client):
        response = client.post(
            "/token",
            data={
                "grant_type": "password",
                "username": "admin",
                "password": "admin",
                "scope": "email",
            },
            headers=SCOPED_AUTH,
        )
        assert response.status_code == 400
        assert json.loads(response.data)["error"] == "invalid_scope"

    def test_password_grant_allowed_scope_accepted(self, client):
        response = client.post(
            "/token",
            data={
                "grant_type": "password",
                "username": "admin",
                "password": "admin",
                "scope": "openid profile",
            },
            headers=SCOPED_AUTH,
        )
        assert response.status_code == 200
        assert json.loads(response.data)["scope"] == "openid profile"


class TestDeviceAuthorizationScopeEnforcement:
    def test_disallowed_scope_rejected(self, client):
        response = client.post(
            "/device_authorization",
            data={"scope": "email"},
            headers=SCOPED_AUTH,
        )
        assert response.status_code == 400
        assert json.loads(response.data)["error"] == "invalid_scope"

    def test_allowed_scope_accepted(self, client):
        response = client.post(
            "/device_authorization",
            data={"scope": "profile"},
            headers=SCOPED_AUTH,
        )
        assert response.status_code == 200
        assert "device_code" in json.loads(response.data)


class TestDeviceCodeRedemptionScopeReValidation:
    """#276: the device grant redeems a prior authorization exactly like
    authorization_code and refresh do, so it must re-validate the stored
    scope against the CURRENT vocabulary/allowed_scopes at the poll - both
    may have changed between /device_authorization and redemption."""

    @pytest.fixture(autouse=True)
    def _cleanup_device_codes(self):
        yield
        from nanoidp.services.device_code import get_device_code_store

        get_device_code_store().clear()

    def _device_flow_authorized(self, client, scope):
        resp = client.post(
            "/device_authorization", data={"scope": scope}, headers=SCOPED_AUTH
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        authorize = client.post(
            "/device",
            data={
                "user_code": data["user_code"],
                "username": "admin",
                "password": "admin",
                "action": "authorize",
            },
        )
        assert authorize.status_code == 200
        return data["device_code"]

    def _poll(self, client, device_code):
        return client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            },
            headers=SCOPED_AUTH,
        )

    def test_scope_still_allowed_redeems_with_it(self, client):
        device_code = self._device_flow_authorized(client, "openid profile")
        resp = self._poll(client, device_code)
        assert resp.status_code == 200
        assert json.loads(resp.data)["scope"] == "openid profile"

    def test_scope_revoked_between_authorization_and_poll_is_rejected(self, client, app):
        """The grant was valid when authorized; allowed_scopes shrank since
        (an operator edit) - the poll must catch it, same as the refresh
        grant's re-check does."""
        device_code = self._device_flow_authorized(client, "openid profile")

        with app.app_context():
            get_config().get_client("scoped-client").allowed_scopes = ["openid"]

        resp = self._poll(client, device_code)
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert data["error"] == "invalid_scope"
        assert "profile" in data["error_description"]


class TestClientCredentialsOpenidNeverMintsIdToken:
    """#186 review: create_token()'s ID Token issuance is grant-agnostic
    (any grant with 'openid' in scope gets one), but client_credentials has
    no end-user context. 'openid' is accepted (it's vocabulary-listed) but
    silently dropped from what's actually granted, preserving this grant's
    pre-#186 behavior (see tests/test_id_token_grants.py)."""

    def test_openid_accepted_but_no_id_token(self, client, auth_header):
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials", "scope": "openid"},
            headers=auth_header,
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "id_token" not in data

    def test_openid_stripped_but_siblings_kept(self, client, auth_header):
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials", "scope": "openid profile"},
            headers=auth_header,
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "id_token" not in data
        assert data["scope"] == "profile"


class TestScopeEnforcementOffEscapeHatch:
    """oauth.scope_enforcement: false (dev-only) restores pre-#186 behavior:
    any scope string is accepted, unchecked."""

    @pytest.fixture
    def enforcement_off(self, app):
        with app.app_context():
            settings = get_config().settings
            settings.scope_enforcement = False
        yield settings
        settings.scope_enforcement = True

    def test_previously_invalid_scope_now_accepted(self, client, enforcement_off, auth_header):
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials", "scope": "admin nonsense"},
            headers=auth_header,
        )
        assert response.status_code == 200
        assert json.loads(response.data)["scope"] == "admin nonsense"

    def test_restricted_client_allow_list_not_consulted(self, client, enforcement_off):
        """scoped-client's allowed_scopes (['openid', 'profile']) has no effect
        while enforcement is off - not even for defaulting an omitted scope."""
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials", "scope": "anything-goes"},
            headers=SCOPED_AUTH,
        )
        assert response.status_code == 200
        assert json.loads(response.data)["scope"] == "anything-goes"


class TestRefreshTokenScopeReValidation:
    """The refresh grant's own coverage (#186 review: previously untested).

    resolve_scope() is called twice on this path: the existing
    narrow-only-never-widen check (unchanged logic, now RFC-shaped errors),
    then a re-validation against the CURRENT vocabulary/allowed_scopes via
    validate_only=True (B1 fix) - an absent original scope must stay absent
    rather than being defaulted to the client's current allowed set.
    """

    def _password_grant(self, client, scope=None):
        data = {"grant_type": "password", "username": "admin", "password": "admin"}
        if scope is not None:
            data["scope"] = scope
        resp = client.post("/token", data=data, headers=SCOPED_AUTH)
        assert resp.status_code == 200
        return json.loads(resp.data)

    def test_legacy_no_scope_refresh_token_does_not_widen(self, client, app):
        """B1 repro: a refresh token minted with no scope at all (enforcement
        off at issuance - the pre-#186 world, or any token minted before
        allowed_scopes was set) must refresh to another no-scope token, not
        the client's current full allowed set - and must never mint an
        ID Token that the original (scopeless) grant never had."""
        with app.app_context():
            get_config().settings.scope_enforcement = False
        minted = self._password_grant(client)
        assert "scope" not in minted
        assert "id_token" not in minted
        refresh_token = minted["refresh_token"]

        with app.app_context():
            get_config().settings.scope_enforcement = True

        resp = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            headers=SCOPED_AUTH,
        )
        assert resp.status_code == 200
        refreshed = json.loads(resp.data)
        assert "scope" not in refreshed
        assert "id_token" not in refreshed

    def test_narrowing_rejection_is_rfc_shaped_invalid_scope(self, client):
        """The pre-#186 narrowing check ('exceeds originally granted scope')
        now answers with the RFC 6749 5.2 JSON error body, not a bare 400."""
        minted = self._password_grant(client, scope="openid")
        resp = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": minted["refresh_token"],
                "scope": "openid profile",
            },
            headers=SCOPED_AUTH,
        )
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert data["error"] == "invalid_scope"
        assert "error_description" in data

    def test_revalidation_rejects_scope_no_longer_allowed(self, client, app):
        """The original grant was valid at the time; allowed_scopes shrank
        since (an operator edit) - the re-check must catch it on refresh,
        even though the client didn't request anything new."""
        minted = self._password_grant(client, scope="openid")

        with app.app_context():
            get_config().get_client("scoped-client").allowed_scopes = ["profile"]

        resp = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": minted["refresh_token"]},
            headers=SCOPED_AUTH,
        )
        assert resp.status_code == 400
        assert json.loads(resp.data)["error"] == "invalid_scope"

    def test_revalidation_accepts_still_allowed_scope(self, client):
        """Sanity: the re-check doesn't reject a refresh that's still fine."""
        minted = self._password_grant(client, scope="openid")
        resp = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": minted["refresh_token"]},
            headers=SCOPED_AUTH,
        )
        assert resp.status_code == 200
        assert json.loads(resp.data)["scope"] == "openid"
