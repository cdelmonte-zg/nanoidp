"""
UI parity for the OAuth toggles (issue #94): require_pkce (#47) and
refresh_token_rotation (#46) are settable from the settings page, like the
SAML section always was.
"""

from nanoidp.config import get_config


def _base_form(settings) -> dict:
    return {
        "issuer": settings.issuer,
        "audience": settings.audience,
        "token_expiry_minutes": settings.token_expiry_minutes,
        "saml_entity_id": settings.saml_entity_id,
        "saml_sso_url": settings.saml_sso_url,
        "default_acs_url": settings.default_acs_url,
        "saml_sign_responses": "true",
        "allowed_identity_classes": "INTERNAL\nEXTERNAL",
    }


class TestOAuthTogglesRoundTrip:
    def test_toggles_enable_and_persist(self, client, preserve_config_files):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        config = get_config()

        response = client.post(
            "/settings",
            data={
                **_base_form(config.settings),
                "require_pkce": "true",
                "refresh_token_rotation": "true",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        config.reload()
        assert config.settings.require_pkce is True
        assert config.settings.refresh_token_rotation is True

    def test_unchecked_toggles_disable(self, client, preserve_config_files):
        """Checkbox semantics: an absent field means off, and off is
        persisted (not skipped)."""
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        config = get_config()
        config.settings.require_pkce = True
        config.settings.refresh_token_rotation = True

        response = client.post(
            "/settings",
            data=_base_form(config.settings),  # both toggles absent
            follow_redirects=True,
        )
        assert response.status_code == 200
        config.reload()
        assert config.settings.require_pkce is False
        assert config.settings.refresh_token_rotation is False


class TestIssuerAllowlistRoundTrip:
    def test_allowlist_persists_as_a_list(self, client, preserve_config_files):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        config = get_config()

        response = client.post(
            "/settings",
            data={
                **_base_form(config.settings),
                "issuer_allowlist": "http://localhost:8000\nhttp://nanoidp:9900",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        config.reload()
        assert config.settings.issuer_allowlist == [
            "http://localhost:8000",
            "http://nanoidp:9900",
        ]

    def test_blank_allowlist_clears_it(self, client, preserve_config_files):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        config = get_config()
        config.settings.issuer_allowlist = ["http://nanoidp:9900"]

        response = client.post(
            "/settings",
            data=_base_form(config.settings),  # issuer_allowlist absent
            follow_redirects=True,
        )
        assert response.status_code == 200
        config.reload()
        assert config.settings.issuer_allowlist == []

    def test_settings_page_renders_the_toggles(self, client):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        r = client.get("/settings")
        assert r.status_code == 200
        assert b'name="require_pkce"' in r.data
        assert b'name="refresh_token_rotation"' in r.data


class TestDeviceVerificationBaseUrlRoundTrip:
    def test_value_persists(self, client, preserve_config_files):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        config = get_config()

        response = client.post(
            "/settings",
            data={
                **_base_form(config.settings),
                "device_verification_base_url": "https://idp.example.com",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        config.reload()
        assert config.settings.device_verification_base_url == "https://idp.example.com"

    def test_blank_value_clears_it(self, client, preserve_config_files):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        config = get_config()
        config.settings.device_verification_base_url = "https://idp.example.com"

        response = client.post(
            "/settings",
            data=_base_form(config.settings),  # device_verification_base_url absent
            follow_redirects=True,
        )
        assert response.status_code == 200
        config.reload()
        assert config.settings.device_verification_base_url is None
