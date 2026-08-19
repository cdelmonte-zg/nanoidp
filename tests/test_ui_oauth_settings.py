"""
UI parity for the OAuth toggles (issue #94): require_pkce (#47) and
refresh_token_rotation (#46) are settable from the settings page, like the
SAML section always was.
"""

from nanoidp.config import get_config


def _base_form(settings) -> dict:
    """Mimic the full settings page form (#131): the real form always carries a
    hidden ``__on_form`` marker per checkbox (so "unchecked" is distinguishable
    from "not on this form") and renders every text field, blank when unset.
    A checkbox absent from this dict therefore means "rendered but unchecked",
    while a truly partial form (no markers) must leave settings unchanged."""
    return {
        "issuer": settings.issuer,
        "audience": settings.audience,
        "token_expiry_minutes": settings.token_expiry_minutes,
        "issuer_allowlist": "\n".join(settings.issuer_allowlist),
        "device_verification_base_url": settings.device_verification_base_url or "",
        "saml_entity_id": settings.saml_entity_id,
        "saml_sso_url": settings.saml_sso_url,
        "default_acs_url": settings.default_acs_url,
        "saml_sign_responses": "true",
        "allowed_identity_classes": "INTERNAL\nEXTERNAL",
        "issuer_from_request__on_form": "1",
        "issuer_from_proxy_headers__on_form": "1",
        "require_pkce__on_form": "1",
        "refresh_token_rotation__on_form": "1",
        "saml_sign_responses__on_form": "1",
        "strict_saml_binding__on_form": "1",
        "saml_want_authn_requests_signed__on_form": "1",
        "saml_export_roles__on_form": "1",
        "saml_export_groups__on_form": "1",
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
            # Present but blank means clear; absent would mean unchanged (#131).
            data={**_base_form(config.settings), "issuer_allowlist": ""},
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
            # Present but blank means clear; absent would mean unchanged (#131).
            data={**_base_form(config.settings), "device_verification_base_url": ""},
            follow_redirects=True,
        )
        assert response.status_code == 200
        config.reload()
        assert config.settings.device_verification_base_url is None


class TestIssuerFromProxyHeadersRoundTrip:
    def test_toggle_enables_and_persists(self, client, preserve_config_files):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        config = get_config()

        response = client.post(
            "/settings",
            data={**_base_form(config.settings), "issuer_from_proxy_headers": "true"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        config.reload()
        assert config.settings.issuer_from_proxy_headers is True

    def test_unchecked_toggle_disables(self, client, preserve_config_files):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        config = get_config()
        config.settings.issuer_from_proxy_headers = True

        response = client.post(
            "/settings",
            data=_base_form(config.settings),  # issuer_from_proxy_headers absent
            follow_redirects=True,
        )
        assert response.status_code == 200
        config.reload()
        assert config.settings.issuer_from_proxy_headers is False

    def test_settings_page_renders_the_toggle(self, client):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        r = client.get("/settings")
        assert r.status_code == 200
        assert b'name="issuer_from_proxy_headers"' in r.data


class TestPartialFormLeavesSettingsUnchanged:
    """#131: a form that does not carry a field must not reset it.

    Reproduces the wipe observed live: the e2e agent's "SAML Exclusive C14N"
    test posts only the fields it knows about, and before the fix that
    round-trip flipped every absent checkbox to false and cleared every absent
    text field (allowlist, device URL, attribute names, expiry)."""

    def test_c14n_style_partial_form_does_not_wipe_other_settings(
        self, client, preserve_config_files
    ):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        config = get_config()

        # Arrange: enable a representative spread of settings via the full form
        response = client.post(
            "/settings",
            data={
                **_base_form(config.settings),
                "issuer_from_request": "true",
                "issuer_allowlist": "http://localhost:8000\nhttp://nanoidp:9900",
                "device_verification_base_url": "https://idp.example.com",
                "saml_export_roles": "true",
                "saml_roles_attr_name": "memberRoles",
                "token_expiry_minutes": "120",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

        # Act: the e2e agent's C14N form shape - no markers, none of the
        # fields enabled above
        response = client.post(
            "/settings",
            data={
                "issuer": config.settings.issuer,
                "audience": config.settings.audience,
                "saml_entity_id": config.settings.saml_entity_id,
                "saml_sso_url": config.settings.saml_sso_url,
                "default_acs_url": config.settings.default_acs_url,
                "saml_sign_responses": "true",
                "strict_saml_binding": "",
                "saml_c14n_algorithm": "exc_c14n",
                "allowed_identity_classes": "INTERNAL\nEXTERNAL",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

        # Assert: everything the partial form did not carry is unchanged...
        config.reload()
        assert config.settings.issuer_from_request is True
        assert config.settings.issuer_allowlist == [
            "http://localhost:8000",
            "http://nanoidp:9900",
        ]
        assert config.settings.device_verification_base_url == "https://idp.example.com"
        assert config.settings.saml_export_roles is True
        assert config.settings.saml_roles_attr_name == "memberRoles"
        assert config.settings.token_expiry_minutes == 120
        # ...while the fields it did carry took effect
        assert config.settings.saml_c14n_algorithm == "exc_c14n"
        assert config.settings.saml_sign_responses is True
