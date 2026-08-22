"""
Regression tests for #165: /api/config must expose every form-editable field.

The e2e agent rebuilds the /settings form from /api/config's document; a
field missing there gets posted blank, and the "present-but-blank = clear"
contract (#131) then wipes it from settings.yaml. That is exactly what
happened to saml.default_acs_url on every e2e run.
"""


class TestApiConfigSamlParity:
    def test_default_acs_url_exposed(self, client):
        """/api/config's saml section carries default_acs_url."""
        resp = client.get("/api/config")
        assert resp.status_code == 200
        saml = resp.get_json()["saml"]
        assert "default_acs_url" in saml

    def test_e2e_round_trip_preserves_default_acs_url(self, client, app):
        """Replaying the e2e agent's settings round-trip (form rebuilt from
        /api/config, posted back unchanged) must not clear default_acs_url."""
        from nanoidp.config import get_config

        with app.app_context():
            config = get_config()
            original = config.settings.default_acs_url
            assert original, "fixture config must define a default_acs_url"

        doc = client.get("/api/config").get_json()
        saml = doc["saml"]
        oauth = doc["oauth"]
        # The exact form the e2e agent's c14n test builds from /api/config.
        resp = client.post(
            "/settings",
            data={
                "issuer": oauth["issuer"],
                "audience": oauth["audience"],
                "token_expiry_minutes": oauth["token_expiry_minutes"],
                "saml_entity_id": saml["entity_id"],
                "saml_sso_url": saml["sso_url"],
                "default_acs_url": saml.get("default_acs_url", ""),
                "saml_sign_responses": "true" if saml["sign_responses"] else "",
                "strict_saml_binding": "true" if saml["strict_binding"] else "",
                "saml_c14n_algorithm": saml["c14n_algorithm"],
                "allowed_identity_classes": "\n".join(
                    doc["allowed_identity_classes"]
                ),
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert get_config().settings.default_acs_url == original
