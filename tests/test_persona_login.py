"""
Tests for persona login mode (passwordless interactive login, a local
dev/testing convenience) on the nanoidp dashboard's /login endpoint.

Off by default ('login_mode: password'); enabling it must not change
password-mode behavior at all - only 'persona' mode skips the credential
check and authenticates by identity selection instead (design contract
point 1/3, see docs/plans/persona-login-mode.md).
"""

import re

from nanoidp.config import User, get_config


def _password_field_is_required(html: bytes) -> bool:
    """Whether the '/users/create'|'/users/.../edit' password <input> tag
    carries the 'required' attribute, regardless of exact template whitespace.
    """
    match = re.search(rb'<input[^>]*id="password"[^>]*>', html)
    assert match, "password input not found in rendered form"
    return b"required" in match.group(0)


def _enable_persona_mode(app) -> None:
    with app.app_context():
        get_config().settings.login_mode = "persona"


class TestPasswordModeUnchanged:
    """Regression: default 'password' mode behaves exactly as before."""

    def test_login_page_shows_password_form(self, client):
        response = client.get("/login")

        assert response.status_code == 200
        assert b'name="password"' in response.data
        assert b"Persona login" not in response.data

    def test_valid_credentials_log_in(self, client):
        response = client.post("/login", data={"username": "admin", "password": "admin"})

        assert response.status_code == 302
        assert response.headers["Location"] == "/"
        with client.session_transaction() as sess:
            assert sess["user"] == "admin"

    def test_missing_password_rejected(self, client):
        response = client.post("/login", data={"username": "admin"})

        assert response.status_code == 302
        assert "error=" in response.headers["Location"]


class TestPersonaLoginPage:
    """GET /login in persona mode: a user picker, no password field."""

    def test_login_page_lists_users_no_password_field(self, app, client):
        _enable_persona_mode(app)

        response = client.get("/login")

        assert response.status_code == 200
        assert b"Persona login" in response.data
        assert b'name="password"' not in response.data
        assert b"admin" in response.data

    def test_login_page_shows_user_description(self, app, client):
        _enable_persona_mode(app)
        with app.app_context():
            config = get_config()
            config.users["finance-fred"] = User(
                username="finance-fred", description="Finance approver persona"
            )

        response = client.get("/login")

        assert response.status_code == 200
        assert b"Finance approver persona" in response.data

    def test_login_page_omits_description_block_when_blank(self, app, client):
        """A user with no description doesn't leave an empty <small> tag."""
        _enable_persona_mode(app)

        response = client.get("/login")

        assert response.status_code == 200
        # admin has no description in the test fixture; the button around it
        # renders without a description <small> block.
        match = re.search(rb'value="admin"[^>]*>.*?</button>', response.data, re.S)
        assert match, "admin's picker button not found"
        assert b"text-muted d-block" not in match.group(0)


class TestPersonaLoginPost:
    """POST /login in persona mode: identity selection, no credential check."""

    def test_selecting_a_user_logs_in(self, app, client):
        _enable_persona_mode(app)

        response = client.post("/login", data={"username": "admin"})

        assert response.status_code == 302
        assert response.headers["Location"] == "/"
        with client.session_transaction() as sess:
            assert sess["user"] == "admin"

    def test_password_is_ignored_even_if_supplied(self, app, client):
        """Persona mode never checks a password, even a wrong one posted anyway."""
        _enable_persona_mode(app)

        response = client.post("/login", data={"username": "admin", "password": "wrong"})

        assert response.status_code == 302
        assert response.headers["Location"] == "/"

    def test_missing_username_rejected(self, app, client):
        _enable_persona_mode(app)

        response = client.post("/login", data={})

        assert response.status_code == 302
        assert "error=" in response.headers["Location"]
        with client.session_transaction() as sess:
            assert "user" not in sess

    def test_nonexistent_user_rejected(self, app, client):
        _enable_persona_mode(app)

        response = client.post("/login", data={"username": "nonexistent"})

        assert response.status_code == 302
        assert "error=" in response.headers["Location"]
        with client.session_transaction() as sess:
            assert "user" not in sess

    def test_passwordless_user_can_log_in(self, app, client):
        """The whole point of the feature: a user with no password authenticates."""
        with app.app_context():
            config = get_config()
            config.settings.login_mode = "persona"
            config.users["persona-bob"] = User(username="persona-bob")

        response = client.post("/login", data={"username": "persona-bob"})

        assert response.status_code == 302
        with client.session_transaction() as sess:
            assert sess["user"] == "persona-bob"


class TestUserCreatePasswordOptional:
    """The '/users/create' admin UI form only relaxes the password
    requirement in persona mode - a password-less user in the default
    'password' mode would just be an unusable, confusing dead-end account,
    so that mode must keep requiring a password exactly as before."""

    def _login_as_admin(self, client) -> None:
        with client.session_transaction() as sess:
            sess["user"] = "admin"

    def test_password_mode_still_requires_a_password_on_the_form(self, client):
        """Regression: default mode's password field stays required."""
        self._login_as_admin(client)

        response = client.get("/users/create")

        assert response.status_code == 200
        assert _password_field_is_required(response.data) is True

    def test_password_mode_rejects_blank_password(self, client, preserve_config_files):
        """Regression: default mode still refuses to create a password-less user."""
        self._login_as_admin(client)

        response = client.post(
            "/users/create",
            data={"username": "should-not-exist", "email": "x@example.org"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert get_config().get_user("should-not-exist") is None

    def test_password_mode_create_with_password_still_works(self, client, preserve_config_files):
        """Regression: supplying a password still creates a normal user."""
        self._login_as_admin(client)

        client.post(
            "/users/create",
            data={"username": "regular-erin", "password": "secret", "email": "erin@example.org"},
            follow_redirects=True,
        )

        assert get_config().get_user("regular-erin").password == "secret"

    def test_password_with_meaningful_whitespace_stored_verbatim(self, client, preserve_config_files):
        """Regression: a password like ' secret ' must not be silently
        trimmed to 'secret' - that would desync the stored hash/plaintext
        from what the user actually typed and later fails authenticate()."""
        self._login_as_admin(client)

        client.post(
            "/users/create",
            data={"username": "regular-frank", "password": " secret ", "email": "frank@example.org"},
            follow_redirects=True,
        )

        assert get_config().get_user("regular-frank").password == " secret "

    def test_whitespace_only_password_rejected_in_password_mode(self, client, preserve_config_files):
        """Regression: a whitespace-only password must still be treated as
        'no password supplied' (Password is required), not stored verbatim."""
        self._login_as_admin(client)

        response = client.post(
            "/users/create",
            data={"username": "should-not-exist-2", "password": "   ", "email": "x@example.org"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert get_config().get_user("should-not-exist-2") is None

    def test_persona_mode_form_password_field_not_required(self, app, client):
        _enable_persona_mode(app)
        self._login_as_admin(client)

        response = client.get("/users/create")

        assert response.status_code == 200
        assert b'name="password"' in response.data
        assert _password_field_is_required(response.data) is False

    def test_persona_mode_create_user_without_password_succeeds(self, app, client, preserve_config_files):
        _enable_persona_mode(app)
        self._login_as_admin(client)

        response = client.post(
            "/users/create",
            data={"username": "persona-charlie", "email": "charlie@example.org"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        user = get_config().get_user("persona-charlie")
        assert user is not None
        assert user.password is None

    def test_persona_mode_create_user_with_blank_password_is_password_none(self, app, client, preserve_config_files):
        _enable_persona_mode(app)
        self._login_as_admin(client)

        client.post(
            "/users/create",
            data={"username": "persona-dana", "password": "   ", "email": "dana@example.org"},
            follow_redirects=True,
        )

        assert get_config().get_user("persona-dana").password is None

    def test_persona_mode_create_user_with_description_succeeds(self, app, client, preserve_config_files):
        _enable_persona_mode(app)
        self._login_as_admin(client)

        client.post(
            "/users/create",
            data={
                "username": "persona-edith",
                "email": "edith@example.org",
                "description": "Finance approver persona",
            },
            follow_redirects=True,
        )

        user = get_config().get_user("persona-edith")
        assert user is not None
        assert user.description == "Finance approver persona"

    def test_user_form_renders_description_field(self, client, preserve_config_files):
        self._login_as_admin(client)

        response = client.get("/users/create")

        assert response.status_code == 200
        assert b'name="description"' in response.data
        assert b'maxlength="200"' in response.data

    def test_persona_mode_create_with_password_still_works(self, app, client, preserve_config_files):
        """Persona mode never forces a password to be blank either."""
        _enable_persona_mode(app)
        self._login_as_admin(client)

        client.post(
            "/users/create",
            data={"username": "regular-frank", "password": "secret", "email": "frank@example.org"},
            follow_redirects=True,
        )

        assert get_config().get_user("regular-frank").password == "secret"


class TestSettingsUiLoginMode:
    """The '/settings' dashboard page persists 'login_mode' via a select
    field, following the same omit-at-default convention as security_profile."""

    def _login_as_admin(self, client) -> None:
        with client.session_transaction() as sess:
            sess["user"] = "admin"

    def _base_form(self, settings) -> dict:
        """Minimal settings form: every other field is 'absent = unchanged'
        (#131) for text/select fields, so only fields relevant to this test
        need to be included."""
        return {
            "issuer": settings.issuer,
            "audience": settings.audience,
            "token_expiry_minutes": settings.token_expiry_minutes,
            "saml_entity_id": settings.saml_entity_id,
            "saml_sso_url": settings.saml_sso_url,
            "default_acs_url": settings.default_acs_url,
            "allowed_identity_classes": "",
        }

    def test_settings_page_shows_login_mode_select(self, client):
        self._login_as_admin(client)

        response = client.get("/settings")

        assert response.status_code == 200
        assert b'name="login_mode"' in response.data
        assert b'value="persona"' in response.data

    def test_switching_to_persona_persists(self, client, preserve_config_files):
        self._login_as_admin(client)
        config = get_config()

        response = client.post(
            "/settings",
            data={**self._base_form(config.settings), "login_mode": "persona"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        config.reload()
        assert config.settings.login_mode == "persona"
        assert config.settings.persona_mode_enabled is True

    def test_switching_back_to_password_persists_and_omits_section(self, client, preserve_config_files):
        self._login_as_admin(client)
        config = get_config()
        client.post(
            "/settings",
            data={**self._base_form(config.settings), "login_mode": "persona"},
            follow_redirects=True,
        )

        response = client.post(
            "/settings",
            data={**self._base_form(config.settings), "login_mode": "password"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        config.reload()
        assert config.settings.login_mode == "password"

        import yaml
        with open(config.config_dir / "settings.yaml") as f:
            doc = yaml.safe_load(f)
        assert "login" not in doc

    def test_invalid_login_mode_rejected_without_writing(self, client, preserve_config_files):
        """Regression: an invalid value must not reach disk (it would brick
        the next startup with a ValidationError until hand-edited)."""
        self._login_as_admin(client)
        config = get_config()

        import yaml
        with open(config.config_dir / "settings.yaml") as f:
            before = yaml.safe_load(f)

        response = client.post(
            "/settings",
            data={**self._base_form(config.settings), "login_mode": "banana"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b"Login mode must be one of" in response.data

        with open(config.config_dir / "settings.yaml") as f:
            after = yaml.safe_load(f)
        assert after == before

        config.reload()
        assert config.settings.login_mode == "password"

    def test_blank_login_mode_treated_as_unchanged(self, client, preserve_config_files):
        """A blank submitted value (unlike other text fields' 'blank =
        clear' convention) must not reset login_mode - there's no sensible
        'cleared' mode."""
        self._login_as_admin(client)
        config = get_config()
        client.post(
            "/settings",
            data={**self._base_form(config.settings), "login_mode": "persona"},
            follow_redirects=True,
        )

        response = client.post(
            "/settings",
            data={**self._base_form(config.settings), "login_mode": ""},
            follow_redirects=True,
        )

        assert response.status_code == 200
        config.reload()
        assert config.settings.login_mode == "persona"

