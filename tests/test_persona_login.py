"""
Tests for persona login mode (passwordless interactive login, a local
dev/testing convenience) on the nanoidp dashboard's /login endpoint.

Off by default ('login_mode: password'); enabling it must not change
password-mode behavior at all - only 'persona' mode skips the credential
check and authenticates by identity selection instead (design contract
point 1/3, see docs/plans/persona-login-mode.md).
"""

from nanoidp.config import User, get_config


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
