"""
Tests for the require_ui_login setting: opt-in login gate for UI routes.

Off by default, when enabled it redirects unauthenticated requests to /login.
"""

import yaml

from nanoidp.app import create_app
from nanoidp.config import get_config


def _write_settings(tmp_path, session_overrides=None):
    """Write settings.yaml with a session section (for require_ui_login)."""
    data = {
        "server": {"host": "0.0.0.0", "port": 8000},
        "oauth": {
            "issuer": "http://localhost:8000",
            "audience": "my-app",
            "token_expiry_minutes": 60,
            "clients": [],
        },
        "session": session_overrides or {},
    }
    (tmp_path / "settings.yaml").write_text(yaml.safe_dump(data))


class TestRequireUiLoginOff:
    def test_default_is_off(self, app):
        """With real config (no require_ui_login set), it defaults to False."""
        with app.app_context():
            assert get_config().settings.require_ui_login is False

    def test_no_regression_unauthenticated_access_allowed(self, client):
        """Default is off: unauthenticated /users request returns 200."""
        resp = client.get("/users")
        assert resp.status_code == 200


class TestRequireUiLoginOn:
    def test_on_unauthenticated_redirects_to_login(self, tmp_path):
        """Enabled: unauthenticated request redirects to /login."""
        _write_settings(tmp_path, session_overrides={"require_ui_login": True})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.get("/users")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_on_login_itself_is_reachable(self, tmp_path):
        """Enabled: /login endpoint itself is reachable (no redirect loop)."""
        _write_settings(tmp_path, session_overrides={"require_ui_login": True})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.get("/login")
        assert resp.status_code == 200

    def test_on_injected_session_passes_through(self, tmp_path):
        """Enabled: request with injected session passes through."""
        _write_settings(tmp_path, session_overrides={"require_ui_login": True})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        with test_client.session_transaction() as sess:
            sess["user"] = "admin"

        resp = test_client.get("/users")
        assert resp.status_code == 200

    def test_on_real_login_grants_access(self, tmp_path):
        """Enabled: successful /login POST grants access to /users."""
        _write_settings(tmp_path, session_overrides={"require_ui_login": True})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        # POST to /login with admin credentials
        resp = test_client.post(
            "/login",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )
        # Should redirect to dashboard after successful login
        assert resp.status_code == 302

        # Now the same test_client (session persists) can access /users
        resp = test_client.get("/users")
        assert resp.status_code == 200
