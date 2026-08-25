"""
Tests for the management_secret setting: opt-in write gate for API and UI routes.

Off by default, when enabled it requires X-Management-Secret header on API mutations
and session["management_verified"] on UI mutations (proven via POST /management/unlock).
"""

import pytest
import yaml
from flask.sessions import SecureCookieSessionInterface
from pydantic import ValidationError

from nanoidp.app import create_app
from nanoidp.config import ConfigManager, get_config
from nanoidp.models import Settings


def _write_settings(tmp_path, session_overrides=None):
    """Write settings.yaml with a session section (for management_secret)."""
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


class TestManagementSecretOff:
    """Tests that management_secret defaults to off and gates nothing."""

    def test_default_is_off(self, app):
        """With real config (no management_secret set), it defaults to None."""
        with app.app_context():
            assert get_config().settings.management_secret is None

    def test_no_regression_api_mutation_allowed_without_header(self, client):
        """Default is off: mutating API POST with no header returns 200."""
        resp = client.post("/api/config/reload")
        assert resp.status_code == 200

    def test_no_regression_ui_mutation_allowed_without_session_flag(self, tmp_path):
        """Default is off: mutating UI POST with no session flag succeeds.

        Uses an isolated tmp_path-backed app/config (like every gated test
        below), not the shared `client` fixture - that fixture's `app`
        points at the repo's real `config/` directory, and a mutating POST
        through it would persist a test user into the tracked
        config/users.yaml (see git history for why this note exists).
        """
        _write_settings(tmp_path)
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.post(
            "/users/create",
            data={"username": "testuser163", "password": "pw"},
            follow_redirects=False,
        )
        # Either the create succeeds (redirect to /users) or fails on some
        # unrelated validation (redirect to /users/create) - either way, not
        # a redirect to /login, which is what the gate being active would do.
        assert resp.status_code == 302
        assert "/login" not in resp.headers["Location"]


class TestManagementSecretApiGate:
    """Tests that api_bp requires X-Management-Secret header on mutations when set."""

    def test_post_without_header_returns_401(self, tmp_path):
        """POST /api/config/reload with no X-Management-Secret header → 401."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.post("/api/config/reload")
        assert resp.status_code == 401
        assert b"error" in resp.data

    def test_post_with_wrong_secret_returns_401(self, tmp_path):
        """POST with wrong X-Management-Secret header → 401."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.post(
            "/api/config/reload",
            headers={"X-Management-Secret": "wrongsecret"},
        )
        assert resp.status_code == 401
        assert b"error" in resp.data

    def test_post_with_correct_secret_returns_200(self, tmp_path):
        """POST with correct X-Management-Secret header → 200."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.post(
            "/api/config/reload",
            headers={"X-Management-Secret": "mysecret163"},
        )
        assert resp.status_code == 200

    def test_get_never_gated(self, tmp_path):
        """GET /api/config (a read, not a mutation) with no header → 200."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.get("/api/config")
        assert resp.status_code == 200


class TestManagementSecretUiGate:
    """Tests that ui_bp requires session["management_verified"] on mutations when set."""

    def test_post_without_session_flag_redirects_to_login(self, tmp_path):
        """Mutating POST without session["management_verified"] → 302 to /login."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.post(
            "/users/create",
            data={"username": "testuser163", "password": "pw"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_get_never_gated(self, tmp_path):
        """GET /users (a read) with no session flag → 200."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.get("/users")
        assert resp.status_code == 200

    def test_login_endpoint_is_reachable(self, tmp_path):
        """GET /login itself is reachable (no redirect loop)."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.get("/login")
        assert resp.status_code == 200

    def test_management_unlock_endpoint_is_reachable(self, tmp_path):
        """POST /management/unlock itself is reachable without gate blocking it."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        # POST with correct secret should redirect to index, not be blocked by the gate
        resp = test_client.post(
            "/management/unlock",
            data={"management_secret": "mysecret163"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/")

    def test_correct_secret_sets_session_flag(self, tmp_path):
        """Posting correct secret to /management/unlock sets session flag."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        # First: unlock with correct secret
        resp = test_client.post(
            "/management/unlock",
            data={"management_secret": "mysecret163"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        # Now: a subsequent mutating POST on the same test_client should succeed
        # (session persists across requests on the same test client)
        resp = test_client.post(
            "/users/create",
            data={"username": "testuser163", "password": "pw"},
            follow_redirects=False,
        )
        # Should not redirect to /login; should either succeed (redirect to /users)
        # or fail with form error (redirect to /users/create), but NOT to /login
        assert resp.status_code == 302
        assert "/login" not in resp.headers["Location"]

    def test_wrong_secret_does_not_set_session_flag(self, tmp_path):
        """Posting wrong secret to /management/unlock does not set flag."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        # First: try to unlock with wrong secret
        resp = test_client.post(
            "/management/unlock",
            data={"management_secret": "wrongsecret"},
            follow_redirects=False,
        )
        # Should redirect to /login with error
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

        # Now: a subsequent mutating POST on the same test_client should still be blocked
        resp = test_client.post(
            "/users/create",
            data={"username": "testuser163", "password": "pw"},
            follow_redirects=False,
        )
        # Should redirect to /login
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


class TestManagementSecretEnvVarPrecedence:
    """#163 non-blocking review item: an explicit key in settings.yaml's
    session: block must win over the env vars even when its value is
    empty/null - presence in YAML is the operator deliberately stating
    "off", distinct from the key being absent entirely (config.py's old `or`
    chain fell through to an inherited env var in that case, despite its own
    comment already claiming "YAML explicit value wins")."""

    def test_explicit_null_in_yaml_overrides_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NANOIDP_MANAGEMENT_SECRET", "from-env")
        _write_settings(tmp_path, session_overrides={"management_secret": None})
        from nanoidp.config import ConfigManager

        config = ConfigManager(str(tmp_path))
        assert config.settings.management_secret is None

    def test_absent_key_falls_back_to_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NANOIDP_MANAGEMENT_SECRET", "from-env")
        _write_settings(tmp_path)  # no "management_secret" key at all
        from nanoidp.config import ConfigManager

        config = ConfigManager(str(tmp_path))
        assert config.settings.management_secret == "from-env"

    def test_explicit_yaml_value_wins_over_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NANOIDP_MANAGEMENT_SECRET", "from-env")
        _write_settings(tmp_path, session_overrides={"management_secret": "from-yaml"})
        from nanoidp.config import ConfigManager

        config = ConfigManager(str(tmp_path))
        assert config.settings.management_secret == "from-yaml"

    def test_legacy_env_var_is_fallback_of_last_resort(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NANOIDP_MANAGEMENT_SECRET", raising=False)
        monkeypatch.setenv("NANOIDP_MCP_ADMIN_SECRET", "from-legacy-env")
        _write_settings(tmp_path)  # no "management_secret" key at all
        from nanoidp.config import ConfigManager

        config = ConfigManager(str(tmp_path))
        assert config.settings.management_secret == "from-legacy-env"


class TestManagementSecretNonAsciiDoesNotCrash:
    """#163 B2 regression: secrets.compare_digest raises TypeError on
    non-ASCII str operands, which without a guard surfaces as an
    unauthenticated 500 instead of a 401/redirect. The fix compares UTF-8
    bytes and type-checks the candidate first - this covers a non-ASCII
    *candidate* against an ASCII-configured secret.

    A non-ASCII *management_secret* itself is a separate problem (round 2
    review): Werkzeug decodes request headers as latin-1, so it could never
    be matched via X-Management-Secret regardless of the compare_digest fix.
    That is now rejected at startup - see TestManagementSecretMustBeAscii."""

    def test_non_ascii_header_on_api_route_is_401_not_500(self, tmp_path):
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.post(
            "/api/config/reload",
            headers={"X-Management-Secret": "segretò"},
        )
        assert resp.status_code == 401


class TestManagementSecretMustBeAscii:
    """#163 review, round 2: Werkzeug decodes request headers as latin-1, so
    a UTF-8 management_secret never matches over X-Management-Secret (it
    would only match a client that happens to send latin-1 bytes, which no
    normal client does) - header, form and MCP JSON would silently disagree
    on what the secret is. Rejected at startup instead, so all three surfaces
    stay on the same footing."""

    def test_non_ascii_secret_rejected_directly(self):
        with pytest.raises(ValidationError, match="ASCII"):
            Settings(management_secret="segretò")

    def test_control_character_secret_rejected(self):
        with pytest.raises(ValidationError, match="ASCII"):
            Settings(management_secret="secret\twith\ttabs")

    def test_ascii_secret_is_accepted(self):
        assert Settings(management_secret="mysecret163").management_secret == "mysecret163"

    def test_none_is_accepted(self):
        assert Settings(management_secret=None).management_secret is None

    def test_non_ascii_secret_in_settings_yaml_fails_at_load(self, tmp_path):
        _write_settings(tmp_path, session_overrides={"management_secret": "segretò"})
        with pytest.raises(ValidationError, match="ASCII"):
            ConfigManager(str(tmp_path))


class TestManagementSecretSessionForgeryResistant:
    """#163 B1 regression.

    session['management_verified'] must not be a bare boolean: secret_key
    (which signs the whole session cookie) defaults to a public, well-known
    value, so a bare True flag would let anyone who knows that default forge
    an unlocked session without ever knowing management_secret. The fix
    stores an HMAC of management_secret itself (see routes/_auth.py:
    _management_verified_marker), so a forged flag isn't enough on its own.
    """

    def test_forged_boolean_flag_in_session_cookie_is_rejected(self, tmp_path):
        """A cookie hand-signed with the (known, default) secret_key setting
        the old bare `management_verified: True` must not unlock mutations."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        serializer = SecureCookieSessionInterface().get_signing_serializer(app)
        forged = serializer.dumps({"management_verified": True})
        test_client.set_cookie("session", forged)

        resp = test_client.post(
            "/users/create",
            data={"username": "testuser163", "password": "pw"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_forged_marker_for_wrong_secret_is_rejected(self, tmp_path):
        """A forged cookie carrying a well-formed-looking marker string that
        doesn't match this instance's actual management_secret must also be
        rejected - guards against a marker-shaped placeholder being treated
        as automatically valid."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        serializer = SecureCookieSessionInterface().get_signing_serializer(app)
        forged = serializer.dumps({"management_verified": "a" * 64})
        test_client.set_cookie("session", forged)

        resp = test_client.post(
            "/users/create",
            data={"username": "testuser163", "password": "pw"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


class TestManagementSecretApiAcceptsUnlockedUiSession:
    """#163 B4 regression: an unlocked ui_bp session should also satisfy
    api_bp's gate, since the dashboard's own JS (users.html, test.html,
    audit.html) calls /api/* with the browser's session cookie and no
    X-Management-Secret header."""

    def test_unlocked_session_satisfies_api_gate_without_header(self, tmp_path):
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.post(
            "/management/unlock",
            data={"management_secret": "mysecret163"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        # Same session cookie jar, no X-Management-Secret header.
        resp = test_client.post("/api/audit/clear")
        assert resp.status_code == 200

    def test_header_still_required_without_unlocked_session(self, tmp_path):
        """Regression pin: a client with no session at all still needs the
        header - the unlocked-session shortcut doesn't weaken the API gate
        for non-browser clients."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.post("/api/audit/clear")
        assert resp.status_code == 401


class TestManagementSecretWithRequireUiLoginBothOn:
    """#163 B3 regression: with require_ui_login and management_secret both
    on, POST /management/unlock must actually be reachable and work - it was
    being redirected to /login by ui_login_required (registered first, and
    exempting only ui.login), so the unlock form login.html renders in this
    combination silently did nothing."""

    def _write_both_on(self, tmp_path):
        _write_settings(
            tmp_path,
            session_overrides={
                "management_secret": "mysecret163",
                "require_ui_login": True,
            },
        )

    def test_anonymous_unlock_with_correct_secret_succeeds(self, tmp_path):
        self._write_both_on(tmp_path)
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.post(
            "/management/unlock",
            data={"management_secret": "mysecret163"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/")

    def test_login_page_still_reachable(self, tmp_path):
        self._write_both_on(tmp_path)
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.get("/login")
        assert resp.status_code == 200

    def test_dashboard_still_requires_login_after_unlock(self, tmp_path):
        """Unlocking management_secret is independent of require_ui_login -
        it must not itself grant access to the dashboard."""
        self._write_both_on(tmp_path)
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        test_client.post(
            "/management/unlock",
            data={"management_secret": "mysecret163"},
            follow_redirects=False,
        )

        resp = test_client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


class TestManagementSecretOtherBlueprintsUnaffected:
    """Regression pin: the gate is api_bp/ui_bp-only, other blueprints unaffected."""

    def test_oauth_blueprint_stays_ungated(self, tmp_path):
        """OAuth discovery endpoint stays reachable without secret."""
        _write_settings(tmp_path, session_overrides={"management_secret": "mysecret163"})
        app = create_app(config_dir=str(tmp_path))
        test_client = app.test_client()

        resp = test_client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
