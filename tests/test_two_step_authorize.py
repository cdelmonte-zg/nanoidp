"""Per-client username-first /authorize login flow (#322)."""

from nanoidp.config import get_config

AUTHORIZE_QS = (
    "response_type=code&client_id=demo-client"
    "&redirect_uri=http://localhost:3000/callback&scope=openid&state=two-step"
)


def _enable_two_step_login(app) -> None:
    with app.app_context():
        client = get_config().get_client("demo-client")
        assert client is not None
        client.two_step_login = True


class TestTwoStepAuthorize:
    def test_default_client_keeps_single_screen(self, client):
        response = client.get(f"/authorize?{AUTHORIZE_QS}")

        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' in response.data
        assert b">Next<" not in response.data

    def test_opted_in_client_collects_username_then_password(self, app, client):
        _enable_two_step_login(app)

        response = client.get(f"/authorize?{AUTHORIZE_QS}")
        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' not in response.data

        response = client.post(
            "/authorize", data={"login_step": "username", "username": "admin"}
        )
        assert response.status_code == 200
        assert b'name="username"' not in response.data
        assert b'name="password"' in response.data
        assert b"Signing in as" in response.data
        assert b"admin" in response.data

    def test_password_step_issues_code_and_preserves_state(self, app, client):
        _enable_two_step_login(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.post("/authorize", data={"login_step": "username", "username": "admin"})

        response = client.post(
            "/authorize",
            data={"login_step": "password", "password": "admin"},
            follow_redirects=False,
        )

        assert response.status_code == 302
        location = response.headers["Location"]
        assert location.startswith("http://localhost:3000/callback?code=")
        assert "state=two-step" in location

    def test_wrong_password_stays_on_password_step(self, app, client):
        _enable_two_step_login(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.post("/authorize", data={"login_step": "username", "username": "admin"})

        response = client.post(
            "/authorize", data={"login_step": "password", "password": "wrong"}
        )

        assert response.status_code == 200
        assert b"Invalid username or password" in response.data
        assert b'name="password"' in response.data
        assert b"admin" in response.data

    def test_change_username_returns_to_first_step_and_preserves_request(self, app, client):
        _enable_two_step_login(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.post("/authorize", data={"login_step": "username", "username": "wrong"})

        response = client.post("/authorize", data={"login_step": "change_username"})

        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' not in response.data
        assert b"wrong" not in response.data

        client.post("/authorize", data={"login_step": "username", "username": "admin"})
        response = client.post(
            "/authorize",
            data={"login_step": "password", "password": "admin"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "state=two-step" in response.headers["Location"]

    def test_new_authorize_request_resets_captured_username(self, app, client):
        _enable_two_step_login(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.post("/authorize", data={"login_step": "username", "username": "admin"})

        response = client.get(f"/authorize?{AUTHORIZE_QS}")

        assert b'name="username"' in response.data
        assert b'name="password"' not in response.data

    def test_persona_mode_remains_passwordless(self, app, client):
        _enable_two_step_login(app)
        with app.app_context():
            get_config().settings.login_mode = "persona"

        client.get(f"/authorize?{AUTHORIZE_QS}")
        response = client.post(
            "/authorize", data={"username": "admin"}, follow_redirects=False
        )

        assert response.status_code == 302
        assert "code=" in response.headers["Location"]

    def test_persona_auto_login_bypasses_both_screens(self, app, client):
        _enable_two_step_login(app)
        with app.app_context():
            config = get_config()
            config.settings.login_mode = "persona"
            config.settings.auto_login = True

        response = client.get(
            f"/authorize?{AUTHORIZE_QS}&login_hint=persona-auto-login:admin",
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert "code=" in response.headers["Location"]
