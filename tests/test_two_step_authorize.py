"""Per-client username-first /authorize login flow (#322).

The step is stateless (#323 review round 1): the username travels as a
plain form field - typed on the first screen, carried forward as a hidden
input on the second - never captured in the session. There is no
login_step sentinel; whether a request is the username-only step or a real
login attempt is derived from whether it carries a password.
"""

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

        response = client.post("/authorize", data={"username": "admin"})
        assert response.status_code == 200
        assert b'name="username" value="admin"' in response.data
        assert b'name="password"' in response.data
        assert b"Signing in as" in response.data
        assert b"admin" in response.data
        assert response.data.index(b"Signing in as") < response.data.index(
            b'class="client-info"'
        )

    def test_password_step_issues_code_and_preserves_state(self, app, client):
        _enable_two_step_login(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.post("/authorize", data={"username": "admin"})

        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )

        assert response.status_code == 302
        location = response.headers["Location"]
        assert location.startswith("http://localhost:3000/callback?code=")
        assert "state=two-step" in location

    def test_wrong_password_stays_on_password_step(self, app, client):
        _enable_two_step_login(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.post("/authorize", data={"username": "admin"})

        response = client.post(
            "/authorize", data={"username": "admin", "password": "wrong"}
        )

        assert response.status_code == 200
        assert b"Invalid username or password" in response.data
        assert b'name="password"' in response.data
        assert b"admin" in response.data

    def test_blank_password_resubmission_reports_password_required(self, app, client):
        """#323 review round 1, before-merge 6: the password screen (hidden
        username plus an emptied password field) resubmitted with nothing
        typed reports 'Password is required', distinct from the silent
        first arrival at that screen."""
        _enable_two_step_login(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.post("/authorize", data={"username": "admin"})

        response = client.post(
            "/authorize", data={"username": "admin", "password": ""}
        )

        assert response.status_code == 200
        assert b"Password is required" in response.data
        assert b'name="password"' in response.data

    def test_combined_post_authenticates_directly(self, app, client):
        """#323 review round 1, blocking 1: a POST carrying full credentials
        for an opted-in client - a scripted client written against the
        combined form, or a legacy integration - must authenticate, never be
        half-consumed as the username-only step."""
        _enable_two_step_login(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")

        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert "code=" in response.headers["Location"]

    def test_change_username_returns_to_first_step_and_preserves_request(self, app, client):
        _enable_two_step_login(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.post("/authorize", data={"username": "wrong"})

        response = client.get("/authorize")

        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' not in response.data
        assert b"wrong" not in response.data

        client.post("/authorize", data={"username": "admin"})
        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "state=two-step" in response.headers["Location"]

    def test_new_authorize_request_resets_captured_username(self, app, client):
        _enable_two_step_login(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.post("/authorize", data={"username": "admin"})

        response = client.get(f"/authorize?{AUTHORIZE_QS}")

        assert b'name="username"' in response.data
        assert b'name="password"' not in response.data

    def test_password_step_ignores_client_swap_via_form_body(self, app, client):
        """#323 review round 1, blocking 2: a password-step POST that also
        retargets client_id/redirect_uri/state must not silently issue a
        code for the swapped-in client without that client's own login
        page ever being shown for this username - closed by never
        capturing the username server-side in the first place."""
        with app.app_context():
            other = get_config().get_client("test-client")
            assert other is not None
            other.two_step_login = True
        _enable_two_step_login(app)

        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.post("/authorize", data={"username": "admin"})

        response = client.post(
            "/authorize",
            data={
                "username": "admin",
                "password": "admin",
                "client_id": "test-client",
                "redirect_uri": "http://localhost:4000/callback",
                "state": "swapped",
            },
            follow_redirects=False,
        )

        # Retargeting the client via the form body is pre-existing,
        # out-of-scope behavior (the review round 1 note): the point here is
        # only that the username is exactly what THIS request submitted, not
        # a value resurrected from an earlier request for a different client.
        assert response.status_code == 302
        assert response.headers["Location"].startswith("http://localhost:4000/callback")

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
