"""Username-first /authorize login flow (#322/#323 review round 2: a global
`login.two_step` setting, not a per-client field - it applies to every
password-form surface, /authorize included).

The step is stateless (#323 review round 1): the username travels as a
plain form field - typed on the first screen, carried forward as a hidden
input on the second - never captured in the session. There is no
login_step sentinel; whether a request is the username-only step or a real
login attempt is derived from whether it carries a password.
"""


from nanoidp.config import get_config
from tests.conftest import transaction_id_of

AUTHORIZE_QS = (
    "response_type=code&client_id=demo-client"
    "&redirect_uri=http://localhost:3000/callback&scope=openid&state=two-step"
)


def _enable_two_step(app) -> None:
    with app.app_context():
        get_config().settings.two_step = True


class TestTwoStepAuthorize:
    def test_default_keeps_single_screen(self, client):
        response = client.get(f"/authorize?{AUTHORIZE_QS}")

        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' in response.data
        assert b">Next<" not in response.data

    def test_enabled_collects_username_then_password(self, app, client):
        _enable_two_step(app)

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
        _enable_two_step(app)
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
        _enable_two_step(app)
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
        _enable_two_step(app)
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
        while two-step is on - a scripted client written against the
        combined form, or a legacy integration - must authenticate, never be
        half-consumed as the username-only step."""
        _enable_two_step(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")

        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert "code=" in response.headers["Location"]

    def test_change_username_returns_to_first_step_and_preserves_request(self, app, client):
        _enable_two_step(app)
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
        _enable_two_step(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.post("/authorize", data={"username": "admin"})

        response = client.get(f"/authorize?{AUTHORIZE_QS}")

        assert b'name="username"' in response.data
        assert b'name="password"' not in response.data

    def test_password_step_does_not_resurrect_a_stale_username(self, app, client):
        """#323 review round 1, blocking 2 (closed): the username used to
        authenticate is exactly what THIS request submitted, never a value
        captured from an earlier one. A password-step POST that also tries
        to retarget client_id/redirect_uri/state via the form body still
        authenticates - and issues the code for - the username THIS POST
        carries, "admin", not anything a previous request might have left
        behind.

        The forged client_id/redirect_uri/state are also a #325 probe: the
        password-step POST has no query string of its own, so it falls back
        to the session the original GET populated and the forged body
        fields are never read - the code is issued for demo-client's
        localhost:3000/callback with state=two-step, exactly what
        AUTHORIZE_QS asked for, not the swapped values (#325 review round
        1, point 4)."""
        _enable_two_step(app)
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

        assert response.status_code == 302
        location = response.headers["Location"]
        assert location.startswith("http://localhost:3000/callback")
        assert "state=two-step" in location
        assert "code=" in location
        code = location.split("code=")[1].split("&")[0]

        from nanoidp.services.auth_code import get_auth_code_store

        with app.app_context():
            info = get_auth_code_store().get_code_info(code)
        assert info is not None
        assert info.username == "admin"

    def test_change_username_is_a_post_on_the_transaction(self, app, client):
        """#346: "Change username" posts back to the page's own transaction
        and needs nothing from the session but the browser binding, so it
        keeps working while another request of the same browser completes."""
        _enable_two_step(app)
        page = client.get(f"/authorize?{AUTHORIZE_QS}")
        response = client.post(
            "/authorize",
            data={"username": "admin", "transaction_id": transaction_id_of(page)},
        )
        body = response.data.decode()
        assert 'name="change_username"' in body

        # Another request of the same browser starts and completes.
        other = "response_type=code&client_id=test-client&redirect_uri=http://localhost:4000/callback"
        other_page = client.get(f"/authorize?{other}")
        client.post(
            "/authorize",
            data={"username": "admin", "transaction_id": transaction_id_of(other_page)},
        )
        completed = client.post(
            "/authorize",
            data={
                "username": "admin",
                "password": "admin",
                "transaction_id": transaction_id_of(other_page),
            },
        )
        assert completed.status_code == 302

        response = client.post(
            "/authorize",
            data={"change_username": "1", "transaction_id": transaction_id_of(page)},
        )
        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' not in response.data
        assert transaction_id_of(response) == transaction_id_of(page)

    def test_persona_mode_remains_passwordless(self, app, client):
        _enable_two_step(app)
        with app.app_context():
            get_config().settings.login_mode = "persona"

        client.get(f"/authorize?{AUTHORIZE_QS}")
        response = client.post(
            "/authorize", data={"username": "admin"}, follow_redirects=False
        )

        assert response.status_code == 302
        assert "code=" in response.headers["Location"]

    def test_persona_auto_login_bypasses_both_screens(self, app, client):
        _enable_two_step(app)
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
