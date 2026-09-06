"""Username-first /authorize login flow (#322/#323 review round 2: a global
`login.two_step` setting, not a per-client field - it applies to every
password-form surface, /authorize included).

The step is stateless (#323 review round 1): the username travels as a
plain form field - typed on the first screen, carried forward as a hidden
input on the second - never captured in the session. There is no
login_step sentinel; whether a request is the username-only step or a real
login attempt is derived from whether it carries a password.
"""

import re

from nanoidp.config import get_config

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
        captured from an earlier one. A password-step POST that also
        retargets client_id/redirect_uri/state via the form body still
        authenticates - and issues the code for - the username THIS POST
        carries, "admin", not anything a previous request might have left
        behind.

        That form-body retarget itself (a POST can redirect the issued code
        to a different client_id/redirect_uri than the GET that started the
        flow) is pre-existing, out-of-scope behavior - tracked separately as
        #325 - so this test does not pin where the redirect goes, only who
        the code was issued to."""
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
        assert "code=" in location
        code = location.split("code=")[1].split("&")[0]

        from nanoidp.services.auth_code import get_auth_code_store

        with app.app_context():
            info = get_auth_code_store().get_code_info(code)
        assert info is not None
        assert info.username == "admin"

    def test_change_username_link_survives_a_cleared_session(self, app, client):
        """A bare url_for('oauth.authorize') relies on the session's oauth_*
        fallback and 400s once those keys are gone - e.g. cleared by an
        unrelated completed login, in another tab, sharing the same cookie
        (_issue_authorization_code clears every oauth_ key on success).
        'Change username' must carry the request's own parameters instead."""
        _enable_two_step(app)
        client.get(f"/authorize?{AUTHORIZE_QS}")
        response = client.post("/authorize", data={"username": "admin"})

        match = re.search(r'href="([^"]+)"[^>]*>Change username', response.data.decode())
        assert match
        href = match.group(1).replace("&amp;", "&")

        with client.session_transaction() as sess:
            for key in list(sess.keys()):
                if key.startswith("oauth_"):
                    sess.pop(key)

        # The bare fallback a naive link would use is now broken - proves
        # the scenario actually reproduces the bug being regression-tested.
        assert client.get("/authorize").status_code == 400

        response = client.get(href)
        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' not in response.data

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
