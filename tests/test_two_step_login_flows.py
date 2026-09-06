"""Two-step login (#322/#323 review round 2: a global `login.two_step`
setting) extended to the remaining interactive surfaces: the dashboard's
/login, SAML /saml/sso, and the device flow's /device. /authorize's own
two-step suite lives in test_two_step_authorize.py.

Off by default; each surface's combined-form behavior must stay unchanged
when it's off. The step is stateless everywhere it appears (#323 review
round 1): the username travels as a plain form field, carried forward as a
hidden input on the password screen - no session-captured identity, no
login_step sentinel.
"""

import base64
import json

import pytest

from nanoidp.config import get_config
from nanoidp.services.device_code import get_device_code_store


def _enable_two_step(app) -> None:
    with app.app_context():
        get_config().settings.two_step = True


@pytest.fixture(autouse=True)
def cleanup_device_codes():
    """device_code store is a process-wide singleton (see
    test_device_flow_complete.py) - clear it so codes from one test never
    leak into the next."""
    yield
    get_device_code_store().clear()


class TestLoginTwoStep:
    """Dashboard /login."""

    def test_password_mode_unaffected(self, client):
        response = client.get("/login")
        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' in response.data
        assert b">Next<" not in response.data

    def test_enabled_collects_username_then_password(self, app, client):
        _enable_two_step(app)

        response = client.get("/login")
        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' not in response.data

        response = client.post("/login", data={"username": "admin"})
        assert response.status_code == 200
        assert b'name="username" value="admin"' in response.data
        assert b'name="password"' in response.data
        assert b"Signing in as" in response.data

    def test_wrong_password_stays_on_password_step(self, app, client):
        _enable_two_step(app)
        client.post("/login", data={"username": "admin"})

        response = client.post("/login", data={"username": "admin", "password": "wrong"})

        assert response.status_code == 200
        assert b"Invalid username or password" in response.data
        assert b'name="password"' in response.data

    def test_blank_password_resubmission_reports_password_required(self, app, client):
        _enable_two_step(app)
        client.post("/login", data={"username": "admin"})

        response = client.post("/login", data={"username": "admin", "password": ""})

        assert response.status_code == 200
        assert b"Password is required" in response.data

    def test_combined_post_authenticates_directly(self, app, client):
        _enable_two_step(app)

        response = client.post(
            "/login", data={"username": "admin", "password": "admin"}, follow_redirects=False
        )

        assert response.status_code == 302
        assert response.headers["Location"].endswith("/")

        with client.session_transaction() as sess:
            assert sess["user"] == "admin"
            assert sess["auth_method"] == "password"

    def test_change_username_returns_to_first_step(self, app, client):
        _enable_two_step(app)
        client.post("/login", data={"username": "wrong"})

        response = client.get("/login")

        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' not in response.data
        assert b"wrong" not in response.data

    def test_persona_mode_remains_passwordless(self, app, client):
        _enable_two_step(app)
        with app.app_context():
            get_config().settings.login_mode = "persona"

        response = client.get("/login")
        assert response.status_code == 200
        assert b'name="password"' not in response.data

        response = client.post("/login", data={"username": "admin"}, follow_redirects=False)
        assert response.status_code == 302
        with client.session_transaction() as sess:
            assert sess["user"] == "admin"


class TestSamlSsoTwoStep:
    """SAML /saml/sso inline login - reuses login.html, no session to fall
    back to, so there is no "change username" affordance on this surface
    (#323 review round 2)."""

    def _authn_request(self, request_id="_two_step_test", acs_url="http://sp.example.com/acs"):
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="2025-01-01T00:00:00Z"
    AssertionConsumerServiceURL="{acs_url}">
    <saml:Issuer>http://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>"""
        return base64.b64encode(xml.encode("utf-8")).decode("ascii")

    def test_password_mode_unaffected(self, client):
        saml_request = self._authn_request()

        response = client.post("/saml/sso", data={"SAMLRequest": saml_request})

        assert response.status_code == 200
        assert b'name="password"' in response.data

    def test_enabled_collects_username_then_password(self, app, client):
        _enable_two_step(app)
        saml_request = self._authn_request()

        response = client.post("/saml/sso", data={"SAMLRequest": saml_request})
        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' not in response.data
        # No stateless GET back into a SAML flow, so no such link here.
        assert b"Change username" not in response.data

        response = client.post(
            "/saml/sso", data={"SAMLRequest": saml_request, "username": "admin"}
        )
        assert response.status_code == 200
        assert b'name="username" value="admin"' in response.data
        assert b'name="password"' in response.data
        assert b"Signing in as" in response.data
        # SAMLRequest must survive onto the password screen or the next
        # POST 400s with "missing SAMLRequest".
        assert saml_request.encode() in response.data

    def test_password_step_completes_sso(self, app, client):
        _enable_two_step(app)
        saml_request = self._authn_request()
        client.post("/saml/sso", data={"SAMLRequest": saml_request, "username": "admin"})

        response = client.post(
            "/saml/sso",
            data={"SAMLRequest": saml_request, "username": "admin", "password": "admin"},
        )

        assert response.status_code == 200
        assert b"SAMLResponse" in response.data

    def test_wrong_password_stays_on_password_step(self, app, client):
        _enable_two_step(app)
        saml_request = self._authn_request()
        client.post("/saml/sso", data={"SAMLRequest": saml_request, "username": "admin"})

        response = client.post(
            "/saml/sso",
            data={"SAMLRequest": saml_request, "username": "admin", "password": "wrong"},
        )

        assert response.status_code == 200
        assert b"Invalid credentials" in response.data
        assert b'name="password"' in response.data

    def test_combined_post_authenticates_directly(self, app, client):
        _enable_two_step(app)
        saml_request = self._authn_request()

        response = client.post(
            "/saml/sso",
            data={"SAMLRequest": saml_request, "username": "admin", "password": "admin"},
        )

        assert response.status_code == 200
        assert b"SAMLResponse" in response.data


class TestDeviceTwoStep:
    """Device authorization flow's /device verification page."""

    def _get_device_code(self, client, auth_header) -> tuple:
        response = client.post("/device_authorization", headers=auth_header)
        data = json.loads(response.data)
        return data["device_code"], data["user_code"]

    def test_password_mode_unaffected(self, client, auth_header):
        _, user_code = self._get_device_code(client, auth_header)

        response = client.get(f"/device?user_code={user_code}")
        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="password"' in response.data

    def test_enabled_collects_username_then_password(self, app, client, auth_header):
        _enable_two_step(app)
        _, user_code = self._get_device_code(client, auth_header)

        response = client.post("/device", data={"user_code": user_code, "username": "admin"})
        assert response.status_code == 200
        assert b'name="username" value="admin"' in response.data
        assert b'name="password"' in response.data
        assert b"Signing in as" in response.data

    def test_wrong_password_stays_on_password_step(self, app, client, auth_header):
        _enable_two_step(app)
        _, user_code = self._get_device_code(client, auth_header)
        client.post("/device", data={"user_code": user_code, "username": "admin"})

        response = client.post(
            "/device",
            data={"user_code": user_code, "username": "admin", "password": "wrong"},
        )

        assert response.status_code == 200
        assert b"Invalid username or password" in response.data
        assert b'name="password"' in response.data

    def test_combined_post_authorizes_device_directly(self, app, client, auth_header):
        _enable_two_step(app)
        device_code, user_code = self._get_device_code(client, auth_header)

        response = client.post(
            "/device",
            data={
                "user_code": user_code,
                "username": "admin",
                "password": "admin",
                "action": "authorize",
            },
        )

        assert response.status_code == 200
        assert b"authorized" in response.data.lower()

    def test_deny_available_from_username_only_step(self, app, client, auth_header):
        """Denying a device must not require entering credentials first,
        same as persona mode's standalone Deny button (#323 review round
        2)."""
        _enable_two_step(app)
        _, user_code = self._get_device_code(client, auth_header)

        response = client.post(
            "/device", data={"user_code": user_code, "action": "deny"}
        )

        assert response.status_code == 200
        assert b"denied" in response.data.lower()

    def test_persona_mode_remains_passwordless(self, app, client, auth_header):
        _enable_two_step(app)
        with app.app_context():
            get_config().settings.login_mode = "persona"
        _, user_code = self._get_device_code(client, auth_header)

        response = client.get(f"/device?user_code={user_code}")
        assert response.status_code == 200
        assert b'name="password"' not in response.data

        response = client.post("/device", data={"user_code": user_code, "username": "admin"})
        assert response.status_code == 200
        assert b"authorized" in response.data.lower()
