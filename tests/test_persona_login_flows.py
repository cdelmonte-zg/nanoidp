"""
Persona login mode (passwordless interactive login, local dev/testing
convenience) extended to the remaining interactive surfaces: OIDC
/authorize, SAML /saml/sso, and the device authorization flow's /device.

Off by default ('login_mode: password'); each surface's password-mode
behavior must stay byte-for-byte unchanged - only 'persona' mode skips the
credential check and authenticates by identity selection instead. See
docs/plans/persona-login-mode.md.
"""

import base64
import json
import re

import pytest
from lxml import etree

from nanoidp.config import get_config
from nanoidp.services.device_code import get_device_code_store

AUTHORIZE_QS = (
    "response_type=code&client_id=demo-client"
    "&redirect_uri=http://localhost:3000/callback&scope=openid&state=xyz"
)


def _enable_persona_mode(app) -> None:
    with app.app_context():
        get_config().settings.login_mode = "persona"


@pytest.fixture(autouse=True)
def cleanup_device_codes():
    """Clean up device codes after each test to prevent state leakage
    (device_code store is a process-wide singleton, see test_device_flow_complete.py)."""
    yield
    get_device_code_store().clear()


class TestAuthorizePersonaMode:
    """OIDC /authorize inline login."""

    def test_password_mode_unaffected(self, client):
        """Regression: default mode still shows the password form and
        requires both fields."""
        response = client.get(f"/authorize?{AUTHORIZE_QS}")
        assert response.status_code == 200
        assert b'name="password"' in response.data

        client.get(f"/authorize?{AUTHORIZE_QS}")
        response = client.post("/authorize", data={"username": "admin"})
        assert response.status_code == 200
        assert b"Username and password are required" in response.data

    def test_persona_mode_shows_picker_no_password_field(self, app, client):
        _enable_persona_mode(app)

        response = client.get(f"/authorize?{AUTHORIZE_QS}")

        assert response.status_code == 200
        assert b'name="password"' not in response.data
        assert b"admin" in response.data

    def test_persona_mode_selecting_user_issues_code(self, app, client):
        _enable_persona_mode(app)

        client.get(f"/authorize?{AUTHORIZE_QS}")
        response = client.post(
            "/authorize", data={"username": "admin"}, follow_redirects=False
        )

        assert response.status_code == 302
        location = response.headers["Location"]
        assert location.startswith("http://localhost:3000/callback?code=")
        assert "state=xyz" in location

    def test_persona_mode_missing_username_shows_select_user(self, app, client):
        _enable_persona_mode(app)

        client.get(f"/authorize?{AUTHORIZE_QS}")
        response = client.post("/authorize", data={})

        assert response.status_code == 200
        assert b"Select a user" in response.data

    def test_persona_mode_nonexistent_user_rejected(self, app, client):
        _enable_persona_mode(app)

        client.get(f"/authorize?{AUTHORIZE_QS}")
        response = client.post("/authorize", data={"username": "nonexistent"})

        assert response.status_code == 200
        assert b"Invalid username or password" in response.data


class TestSamlSsoPersonaMode:
    """SAML /saml/sso inline login and AuthnContextClassRef."""

    UNSPECIFIED_CTX = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
    PASSWORD_CTX = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    def _authn_request(self, request_id="_persona_test", acs_url="http://sp.example.com/acs"):
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

    def _authn_context_of(self, response_data: bytes) -> str:
        text = response_data.decode("utf-8")
        match = re.search(r'name="SAMLResponse"\s+value="([^"]+)"', text)
        assert match, "SAMLResponse not found"
        root = etree.fromstring(base64.b64decode(match.group(1)))
        ctx = root.find(
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef"
        )
        assert ctx is not None
        return ctx.text

    def test_password_mode_unaffected(self, client):
        """Regression: default mode still shows the password form inline."""
        saml_request = self._authn_request()

        response = client.post("/saml/sso", data={"SAMLRequest": saml_request})

        assert response.status_code == 200
        assert b'name="password"' in response.data

    def test_password_mode_uses_password_protected_transport(self, client):
        saml_request = self._authn_request()

        response = client.post(
            "/saml/sso",
            data={"SAMLRequest": saml_request, "username": "admin", "password": "admin"},
        )

        assert response.status_code == 200
        assert self._authn_context_of(response.data) == self.PASSWORD_CTX

    def test_persona_mode_shows_picker_no_password_field(self, app, client):
        _enable_persona_mode(app)
        saml_request = self._authn_request()

        response = client.post("/saml/sso", data={"SAMLRequest": saml_request})

        assert response.status_code == 200
        assert b'name="password"' not in response.data
        assert b"admin" in response.data

    def test_persona_mode_selection_completes_sso_with_unspecified_context(self, app, client):
        _enable_persona_mode(app)
        saml_request = self._authn_request()

        response = client.post(
            "/saml/sso", data={"SAMLRequest": saml_request, "username": "admin"}
        )

        assert response.status_code == 200
        assert self._authn_context_of(response.data) == self.UNSPECIFIED_CTX

    def test_persona_mode_nonexistent_user_rejected(self, app, client):
        _enable_persona_mode(app)
        saml_request = self._authn_request()

        response = client.post(
            "/saml/sso", data={"SAMLRequest": saml_request, "username": "nonexistent"}
        )

        assert response.status_code == 200
        assert b"Invalid credentials" in response.data

    def test_prior_persona_dashboard_login_reused_gets_unspecified_context(self, app, client):
        """A session already authenticated via the dashboard's persona /login
        (not SAML's own inline login) must still get 'unspecified', since
        AuthnContextClassRef describes how the session actually authenticated."""
        _enable_persona_mode(app)
        client.post("/login", data={"username": "admin"})

        saml_request = self._authn_request()
        response = client.post("/saml/sso", data={"SAMLRequest": saml_request})

        assert response.status_code == 200
        assert self._authn_context_of(response.data) == self.UNSPECIFIED_CTX


class TestDevicePersonaMode:
    """Device authorization flow's /device verification page."""

    def _get_device_code(self, client, auth_header) -> tuple:
        response = client.post("/device_authorization", headers=auth_header)
        data = json.loads(response.data)
        return data["device_code"], data["user_code"]

    def test_password_mode_unaffected(self, client, auth_header):
        """Regression: default mode still shows the password form and
        requires both fields."""
        _, user_code = self._get_device_code(client, auth_header)

        response = client.get(f"/device?user_code={user_code}")
        assert response.status_code == 200
        assert b'name="password"' in response.data

        response = client.post("/device", data={"user_code": user_code, "username": "admin"})
        assert response.status_code == 200
        assert b"Username and password are required" in response.data

    def test_persona_mode_shows_picker_no_password_field(self, app, client, auth_header):
        _enable_persona_mode(app)
        _, user_code = self._get_device_code(client, auth_header)

        response = client.get(f"/device?user_code={user_code}")

        assert response.status_code == 200
        assert b'name="password"' not in response.data
        assert b"admin" in response.data

    def test_persona_mode_picker_buttons_not_implicit_submit(self, app, client, auth_header):
        """Regression for the maintainer-reported bug: the per-user picker
        buttons must not be submit controls, so implicit form submission
        (pressing Enter in the device code field) can't silently authorize
        whichever user happens to be listed first."""
        _enable_persona_mode(app)
        _, user_code = self._get_device_code(client, auth_header)

        response = client.get(f"/device?user_code={user_code}")

        assert response.status_code == 200
        assert b'type="submit" value="admin"' not in response.data
        assert b'type="submit" name="username"' not in response.data
        assert b'type="button" value="admin"' in response.data

    def test_persona_mode_selecting_user_authorizes_device(self, app, client, auth_header):
        _enable_persona_mode(app)
        device_code, user_code = self._get_device_code(client, auth_header)

        response = client.post(
            "/device", data={"user_code": user_code, "username": "admin"}
        )
        assert response.status_code == 200
        assert b"authorized successfully" in response.data

        token_response = client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            },
            headers=auth_header,
        )
        assert token_response.status_code == 200
        assert "access_token" in json.loads(token_response.data)

    def test_persona_mode_missing_username_shows_select_user(self, app, client, auth_header):
        _enable_persona_mode(app)
        _, user_code = self._get_device_code(client, auth_header)

        response = client.post("/device", data={"user_code": user_code})

        assert response.status_code == 200
        assert b"Select a user" in response.data

    def test_persona_mode_deny_still_works(self, app, client, auth_header):
        _enable_persona_mode(app)
        _, user_code = self._get_device_code(client, auth_header)

        response = client.post(
            "/device", data={"user_code": user_code, "action": "deny"}
        )

        assert response.status_code == 200
        assert b"denied" in response.data
