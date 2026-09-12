"""Declarative TOTP second factor (#348) across the four interactive login
surfaces, exactly the way test_two_step_login_flows.py covers two_step.

Off by default; each surface's plain-password behavior must stay unchanged
when it's off, and a user without a totp_secret must see no change either
way. The step rides two_step's machinery (routes/_auth.second_factor_phase)
and is likewise stateless: since nothing is stored server-side, the code
screen carries the password forward as a hidden field too, re-checked on
submit.
"""

import base64
import json
import re

import jwt as pyjwt

from nanoidp.config import get_config
from nanoidp.services.totp import generate_totp

_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii")


def _decode(token: str) -> dict:
    return pyjwt.decode(token, options={"verify_signature": False})


def _enable_totp(app) -> None:
    with app.app_context():
        get_config().settings.totp = True


def _give_admin_a_secret(app, secret: str = _SECRET) -> None:
    with app.app_context():
        get_config().users["admin"].totp_secret = secret


class TestLoginTotp:
    """Dashboard /login."""

    def test_no_secret_is_unaffected(self, app, client):
        _enable_totp(app)

        response = client.post(
            "/login", data={"username": "admin", "password": "admin"}, follow_redirects=False
        )
        assert response.status_code == 302
        with client.session_transaction() as sess:
            assert sess["user"] == "admin"
            assert sess["auth_method"] == "password"

    def test_totp_inactive_is_unaffected_even_with_a_secret(self, app, client):
        _give_admin_a_secret(app)

        response = client.post(
            "/login", data={"username": "admin", "password": "admin"}, follow_redirects=False
        )
        assert response.status_code == 302
        with client.session_transaction() as sess:
            assert sess["auth_method"] == "password"

    def test_correct_password_gets_code_screen(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)

        response = client.post("/login", data={"username": "admin", "password": "admin"})

        assert response.status_code == 200
        assert b'name="totp_code"' in response.data
        assert b'name="password" value="admin"' in response.data
        assert b"Signing in as" in response.data

    def test_wrong_password_never_reaches_code_screen(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)

        response = client.post(
            "/login", data={"username": "admin", "password": "wrong"}, follow_redirects=False
        )

        # login.two_step is off here, so a failed combined-form login keeps
        # its existing redirect-with-error behavior, unaffected by #348.
        assert response.status_code == 302
        assert "Invalid+credentials" in response.headers["Location"] or (
            "error=" in response.headers["Location"]
        )

    def test_blank_code_resubmission_reports_code_required(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)

        response = client.post(
            "/login",
            data={"username": "admin", "password": "admin", "totp_code": ""},
        )

        assert response.status_code == 200
        assert b"Code is required" in response.data
        assert b'name="totp_code"' in response.data

    def test_wrong_code_stays_on_code_screen(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)

        response = client.post(
            "/login",
            data={"username": "admin", "password": "admin", "totp_code": "000000"},
        )

        assert response.status_code == 200
        assert b"Invalid code" in response.data
        assert b'name="totp_code"' in response.data

    def test_valid_code_completes_login_and_records_password_otp(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)
        code = generate_totp(_SECRET)

        response = client.post(
            "/login",
            data={"username": "admin", "password": "admin", "totp_code": code},
            follow_redirects=False,
        )

        assert response.status_code == 302
        with client.session_transaction() as sess:
            assert sess["user"] == "admin"
            assert sess["auth_method"] == "password_otp"

    def test_combined_post_with_valid_code_authenticates_directly(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)
        code = generate_totp(_SECRET)

        response = client.post(
            "/login",
            data={"username": "admin", "password": "admin", "totp_code": code},
            follow_redirects=False,
        )
        assert response.status_code == 302

    def test_change_username_returns_to_first_step(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)
        client.post("/login", data={"username": "admin", "password": "admin"})

        response = client.get("/login")

        assert response.status_code == 200
        assert b'name="username"' in response.data
        assert b'name="totp_code"' not in response.data


class TestSamlSsoTotp:
    """SAML /saml/sso inline login - reuses login.html."""

    def _authn_request(self, request_id="_totp_test", acs_url="http://sp.example.com/acs"):
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

    def _authn_context_of(self, xml_bytes: bytes) -> str:
        match = re.search(rb"<[^>]*AuthnContextClassRef[^>]*>([^<]+)</", xml_bytes)
        assert match, xml_bytes
        return match.group(1).decode("utf-8")

    def test_correct_password_gets_code_screen(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)
        saml_request = self._authn_request()

        response = client.post(
            "/saml/sso",
            data={"SAMLRequest": saml_request, "username": "admin", "password": "admin"},
        )

        assert response.status_code == 200
        assert b'name="totp_code"' in response.data
        assert b'name="SAMLRequest"' in response.data

    def test_valid_code_completes_sso_with_time_sync_token_context(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)
        saml_request = self._authn_request(acs_url="http://localhost:9999/sp/acs")
        code = generate_totp(_SECRET)

        response = client.post(
            "/saml/sso",
            data={
                "SAMLRequest": saml_request,
                "username": "admin",
                "password": "admin",
                "totp_code": code,
            },
        )

        assert response.status_code == 200
        saml_response_b64 = None
        for m in re.finditer(rb'name="SAMLResponse" value="([^"]+)"', response.data):
            saml_response_b64 = m.group(1)
        assert saml_response_b64 is not None, response.data
        xml = base64.b64decode(saml_response_b64)
        assert (
            self._authn_context_of(xml)
            == "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
        )

    def test_wrong_code_stays_on_code_screen(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)
        saml_request = self._authn_request()

        response = client.post(
            "/saml/sso",
            data={
                "SAMLRequest": saml_request,
                "username": "admin",
                "password": "admin",
                "totp_code": "000000",
            },
        )

        assert response.status_code == 200
        assert b"Invalid code" in response.data
        assert b'name="totp_code"' in response.data


class TestAuthorizeTotp:
    AUTHORIZE_QS = (
        "response_type=code&client_id=demo-client"
        "&redirect_uri=http://localhost:3000/callback&scope=openid&state=totp"
    )

    def test_correct_password_gets_code_screen(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)
        client.get(f"/authorize?{self.AUTHORIZE_QS}")

        response = client.post("/authorize", data={"username": "admin", "password": "admin"})

        assert response.status_code == 200
        assert b'name="totp_code"' in response.data
        assert b'name="password" value="admin"' in response.data

    def test_valid_code_issues_code_and_amr_reaches_id_token(self, app, client, auth_header):
        _enable_totp(app)
        _give_admin_a_secret(app)
        client.get(f"/authorize?{self.AUTHORIZE_QS}")
        code = generate_totp(_SECRET)

        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin", "totp_code": code},
            follow_redirects=False,
        )
        assert response.status_code in (302, 303)
        location = response.headers["Location"]
        auth_code = re.search(r"[?&]code=([^&]+)", location).group(1)

        token_response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://localhost:3000/callback",
            },
            headers=auth_header,
        )
        assert token_response.status_code == 200
        payload = json.loads(token_response.data)
        id_token = _decode(payload["id_token"])
        assert id_token["amr"] == ["pwd", "otp"]

    def test_wrong_code_stays_on_code_screen(self, app, client):
        _enable_totp(app)
        _give_admin_a_secret(app)
        client.get(f"/authorize?{self.AUTHORIZE_QS}")

        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin", "totp_code": "000000"},
        )

        assert response.status_code == 200
        assert b"Invalid code" in response.data
        assert b'name="totp_code"' in response.data

    def test_password_only_login_has_pwd_only_amr(self, app, client, auth_header):
        """A password login with no secret still gets an amr claim (#348):
        ["pwd"], never omitted just because no second factor exists."""
        _enable_totp(app)
        client.get(f"/authorize?{self.AUTHORIZE_QS}")

        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )
        assert response.status_code in (302, 303)
        location = response.headers["Location"]
        auth_code = re.search(r"[?&]code=([^&]+)", location).group(1)

        token_response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://localhost:3000/callback",
            },
            headers=auth_header,
        )
        assert token_response.status_code == 200
        id_token = _decode(json.loads(token_response.data)["id_token"])
        assert id_token["amr"] == ["pwd"]


class TestDeviceTotp:
    def _get_device_code(self, client, auth_header) -> tuple:
        response = client.post("/device_authorization", headers=auth_header)
        data = json.loads(response.data)
        return data["device_code"], data["user_code"]

    def test_correct_password_gets_code_screen(self, app, client, auth_header):
        _enable_totp(app)
        _give_admin_a_secret(app)
        _, user_code = self._get_device_code(client, auth_header)

        response = client.post(
            "/device",
            data={"user_code": user_code, "username": "admin", "password": "admin"},
        )

        assert response.status_code == 200
        assert b'name="totp_code"' in response.data
        assert b'name="password" value="admin"' in response.data

    def test_wrong_code_stays_on_code_screen(self, app, client, auth_header):
        _enable_totp(app)
        _give_admin_a_secret(app)
        _, user_code = self._get_device_code(client, auth_header)

        response = client.post(
            "/device",
            data={
                "user_code": user_code,
                "username": "admin",
                "password": "admin",
                "totp_code": "000000",
            },
        )

        assert response.status_code == 200
        assert b"Invalid code" in response.data
        assert b'name="totp_code"' in response.data

    def test_valid_code_authorizes_device_and_amr_reaches_token(self, app, client, auth_header):
        _enable_totp(app)
        _give_admin_a_secret(app)
        device_code, user_code = self._get_device_code(client, auth_header)
        code = generate_totp(_SECRET)

        response = client.post(
            "/device",
            data={
                "user_code": user_code,
                "username": "admin",
                "password": "admin",
                "totp_code": code,
                "action": "authorize",
            },
        )
        assert response.status_code == 200
        assert b"authorized" in response.data.lower()

        token_response = client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            },
            headers=auth_header,
        )
        assert token_response.status_code == 200
        payload = json.loads(token_response.data)
        id_token = _decode(payload["id_token"])
        assert id_token["amr"] == ["pwd", "otp"]

    def test_deny_available_from_password_step_without_a_code(self, app, client, auth_header):
        """Deny bypasses the credential/second-factor gate entirely, the
        same carve-out two_step already has for it."""
        _enable_totp(app)
        _give_admin_a_secret(app)
        _, user_code = self._get_device_code(client, auth_header)

        response = client.post(
            "/device", data={"user_code": user_code, "action": "deny"}
        )

        assert response.status_code == 200
        assert b"denied" in response.data.lower()


class TestReviewFollowUps:
    """Behaviour the review of #348 pinned: opt-in on the wire, audited
    failures, uncacheable code screens, and no password oracle on /device."""

    AUTHORIZE_QS = TestAuthorizeTotp.AUTHORIZE_QS

    def _exchange(self, client, auth_header, location):
        auth_code = re.search(r"[?&]code=([^&]+)", location).group(1)
        token_response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": "http://localhost:3000/callback",
            },
            headers=auth_header,
        )
        assert token_response.status_code == 200
        return json.loads(token_response.data)

    def test_totp_off_emits_no_amr_at_all(self, app, client, auth_header):
        """login.totp is off by default, so a deployment that never turned
        it on must see no new claim in its ID Tokens or refresh tokens."""
        client.get(f"/authorize?{self.AUTHORIZE_QS}")
        response = client.post(
            "/authorize", data={"username": "admin", "password": "admin"}, follow_redirects=False
        )
        payload = self._exchange(client, auth_header, response.headers["Location"])
        assert "amr" not in _decode(payload["id_token"])
        assert "amr" not in _decode(payload["refresh_token"])

    def test_refresh_preserves_amr(self, app, client, auth_header):
        _enable_totp(app)
        _give_admin_a_secret(app)
        client.get(f"/authorize?{self.AUTHORIZE_QS}")
        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin", "totp_code": generate_totp(_SECRET)},
            follow_redirects=False,
        )
        payload = self._exchange(client, auth_header, response.headers["Location"])
        refreshed = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": payload["refresh_token"]},
            headers=auth_header,
        )
        assert refreshed.status_code == 200
        assert _decode(json.loads(refreshed.data)["id_token"])["amr"] == ["pwd", "otp"]

    def test_wrong_code_is_audited_like_a_wrong_password(self, app, client):
        from nanoidp.services import get_audit_log

        _enable_totp(app)
        _give_admin_a_secret(app)
        client.post(
            "/login", data={"username": "admin", "password": "admin", "totp_code": "000000"}
        )
        with app.app_context():
            reasons = [
                (e.get("details") or {}).get("reason")
                for e in get_audit_log().get_entries(event_type="login")
                if e.get("status") == "failed"
            ]
        assert "Invalid code" in reasons

    def test_code_screen_is_not_cacheable(self, app, client, auth_header):
        _enable_totp(app)
        _give_admin_a_secret(app)
        login_screen = client.post("/login", data={"username": "admin", "password": "admin"})
        assert login_screen.headers.get("Cache-Control") == "no-store"

        client.get(f"/authorize?{self.AUTHORIZE_QS}")
        authorize_screen = client.post(
            "/authorize", data={"username": "admin", "password": "admin"}
        )
        assert authorize_screen.headers.get("Cache-Control") == "no-store"

    def test_device_does_not_check_the_password_for_a_dead_user_code(self, app, client):
        """A correct password with no live device code must answer exactly
        like a wrong one: the code error, never the TOTP screen."""
        _enable_totp(app)
        _give_admin_a_secret(app)

        right = client.post(
            "/device",
            data={"user_code": "ZZZZZZZZ", "username": "admin", "password": "admin"},
        )
        wrong = client.post(
            "/device",
            data={"user_code": "ZZZZZZZZ", "username": "admin", "password": "nope"},
        )
        for response in (right, wrong):
            assert response.status_code == 200
            assert b"Invalid or expired user code" in response.data
            assert b'name="totp_code"' not in response.data
