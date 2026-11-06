"""The page that carries a SAMLResponse (#478, SAML 2.0 Bindings 3.5.5.1).

It holds a signed assertion in a 200 body: no cache may keep it, with the
exact directives the Bindings text recommends, and no script of another
origin may read it, which the app-wide CORS rule would otherwise allow. The
form to the ACS is what delivers it, and that keeps working.
"""

import base64
import re
import zlib
from urllib.parse import quote

from nanoidp.config import get_config

ACS = "http://localhost:8080/acs"
EVIL = {"Origin": "http://evil.example"}


def _redirect_binding_query():
    xml = (
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1" '
        f'Version="2.0" IssueInstant="2026-11-06T00:00:00Z" AssertionConsumerServiceURL="{ACS}">'
        '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer>'
        "</samlp:AuthnRequest>"
    )
    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(xml.encode()) + compressor.flush()
    return f"SAMLRequest={quote(base64.b64encode(deflated).decode())}&RelayState=r"


def _hidden_fields(response):
    return dict(re.findall(r'name="([^"]+)" value="([^"]*)"', response.get_data(as_text=True)))


def _login(client, credentials, headers=None):
    query = _redirect_binding_query()
    page = client.get(f"/saml/sso?{query}")
    return client.post(
        f"/saml/sso?{query}", data={**_hidden_fields(page), **credentials}, headers=headers or {}
    )


def _assert_delivers_to_the_acs(response):
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert f'action="{ACS}"' in html
    assert 'onload="document.forms[0].submit()"' in html
    fields = _hidden_fields(response)
    assert base64.b64decode(fields["SAMLResponse"]).startswith(b"<")
    assert fields["RelayState"] == "r"


class TestNoCacheKeepsThePage:
    def test_the_bindings_directives_after_a_real_login(self, client):
        page = _login(client, {"username": "admin", "password": "admin"})

        _assert_delivers_to_the_acs(page)
        assert page.headers["Cache-Control"] == "no-cache, no-store"
        assert page.headers["Pragma"] == "no-cache"

    def test_the_oauth_surfaces_keep_no_store(self, client, auth_header):
        token = client.post(
            "/token", data={"grant_type": "client_credentials"}, headers=auth_header
        )

        assert token.headers["Cache-Control"] == "no-store"


class TestNoOtherOriginReadsThePage:
    def test_a_cross_origin_post_without_credentials_in_persona_mode(self, client, app):
        """Persona mode needs no password and no cookie, so without this a
        script of any origin could read a signed assertion."""
        with app.app_context():
            get_config().settings.login_mode = "persona"

        page = _login(app.test_client(), {"username": "admin"}, headers=EVIL)

        _assert_delivers_to_the_acs(page)
        allowed = page.headers.get("Access-Control-Allow-Origin")
        assert allowed == "http://localhost"
        assert "Access-Control-Allow-Credentials" not in page.headers

    def test_the_rule_stays_open_elsewhere(self, client):
        other = client.get("/.well-known/openid-configuration", headers=EVIL)

        assert other.headers.get("Access-Control-Allow-Origin") is not None
