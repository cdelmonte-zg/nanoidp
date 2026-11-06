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


def _authn_request():
    return (
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1" '
        f'Version="2.0" IssueInstant="2026-11-06T00:00:00Z" AssertionConsumerServiceURL="{ACS}">'
        '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer>'
        "</samlp:AuthnRequest>"
    )


def _redirect_binding_query():
    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(_authn_request().encode()) + compressor.flush()
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


def _one_shot_post(client, headers):
    """The attack: one POST from a page of another origin, the HTTP-POST
    binding, no GET before it, no cookie, no password."""
    xml = _authn_request()
    return client.post(
        "/saml/sso",
        data={
            "SAMLRequest": base64.b64encode(xml.encode()).decode(),
            "RelayState": "r",
            "username": "admin",
        },
        headers=headers,
    )


class TestNoOtherOriginReadsThePage:
    def test_a_one_shot_cross_origin_post_in_persona_mode(self, client, app):
        """Persona mode needs no password and no cookie, so without this a
        script of any origin could read a signed assertion. The header is
        absent, not narrowed: a same-origin read needs none."""
        with app.app_context():
            get_config().settings.login_mode = "persona"

        page = _one_shot_post(client, EVIL)

        _assert_delivers_to_the_acs(page)
        assert "Access-Control-Allow-Origin" not in page.headers

    def test_a_forwarded_host_cannot_name_the_allowed_origin(self, client, app):
        """X-Forwarded-Host is a header a script may set: nothing about
        this page's CORS answer comes from the request."""
        with app.app_context():
            settings = get_config().settings
            settings.login_mode = "persona"
            settings.issuer_from_proxy_headers = True

        page = _one_shot_post(
            client,
            {**EVIL, "X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http"},
        )

        assert "Access-Control-Allow-Origin" not in page.headers

    def test_an_origin_the_operator_named_may_still_read_it(self, isolated_repo_config):
        """A declared cors_allowed_origins is the operator's decision: it
        stays the list on these pages too (a browser test harness), and an
        origin outside it reads nothing."""
        from tests.test_timing_and_cors_settings import _client

        client = _client(
            isolated_repo_config,
            cors_allowed_origins=["http://harness.test:3000"],
            login={"mode": "persona"},
        )

        named = _one_shot_post(client, {"Origin": "http://harness.test:3000"})
        other = _one_shot_post(client, EVIL)

        assert named.headers.get("Access-Control-Allow-Origin") == "http://harness.test:3000"
        assert "Access-Control-Allow-Origin" not in other.headers

    def test_the_rule_stays_open_elsewhere(self, client):
        other = client.get("/.well-known/openid-configuration", headers=EVIL)

        assert other.headers.get("Access-Control-Allow-Origin") is not None
