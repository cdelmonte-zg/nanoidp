"""
The SSO assertion's Audience is the requesting service provider (#443).

SAML 2.0 Profiles §4.1.4.2: the assertion of a Web Browser SSO response
carries an AudienceRestriction with the service provider's unique
identifier, which §4.1.4.1 requires the AuthnRequest to name in its Issuer.
Up to #443 every assertion carried ``oauth.audience`` instead, so a service
provider that checks the audience (Spring Security does) rejected the
response unless its entity ID happened to equal that setting.

A request that names no Issuer is outside the profile; nanoidp accepts it
as before and answers with ``oauth.audience``.
"""

import base64
import re
import zlib

import pytest
from lxml import etree

from nanoidp.config import get_config
from nanoidp.services.audit import get_audit_log

SAML_NS = {
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
}
SP = "http://localhost:8080/saml2/service-provider-metadata/nanoidp"
ACS = "http://sp.example.com/acs"


def _authn_request(issuer=SP, request_id="_req443", compress=True):
    issuer_el = f"<saml:Issuer>{issuer}</saml:Issuer>" if issuer is not None else ""
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="2025-01-01T00:00:00Z"
    AssertionConsumerServiceURL="{ACS}">
    {issuer_el}
</samlp:AuthnRequest>"""
    raw = xml.encode("utf-8")
    if compress:
        raw = zlib.compress(raw)[2:-4]
    return base64.b64encode(raw).decode("ascii")


def _response_of(page):
    assert page.status_code == 200, page.get_data(as_text=True)[:300]
    match = re.search(r'name="SAMLResponse"\s+value="([^"]+)"', page.get_data(as_text=True))
    assert match, "no SAMLResponse in the page"
    return etree.fromstring(base64.b64decode(match.group(1)))


def _audience(root):
    return [a.text for a in root.findall(".//saml2:Audience", SAML_NS)]


def _sso(client, saml_request, method="POST"):
    # An authenticated browser: the inline login is exercised on its own below
    with client.session_transaction() as session:
        session["user"] = "admin"
    if method == "GET":
        return client.get("/saml/sso", query_string={"SAMLRequest": saml_request})
    return client.post("/saml/sso", data={"SAMLRequest": saml_request})


class TestTheAudienceIsTheRequestingServiceProvider:
    def test_post_binding(self, client):
        root = _response_of(_sso(client, _authn_request(compress=False)))
        assert _audience(root) == [SP]

    def test_redirect_binding(self, client):
        root = _response_of(_sso(client, _authn_request(compress=True), method="GET"))
        assert _audience(root) == [SP]

    def test_it_is_not_oauth_audience(self, client, app):
        with app.app_context():
            oauth_audience = get_config().settings.audience
        assert SP != oauth_audience
        root = _response_of(_sso(client, _authn_request()))
        assert oauth_audience not in _audience(root)

    def test_each_service_provider_gets_its_own(self, client):
        first = _response_of(_sso(client, _authn_request(issuer="urn:sp:one", request_id="_a")))
        second = _response_of(_sso(client, _authn_request(issuer="urn:sp:two", request_id="_b")))
        assert _audience(first) == ["urn:sp:one"]
        assert _audience(second) == ["urn:sp:two"]

    def test_surrounding_whitespace_is_not_part_of_the_identifier(self, client):
        root = _response_of(_sso(client, _authn_request(issuer=f"\n      {SP}\n    ")))
        assert _audience(root) == [SP]

    def test_the_rest_of_the_response_is_unchanged(self, client):
        root = _response_of(_sso(client, _authn_request(request_id="_same")))
        assert root.get("InResponseTo") == "_same"
        assert root.get("Destination") == ACS
        confirmation = root.find(".//saml2:SubjectConfirmationData", SAML_NS)
        assert confirmation.get("Recipient") == ACS
        assert confirmation.get("InResponseTo") == "_same"


class TestARequestThatNamesNoIssuer:
    """Outside the Browser SSO profile, accepted as before, answered with
    oauth.audience: this issue adds no new reason for a 400."""

    @pytest.mark.parametrize("issuer", [None, "", "   "])
    def test_gets_oauth_audience(self, client, app, issuer):
        with app.app_context():
            oauth_audience = get_config().settings.audience
        root = _response_of(_sso(client, _authn_request(issuer=issuer)))
        assert _audience(root) == [oauth_audience]


class TestThroughTheInlineLogin:
    """The login form re-POSTs the SAMLRequest it was shown for; the
    Issuer travels with it, whichever binding the request arrived by."""

    @pytest.mark.parametrize("compress", [True, False])
    def test_the_audience_survives_the_form(self, app, compress):
        fresh = app.test_client()  # no session: the form is shown
        request = _authn_request(compress=compress)
        if compress:
            first = fresh.get("/saml/sso", query_string={"SAMLRequest": request})
        else:
            first = fresh.post("/saml/sso", data={"SAMLRequest": request})
        assert first.status_code == 200
        page = first.get_data(as_text=True)
        assert "SAMLResponse" not in page, "expected the login form for a fresh browser"
        original_verb = re.search(r'name="saml_original_verb"\s+value="([^"]+)"', page)
        form = {
            "username": "admin", "password": "admin",
            "SAMLRequest": request, "RelayState": "",
        }
        if original_verb:
            form["saml_original_verb"] = original_verb.group(1)
        root = _response_of(fresh.post("/saml/sso", data=form))
        assert _audience(root) == [SP]


class TestTheAuditSaysWhichServiceProviderGotWhichAudience:
    def test_with_an_issuer(self, client):
        _response_of(_sso(client, _authn_request()))
        entry = get_audit_log().get_entries(limit=5, event_type="saml_request")[0]
        assert entry["details"]["sp_issuer"] == SP
        assert entry["details"]["audience"] == SP
        assert entry["details"]["acs_url"] == ACS

    @pytest.mark.parametrize("issuer", [None, "", "   "])
    def test_without_one(self, client, app, issuer):
        """Absent or blank, the audit says null: a blank identifier is no
        identifier, and the fallback is visible as such."""
        with app.app_context():
            oauth_audience = get_config().settings.audience
        _response_of(_sso(client, _authn_request(issuer=issuer)))
        entry = get_audit_log().get_entries(limit=5, event_type="saml_request")[0]
        assert entry["details"]["sp_issuer"] is None
        assert entry["details"]["audience"] == oauth_audience
