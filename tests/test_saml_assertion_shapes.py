"""The exact documents the two SAML builders produce (#317).

Byte-level pins taken BEFORE the assertion core is extracted, so the
extraction can be shown to change nothing. A direct comparison is only
stable once the two sources of entropy are fixed: ``IssueInstant``, the
``Conditions`` window and ``SessionIndex`` all come from ``datetime.now``,
and every ID from ``uuid.uuid4``. Both are module-level names in
``routes/saml.py``, so the fixture replaces them there. The SSO builder is
compared with ``sign=False``: a signature puts a fresh digest in every run
and is not what this file is about.

These goldens ARE the observable output. Regenerating one because it failed
is the exact thing they exist to prevent: a change here is a change to what
a service provider receives, and it belongs in the CHANGELOG with a reason.

The class below spells out the divergences the #317 census found, so a
failure reads as a sentence rather than as a blob diff - including the two
that were in neither the docs nor any test: the Conditions window (5
minutes against 1 hour) and the ds namespace declaration.
"""

from datetime import datetime, timezone

import pytest
from lxml import etree

import nanoidp.routes.saml as saml

_INSTANT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


class _FrozenDateTime:
    """Only ``now`` is reached by the builders."""

    @staticmethod
    def now(tz=None):
        return _INSTANT.astimezone(tz) if tz else _INSTANT


class _SequencedUUID:
    """Ids in the order the builder asks for them, so a reordering of the
    id-consuming elements shows up in the golden too."""

    def __init__(self):
        self.count = 0

    def uuid4(self):
        self.count += 1
        return type("_U", (), {"hex": f"{self.count:032x}"})()


@pytest.fixture
def frozen(monkeypatch):
    monkeypatch.setattr(saml, "datetime", _FrozenDateTime)
    monkeypatch.setattr(saml, "uuid", _SequencedUUID())


def _sso(**overrides):
    arguments = {
        "acs_url": "https://sp.example/acs",
        "issuer": "https://idp.example",
        "audience": "aud-x",
        "name_id": "alice",
        "attributes": {"email": "a@b.c"},
        "in_response_to": "_req1",
        "sign": False,
    }
    arguments.update(overrides)
    return saml._build_saml_response(**arguments)


def _query(**overrides):
    arguments = {
        "user_id": "alice",
        "attributes": {"email": "a@b.c"},
        "request_id": "_req1",
        "issuer_url": "https://idp.example",
    }
    arguments.update(overrides)
    return saml._build_attribute_query_response(**arguments)


SSO_RESPONSE = (
    b'<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_00000000000000000000000000000001" Version="2.0" IssueInstant="2026-01-02T03:04:05Z" Destination="https://sp.example/acs" InResponseTo="_req1">'
    b'<saml2:Issuer>https://idp.example</saml2:Issuer><saml2p:Status>'
    b'<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
    b'</saml2p:Status>'
    b'<saml2:Assertion ID="_00000000000000000000000000000002" Version="2.0" IssueInstant="2026-01-02T03:04:05Z">'
    b'<saml2:Issuer>https://idp.example</saml2:Issuer><saml2:Subject>'
    b'<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml2:NameID>'
    b'<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
    b'<saml2:SubjectConfirmationData NotOnOrAfter="2026-01-02T03:09:05Z" Recipient="https://sp.example/acs" InResponseTo="_req1"/>'
    b'</saml2:SubjectConfirmation></saml2:Subject>'
    b'<saml2:Conditions NotBefore="2026-01-02T03:04:05Z" NotOnOrAfter="2026-01-02T03:09:05Z">'
    b'<saml2:AudienceRestriction><saml2:Audience>aud-x</saml2:Audience>'
    b'</saml2:AudienceRestriction></saml2:Conditions>'
    b'<saml2:AuthnStatement AuthnInstant="2026-01-02T03:04:05Z" SessionIndex="_00000000000000000000000000000003">'
    b'<saml2:AuthnContext>'
    b'<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>'
    b'</saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement>'
    b'<saml2:Attribute Name="email"><saml2:AttributeValue>a@b.c</saml2:AttributeValue>'
    b'</saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>'
    b'</saml2p:Response>'
)

ATTRIBUTE_QUERY_RESPONSE = (
    '<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_00000000000000000000000000000001" Version="2.0" IssueInstant="2026-01-02T03:04:05Z" InResponseTo="_req1">\n'
    '  <saml2:Issuer>https://idp.example</saml2:Issuer>\n'
    '  <saml2p:Status>\n'
    '    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>\n'
    '  </saml2p:Status>\n'
    '  <saml2:Assertion ID="_00000000000000000000000000000002" Version="2.0" IssueInstant="2026-01-02T03:04:05Z">\n'
    '    <saml2:Issuer>https://idp.example</saml2:Issuer>\n'
    '    <saml2:Subject>\n'
    '      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml2:NameID>\n'
    '    </saml2:Subject>\n'
    '    <saml2:Conditions NotBefore="2026-01-02T03:04:05Z" NotOnOrAfter="2026-01-02T04:04:05Z"/>\n'
    '    <saml2:AttributeStatement>\n'
    '      <saml2:Attribute Name="email">\n'
    '        <saml2:AttributeValue>a@b.c</saml2:AttributeValue>\n'
    '      </saml2:Attribute>\n'
    '    </saml2:AttributeStatement>\n'
    '  </saml2:Assertion>\n'
    '</saml2p:Response>\n'
)


ATTRIBUTE_QUERY_ERROR_RESPONSE = (
    '<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_00000000000000000000000000000001" Version="2.0" IssueInstant="2026-01-02T03:04:05Z" InResponseTo="_req1">'
    '<saml2:Issuer>https://idp.example</saml2:Issuer><saml2p:Status>'
    '<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">'
    '<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"/>'
    '</saml2p:StatusCode></saml2p:Status></saml2p:Response>'
)


def _query_error(**overrides):
    arguments = {"request_id": "_req1", "issuer_url": "https://idp.example"}
    arguments.update(overrides)
    return saml._build_attribute_query_error_response(**arguments)


class TestTheDocumentsThemselves:
    def test_the_sso_response_is_this_document(self, app, frozen):
        with app.app_context():
            assert _sso() == SSO_RESPONSE

    def test_the_attribute_query_response_is_this_document(self, app, frozen):
        with app.app_context():
            assert _query() == ATTRIBUTE_QUERY_RESPONSE

    def test_the_attribute_query_error_response_is_this_document(self, app, frozen):
        """The third envelope builder, which the #317 census first missed:
        an unknown principal gets a Response with no assertion (#275)."""
        with app.app_context():
            assert _query_error() == ATTRIBUTE_QUERY_ERROR_RESPONSE


class TestWhatTheTwoBuildersDoNotShare:
    """The census table of #317, asserted. Each row is a difference that
    must survive the extraction, not one to be tidied away by it."""

    def test_the_conditions_windows_differ(self, app, frozen):
        """Five minutes against one hour. Undocumented and untested before
        #317: the only assertion on Conditions was "not None"."""
        with app.app_context():
            assert b'NotOnOrAfter="2026-01-02T03:09:05Z"' in _sso()
            assert 'NotOnOrAfter="2026-01-02T04:04:05Z"' in _query()

    def test_only_the_sso_response_names_a_destination(self, app, frozen):
        with app.app_context():
            assert b'Destination="https://sp.example/acs"' in _sso()
            assert "Destination" not in _query()

    def test_only_the_sso_response_declares_the_signature_namespace(self, app, frozen):
        """``ds`` is declared on the envelope whether or not the document is
        signed. An implementation detail that is part of the bytes an SP
        receives, so it is pinned rather than cleaned up."""
        with app.app_context():
            assert b'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"' in _sso()
            assert "xmlns:ds" not in _query()

    def test_in_response_to_is_conditional_on_one_side_and_always_on_the_other(
        self, app, frozen
    ):
        """An IdP-initiated login has no request to answer; an attribute
        query always does."""
        with app.app_context():
            unsolicited = _sso(in_response_to=None)

        assert b"InResponseTo" not in unsolicited
        with app.app_context():
            assert 'InResponseTo="_req1"' in _query()

    def test_the_two_documents_are_serialized_differently(self, app, frozen):
        """bytes with an XML declaration against a pretty-printed unicode
        string: the return TYPES differ, which is why neither builder can
        simply call the other."""
        with app.app_context():
            sso, query = _sso(), _query()

        assert isinstance(sso, bytes) and sso.startswith(b"<?xml version=")
        assert isinstance(query, str) and not query.startswith("<?xml")
        # The SSO document breaks the line once, after the declaration, and
        # is one line from there; the query is indented throughout.
        assert sso.count(b"\n") == 1
        assert query.count("\n") > 5

    def test_the_error_response_shares_the_envelope_and_differs_in_status(self, app, frozen):
        """Same Response attributes and same Issuer as the success builder
        two functions above, a nested failure status instead of Success, and
        no assertion at all: the part that makes the core worth having, and
        the part that must not be folded into it."""
        with app.app_context():
            success, failure = _query(), _query_error()

        envelope = {}
        for name, document in (("success", success), ("failure", failure)):
            root = etree.fromstring(document.encode())
            # The ID is a fresh uuid per document by design; everything else
            # on the envelope is the part the two share.
            envelope[name] = {k: v for k, v in root.attrib.items() if k != "ID"}
        assert envelope["success"] == envelope["failure"]
        assert "<saml2:Issuer>https://idp.example</saml2:Issuer>" in failure
        assert "urn:oasis:names:tc:SAML:2.0:status:Success" in success
        assert "urn:oasis:names:tc:SAML:2.0:status:Requester" in failure
        assert "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal" in failure
        assert "Assertion" not in failure

    def test_the_error_response_is_serialized_differently_again(self, app, frozen):
        """A third spelling: unicode, no XML declaration, not pretty-printed."""
        with app.app_context():
            failure = _query_error()

        assert isinstance(failure, str)
        assert not failure.startswith("<?xml")
        assert "\n" not in failure

    def test_only_the_sso_assertion_carries_the_login_elements(self, app, frozen):
        """Already documented in saml.md, pinned here with the rest."""
        with app.app_context():
            sso, query = _sso(), _query()

        for element in (b"AuthnStatement", b"SubjectConfirmation", b"AudienceRestriction"):
            assert element in sso
            assert element.decode() not in query
