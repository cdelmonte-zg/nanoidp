"""
The single home for SAML attribute resolution (#302), and the pins for
what the unification deliberately changed vs deliberately kept different.

Divergence table (see services/saml_attributes.py and saml.md):
CHANGED (finishing existing rules): no fabricated email (#275); list
customs per-value, strings never comma-split (#134); empty collections
omitted. KEPT: source_acl only on the attribute query; the query assertion
carries no AuthnStatement/SubjectConfirmation (an attribute lookup is not
an authentication event).
"""

from lxml import etree

from nanoidp.config import get_config
from nanoidp.services.saml_attributes import (
    append_attribute_statement,
    resolve_saml_attributes,
)

SAML_NS = {
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
}


class _U:
    """Minimal user stand-in."""

    def __init__(self, **kw):
        self.email = kw.get("email")
        self.identity_class = kw.get("identity_class")
        self.entitlements = kw.get("entitlements", [])
        self.source_acl = kw.get("source_acl", [])
        self.roles = kw.get("roles", [])
        self.groups = kw.get("groups", [])
        self.attributes = kw.get("attributes", {})


class _S:
    saml_export_roles = False
    saml_export_groups = False
    saml_roles_attr_name = "roles"
    saml_groups_attr_name = "groups"


class TestResolver:
    def test_full_user_both_surfaces_differ_only_by_source_acl(self):
        user = _U(
            email="a@b.c",
            identity_class="INTERNAL",
            entitlements=["E1"],
            source_acl=["ACL_READ"],
            attributes={"dept": "eng"},
        )
        sso = resolve_saml_attributes(_S(), user, include_source_acl=False)
        query = resolve_saml_attributes(_S(), user, include_source_acl=True)
        assert set(query) - set(sso) == {"source_acl"}
        assert {k: v for k, v in query.items() if k != "source_acl"} == sso

    def test_no_email_is_no_email_attribute(self):
        """#275 rule extended here: the old query surface fabricated
        <user>@example.com."""
        attrs = resolve_saml_attributes(_S(), _U(), include_source_acl=True)
        assert "email" not in attrs

    def test_empty_collections_are_omitted(self):
        attrs = resolve_saml_attributes(
            _S(),
            _U(entitlements=[], attributes={"x": [], "y": "", "z": None}),
            include_source_acl=True,
        )
        assert attrs == {}

    def test_custom_list_stays_a_list(self):
        attrs = resolve_saml_attributes(
            _S(), _U(attributes={"teams": ["a", "b"]}), include_source_acl=False
        )
        assert attrs["teams"] == ["a", "b"]

    def test_export_collision_merges_roles_first(self):
        class S(_S):
            saml_export_roles = True
            saml_export_groups = True
            saml_roles_attr_name = "memberOf"
            saml_groups_attr_name = "memberOf"

        attrs = resolve_saml_attributes(
            S(), _U(roles=["R1"], groups=["G1", "R1"]), include_source_acl=False
        )
        assert attrs["memberOf"] == ["R1", "G1"]


class TestEmission:
    def _emit(self, attributes):
        assertion = etree.Element("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        append_attribute_statement(assertion, attributes)
        return assertion

    def test_list_becomes_one_value_per_entry(self):
        assertion = self._emit({"entitlements": ["A", "B"]})
        values = assertion.findall(".//saml2:AttributeValue", SAML_NS)
        assert [v.text for v in values] == ["A", "B"]

    def test_comma_bearing_string_stays_one_value(self):
        """The #134 rule the old query builder contradicted: strings are
        never comma-split."""
        assertion = self._emit({"note": "a,b,c"})
        values = assertion.findall(".//saml2:AttributeValue", SAML_NS)
        assert [v.text for v in values] == ["a,b,c"]

    def test_empty_dict_emits_no_statement(self):
        assertion = self._emit({})
        assert assertion.findall(".//saml2:AttributeStatement", SAML_NS) == []


class TestSurfacesEndToEnd:
    def _query(self, user_id):
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            "<soap:Body>"
            '<samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' ID="_aq" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">'
            "<saml:Issuer>sp</saml:Issuer>"
            f"<saml:Subject><saml:NameID>{user_id}</saml:NameID></saml:Subject>"
            "</samlp:AttributeQuery></soap:Body></soap:Envelope>"
        )

    def test_query_no_fabricated_email_and_lists_per_value(self, client, app):
        with app.app_context():
            user = get_config().get_user("admin")
            original_email = user.email
            original_attrs = user.attributes
            user.email = ""  # User.email is non-Optional str; falsy = absent
            user.attributes = {"teams": ["alpha", "beta"], "note": "x,y"}
        try:
            resp = client.post(
                "/saml/attribute-query",
                data=self._query("admin"),
                content_type="text/xml",
            )
            assert resp.status_code == 200
            root = etree.fromstring(resp.data)
            names = [
                a.get("Name") for a in root.findall(".//saml2:Attribute", SAML_NS)
            ]
            assert "email" not in names, "no fabricated email (#275 rule)"
            teams = [
                v.text
                for a in root.findall(".//saml2:Attribute", SAML_NS)
                if a.get("Name") == "teams"
                for v in a.findall("saml2:AttributeValue", SAML_NS)
            ]
            assert teams == ["alpha", "beta"], "list customs per-value (#134)"
            note = [
                v.text
                for a in root.findall(".//saml2:Attribute", SAML_NS)
                if a.get("Name") == "note"
                for v in a.findall("saml2:AttributeValue", SAML_NS)
            ]
            assert note == ["x,y"], "comma-bearing string stays one value (#134)"
        finally:
            with app.app_context():
                user = get_config().get_user("admin")
                user.email = original_email
                user.attributes = original_attrs

    def test_query_assertion_has_no_authn_statement(self, client):
        """Deliberate (documented, NOT a gap): an attribute lookup is not an
        authentication event."""
        resp = client.post(
            "/saml/attribute-query",
            data=self._query("admin"),
            content_type="text/xml",
        )
        root = etree.fromstring(resp.data)
        assert root.findall(".//saml2:AuthnStatement", SAML_NS) == []
        assert root.findall(".//saml2:Assertion", SAML_NS) != []
