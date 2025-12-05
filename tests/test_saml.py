"""
Tests for SAML 2.0 functionality in NanoIDP.

Tests cover:
- SAML IdP metadata endpoint
- SAML assertion generation
- SAML SSO flow
- SAML AttributeQuery endpoint
- SAML signature handling
"""

import base64
import zlib
import pytest
from lxml import etree
from unittest.mock import patch

SAML_NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
    "soap": "http://schemas.xmlsoap.org/soap/envelope/",
}


class TestSAMLMetadata:
    """Tests for SAML IdP metadata endpoint."""

    def test_metadata_endpoint_returns_xml(self, client):
        """Test that metadata endpoint returns XML content."""
        response = client.get('/saml/metadata')
        assert response.status_code == 200
        assert 'xml' in response.content_type.lower()

    def test_metadata_is_valid_xml(self, client):
        """Test that metadata is well-formed XML."""
        response = client.get('/saml/metadata')
        # Should not raise parsing error
        root = etree.fromstring(response.data)
        assert root is not None

    def test_metadata_contains_entity_id(self, client):
        """Test that metadata contains EntityID."""
        response = client.get('/saml/metadata')
        root = etree.fromstring(response.data)

        entity_id = root.get("entityID")
        assert entity_id is not None
        assert len(entity_id) > 0

    def test_metadata_contains_idp_descriptor(self, client):
        """Test that metadata contains IDPSSODescriptor."""
        response = client.get('/saml/metadata')
        root = etree.fromstring(response.data)

        idp_descriptor = root.find(".//md:IDPSSODescriptor", SAML_NS)
        assert idp_descriptor is not None

    def test_metadata_contains_sso_service(self, client):
        """Test that metadata contains SingleSignOnService."""
        response = client.get('/saml/metadata')
        root = etree.fromstring(response.data)

        sso_service = root.find(".//md:SingleSignOnService", SAML_NS)
        assert sso_service is not None

        location = sso_service.get("Location")
        assert location is not None
        assert '/saml/sso' in location

    def test_metadata_contains_signing_key(self, client):
        """Test that metadata contains KeyDescriptor for signing."""
        response = client.get('/saml/metadata')
        root = etree.fromstring(response.data)

        key_descriptor = root.find(".//md:KeyDescriptor[@use='signing']", SAML_NS)
        assert key_descriptor is not None

        x509_cert = key_descriptor.find(".//ds:X509Certificate", SAML_NS)
        assert x509_cert is not None
        assert x509_cert.text is not None
        # Certificate should be base64 encoded
        assert len(x509_cert.text.strip()) > 100


class TestSAMLCertificate:
    """Tests for SAML certificate endpoint."""

    def test_cert_endpoint_returns_pem(self, client):
        """Test that certificate endpoint returns PEM format."""
        response = client.get('/saml/cert.pem')
        assert response.status_code == 200
        assert response.data.startswith(b'-----BEGIN CERTIFICATE-----')

    def test_cert_is_valid_pem(self, client):
        """Test that certificate is valid PEM format."""
        response = client.get('/saml/cert.pem')
        cert_data = response.data.decode('utf-8')

        assert '-----BEGIN CERTIFICATE-----' in cert_data
        assert '-----END CERTIFICATE-----' in cert_data


class TestSAMLSSO:
    """Tests for SAML SSO endpoint."""

    def _create_saml_request(self, acs_url=None, request_id="_req123"):
        """Create a minimal SAMLRequest for testing."""
        acs_attr = f' AssertionConsumerServiceURL="{acs_url}"' if acs_url else ""
        saml_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="2025-01-01T00:00:00Z"{acs_attr}>
    <saml:Issuer>http://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>"""

        # Compress and base64 encode
        compressed = zlib.compress(saml_request.encode('utf-8'))[2:-4]  # Remove zlib header/trailer
        return base64.b64encode(compressed).decode('ascii')

    def test_sso_requires_saml_request(self, client):
        """Test that SSO endpoint requires SAMLRequest."""
        response = client.post('/saml/sso')
        assert response.status_code == 400

    def test_sso_redirects_to_login_when_not_authenticated(self, client):
        """Test that SSO redirects to login for unauthenticated users."""
        saml_request = self._create_saml_request()
        response = client.post('/saml/sso',
            data={'SAMLRequest': saml_request},
            follow_redirects=False
        )
        assert response.status_code == 302
        assert '/login' in response.headers.get('Location', '')

    def test_sso_returns_saml_response_when_authenticated(self, client):
        """Test that SSO returns SAML response for authenticated users."""
        # First authenticate
        with client.session_transaction() as sess:
            sess['user'] = 'admin'

        saml_request = self._create_saml_request(acs_url='http://sp.example.com/acs')
        response = client.post('/saml/sso',
            data={'SAMLRequest': saml_request}
        )

        assert response.status_code == 200
        # Response should contain auto-submit form with SAMLResponse
        response_text = response.data.decode('utf-8')
        assert 'SAMLResponse' in response_text
        assert 'form' in response_text.lower()

    def test_sso_includes_relay_state(self, client):
        """Test that SSO preserves RelayState."""
        with client.session_transaction() as sess:
            sess['user'] = 'admin'

        saml_request = self._create_saml_request(acs_url='http://sp.example.com/acs')
        relay_state = 'https://app.example.com/target'

        response = client.post('/saml/sso',
            data={'SAMLRequest': saml_request, 'RelayState': relay_state}
        )

        response_text = response.data.decode('utf-8')
        assert relay_state in response_text


class TestSAMLResponse:
    """Tests for SAML response generation."""

    def test_saml_response_contains_assertion(self, client):
        """Test that SAML response contains an Assertion."""
        from nanoidp.routes.saml import _build_saml_response

        xml = _build_saml_response(
            acs_url='http://sp.example.com/acs',
            issuer='http://localhost:8000/saml',
            audience='http://sp.example.com',
            name_id='admin',
            attributes={'email': 'admin@example.com'},
            sign=False
        )

        root = etree.fromstring(xml)
        assertion = root.find(".//saml2:Assertion", SAML_NS)
        assert assertion is not None

    def test_saml_response_contains_issuer(self, client):
        """Test that SAML response contains Issuer."""
        from nanoidp.routes.saml import _build_saml_response

        issuer_url = 'http://localhost:8000/saml'
        xml = _build_saml_response(
            acs_url='http://sp.example.com/acs',
            issuer=issuer_url,
            audience='http://sp.example.com',
            name_id='admin',
            attributes={},
            sign=False
        )

        root = etree.fromstring(xml)
        issuer_el = root.find(".//saml2:Issuer", SAML_NS)
        assert issuer_el is not None
        assert issuer_el.text == issuer_url

    def test_saml_response_contains_name_id(self, client):
        """Test that SAML response contains NameID."""
        from nanoidp.routes.saml import _build_saml_response

        name_id = 'testuser@example.com'
        xml = _build_saml_response(
            acs_url='http://sp.example.com/acs',
            issuer='http://localhost:8000/saml',
            audience='http://sp.example.com',
            name_id=name_id,
            attributes={},
            sign=False
        )

        root = etree.fromstring(xml)
        name_id_el = root.find(".//saml2:NameID", SAML_NS)
        assert name_id_el is not None
        assert name_id_el.text == name_id

    def test_saml_response_contains_conditions(self, client):
        """Test that SAML response contains Conditions with time bounds."""
        from nanoidp.routes.saml import _build_saml_response

        xml = _build_saml_response(
            acs_url='http://sp.example.com/acs',
            issuer='http://localhost:8000/saml',
            audience='http://sp.example.com',
            name_id='admin',
            attributes={},
            sign=False
        )

        root = etree.fromstring(xml)
        conditions = root.find(".//saml2:Conditions", SAML_NS)
        assert conditions is not None
        assert conditions.get("NotBefore") is not None
        assert conditions.get("NotOnOrAfter") is not None

    def test_saml_response_contains_audience(self, client):
        """Test that SAML response contains Audience restriction."""
        from nanoidp.routes.saml import _build_saml_response

        audience = 'http://sp.example.com'
        xml = _build_saml_response(
            acs_url='http://sp.example.com/acs',
            issuer='http://localhost:8000/saml',
            audience=audience,
            name_id='admin',
            attributes={},
            sign=False
        )

        root = etree.fromstring(xml)
        audience_el = root.find(".//saml2:Audience", SAML_NS)
        assert audience_el is not None
        assert audience_el.text == audience

    def test_saml_response_contains_attributes(self, client):
        """Test that SAML response contains user attributes."""
        from nanoidp.routes.saml import _build_saml_response

        attributes = {
            'email': 'user@example.com',
            'roles': ['USER', 'ADMIN'],
            'identity_class': 'INTERNAL'
        }

        xml = _build_saml_response(
            acs_url='http://sp.example.com/acs',
            issuer='http://localhost:8000/saml',
            audience='http://sp.example.com',
            name_id='admin',
            attributes=attributes,
            sign=False
        )

        root = etree.fromstring(xml)
        attr_statement = root.find(".//saml2:AttributeStatement", SAML_NS)
        assert attr_statement is not None

        # Find email attribute
        attrs = attr_statement.findall(".//saml2:Attribute", SAML_NS)
        attr_names = [a.get("Name") for a in attrs]
        assert 'email' in attr_names
        assert 'roles' in attr_names
        assert 'identity_class' in attr_names

    def test_saml_response_in_response_to(self, client):
        """Test that SAML response includes InResponseTo when provided."""
        from nanoidp.routes.saml import _build_saml_response

        request_id = '_req_abc123'
        xml = _build_saml_response(
            acs_url='http://sp.example.com/acs',
            issuer='http://localhost:8000/saml',
            audience='http://sp.example.com',
            name_id='admin',
            attributes={},
            in_response_to=request_id,
            sign=False
        )

        root = etree.fromstring(xml)
        assert root.get("InResponseTo") == request_id


class TestSAMLAttributeQuery:
    """Tests for SAML AttributeQuery endpoint."""

    def _create_attribute_query(self, user_id='admin', request_id='_req123'):
        """Create a SOAP-wrapped AttributeQuery for testing."""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <saml2p:AttributeQuery
            xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="{request_id}"
            Version="2.0"
            IssueInstant="2025-01-01T00:00:00Z">
            <saml2:Issuer>http://sp.example.com</saml2:Issuer>
            <saml2:Subject>
                <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{user_id}</saml2:NameID>
            </saml2:Subject>
        </saml2p:AttributeQuery>
    </soap:Body>
</soap:Envelope>"""

    def test_attribute_query_returns_response(self, client):
        """Test that AttributeQuery returns a SOAP response."""
        query = self._create_attribute_query(user_id='admin')
        response = client.post('/saml/attribute-query',
            data=query,
            content_type='text/xml'
        )

        assert response.status_code == 200
        assert 'xml' in response.content_type.lower()

    def test_attribute_query_contains_soap_envelope(self, client):
        """Test that AttributeQuery response is wrapped in SOAP."""
        query = self._create_attribute_query(user_id='admin')
        response = client.post('/saml/attribute-query',
            data=query,
            content_type='text/xml'
        )

        root = etree.fromstring(response.data)
        # Should have SOAP envelope
        assert 'Envelope' in root.tag

    def test_attribute_query_returns_user_attributes(self, client):
        """Test that AttributeQuery returns user attributes."""
        query = self._create_attribute_query(user_id='admin')
        response = client.post('/saml/attribute-query',
            data=query,
            content_type='text/xml'
        )

        root = etree.fromstring(response.data)
        attrs = root.findall(".//saml2:Attribute", SAML_NS)

        # Should have at least email attribute
        attr_names = [a.get("Name") for a in attrs]
        assert 'email' in attr_names

    def test_attribute_query_requires_subject(self, client):
        """Test that AttributeQuery requires Subject."""
        # Malformed query without Subject
        bad_query = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <saml2p:AttributeQuery
            xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
            ID="_req123"
            Version="2.0">
        </saml2p:AttributeQuery>
    </soap:Body>
</soap:Envelope>"""

        response = client.post('/saml/attribute-query',
            data=bad_query,
            content_type='text/xml'
        )

        assert response.status_code == 400

    def test_attribute_query_unknown_user_returns_defaults(self, client):
        """Test that AttributeQuery for unknown user returns default attributes."""
        query = self._create_attribute_query(user_id='unknown_user_xyz')
        response = client.post('/saml/attribute-query',
            data=query,
            content_type='text/xml'
        )

        # Should return 200 with default attributes (NanoIDP is permissive)
        assert response.status_code == 200

        root = etree.fromstring(response.data)
        attrs = root.findall(".//saml2:Attribute", SAML_NS)
        attr_names = [a.get("Name") for a in attrs]

        # Should have default attributes
        assert 'email' in attr_names
        assert 'identity_class' in attr_names


class TestSAMLStatus:
    """Tests for SAML status codes in responses."""

    def test_successful_response_has_success_status(self, client):
        """Test that successful SAML response has Success status."""
        from nanoidp.routes.saml import _build_saml_response

        xml = _build_saml_response(
            acs_url='http://sp.example.com/acs',
            issuer='http://localhost:8000/saml',
            audience='http://sp.example.com',
            name_id='admin',
            attributes={},
            sign=False
        )

        root = etree.fromstring(xml)
        status_code = root.find(".//saml2p:StatusCode", SAML_NS)
        assert status_code is not None
        assert 'Success' in status_code.get("Value", "")
