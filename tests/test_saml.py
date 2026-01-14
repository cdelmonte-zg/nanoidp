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


class TestSAMLSigningConfiguration:
    """Tests for configurable SAML response signing."""

    def test_unsigned_response_has_no_signature(self, client):
        """Test that SAML response without signing has no Signature element."""
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
        signature = root.find(".//ds:Signature", SAML_NS)
        assert signature is None, "Unsigned response should not contain Signature element"

    def test_signed_response_has_signature(self, client):
        """Test that SAML response with signing has Signature element."""
        from nanoidp.routes.saml import _build_saml_response

        xml = _build_saml_response(
            acs_url='http://sp.example.com/acs',
            issuer='http://localhost:8000/saml',
            audience='http://sp.example.com',
            name_id='admin',
            attributes={'email': 'admin@example.com'},
            sign=True
        )

        root = etree.fromstring(xml)
        # If signxml is available, signature should be present
        try:
            from signxml import XMLSigner
            signature = root.find(".//ds:Signature", SAML_NS)
            assert signature is not None, "Signed response should contain Signature element"
        except ImportError:
            # signxml not available, skip signature check
            pass

    def test_config_controls_sso_signing(self, client):
        """Test that saml_sign_responses config controls SSO response signing."""
        from nanoidp.config import get_config

        # Authenticate
        with client.session_transaction() as sess:
            sess['user'] = 'admin'

        # Create a minimal SAMLRequest
        saml_request = """<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_req123"
    Version="2.0"
    IssueInstant="2025-01-01T00:00:00Z"
    AssertionConsumerServiceURL="http://sp.example.com/acs">
    <saml:Issuer>http://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>"""
        compressed = zlib.compress(saml_request.encode('utf-8'))[2:-4]
        saml_request_b64 = base64.b64encode(compressed).decode('ascii')

        # Get config and temporarily disable signing
        config = get_config()
        original_value = config.settings.saml_sign_responses
        config.settings.saml_sign_responses = False

        try:
            response = client.post('/saml/sso',
                data={'SAMLRequest': saml_request_b64}
            )
            assert response.status_code == 200

            # Extract SAMLResponse from the form
            response_text = response.data.decode('utf-8')
            import re
            match = re.search(r'name="SAMLResponse"\s+value="([^"]+)"', response_text)
            assert match, "SAMLResponse not found in form"

            saml_response_b64 = match.group(1)
            saml_response_xml = base64.b64decode(saml_response_b64)
            root = etree.fromstring(saml_response_xml)

            # When sign_responses=False, there should be no signature
            signature = root.find(".//ds:Signature", SAML_NS)
            assert signature is None, "Response should be unsigned when saml_sign_responses=False"
        finally:
            # Restore original config
            config.settings.saml_sign_responses = original_value

    def test_attribute_query_respects_signing_config(self, client):
        """Test that AttributeQuery response respects saml_sign_responses config."""
        from nanoidp.config import get_config

        config = get_config()
        original_value = config.settings.saml_sign_responses
        config.settings.saml_sign_responses = False

        try:
            query = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <saml2p:AttributeQuery
            xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_req123"
            Version="2.0"
            IssueInstant="2025-01-01T00:00:00Z">
            <saml2:Issuer>http://sp.example.com</saml2:Issuer>
            <saml2:Subject>
                <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">admin</saml2:NameID>
            </saml2:Subject>
        </saml2p:AttributeQuery>
    </soap:Body>
</soap:Envelope>"""

            response = client.post('/saml/attribute-query',
                data=query,
                content_type='text/xml'
            )

            assert response.status_code == 200
            root = etree.fromstring(response.data)

            # When sign_responses=False, there should be no signature
            signature = root.find(".//ds:Signature", SAML_NS)
            assert signature is None, "AttributeQuery response should be unsigned when saml_sign_responses=False"
        finally:
            config.settings.saml_sign_responses = original_value

    def test_signed_response_uses_c14n_1_0(self, client):
        """Test that signed SAML response uses C14N 1.0 for pysaml2 compatibility.

        pysaml2 and many other SAML libraries expect C14N 1.0:
        http://www.w3.org/TR/2001/REC-xml-c14n-20010315

        Not C14N 1.1:
        http://www.w3.org/2006/12/xml-c14n11
        """
        from nanoidp.routes.saml import _build_saml_response

        try:
            from signxml import XMLSigner
        except ImportError:
            pytest.skip("signxml not available")

        xml = _build_saml_response(
            acs_url='http://sp.example.com/acs',
            issuer='http://localhost:8000/saml',
            audience='http://sp.example.com',
            name_id='admin',
            attributes={'email': 'admin@example.com'},
            sign=True
        )

        root = etree.fromstring(xml)

        # Check CanonicalizationMethod
        c14n_method = root.find(".//ds:CanonicalizationMethod", SAML_NS)
        assert c14n_method is not None, "CanonicalizationMethod element not found"

        c14n_algo = c14n_method.get("Algorithm")
        # C14N 1.0 (compatible with pysaml2)
        expected_c14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        # C14N 1.1 (NOT compatible with pysaml2)
        incompatible_c14n = "http://www.w3.org/2006/12/xml-c14n11"

        assert c14n_algo != incompatible_c14n, \
            f"C14N 1.1 is not compatible with pysaml2. Use C14N 1.0 instead."
        assert c14n_algo == expected_c14n, \
            f"Expected C14N 1.0 algorithm, got: {c14n_algo}"

    def test_signed_response_transform_uses_c14n_1_0(self, client):
        """Test that Transform element also uses C14N 1.0."""
        from nanoidp.routes.saml import _build_saml_response

        try:
            from signxml import XMLSigner
        except ImportError:
            pytest.skip("signxml not available")

        xml = _build_saml_response(
            acs_url='http://sp.example.com/acs',
            issuer='http://localhost:8000/saml',
            audience='http://sp.example.com',
            name_id='admin',
            attributes={'email': 'admin@example.com'},
            sign=True
        )

        root = etree.fromstring(xml)

        # Check Transform elements for C14N algorithm
        transforms = root.findall(".//ds:Transform", SAML_NS)

        incompatible_c14n = "http://www.w3.org/2006/12/xml-c14n11"
        expected_c14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"

        for transform in transforms:
            algo = transform.get("Algorithm")
            if "c14n" in algo.lower():
                assert algo != incompatible_c14n, \
                    f"Transform uses C14N 1.1 which is not compatible with pysaml2"
                assert algo == expected_c14n, \
                    f"Expected C14N 1.0 in Transform, got: {algo}"

    def test_c14n_algorithm_configurable_to_c14n11(self, client):
        """Test that c14n_algorithm can be configured to use C14N 1.1."""
        from nanoidp.config import get_config
        from nanoidp.routes.saml import _build_saml_response

        try:
            from signxml import XMLSigner
        except ImportError:
            pytest.skip("signxml not available")

        config = get_config()
        original_value = config.settings.saml_c14n_algorithm
        config.settings.saml_c14n_algorithm = "c14n11"

        try:
            xml = _build_saml_response(
                acs_url='http://sp.example.com/acs',
                issuer='http://localhost:8000/saml',
                audience='http://sp.example.com',
                name_id='admin',
                attributes={'email': 'admin@example.com'},
                sign=True
            )

            root = etree.fromstring(xml)
            c14n_method = root.find(".//ds:CanonicalizationMethod", SAML_NS)
            assert c14n_method is not None

            c14n_algo = c14n_method.get("Algorithm")
            expected_c14n11 = "http://www.w3.org/2006/12/xml-c14n11"

            assert c14n_algo == expected_c14n11, \
                f"Expected C14N 1.1 when configured, got: {c14n_algo}"
        finally:
            config.settings.saml_c14n_algorithm = original_value


class TestSAMLSigningUI:
    """Tests for SAML signing configuration via UI."""

    def test_settings_page_shows_sign_responses_toggle(self, client):
        """Test that settings page contains sign_responses checkbox."""
        # Login first
        with client.session_transaction() as sess:
            sess['user'] = 'admin'

        response = client.get('/settings')
        assert response.status_code == 200
        assert b'saml_sign_responses' in response.data
        assert b'Sign SAML Responses' in response.data

    def test_settings_page_shows_current_sign_responses_value(self, client):
        """Test that settings page shows current sign_responses value."""
        from nanoidp.config import get_config

        with client.session_transaction() as sess:
            sess['user'] = 'admin'

        config = get_config()
        original_value = config.settings.saml_sign_responses

        response = client.get('/settings')
        assert response.status_code == 200

        # If sign_responses is True, checkbox should be checked
        if original_value:
            assert b'checked' in response.data

    def test_settings_post_updates_sign_responses_true(self, client):
        """Test that POST to settings can enable sign_responses."""
        from nanoidp.config import get_config

        with client.session_transaction() as sess:
            sess['user'] = 'admin'

        config = get_config()
        original_value = config.settings.saml_sign_responses

        try:
            # POST with sign_responses checked
            response = client.post('/settings', data={
                'issuer': config.settings.issuer,
                'audience': config.settings.audience,
                'token_expiry_minutes': config.settings.token_expiry_minutes,
                'saml_entity_id': config.settings.saml_entity_id,
                'saml_sso_url': config.settings.saml_sso_url,
                'default_acs_url': config.settings.default_acs_url,
                'saml_sign_responses': 'true',
                'allowed_identity_classes': 'INTERNAL\nEXTERNAL',
            }, follow_redirects=True)

            assert response.status_code == 200
            config.reload()
            assert config.settings.saml_sign_responses is True
        finally:
            # Restore original value
            config.settings.saml_sign_responses = original_value

    def test_settings_post_updates_sign_responses_false(self, client):
        """Test that POST to settings can disable sign_responses."""
        from nanoidp.config import get_config

        with client.session_transaction() as sess:
            sess['user'] = 'admin'

        config = get_config()
        original_value = config.settings.saml_sign_responses

        try:
            # POST without sign_responses (unchecked checkbox)
            response = client.post('/settings', data={
                'issuer': config.settings.issuer,
                'audience': config.settings.audience,
                'token_expiry_minutes': config.settings.token_expiry_minutes,
                'saml_entity_id': config.settings.saml_entity_id,
                'saml_sso_url': config.settings.saml_sso_url,
                'default_acs_url': config.settings.default_acs_url,
                # saml_sign_responses NOT included = unchecked
                'allowed_identity_classes': 'INTERNAL\nEXTERNAL',
            }, follow_redirects=True)

            assert response.status_code == 200
            config.reload()
            assert config.settings.saml_sign_responses is False
        finally:
            # Restore original value
            config.settings.saml_sign_responses = original_value


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
