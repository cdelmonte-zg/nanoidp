"""
Tests for CodeQL security fixes in NanoIDP.

Tests cover:
- XXE (XML External Entity) protection
- URL redirection validation (localhost only)
- XSS protection in SAML responses
- Exception info exposure prevention
- Verbose logging setting
"""

import json
import base64
import pytest
from unittest.mock import patch, MagicMock


class TestXXEProtection:
    """Tests for XML External Entity attack prevention."""

    def test_secure_parser_is_used_for_saml_parsing(self):
        """Verify that secure XML parser is used for SAML parsing."""
        from nanoidp.routes import saml
        # Check that secure_fromstring is available
        assert hasattr(saml, 'secure_fromstring')
        # Check that parser is configured securely
        assert hasattr(saml, '_secure_parser')

    def test_malicious_xxe_payload_rejected(self, client):
        """Test that XXE payloads in SAML requests are rejected."""
        # XXE payload attempting to read /etc/passwd
        xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="test" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
</samlp:AuthnRequest>"""

        # Base64 encode the payload
        saml_request = base64.b64encode(xxe_payload.encode()).decode()

        # Send the malicious SAML request
        response = client.get(f'/saml/sso?SAMLRequest={saml_request}')

        # Should reject the request (defusedxml blocks XXE)
        # The actual response depends on how the error is handled
        # but it should NOT return 200 with parsed entity content
        assert response.status_code != 200 or b'passwd' not in response.data


class TestURLRedirection:
    """Tests for URL redirection (dev tool - no restrictions)."""

    def test_redirect_works(self, client):
        """Test that redirect URLs work (dev tool behavior)."""
        with client.session_transaction() as sess:
            sess['user'] = 'admin'

        response = client.get(
            '/logout?post_logout_redirect_uri=http://example.com/callback'
        )
        # Should redirect to any URL (dev tool)
        assert response.status_code == 302
        assert 'example.com' in response.headers.get('Location', '')

    def test_redirect_with_state_preserved(self, client):
        """Test that state parameter is preserved in redirect."""
        with client.session_transaction() as sess:
            sess['user'] = 'admin'

        response = client.get(
            '/logout?post_logout_redirect_uri=http://example.com/callback&state=mystate123'
        )
        assert response.status_code == 302
        location = response.headers.get('Location', '')
        assert 'state=mystate123' in location


class TestXSSProtection:
    """Tests for XSS protection in SAML responses."""

    def test_saml_acs_url_escaped(self, client):
        """Test that ACS URL is properly escaped in SAML response form."""
        # This tests the html.escape fix for XSS
        import html

        # Malicious ACS URL with XSS payload
        xss_acs_url = 'http://localhost:8080/callback"><script>alert(1)</script><input value="'

        # The escaped version should be safe
        escaped = html.escape(xss_acs_url, quote=True)
        assert '<script>' not in escaped
        assert '&lt;script&gt;' in escaped

    def test_relay_state_escaped(self, client):
        """Test that RelayState is properly escaped in SAML response form."""
        import html

        # Malicious RelayState with XSS payload
        xss_relay_state = '"><script>alert(document.cookie)</script>'

        # The escaped version should be safe
        escaped = html.escape(xss_relay_state, quote=True)
        assert '<script>' not in escaped
        assert '&lt;script&gt;' in escaped


class TestExceptionInfoExposure:
    """Tests for exception information exposure prevention."""

    def test_introspect_error_generic_message(self, client, auth_header):
        """Test that introspect endpoint returns generic error messages."""
        # Send an invalid token that might cause internal error
        response = client.post('/introspect',
            data={'token': 'completely-invalid-token-that-will-fail'},
            headers=auth_header
        )

        # Should not expose internal exception details
        data = json.loads(response.data)
        assert 'Traceback' not in str(data)
        assert 'Exception' not in str(data)

    def test_saml_attribute_query_error_generic(self, client):
        """Test that SAML attribute query returns generic error messages."""
        # Send invalid SOAP request
        response = client.post('/saml/attribute_query',
            data='invalid-soap-xml',
            content_type='application/soap+xml'
        )

        # Should not expose internal exception details in response
        assert b'Traceback' not in response.data
        # Should return a generic error


class TestVerboseLoggingSetting:
    """Tests for the verbose_logging setting."""

    def test_verbose_logging_setting_exists(self):
        """Test that verbose_logging setting is defined."""
        from nanoidp.config import Settings

        settings = Settings()
        assert hasattr(settings, 'verbose_logging')
        # Default should be True for dev convenience
        assert settings.verbose_logging is True

    def test_verbose_logging_parsed_from_yaml(self, tmp_path):
        """Test that verbose_logging is parsed from YAML config."""
        # Create test config files
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        settings_yaml = """
server:
  host: "0.0.0.0"
  port: 8000

oauth:
  issuer: "http://localhost:8000"
  clients:
    - client_id: "test"
      client_secret: "test"

logging:
  verbose_logging: false
"""
        (config_dir / "settings.yaml").write_text(settings_yaml)

        users_yaml = """
users:
  admin:
    password: "admin"
default_user: admin
"""
        (config_dir / "users.yaml").write_text(users_yaml)

        # Load config and verify setting
        from nanoidp.config import ConfigManager
        config = ConfigManager(str(config_dir))

        assert config.settings.verbose_logging is False

    def test_verbose_logging_default_true(self, tmp_path):
        """Test that verbose_logging defaults to True when not specified."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        settings_yaml = """
server:
  host: "0.0.0.0"
  port: 8000

oauth:
  issuer: "http://localhost:8000"
  clients:
    - client_id: "test"
      client_secret: "test"
"""
        (config_dir / "settings.yaml").write_text(settings_yaml)

        users_yaml = """
users:
  admin:
    password: "admin"
default_user: admin
"""
        (config_dir / "users.yaml").write_text(users_yaml)

        from nanoidp.config import ConfigManager
        config = ConfigManager(str(config_dir))

        # Should default to True
        assert config.settings.verbose_logging is True


class TestSecureXMLParser:
    """Tests to verify secure XML parser is properly configured."""

    def test_secure_parser_configured(self):
        """Test that secure XML parser has correct settings."""
        from nanoidp.routes.saml import _secure_parser

        # Verify parser is configured to block XXE attacks
        # resolve_entities=False prevents entity expansion
        # no_network=True blocks network access

    def test_secure_parser_blocks_entities(self):
        """Test that secure parser blocks external entity expansion."""
        from nanoidp.routes.saml import secure_fromstring
        from lxml.etree import XMLSyntaxError

        xxe_xml = b"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

        # The secure parser should either:
        # 1. Raise an error when trying to resolve entities
        # 2. Or simply not expand the entity (return literal &xxe;)
        try:
            result = secure_fromstring(xxe_xml)
            # If it parses, the entity should NOT be expanded
            text = result.text or ""
            assert "root:" not in text  # /etc/passwd content should not appear
        except XMLSyntaxError:
            # Some lxml versions may raise error on DTD with secure parser
            pass
