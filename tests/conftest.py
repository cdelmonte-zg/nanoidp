"""
Pytest configuration and shared fixtures for NanoIDP tests.
"""

import base64
import pytest
from typing import Generator

from nanoidp.app import create_app
from nanoidp.config import ConfigManager, User, OAuthClient, Settings
import nanoidp.services.crypto as crypto_module
import nanoidp.config as config_module


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset service singletons before and after each test.

    This ensures test isolation by preventing state leakage between tests.
    """
    # Reset before test
    crypto_module._crypto_service = None
    config_module._config = None
    yield
    # Reset after test
    crypto_module._crypto_service = None
    config_module._config = None


@pytest.fixture
def app():
    """Create a test Flask application."""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    return app


@pytest.fixture
def client(app):
    """Create a test client for the Flask application."""
    return app.test_client()


@pytest.fixture
def auth_header():
    """Create Basic auth header for demo-client."""
    credentials = base64.b64encode(b'demo-client:demo-secret').decode()
    return {'Authorization': f'Basic {credentials}'}


@pytest.fixture
def test_auth_header():
    """Create Basic auth header for test-client."""
    credentials = base64.b64encode(b'test-client:test-secret').decode()
    return {'Authorization': f'Basic {credentials}'}


@pytest.fixture
def sample_user():
    """Create a sample user for testing."""
    return User(
        username="test-user",
        password="test-password",
        email="test@example.org",
        roles=["USER", "TESTER"],
        tenant="test-tenant",
        identity_class="INTERNAL",
        entitlements=["TEST_ACCESS"],
        source_acl=["ACL_TEST"],
        attributes={"custom_attr": "custom_value"},
    )


@pytest.fixture
def sample_client():
    """Create a sample OAuth client for testing."""
    return OAuthClient(
        client_id="test-client",
        client_secret="test-secret",
        description="Test OAuth client",
    )


@pytest.fixture
def access_token(client, auth_header):
    """Get a valid access token."""
    response = client.post('/token',
        data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        },
        headers=auth_header
    )
    import json
    data = json.loads(response.data)
    return data['access_token']


@pytest.fixture
def bearer_header(access_token):
    """Create Bearer auth header with access token."""
    return {'Authorization': f'Bearer {access_token}'}


@pytest.fixture
def pkce_verifier():
    """Generate a PKCE code verifier."""
    import secrets
    return secrets.token_urlsafe(32)


@pytest.fixture
def pkce_challenge_s256(pkce_verifier):
    """Generate a PKCE code challenge using S256 method."""
    import hashlib
    import base64
    digest = hashlib.sha256(pkce_verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


@pytest.fixture
def pkce_challenge_plain(pkce_verifier):
    """Generate a PKCE code challenge using plain method."""
    return pkce_verifier
