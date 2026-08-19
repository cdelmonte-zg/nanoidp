"""
Pytest configuration and shared fixtures for NanoIDP tests.
"""

import base64
from typing import Optional

import pytest

import nanoidp.config as config_module
import nanoidp.mcp_server as mcp_server_module
import nanoidp.services.crypto as crypto_module
import nanoidp.services.token as token_module
from nanoidp.app import create_app
from nanoidp.config import OAuthClient, User


async def call_mcp_tool(name: str, arguments: Optional[dict] = None):
    """Drive tools/call through the mcp 2.0 in-memory client.

    The client speaks the real protocol to nanoidp's ``server`` over an
    in-memory transport - SDK dispatch, argument delivery and result
    serialization included - instead of invoking the lowlevel handler with a
    fake ``ctx``. Wire-level regressions (isError aliasing, result-schema
    validation) therefore fail the suite instead of only breaking a real
    client (#122).
    """
    from mcp import Client

    from nanoidp.mcp_server import server

    async with Client(server) as client:
        return await client.call_tool(name, arguments)


async def list_mcp_tools():
    """Drive tools/list through the mcp 2.0 in-memory client (see call_mcp_tool)."""
    from mcp import Client

    from nanoidp.mcp_server import server

    async with Client(server) as client:
        return (await client.list_tools()).tools


@pytest.fixture
def mcp_call_tool():
    """The MCP tools/call handler, callable as ``await f(name, arguments)``."""
    return call_mcp_tool


@pytest.fixture
def mcp_list_tools():
    """The MCP tools/list handler, callable as ``await f()``."""
    return list_mcp_tools


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset service singletons before and after each test.

    This ensures test isolation by preventing state leakage between tests.
    The token service is reset too so it never holds a reference to a stale
    config singleton (relevant when a test mutates the active configuration).
    mcp_server keeps its own separate config singleton (populated via
    _ensure_config()), which must be reset the same way or a test that drives
    it caches a ConfigManager into that global for the rest of the session.
    """
    # Reset before test
    crypto_module._crypto_service = None
    config_module._config = None
    token_module._token_service = None
    mcp_server_module._config = None
    yield
    # Reset after test
    crypto_module._crypto_service = None
    config_module._config = None
    token_module._token_service = None
    mcp_server_module._config = None


@pytest.fixture
def preserve_config_files():
    """Snapshot ``config/*.yaml`` and restore them verbatim after the test.

    A few tests exercise code paths that persist settings to the real config
    directory (e.g. POST ``/settings`` goes through the YAML writer). Without
    this, those tests leave the repo's ``config/settings.yaml`` modified with
    whatever fields they genuinely changed (unrelated fields, ``${VAR}``
    placeholders and comments are left untouched since #127). Restoring the
    exact bytes keeps the working tree clean.
    """
    import pathlib

    config_dir = pathlib.Path(__file__).resolve().parent.parent / "config"
    backups = {f: f.read_bytes() for f in config_dir.glob("*.yaml")}
    yield
    for path, content in backups.items():
        path.write_bytes(content)


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
        groups=["ENGINEERING"],
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
    import base64
    import hashlib
    digest = hashlib.sha256(pkce_verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


@pytest.fixture
def pkce_challenge_plain(pkce_verifier):
    """Generate a PKCE code challenge using plain method."""
    return pkce_verifier
