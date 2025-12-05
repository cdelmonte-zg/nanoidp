"""
Integration tests for new endpoints: OIDC Logout and Device Authorization Grant.
Tests end session endpoint and RFC 8628 device flow.
"""

import pytest
import json
import time


class TestOIDCLogout:
    """Tests for OIDC End Session / Logout endpoint."""

    def test_logout_endpoint_exists(self, client):
        """Test that logout endpoint returns 200."""
        response = client.get('/logout')
        assert response.status_code == 200

    def test_end_session_endpoint_alias(self, client):
        """Test that /end_session is an alias for /logout."""
        response = client.get('/end_session')
        assert response.status_code == 200

    def test_logout_clears_session(self, client):
        """Test that logout clears the session."""
        # First, set up a session by starting authorization flow
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid'
        )

        # Now logout
        response = client.get('/logout')
        assert response.status_code == 200

    def test_logout_with_redirect(self, client):
        """Test logout with post_logout_redirect_uri."""
        response = client.get(
            '/logout?post_logout_redirect_uri=http://example.com/logged-out',
            follow_redirects=False
        )
        assert response.status_code == 302
        assert 'http://example.com/logged-out' in response.headers.get('Location', '')

    def test_logout_with_redirect_and_state(self, client):
        """Test logout with redirect and state parameter."""
        response = client.get(
            '/logout?post_logout_redirect_uri=http://example.com/logged-out&state=mystate123',
            follow_redirects=False
        )
        assert response.status_code == 302
        location = response.headers.get('Location', '')
        assert 'http://example.com/logged-out' in location
        assert 'state=mystate123' in location

    def test_logout_with_id_token_hint(self, client, auth_header, access_token):
        """Test logout with id_token_hint revokes the token."""
        # Logout with the token as id_token_hint
        response = client.get(
            f'/logout?id_token_hint={access_token}',
            follow_redirects=True
        )
        assert response.status_code == 200

        # Token should now be revoked - check introspection
        response = client.post('/introspect', data={
            'token': access_token
        }, headers=auth_header)
        data = json.loads(response.data)
        assert data['active'] is False

    def test_logout_post_method(self, client):
        """Test that POST method works for logout."""
        response = client.post('/logout')
        assert response.status_code == 200

    def test_logout_shows_confirmation_page(self, client):
        """Test that logout shows confirmation message."""
        response = client.get('/logout')
        assert b'logged out' in response.data.lower()

    def test_discovery_includes_end_session_endpoint(self, client):
        """Test that discovery includes end_session_endpoint."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)
        assert 'end_session_endpoint' in data
        assert '/logout' in data['end_session_endpoint']


class TestDeviceAuthorizationFlow:
    """Tests for Device Authorization Grant (RFC 8628)."""

    def test_device_authorization_endpoint_exists(self, client, auth_header):
        """Test that device authorization endpoint exists."""
        response = client.post('/device_authorization', headers=auth_header)
        assert response.status_code == 200

    def test_device_code_alias(self, client, auth_header):
        """Test that /device/code is an alias for /device_authorization."""
        response = client.post('/device/code', headers=auth_header)
        assert response.status_code == 200

    def test_device_authorization_requires_auth(self, client):
        """Test that device authorization requires client authentication."""
        response = client.post('/device_authorization')
        assert response.status_code == 401

    def test_device_authorization_returns_codes(self, client, auth_header):
        """Test that device authorization returns required codes."""
        response = client.post('/device_authorization', headers=auth_header)
        assert response.status_code == 200

        data = json.loads(response.data)
        assert 'device_code' in data
        assert 'user_code' in data
        assert 'verification_uri' in data
        assert 'verification_uri_complete' in data
        assert 'expires_in' in data
        assert 'interval' in data

    def test_device_authorization_user_code_format(self, client, auth_header):
        """Test that user_code is uppercase alphanumeric."""
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)

        user_code = data['user_code']
        assert len(user_code) == 8
        assert user_code.isupper() or user_code.isdigit()

    def test_device_authorization_with_scope(self, client, auth_header):
        """Test device authorization with custom scope."""
        response = client.post('/device_authorization',
            data={'scope': 'openid profile'},
            headers=auth_header
        )
        assert response.status_code == 200

    def test_device_verification_page_exists(self, client):
        """Test that device verification page exists."""
        response = client.get('/device')
        assert response.status_code == 200
        assert b'Device' in response.data

    def test_device_verification_with_user_code(self, client):
        """Test device verification page with user_code parameter."""
        response = client.get('/device?user_code=TESTCODE')
        assert response.status_code == 200
        assert b'TESTCODE' in response.data

    def test_device_verification_invalid_code(self, client):
        """Test device verification with invalid code."""
        response = client.post('/device', data={
            'user_code': 'INVALIDX',
            'username': 'admin',
            'password': 'admin'
        })
        assert response.status_code == 200
        assert b'Invalid' in response.data or b'expired' in response.data.lower()

    def test_device_token_exchange_pending(self, client, auth_header):
        """Test token exchange returns authorization_pending when not yet authorized."""
        # Get device codes
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)
        device_code = data['device_code']

        # Try to exchange immediately (user hasn't authorized yet)
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)

        assert response.status_code == 400
        error_data = json.loads(response.data)
        assert error_data['error'] == 'authorization_pending'

    def test_device_token_exchange_invalid_code(self, client, auth_header):
        """Test token exchange with invalid device code."""
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': 'invalid-device-code'
        }, headers=auth_header)

        assert response.status_code == 400
        error_data = json.loads(response.data)
        assert error_data['error'] == 'invalid_grant'

    def test_device_token_exchange_missing_code(self, client, auth_header):
        """Test token exchange without device_code."""
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'
        }, headers=auth_header)

        assert response.status_code == 400
        error_data = json.loads(response.data)
        assert error_data['error'] == 'invalid_request'

    def test_discovery_includes_device_authorization_endpoint(self, client):
        """Test that discovery includes device_authorization_endpoint."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)
        assert 'device_authorization_endpoint' in data
        assert '/device_authorization' in data['device_authorization_endpoint']

    def test_discovery_includes_device_grant_type(self, client):
        """Test that discovery lists device_code grant type."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)
        assert 'urn:ietf:params:oauth:grant-type:device_code' in data['grant_types_supported']


class TestDeviceAuthorizationFullFlow:
    """Tests for complete device authorization flow."""

    def test_full_device_flow(self, client, auth_header):
        """Test complete device authorization flow."""
        # 1. Request device code
        response = client.post('/device_authorization', headers=auth_header)
        assert response.status_code == 200
        device_data = json.loads(response.data)
        device_code = device_data['device_code']
        user_code = device_data['user_code']

        # 2. User authorizes the device
        response = client.post('/device', data={
            'user_code': user_code,
            'username': 'admin',
            'password': 'admin',
            'action': 'authorize'
        })
        assert response.status_code == 200
        assert b'authorized' in response.data.lower() or b'success' in response.data.lower()

        # 3. Exchange device code for tokens
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)

        assert response.status_code == 200
        tokens = json.loads(response.data)
        assert 'access_token' in tokens
        assert 'refresh_token' in tokens
        assert tokens['token_type'] == 'Bearer'

        # 4. Verify token works
        response = client.get('/userinfo', headers={
            'Authorization': f'Bearer {tokens["access_token"]}'
        })
        assert response.status_code == 200
        userinfo = json.loads(response.data)
        assert userinfo['sub'] == 'admin'

    def test_device_flow_deny(self, client, auth_header):
        """Test device authorization denial."""
        # 1. Request device code
        response = client.post('/device_authorization', headers=auth_header)
        device_data = json.loads(response.data)
        device_code = device_data['device_code']
        user_code = device_data['user_code']

        # 2. User denies the device
        response = client.post('/device', data={
            'user_code': user_code,
            'username': 'admin',
            'password': 'admin',
            'action': 'deny'
        })
        assert response.status_code == 200

        # 3. Token exchange should fail with access_denied
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)

        assert response.status_code == 400
        error_data = json.loads(response.data)
        assert error_data['error'] == 'access_denied'

    def test_device_code_one_time_use(self, client, auth_header):
        """Test that device code can only be used once."""
        # 1. Request device code
        response = client.post('/device_authorization', headers=auth_header)
        device_data = json.loads(response.data)
        device_code = device_data['device_code']
        user_code = device_data['user_code']

        # 2. User authorizes
        client.post('/device', data={
            'user_code': user_code,
            'username': 'admin',
            'password': 'admin',
            'action': 'authorize'
        })

        # 3. First exchange - should succeed
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)
        assert response.status_code == 200

        # 4. Second exchange - should fail
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)
        assert response.status_code == 400

    def test_device_wrong_credentials(self, client, auth_header):
        """Test device authorization with wrong credentials."""
        # 1. Request device code
        response = client.post('/device_authorization', headers=auth_header)
        device_data = json.loads(response.data)
        user_code = device_data['user_code']

        # 2. Try to authorize with wrong password
        response = client.post('/device', data={
            'user_code': user_code,
            'username': 'admin',
            'password': 'wrongpassword',
            'action': 'authorize'
        })
        assert response.status_code == 200
        assert b'Invalid' in response.data


class TestNewEndpointsContentTypes:
    """Tests for Content-Type headers on new endpoints."""

    def test_device_authorization_content_type(self, client, auth_header):
        """Test that device authorization returns application/json."""
        response = client.post('/device_authorization', headers=auth_header)
        assert 'application/json' in response.content_type

    def test_logout_redirect_no_content_type_json(self, client):
        """Test that logout with redirect performs redirect."""
        response = client.get(
            '/logout?post_logout_redirect_uri=http://example.com',
            follow_redirects=False
        )
        assert response.status_code == 302
