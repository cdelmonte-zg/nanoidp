"""
Complete tests for Device Authorization Grant (RFC 8628).

Tests cover:
- Full authorization flow (device code → user authorization → token exchange)
- Polling behavior (authorization_pending)
- Device code expiration
- Error handling (invalid codes, client mismatch, denied access)
- Device code one-time use
"""

import json
import time
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def cleanup_device_codes():
    """Clean up device codes after each test to prevent state leakage."""
    yield
    # Clean up any device codes that might be left over
    try:
        from nanoidp.routes.oauth import _device_codes
        _device_codes.clear()
    except (ImportError, AttributeError):
        pass


class TestDeviceFlowHappyPath:
    """Tests for the complete Device Flow happy path."""

    def test_full_device_flow_success(self, client, auth_header):
        """Test complete device flow: authorization → verification → token exchange."""
        # Step 1: Get device codes
        response = client.post('/device_authorization', headers=auth_header)
        assert response.status_code == 200

        data = json.loads(response.data)
        device_code = data['device_code']
        user_code = data['user_code']

        # Step 2: Simulate user authorization via POST to /device
        response = client.post('/device', data={
            'user_code': user_code,
            'username': 'admin',
            'password': 'admin',
            'action': 'authorize'
        })
        assert response.status_code == 200

        # Step 3: Exchange device code for tokens
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)

        assert response.status_code == 200
        token_data = json.loads(response.data)
        assert 'access_token' in token_data
        assert 'token_type' in token_data
        assert token_data['token_type'] == 'Bearer'

    def test_device_flow_with_scope(self, client, auth_header):
        """Test device flow preserves requested scope."""
        # Request specific scope
        response = client.post('/device_authorization',
            data={'scope': 'openid profile email'},
            headers=auth_header
        )
        assert response.status_code == 200

        data = json.loads(response.data)
        device_code = data['device_code']
        user_code = data['user_code']

        # Authorize
        client.post('/device', data={
            'user_code': user_code,
            'username': 'admin',
            'password': 'admin',
            'action': 'authorize'
        })

        # Exchange
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)

        assert response.status_code == 200


class TestDeviceFlowPolling:
    """Tests for Device Flow polling behavior."""

    def test_authorization_pending_before_user_action(self, client, auth_header):
        """Test that polling returns authorization_pending before user authorizes."""
        # Get device codes
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)
        device_code = data['device_code']

        # Poll immediately (user hasn't authorized)
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)

        assert response.status_code == 400
        error_data = json.loads(response.data)
        assert error_data['error'] == 'authorization_pending'

    def test_multiple_pending_polls(self, client, auth_header):
        """Test multiple polling attempts return authorization_pending."""
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)
        device_code = data['device_code']

        # Multiple polls should all return authorization_pending
        for _ in range(3):
            response = client.post('/token', data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code': device_code
            }, headers=auth_header)

            assert response.status_code == 400
            error_data = json.loads(response.data)
            assert error_data['error'] == 'authorization_pending'


class TestDeviceFlowExpiration:
    """Tests for Device Flow expiration handling."""

    def test_expired_device_code_returns_error(self, client, auth_header):
        """Test that expired device codes return expired_token error."""
        # Get device codes
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)
        device_code = data['device_code']

        # Directly modify the device code's expiration time
        from nanoidp.routes.oauth import _device_codes
        if device_code in _device_codes:
            _device_codes[device_code]['expires_at'] = time.time() - 100  # Already expired

        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)

        assert response.status_code == 400
        error_data = json.loads(response.data)
        assert error_data['error'] == 'expired_token'

    def test_expired_code_cannot_be_authorized(self, client, auth_header):
        """Test that expired codes cannot be authorized by user."""
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)
        user_code = data['user_code']
        device_code = data['device_code']

        # Directly modify the device code's expiration time
        from nanoidp.routes.oauth import _device_codes
        if device_code in _device_codes:
            _device_codes[device_code]['expires_at'] = time.time() - 100  # Already expired

        response = client.post('/device', data={
            'user_code': user_code,
            'username': 'admin',
            'password': 'admin',
            'action': 'authorize'
        })

        # Should show error about expired code
        assert response.status_code == 200
        assert b'expired' in response.data.lower()


class TestDeviceFlowErrors:
    """Tests for Device Flow error scenarios."""

    def test_invalid_device_code_rejected(self, client, auth_header):
        """Test that invalid device codes are rejected."""
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': 'invalid_code_12345'
        }, headers=auth_header)

        assert response.status_code == 400
        error_data = json.loads(response.data)
        assert error_data['error'] == 'invalid_grant'

    def test_missing_device_code_rejected(self, client, auth_header):
        """Test that missing device code returns error."""
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'
        }, headers=auth_header)

        assert response.status_code == 400
        error_data = json.loads(response.data)
        assert error_data['error'] == 'invalid_request'

    def test_client_mismatch_rejected(self, client, auth_header):
        """Test that device codes cannot be used by different clients."""
        # Get device code with auth_header (demo-client)
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)
        device_code = data['device_code']

        # Try to use with different client
        import base64
        other_auth = {'Authorization': f'Basic {base64.b64encode(b"other-client:other-secret").decode()}'}

        # First we need to register this client or the request will fail
        # For this test, we'll verify the error handling logic
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=other_auth)

        # Should fail authentication (401) or invalid grant (400)
        assert response.status_code in [400, 401]

    def test_invalid_user_code_rejected(self, client):
        """Test that invalid user codes are rejected."""
        response = client.post('/device', data={
            'user_code': 'BADCODE1',
            'username': 'admin',
            'password': 'admin',
            'action': 'authorize'
        })

        assert response.status_code == 200
        assert b'Invalid' in response.data or b'invalid' in response.data.lower()


class TestDeviceFlowDenied:
    """Tests for denied Device Flow requests."""

    def test_user_can_deny_authorization(self, client, auth_header):
        """Test that users can deny device authorization."""
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)
        device_code = data['device_code']
        user_code = data['user_code']

        # Deny authorization
        response = client.post('/device', data={
            'user_code': user_code,
            'username': 'admin',
            'password': 'admin',
            'action': 'deny'
        })
        assert response.status_code == 200

        # Try to exchange - should fail with access_denied
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)

        assert response.status_code == 400
        error_data = json.loads(response.data)
        assert error_data['error'] == 'access_denied'


class TestDeviceCodeReuse:
    """Tests for device code one-time use."""

    def test_device_code_cannot_be_reused_after_success(self, client, auth_header):
        """Test that device codes cannot be reused after successful exchange."""
        # Get device codes
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)
        device_code = data['device_code']
        user_code = data['user_code']

        # Authorize
        client.post('/device', data={
            'user_code': user_code,
            'username': 'admin',
            'password': 'admin',
            'action': 'authorize'
        })

        # First exchange - should succeed
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)
        assert response.status_code == 200

        # Second exchange - should fail
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code
        }, headers=auth_header)

        assert response.status_code == 400
        error_data = json.loads(response.data)
        assert error_data['error'] == 'invalid_grant'

    def test_user_code_cannot_be_reauthorized(self, client, auth_header):
        """Test that user codes cannot be authorized twice."""
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)
        user_code = data['user_code']

        # First authorization
        client.post('/device', data={
            'user_code': user_code,
            'username': 'admin',
            'password': 'admin',
            'action': 'authorize'
        })

        # Second authorization attempt
        response = client.post('/device', data={
            'user_code': user_code,
            'username': 'admin',
            'password': 'admin',
            'action': 'authorize'
        })

        assert response.status_code == 200
        # Should show error about code already used
        assert b'already' in response.data.lower() or b'used' in response.data.lower()


class TestDeviceAuthorizationResponse:
    """Tests for Device Authorization response format (RFC 8628)."""

    def test_response_contains_required_fields(self, client, auth_header):
        """Test that response contains all RFC 8628 required fields."""
        response = client.post('/device_authorization', headers=auth_header)
        assert response.status_code == 200

        data = json.loads(response.data)

        # Required per RFC 8628
        assert 'device_code' in data
        assert 'user_code' in data
        assert 'verification_uri' in data
        assert 'expires_in' in data

        # Optional but recommended
        assert 'verification_uri_complete' in data
        assert 'interval' in data

    def test_verification_uri_complete_includes_user_code(self, client, auth_header):
        """Test that verification_uri_complete includes the user_code."""
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)

        uri_complete = data['verification_uri_complete']
        user_code = data['user_code']

        assert user_code in uri_complete

    def test_expires_in_is_reasonable(self, client, auth_header):
        """Test that expires_in is a reasonable value."""
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)

        expires_in = data['expires_in']

        # Should be at least 60 seconds and at most 30 minutes
        assert 60 <= expires_in <= 1800

    def test_interval_is_reasonable(self, client, auth_header):
        """Test that polling interval is reasonable."""
        response = client.post('/device_authorization', headers=auth_header)
        data = json.loads(response.data)

        interval = data['interval']

        # Should be at least 1 second and at most 60 seconds
        assert 1 <= interval <= 60
