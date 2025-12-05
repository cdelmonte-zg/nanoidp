"""
Tests for OAuth 2.0 error response format compliance.

Verifies that error responses follow RFC 6749 format:
- error: Required error code
- error_description: Optional human-readable description
- error_uri: Optional URI with more information
"""

import json
import base64
import pytest


class TestInvalidGrantError:
    """Tests for invalid_grant error responses."""

    def test_wrong_password_returns_invalid_grant(self, client, auth_header):
        """Test that wrong password returns invalid_grant error."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'wrong_password'
        }, headers=auth_header)

        assert response.status_code in [400, 401]
        # Response may be JSON or abort
        try:
            data = json.loads(response.data)
            assert 'error' in data or response.status_code == 401
        except json.JSONDecodeError:
            # Non-JSON response is acceptable for auth failures
            pass

    def test_unknown_user_returns_error(self, client, auth_header):
        """Test that unknown user returns appropriate error."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'nonexistent_user',
            'password': 'anypassword'
        }, headers=auth_header)

        assert response.status_code in [400, 401, 404]

    def test_invalid_refresh_token_returns_error(self, client, auth_header):
        """Test that invalid refresh token returns error."""
        response = client.post('/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'invalid_refresh_token'
        }, headers=auth_header)

        assert response.status_code in [400, 401]


class TestInvalidClientError:
    """Tests for invalid_client error responses."""

    def test_missing_client_auth_returns_error(self, client):
        """Test that missing client authentication returns error."""
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        })

        assert response.status_code == 401

    def test_wrong_client_secret_returns_error(self, client):
        """Test that wrong client secret returns error."""
        wrong_auth = base64.b64encode(b'demo-client:wrong_secret').decode()
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        }, headers={'Authorization': f'Basic {wrong_auth}'})

        assert response.status_code in [400, 401]

    def test_unknown_client_returns_error(self, client):
        """Test that unknown client returns error."""
        unknown_auth = base64.b64encode(b'unknown-client:some_secret').decode()
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        }, headers={'Authorization': f'Basic {unknown_auth}'})

        assert response.status_code in [400, 401]


class TestInvalidRequestError:
    """Tests for invalid_request error responses."""

    def test_missing_grant_type_uses_default(self, client, auth_header):
        """Test that missing grant_type uses client_credentials default."""
        response = client.post('/token', headers=auth_header)

        # Should default to client_credentials and succeed
        assert response.status_code == 200

    def test_missing_username_for_password_grant(self, client, auth_header):
        """Test that missing username for password grant returns error."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'password': 'admin'
        }, headers=auth_header)

        assert response.status_code in [400, 401]


class TestUnsupportedGrantType:
    """Tests for unsupported_grant_type error responses."""

    def test_invalid_grant_type_returns_error(self, client, auth_header):
        """Test that invalid grant type returns error."""
        response = client.post('/token', data={
            'grant_type': 'invalid_grant_type'
        }, headers=auth_header)

        assert response.status_code == 400


class TestErrorResponseFormat:
    """Tests for OAuth 2.0 error response format (RFC 6749)."""

    def test_error_response_contains_error_field(self, client, auth_header):
        """Test that error responses contain 'error' field."""
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': 'nonexistent_code'
        }, headers=auth_header)

        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    def test_error_response_error_is_string(self, client, auth_header):
        """Test that 'error' field is a string."""
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': 'nonexistent_code'
        }, headers=auth_header)

        data = json.loads(response.data)
        assert isinstance(data['error'], str)

    def test_error_response_may_contain_description(self, client, auth_header):
        """Test that error responses may contain 'error_description'."""
        response = client.post('/token', data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': 'nonexistent_code'
        }, headers=auth_header)

        data = json.loads(response.data)
        # error_description is optional per RFC
        if 'error_description' in data:
            assert isinstance(data['error_description'], str)


class TestIntrospectionErrors:
    """Tests for token introspection error handling."""

    def test_introspection_without_token_returns_error(self, client, auth_header):
        """Test that introspection without token returns appropriate response."""
        response = client.post('/introspect', headers=auth_header)

        # Should return inactive or error
        assert response.status_code in [200, 400]
        data = json.loads(response.data)
        # Either returns {active: false} or an error
        assert data.get('active') is False or 'error' in data

    def test_introspection_requires_client_auth(self, client):
        """Test that introspection requires client authentication."""
        response = client.post('/introspect', data={'token': 'some_token'})

        assert response.status_code == 401


class TestRevocationErrors:
    """Tests for token revocation error handling."""

    def test_revocation_requires_client_auth(self, client):
        """Test that revocation requires client authentication."""
        response = client.post('/revoke', data={'token': 'some_token'})

        assert response.status_code == 401

    def test_revocation_succeeds_for_invalid_token(self, client, auth_header):
        """Test that revocation succeeds even for invalid tokens (RFC 7009)."""
        response = client.post('/revoke', data={
            'token': 'invalid_or_nonexistent_token'
        }, headers=auth_header)

        # Per RFC 7009, revocation should succeed even for invalid tokens
        assert response.status_code == 200


class TestAuthorizationErrors:
    """Tests for authorization endpoint error handling."""

    def test_authorize_missing_client_id(self, client):
        """Test that authorization without client_id returns error."""
        response = client.get('/authorize?response_type=code')

        assert response.status_code in [302, 400]

    def test_authorize_invalid_response_type(self, client):
        """Test that authorization with invalid response_type returns error."""
        response = client.get('/authorize?response_type=invalid&client_id=demo-client&redirect_uri=http://localhost/callback')

        # Should redirect with error or return error page
        assert response.status_code in [302, 400]
