"""
Integration tests for OAuth2 flows.
Tests complete authorization code flow, password grant, client credentials, and refresh token.
"""

import pytest
import json
import hashlib
import base64
import secrets


class TestAuthorizationCodeFlow:
    """Tests for OAuth2 Authorization Code Flow."""

    def test_authorize_get_shows_login_form(self, client):
        """Test that GET /authorize shows the login form."""
        response = client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid'
        )

        assert response.status_code == 200
        assert b'username' in response.data
        assert b'password' in response.data

    def test_authorize_requires_response_type(self, client):
        """Test that response_type is required."""
        response = client.get(
            '/authorize?client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback'
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "unsupported_response_type"

    def test_authorize_requires_client_id(self, client):
        """Test that client_id is required."""
        response = client.get(
            '/authorize?response_type=code'
            '&redirect_uri=http://localhost:3000/callback'
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "invalid_request"

    def test_authorize_requires_redirect_uri(self, client):
        """Test that redirect_uri is required."""
        response = client.get(
            '/authorize?response_type=code&client_id=demo-client'
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "invalid_request"

    def test_authorize_validates_client_id(self, client):
        """Test that invalid client_id is rejected."""
        response = client.get(
            '/authorize?response_type=code&client_id=unknown-client'
            '&redirect_uri=http://localhost:3000/callback'
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "invalid_client"

    def test_authorize_post_invalid_credentials(self, client):
        """Test that invalid login credentials show error."""
        # First GET to set session
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid'
        )

        # POST with wrong credentials
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'wrong-password'
        })

        assert response.status_code == 200
        assert b'Invalid username or password' in response.data

    def test_authorize_post_success_redirects(self, client):
        """Test that successful login redirects with code."""
        # First GET to set session
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid&state=test123'
        )

        # POST with valid credentials
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        assert response.status_code == 302
        location = response.headers.get('Location')
        assert 'http://localhost:3000/callback' in location
        assert 'code=' in location
        assert 'state=test123' in location

    def test_authorize_code_exchange(self, client, auth_header):
        """Test exchanging authorization code for tokens."""
        # Get authorization code
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # Exchange code for tokens
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback'
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert data['token_type'] == 'Bearer'

    def test_authorize_code_one_time_use(self, client, auth_header):
        """Test that authorization codes can only be used once."""
        # Get authorization code
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # First exchange - should succeed
        response1 = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback'
        }, headers=auth_header)
        assert response1.status_code == 200

        # Second exchange - should fail
        response2 = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback'
        }, headers=auth_header)
        assert response2.status_code == 400


class TestAuthorizationCodeFlowWithPKCE:
    """Tests for Authorization Code Flow with PKCE."""

    def test_pkce_s256_flow(self, client, auth_header, pkce_verifier, pkce_challenge_s256):
        """Test complete flow with PKCE S256."""
        # Get authorization code with code_challenge
        client.get(
            f'/authorize?response_type=code&client_id=demo-client'
            f'&redirect_uri=http://localhost:3000/callback&scope=openid'
            f'&code_challenge={pkce_challenge_s256}&code_challenge_method=S256'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # Exchange with code_verifier
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback',
            'code_verifier': pkce_verifier
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data

    def test_pkce_plain_flow(self, client, auth_header, pkce_verifier):
        """Test complete flow with PKCE plain method."""
        # Get authorization code with plain challenge
        client.get(
            f'/authorize?response_type=code&client_id=demo-client'
            f'&redirect_uri=http://localhost:3000/callback&scope=openid'
            f'&code_challenge={pkce_verifier}&code_challenge_method=plain'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # Exchange with code_verifier
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback',
            'code_verifier': pkce_verifier
        }, headers=auth_header)

        assert response.status_code == 200

    def test_pkce_missing_verifier_fails(self, client, auth_header, pkce_challenge_s256):
        """Test that missing code_verifier fails when challenge was provided."""
        # Get authorization code with code_challenge
        client.get(
            f'/authorize?response_type=code&client_id=demo-client'
            f'&redirect_uri=http://localhost:3000/callback'
            f'&code_challenge={pkce_challenge_s256}&code_challenge_method=S256'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # Exchange WITHOUT code_verifier - should fail
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback'
        }, headers=auth_header)

        assert response.status_code == 400

    def test_pkce_wrong_verifier_fails(self, client, auth_header, pkce_challenge_s256):
        """Test that wrong code_verifier fails."""
        # Get authorization code
        client.get(
            f'/authorize?response_type=code&client_id=demo-client'
            f'&redirect_uri=http://localhost:3000/callback'
            f'&code_challenge={pkce_challenge_s256}&code_challenge_method=S256'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # Exchange with WRONG code_verifier
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback',
            'code_verifier': 'wrong_verifier'
        }, headers=auth_header)

        assert response.status_code == 400


class TestPasswordGrant:
    """Tests for OAuth2 Password Grant."""

    def test_password_grant_success(self, client, auth_header):
        """Test successful password grant."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert data['token_type'] == 'Bearer'

    def test_password_grant_invalid_credentials(self, client, auth_header):
        """Test password grant with invalid credentials."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'wrong-password'
        }, headers=auth_header)

        assert response.status_code == 401

    def test_password_grant_missing_username(self, client, auth_header):
        """Test password grant without username."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'password': 'admin'
        }, headers=auth_header)

        assert response.status_code == 400

    def test_password_grant_missing_password(self, client, auth_header):
        """Test password grant without password."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin'
        }, headers=auth_header)

        assert response.status_code == 400

    def test_password_grant_no_client_auth_fails(self, client):
        """Test that password grant requires client authentication."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        })

        assert response.status_code == 401


class TestClientCredentialsGrant:
    """Tests for OAuth2 Client Credentials Grant."""

    def test_client_credentials_success(self, client, auth_header):
        """Test successful client credentials grant."""
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert data['token_type'] == 'Bearer'

    def test_client_credentials_invalid_client(self, client):
        """Test client credentials with invalid client."""
        invalid_auth = base64.b64encode(b'wrong:credentials').decode()
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        }, headers={'Authorization': f'Basic {invalid_auth}'})

        assert response.status_code == 401

    def test_client_credentials_no_auth_fails(self, client):
        """Test that client credentials requires client authentication."""
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        })

        assert response.status_code == 401


class TestRefreshTokenGrant:
    """Tests for OAuth2 Refresh Token Grant."""

    def test_refresh_token_success(self, client, auth_header):
        """Test successful refresh token grant."""
        # First get tokens via password grant
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        tokens = json.loads(response.data)
        refresh_token = tokens['refresh_token']

        # Use refresh token to get new tokens
        response = client.post('/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert 'refresh_token' in data

    def test_refresh_token_missing_token(self, client, auth_header):
        """Test refresh token grant without refresh_token."""
        response = client.post('/token', data={
            'grant_type': 'refresh_token'
        }, headers=auth_header)

        assert response.status_code == 400

    def test_refresh_token_invalid_token(self, client, auth_header):
        """Test refresh token grant with invalid token."""
        response = client.post('/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'invalid-token'
        }, headers=auth_header)

        assert response.status_code == 401

    def test_refresh_token_with_access_token_fails(self, client, auth_header):
        """Test that using access_token as refresh_token fails."""
        # Get tokens
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        tokens = json.loads(response.data)
        access_token = tokens['access_token']

        # Try to use access_token as refresh_token
        response = client.post('/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': access_token
        }, headers=auth_header)

        assert response.status_code == 400


class TestUnsupportedGrantType:
    """Tests for unsupported grant types."""

    def test_unsupported_grant_type(self, client, auth_header):
        """Test that unsupported grant types return error."""
        response = client.post('/token', data={
            'grant_type': 'implicit'  # Not supported
        }, headers=auth_header)

        assert response.status_code == 400
