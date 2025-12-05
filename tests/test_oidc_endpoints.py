"""
Integration tests for OIDC endpoints.
Tests discovery, JWKS, userinfo, introspection, and revocation.
"""

import pytest
import json
import jwt as pyjwt


class TestOIDCDiscovery:
    """Tests for OIDC Discovery endpoint."""

    def test_discovery_endpoint_exists(self, client):
        """Test that discovery endpoint returns 200."""
        response = client.get('/.well-known/openid-configuration')
        assert response.status_code == 200

    def test_discovery_returns_json(self, client):
        """Test that discovery returns valid JSON."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)
        assert isinstance(data, dict)

    def test_discovery_has_issuer(self, client):
        """Test that discovery contains issuer."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)
        assert 'issuer' in data
        assert data['issuer'].startswith('http')

    def test_discovery_has_endpoints(self, client):
        """Test that discovery contains all required endpoints."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)

        assert 'authorization_endpoint' in data
        assert 'token_endpoint' in data
        assert 'userinfo_endpoint' in data
        assert 'jwks_uri' in data

    def test_discovery_has_oidc_endpoints(self, client):
        """Test that discovery contains OIDC-specific endpoints."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)

        assert 'introspection_endpoint' in data
        assert 'revocation_endpoint' in data

    def test_discovery_has_grant_types(self, client):
        """Test that discovery lists supported grant types."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)

        grant_types = data.get('grant_types_supported', [])
        assert 'authorization_code' in grant_types
        assert 'client_credentials' in grant_types
        assert 'password' in grant_types
        assert 'refresh_token' in grant_types

    def test_discovery_has_pkce_methods(self, client):
        """Test that discovery lists PKCE methods."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)

        methods = data.get('code_challenge_methods_supported', [])
        assert 'plain' in methods
        assert 'S256' in methods

    def test_discovery_has_response_types(self, client):
        """Test that discovery lists supported response types."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)

        response_types = data.get('response_types_supported', [])
        assert 'code' in response_types

    def test_discovery_has_scopes(self, client):
        """Test that discovery lists supported scopes."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)

        scopes = data.get('scopes_supported', [])
        assert 'openid' in scopes

    def test_discovery_has_claims(self, client):
        """Test that discovery lists supported claims."""
        response = client.get('/.well-known/openid-configuration')
        data = json.loads(response.data)

        claims = data.get('claims_supported', [])
        assert 'sub' in claims
        assert 'iss' in claims
        assert 'aud' in claims


class TestJWKS:
    """Tests for JWKS (JSON Web Key Set) endpoint."""

    def test_jwks_endpoint_exists(self, client):
        """Test that JWKS endpoint returns 200."""
        response = client.get('/.well-known/jwks.json')
        assert response.status_code == 200

    def test_jwks_returns_json(self, client):
        """Test that JWKS returns valid JSON."""
        response = client.get('/.well-known/jwks.json')
        data = json.loads(response.data)
        assert isinstance(data, dict)

    def test_jwks_has_keys(self, client):
        """Test that JWKS contains keys array."""
        response = client.get('/.well-known/jwks.json')
        data = json.loads(response.data)

        assert 'keys' in data
        assert isinstance(data['keys'], list)
        assert len(data['keys']) > 0

    def test_jwks_key_has_required_fields(self, client):
        """Test that JWK has required fields."""
        response = client.get('/.well-known/jwks.json')
        data = json.loads(response.data)
        key = data['keys'][0]

        assert 'kty' in key  # Key type
        assert 'kid' in key  # Key ID
        assert 'use' in key  # Key use
        assert 'alg' in key  # Algorithm

    def test_jwks_key_is_rsa(self, client):
        """Test that JWK is an RSA key."""
        response = client.get('/.well-known/jwks.json')
        data = json.loads(response.data)
        key = data['keys'][0]

        assert key['kty'] == 'RSA'
        assert 'n' in key  # RSA modulus
        assert 'e' in key  # RSA exponent


class TestUserinfo:
    """Tests for OIDC Userinfo endpoint."""

    def test_userinfo_requires_auth(self, client):
        """Test that userinfo requires authentication."""
        response = client.get('/userinfo')
        assert response.status_code == 401

    def test_userinfo_with_valid_token(self, client, bearer_header):
        """Test userinfo with valid Bearer token."""
        response = client.get('/userinfo', headers=bearer_header)
        assert response.status_code == 200

    def test_userinfo_returns_subject(self, client, bearer_header):
        """Test that userinfo returns subject claim."""
        response = client.get('/userinfo', headers=bearer_header)
        data = json.loads(response.data)

        assert 'sub' in data
        assert data['sub'] == 'admin'

    def test_userinfo_returns_email(self, client, bearer_header):
        """Test that userinfo returns email claim."""
        response = client.get('/userinfo', headers=bearer_header)
        data = json.loads(response.data)

        assert 'email' in data
        assert 'email_verified' in data

    def test_userinfo_returns_profile_claims(self, client, bearer_header):
        """Test that userinfo returns profile claims."""
        response = client.get('/userinfo', headers=bearer_header)
        data = json.loads(response.data)

        assert 'preferred_username' in data
        assert 'roles' in data
        assert 'tenant' in data

    def test_userinfo_post_method(self, client, bearer_header):
        """Test that userinfo supports POST method."""
        response = client.post('/userinfo', headers=bearer_header)
        assert response.status_code == 200

    def test_userinfo_invalid_token(self, client):
        """Test userinfo with invalid token."""
        response = client.get('/userinfo', headers={
            'Authorization': 'Bearer invalid-token'
        })
        assert response.status_code == 401


class TestIntrospection:
    """Tests for Token Introspection endpoint (RFC 7662)."""

    def test_introspect_requires_client_auth(self, client, access_token):
        """Test that introspection requires client authentication."""
        response = client.post('/introspect', data={
            'token': access_token
        })
        assert response.status_code == 401

    def test_introspect_valid_token(self, client, auth_header, access_token):
        """Test introspection of valid token."""
        response = client.post('/introspect', data={
            'token': access_token
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['active'] is True

    def test_introspect_returns_claims(self, client, auth_header, access_token):
        """Test that introspection returns token claims."""
        response = client.post('/introspect', data={
            'token': access_token
        }, headers=auth_header)

        data = json.loads(response.data)
        assert 'sub' in data
        assert 'iss' in data
        assert 'aud' in data
        assert 'exp' in data
        assert 'iat' in data

    def test_introspect_returns_token_type(self, client, auth_header, access_token):
        """Test that introspection returns token type."""
        response = client.post('/introspect', data={
            'token': access_token
        }, headers=auth_header)

        data = json.loads(response.data)
        assert data['token_type'] == 'Bearer'

    def test_introspect_returns_scope(self, client, auth_header, access_token):
        """Test that introspection returns scope."""
        response = client.post('/introspect', data={
            'token': access_token
        }, headers=auth_header)

        data = json.loads(response.data)
        assert 'scope' in data

    def test_introspect_invalid_token(self, client, auth_header):
        """Test introspection of invalid token."""
        response = client.post('/introspect', data={
            'token': 'invalid-token'
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['active'] is False

    def test_introspect_missing_token(self, client, auth_header):
        """Test introspection without token."""
        response = client.post('/introspect', data={},
            headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['active'] is False


class TestRevocation:
    """Tests for Token Revocation endpoint (RFC 7009)."""

    def test_revoke_requires_client_auth(self, client, access_token):
        """Test that revocation requires client authentication."""
        response = client.post('/revoke', data={
            'token': access_token
        })
        assert response.status_code == 401

    def test_revoke_returns_200(self, client, auth_header, access_token):
        """Test that revocation returns 200 OK."""
        response = client.post('/revoke', data={
            'token': access_token
        }, headers=auth_header)

        assert response.status_code == 200

    def test_revoke_without_token_returns_200(self, client, auth_header):
        """Test that revocation without token returns 200 (per RFC 7009)."""
        response = client.post('/revoke', data={},
            headers=auth_header)

        assert response.status_code == 200

    def test_revoke_invalid_token_returns_200(self, client, auth_header):
        """Test that revocation of invalid token returns 200 (per RFC 7009)."""
        response = client.post('/revoke', data={
            'token': 'invalid-token'
        }, headers=auth_header)

        assert response.status_code == 200

    def test_revoked_token_inactive(self, client, auth_header, access_token):
        """Test that revoked token becomes inactive."""
        # Revoke the token
        client.post('/revoke', data={
            'token': access_token
        }, headers=auth_header)

        # Check introspection shows inactive
        response = client.post('/introspect', data={
            'token': access_token
        }, headers=auth_header)

        data = json.loads(response.data)
        assert data['active'] is False

    def test_revoked_token_rejected_by_userinfo(self, client, auth_header, access_token):
        """Test that revoked token is rejected by userinfo."""
        # Revoke the token
        client.post('/revoke', data={
            'token': access_token
        }, headers=auth_header)

        # Try to use revoked token
        response = client.get('/userinfo', headers={
            'Authorization': f'Bearer {access_token}'
        })

        assert response.status_code == 401


class TestTokenContentType:
    """Tests for correct Content-Type headers."""

    def test_discovery_content_type(self, client):
        """Test that discovery returns application/json."""
        response = client.get('/.well-known/openid-configuration')
        assert 'application/json' in response.content_type

    def test_jwks_content_type(self, client):
        """Test that JWKS returns application/json."""
        response = client.get('/.well-known/jwks.json')
        assert 'application/json' in response.content_type

    def test_token_content_type(self, client, auth_header):
        """Test that token endpoint returns application/json."""
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        }, headers=auth_header)
        assert 'application/json' in response.content_type

    def test_userinfo_content_type(self, client, bearer_header):
        """Test that userinfo returns application/json."""
        response = client.get('/userinfo', headers=bearer_header)
        assert 'application/json' in response.content_type

    def test_introspect_content_type(self, client, auth_header, access_token):
        """Test that introspection returns application/json."""
        response = client.post('/introspect', data={
            'token': access_token
        }, headers=auth_header)
        assert 'application/json' in response.content_type
