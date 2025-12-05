"""
Integration tests for complete token lifecycle.
Tests end-to-end journeys including token issuance, usage, refresh, and revocation.
"""

import pytest
import json
import jwt as pyjwt
import time


class TestCompleteAuthorizationCodeJourney:
    """Tests for complete Authorization Code Flow journey."""

    def test_full_auth_code_journey(self, client, auth_header):
        """Test complete journey: authorize -> login -> token -> userinfo -> revoke."""
        # 1. Start authorization request
        response = client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid profile'
            '&state=random-state-123'
        )
        assert response.status_code == 200
        assert b'username' in response.data

        # 2. Submit login credentials
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)
        assert response.status_code == 302

        # 3. Extract authorization code
        location = response.headers.get('Location')
        assert 'code=' in location
        assert 'state=random-state-123' in location
        code = location.split('code=')[1].split('&')[0]

        # 4. Exchange code for tokens
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback'
        }, headers=auth_header)
        assert response.status_code == 200
        tokens = json.loads(response.data)
        access_token = tokens['access_token']
        refresh_token = tokens['refresh_token']

        # 5. Use access token to get userinfo
        response = client.get('/userinfo', headers={
            'Authorization': f'Bearer {access_token}'
        })
        assert response.status_code == 200
        userinfo = json.loads(response.data)
        assert userinfo['sub'] == 'admin'

        # 6. Introspect the token
        response = client.post('/introspect', data={
            'token': access_token
        }, headers=auth_header)
        introspection = json.loads(response.data)
        assert introspection['active'] is True

        # 7. Revoke the token
        response = client.post('/revoke', data={
            'token': access_token
        }, headers=auth_header)
        assert response.status_code == 200

        # 8. Verify token is no longer valid
        response = client.get('/userinfo', headers={
            'Authorization': f'Bearer {access_token}'
        })
        assert response.status_code == 401

        # 9. Verify introspection shows inactive
        response = client.post('/introspect', data={
            'token': access_token
        }, headers=auth_header)
        introspection = json.loads(response.data)
        assert introspection['active'] is False

    def test_full_pkce_journey(self, client, auth_header, pkce_verifier, pkce_challenge_s256):
        """Test complete PKCE flow journey."""
        # 1. Start authorization with PKCE
        response = client.get(
            f'/authorize?response_type=code&client_id=demo-client'
            f'&redirect_uri=http://localhost:3000/callback&scope=openid'
            f'&code_challenge={pkce_challenge_s256}&code_challenge_method=S256'
        )
        assert response.status_code == 200

        # 2. Login
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)
        code = response.headers.get('Location').split('code=')[1].split('&')[0]

        # 3. Exchange with code_verifier
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback',
            'code_verifier': pkce_verifier
        }, headers=auth_header)
        assert response.status_code == 200
        tokens = json.loads(response.data)

        # 4. Verify token works
        response = client.get('/userinfo', headers={
            'Authorization': f'Bearer {tokens["access_token"]}'
        })
        assert response.status_code == 200


class TestTokenRefreshJourney:
    """Tests for token refresh lifecycle."""

    def test_refresh_preserves_user_context(self, client, auth_header):
        """Test that refreshed tokens preserve user context."""
        # 1. Get initial tokens
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        tokens = json.loads(response.data)

        # 2. Decode original token to get user
        original_payload = pyjwt.decode(
            tokens['access_token'],
            options={'verify_signature': False}
        )

        # 3. Refresh tokens
        response = client.post('/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': tokens['refresh_token']
        }, headers=auth_header)
        new_tokens = json.loads(response.data)

        # 4. Decode new token
        new_payload = pyjwt.decode(
            new_tokens['access_token'],
            options={'verify_signature': False}
        )

        # 5. Verify user context is preserved
        assert new_payload['sub'] == original_payload['sub']
        assert new_payload['roles'] == original_payload['roles']
        assert new_payload['tenant'] == original_payload['tenant']

    def test_refresh_generates_new_jti(self, client, auth_header):
        """Test that refreshed tokens have new JTI."""
        # 1. Get initial tokens
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        tokens = json.loads(response.data)

        original_payload = pyjwt.decode(
            tokens['access_token'],
            options={'verify_signature': False}
        )

        # 2. Refresh
        response = client.post('/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': tokens['refresh_token']
        }, headers=auth_header)
        new_tokens = json.loads(response.data)

        new_payload = pyjwt.decode(
            new_tokens['access_token'],
            options={'verify_signature': False}
        )

        # 3. JTI should be different
        assert new_payload['jti'] != original_payload['jti']

    def test_old_access_token_works_after_refresh(self, client, auth_header):
        """Test that old access token still works after refresh (until expiry)."""
        # 1. Get initial tokens
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        tokens = json.loads(response.data)
        old_access_token = tokens['access_token']

        # 2. Refresh
        response = client.post('/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': tokens['refresh_token']
        }, headers=auth_header)

        # 3. Old token should still work (not revoked)
        response = client.get('/userinfo', headers={
            'Authorization': f'Bearer {old_access_token}'
        })
        assert response.status_code == 200


class TestMultipleTokenRevocation:
    """Tests for revoking multiple tokens."""

    def test_revoke_access_token_only(self, client, auth_header):
        """Test that revoking access token doesn't affect refresh token."""
        # 1. Get tokens
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        tokens = json.loads(response.data)

        # 2. Revoke access token
        client.post('/revoke', data={
            'token': tokens['access_token']
        }, headers=auth_header)

        # 3. Refresh token should still work
        response = client.post('/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': tokens['refresh_token']
        }, headers=auth_header)
        assert response.status_code == 200


class TestTokenValidation:
    """Tests for token validation across endpoints."""

    def test_token_jti_is_uuid(self, client, auth_header):
        """Test that token JTI is a valid UUID format."""
        import uuid

        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        }, headers=auth_header)
        tokens = json.loads(response.data)

        payload = pyjwt.decode(
            tokens['access_token'],
            options={'verify_signature': False}
        )

        # Should be valid UUID
        jti = payload['jti']
        uuid.UUID(jti)  # Will raise if invalid

    def test_token_has_correct_issuer(self, client, auth_header):
        """Test that token issuer matches discovery endpoint."""
        # 1. Get discovery
        response = client.get('/.well-known/openid-configuration')
        discovery = json.loads(response.data)

        # 2. Get token
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        }, headers=auth_header)
        tokens = json.loads(response.data)

        payload = pyjwt.decode(
            tokens['access_token'],
            options={'verify_signature': False}
        )

        assert payload['iss'] == discovery['issuer']

    def test_token_timestamps_are_valid(self, client, auth_header):
        """Test that token timestamps are properly set."""
        import time

        before = int(time.time())

        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        }, headers=auth_header)
        tokens = json.loads(response.data)

        after = int(time.time())

        payload = pyjwt.decode(
            tokens['access_token'],
            options={'verify_signature': False}
        )

        # iat should be between before and after
        assert before <= payload['iat'] <= after

        # nbf should equal iat
        assert payload['nbf'] == payload['iat']

        # exp should be in the future
        assert payload['exp'] > payload['iat']


class TestDifferentUsersJourney:
    """Tests for journeys with different users."""

    def test_different_users_get_different_tokens(self, client, auth_header):
        """Test that different users get tokens with different claims."""
        # Get token for admin
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        admin_tokens = json.loads(response.data)

        admin_payload = pyjwt.decode(
            admin_tokens['access_token'],
            options={'verify_signature': False}
        )

        # Get token for user1 (if exists, otherwise test passes)
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'user1',
            'password': 'user1'
        }, headers=auth_header)

        if response.status_code == 200:
            user1_tokens = json.loads(response.data)
            user1_payload = pyjwt.decode(
                user1_tokens['access_token'],
                options={'verify_signature': False}
            )

            assert admin_payload['sub'] != user1_payload['sub']
            assert admin_payload['jti'] != user1_payload['jti']


class TestClientCredentialsJourney:
    """Tests for Client Credentials flow journey."""

    def test_client_credentials_full_journey(self, client, auth_header):
        """Test complete client credentials journey."""
        # 1. Get token via client credentials
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        }, headers=auth_header)
        assert response.status_code == 200
        tokens = json.loads(response.data)

        # 2. Introspect - should be active
        response = client.post('/introspect', data={
            'token': tokens['access_token']
        }, headers=auth_header)
        data = json.loads(response.data)
        assert data['active'] is True

        # 3. Revoke
        response = client.post('/revoke', data={
            'token': tokens['access_token']
        }, headers=auth_header)
        assert response.status_code == 200

        # 4. Introspect again - should be inactive
        response = client.post('/introspect', data={
            'token': tokens['access_token']
        }, headers=auth_header)
        data = json.loads(response.data)
        assert data['active'] is False


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_simultaneous_tokens_for_same_user(self, client, auth_header):
        """Test that same user can have multiple valid tokens."""
        # Get first token
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        token1 = json.loads(response.data)['access_token']

        # Get second token
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        token2 = json.loads(response.data)['access_token']

        # Both should work
        response = client.get('/userinfo', headers={
            'Authorization': f'Bearer {token1}'
        })
        assert response.status_code == 200

        response = client.get('/userinfo', headers={
            'Authorization': f'Bearer {token2}'
        })
        assert response.status_code == 200

        # Tokens should be different
        assert token1 != token2

    def test_revoke_one_token_doesnt_affect_others(self, client, auth_header):
        """Test that revoking one token doesn't affect other tokens."""
        # Get two tokens
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        token1 = json.loads(response.data)['access_token']

        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        token2 = json.loads(response.data)['access_token']

        # Revoke first token
        client.post('/revoke', data={'token': token1}, headers=auth_header)

        # First token should be inactive
        response = client.post('/introspect', data={
            'token': token1
        }, headers=auth_header)
        assert json.loads(response.data)['active'] is False

        # Second token should still be active
        response = client.post('/introspect', data={
            'token': token2
        }, headers=auth_header)
        assert json.loads(response.data)['active'] is True
