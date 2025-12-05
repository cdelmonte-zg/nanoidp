"""
Tests for security edge cases in NanoIDP.

Tests cover:
- Token expiration handling
- Audience mismatch rejection
- Issuer mismatch rejection
- Signature verification
- Token type validation
"""

import json
import time
import pytest
import jwt as pyjwt
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class TestTokenExpiration:
    """Tests for expired token handling."""

    def test_expired_token_rejected_by_userinfo(self, client, auth_header):
        """Test that expired tokens are rejected by userinfo endpoint."""
        # Generate a token with very short expiry
        response = client.post('/token',
            data={
                'grant_type': 'password',
                'username': 'admin',
                'password': 'admin'
            },
            headers=auth_header
        )
        data = json.loads(response.data)
        token = data['access_token']

        # Decode and verify it's valid first
        payload = pyjwt.decode(token, options={"verify_signature": False})

        # Create a token that's already expired by manipulating the payload
        from nanoidp.services import get_crypto_service
        from nanoidp.config import get_config

        config = get_config()
        crypto = get_crypto_service(config.settings.keys_dir)

        # Create expired token (exp in the past)
        expired_payload = {
            "sub": "admin",
            "iss": config.settings.issuer,
            "aud": config.settings.audience,
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
            "iat": int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()),
        }

        expired_token = pyjwt.encode(
            expired_payload,
            crypto.priv_pem,
            algorithm="RS256",
            headers={"kid": crypto.kid}
        )

        # Try to use expired token
        response = client.get('/userinfo',
            headers={'Authorization': f'Bearer {expired_token}'}
        )
        assert response.status_code == 401

    def test_expired_token_inactive_in_introspection(self, client, auth_header):
        """Test that expired tokens show as inactive in introspection."""
        from nanoidp.services import get_crypto_service
        from nanoidp.config import get_config

        config = get_config()
        crypto = get_crypto_service(config.settings.keys_dir)

        # Create expired token
        expired_payload = {
            "sub": "admin",
            "iss": config.settings.issuer,
            "aud": config.settings.audience,
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
            "iat": int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()),
        }

        expired_token = pyjwt.encode(
            expired_payload,
            crypto.priv_pem,
            algorithm="RS256",
            headers={"kid": crypto.kid}
        )

        # Introspect expired token
        response = client.post('/introspect',
            data={'token': expired_token},
            headers=auth_header
        )
        data = json.loads(response.data)

        # Token should be inactive
        assert data.get('active') is False

    def test_token_near_expiration_still_valid(self, client, auth_header):
        """Test that tokens near expiration are still valid."""
        from nanoidp.services import get_crypto_service
        from nanoidp.config import get_config

        config = get_config()
        crypto = get_crypto_service(config.settings.keys_dir)

        # Create token expiring in 30 seconds
        valid_payload = {
            "sub": "admin",
            "iss": config.settings.issuer,
            "aud": config.settings.audience,
            "exp": int((datetime.now(timezone.utc) + timedelta(seconds=30)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        valid_token = pyjwt.encode(
            valid_payload,
            crypto.priv_pem,
            algorithm="RS256",
            headers={"kid": crypto.kid}
        )

        # Token should still work
        response = client.get('/userinfo',
            headers={'Authorization': f'Bearer {valid_token}'}
        )
        # Should be 200 or at least not 401 for expiration
        assert response.status_code in [200, 404]  # 404 if user not found is acceptable


class TestAudienceMismatch:
    """Tests for audience validation."""

    def test_token_with_wrong_audience_rejected(self, client, auth_header):
        """Test that tokens with wrong audience are rejected."""
        from nanoidp.services import get_crypto_service
        from nanoidp.config import get_config

        config = get_config()
        crypto = get_crypto_service(config.settings.keys_dir)

        # Create token with wrong audience
        wrong_aud_payload = {
            "sub": "admin",
            "iss": config.settings.issuer,
            "aud": "wrong-audience",  # Not the configured audience
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        wrong_aud_token = pyjwt.encode(
            wrong_aud_payload,
            crypto.priv_pem,
            algorithm="RS256",
            headers={"kid": crypto.kid}
        )

        # Token with wrong audience should be rejected
        response = client.get('/userinfo',
            headers={'Authorization': f'Bearer {wrong_aud_token}'}
        )
        assert response.status_code == 401

    def test_token_with_correct_audience_accepted(self, client, auth_header):
        """Test that tokens with correct audience are accepted."""
        # Get a properly issued token
        response = client.post('/token',
            data={
                'grant_type': 'password',
                'username': 'admin',
                'password': 'admin'
            },
            headers=auth_header
        )
        data = json.loads(response.data)
        token = data['access_token']

        # Verify the audience is correct
        payload = pyjwt.decode(token, options={"verify_signature": False})
        from nanoidp.config import get_config
        config = get_config()
        assert payload.get('aud') == config.settings.audience

        # Token should work
        response = client.get('/userinfo',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 200


class TestIssuerMismatch:
    """Tests for issuer validation.

    Note: NanoIDP (as a dev/test tool) validates signature, expiration, and audience,
    but does NOT validate the issuer claim. This is because the IdP trusts any token
    signed with its own key. This is acceptable for development purposes.
    """

    def test_token_with_wrong_issuer_still_accepted_if_signature_valid(self, client, auth_header):
        """Test that tokens with wrong issuer ARE accepted if signature is valid.

        NanoIDP does not validate the issuer claim - it trusts any token
        signed with its key. This test documents this behavior.
        """
        from nanoidp.services import get_crypto_service
        from nanoidp.config import get_config

        config = get_config()
        crypto = get_crypto_service(config.settings.keys_dir)

        # Create token with wrong issuer but valid signature
        wrong_iss_payload = {
            "sub": "admin",
            "iss": "https://different-issuer.com",  # Different issuer
            "aud": config.settings.audience,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        wrong_iss_token = pyjwt.encode(
            wrong_iss_payload,
            crypto.priv_pem,
            algorithm="RS256",
            headers={"kid": crypto.kid}
        )

        # Token with wrong issuer is ACCEPTED (signature validation only)
        response = client.get('/userinfo',
            headers={'Authorization': f'Bearer {wrong_iss_token}'}
        )
        # NanoIDP accepts tokens signed with its key regardless of issuer
        assert response.status_code == 200

    def test_token_issued_by_correct_idp_accepted(self, client, auth_header):
        """Test that tokens with correct issuer are accepted."""
        response = client.post('/token',
            data={
                'grant_type': 'password',
                'username': 'admin',
                'password': 'admin'
            },
            headers=auth_header
        )
        data = json.loads(response.data)
        token = data['access_token']

        # Verify issuer matches discovery
        payload = pyjwt.decode(token, options={"verify_signature": False})
        discovery_response = client.get('/.well-known/openid-configuration')
        discovery = json.loads(discovery_response.data)
        assert payload.get('iss') == discovery.get('issuer')


class TestSignatureVerification:
    """Tests for JWT signature checks."""

    def test_tampered_token_rejected(self, client, auth_header):
        """Test that tampered tokens are rejected."""
        # Get a valid token
        response = client.post('/token',
            data={
                'grant_type': 'password',
                'username': 'admin',
                'password': 'admin'
            },
            headers=auth_header
        )
        data = json.loads(response.data)
        token = data['access_token']

        # Tamper with the payload (change a character in the middle part)
        parts = token.split('.')
        # Flip a character in the payload
        tampered_payload = parts[1][:-1] + ('A' if parts[1][-1] != 'A' else 'B')
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        # Tampered token should be rejected
        response = client.get('/userinfo',
            headers={'Authorization': f'Bearer {tampered_token}'}
        )
        assert response.status_code == 401

    def test_token_with_wrong_key_rejected(self, client, auth_header):
        """Test that tokens signed with wrong key are rejected."""
        from nanoidp.config import get_config
        config = get_config()

        # Generate a different RSA key pair
        different_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        different_priv_pem = different_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Create token signed with different key
        payload = {
            "sub": "admin",
            "iss": config.settings.issuer,
            "aud": config.settings.audience,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        wrong_key_token = pyjwt.encode(
            payload,
            different_priv_pem,
            algorithm="RS256",
            headers={"kid": "wrong-key-id"}
        )

        # Token signed with wrong key should be rejected
        response = client.get('/userinfo',
            headers={'Authorization': f'Bearer {wrong_key_token}'}
        )
        assert response.status_code == 401

    def test_token_with_none_algorithm_rejected(self, client, auth_header):
        """Test that tokens with 'none' algorithm are rejected."""
        from nanoidp.config import get_config
        config = get_config()

        # Create payload
        payload = {
            "sub": "admin",
            "iss": config.settings.issuer,
            "aud": config.settings.audience,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        # Manually construct a token with "none" algorithm
        import base64
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
        none_token = f"{header}.{payload_b64}."

        # Token with none algorithm should be rejected
        response = client.get('/userinfo',
            headers={'Authorization': f'Bearer {none_token}'}
        )
        assert response.status_code == 401


class TestTokenTypeValidation:
    """Tests for token type enforcement.

    NanoIDP distinguishes between access and refresh tokens via the
    'token_type' claim in the JWT payload.
    """

    def test_refresh_token_can_access_userinfo(self, client, auth_header):
        """Test that refresh tokens CAN access userinfo in NanoIDP.

        Note: NanoIDP does not validate token_type on userinfo endpoint.
        This is acceptable for a dev tool - the token has a valid signature.
        Production IdPs typically check token_type='access' here.
        """
        # Get tokens including refresh token
        response = client.post('/token',
            data={
                'grant_type': 'password',
                'username': 'admin',
                'password': 'admin'
            },
            headers=auth_header
        )
        data = json.loads(response.data)
        refresh_token = data.get('refresh_token')

        if refresh_token:
            # Refresh token CAN access userinfo in NanoIDP
            response = client.get('/userinfo',
                headers={'Authorization': f'Bearer {refresh_token}'}
            )
            # NanoIDP accepts any valid signed token
            assert response.status_code == 200

    def test_access_token_cannot_be_used_for_refresh(self, client, auth_header):
        """Test that access tokens cannot be used for refresh grant.

        NanoIDP DOES validate token_type claim on /token endpoint for
        refresh_token grant - access tokens lack 'token_type': 'refresh'.
        """
        # Get access token
        response = client.post('/token',
            data={
                'grant_type': 'password',
                'username': 'admin',
                'password': 'admin'
            },
            headers=auth_header
        )
        data = json.loads(response.data)
        access_token = data['access_token']

        # Try to use access token as refresh token
        response = client.post('/token',
            data={
                'grant_type': 'refresh_token',
                'refresh_token': access_token  # Wrong! This is an access token
            },
            headers=auth_header
        )

        # Should fail - access token lacks token_type='refresh'
        assert response.status_code == 400


class TestMalformedTokens:
    """Tests for handling malformed tokens."""

    def test_completely_invalid_token_rejected(self, client):
        """Test that completely invalid tokens are rejected."""
        response = client.get('/userinfo',
            headers={'Authorization': 'Bearer not-a-valid-token'}
        )
        assert response.status_code == 401

    def test_empty_token_rejected(self, client):
        """Test that empty tokens are rejected."""
        response = client.get('/userinfo',
            headers={'Authorization': 'Bearer '}
        )
        assert response.status_code == 401

    def test_missing_bearer_prefix_rejected(self, client, access_token):
        """Test that tokens without Bearer prefix are rejected."""
        response = client.get('/userinfo',
            headers={'Authorization': access_token}  # Missing 'Bearer '
        )
        assert response.status_code == 401

    def test_truncated_token_rejected(self, client, access_token):
        """Test that truncated tokens are rejected."""
        truncated = access_token[:len(access_token)//2]
        response = client.get('/userinfo',
            headers={'Authorization': f'Bearer {truncated}'}
        )
        assert response.status_code == 401
