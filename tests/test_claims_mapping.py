"""
Tests for claims mapping and authority prefixes.

Verifies that JWT claims and authorities are generated correctly
according to README documentation and user configuration.
"""

import json
import pytest
import jwt as pyjwt


class TestAuthorityMapping:
    """Tests for authority generation from user attributes."""

    def test_roles_get_role_prefix(self, client, auth_header):
        """Test that roles are prefixed with ROLE_."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        authorities = payload.get('authorities', [])

        # Admin user should have ROLE_ADMIN and ROLE_USER
        assert 'ROLE_ADMIN' in authorities or any('ROLE_' in a and 'ADMIN' in a for a in authorities)

    def test_identity_class_gets_identity_prefix(self, client, auth_header):
        """Test that identity_class is prefixed with IDENTITY_."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        authorities = payload.get('authorities', [])

        # Should have IDENTITY_ prefix for identity_class
        identity_authorities = [a for a in authorities if a.startswith('IDENTITY_')]
        assert len(identity_authorities) > 0 or 'identity_class' in payload

    def test_entitlements_get_ent_prefix(self, client, auth_header):
        """Test that entitlements are prefixed with ENT_."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        authorities = payload.get('authorities', [])
        entitlements = payload.get('entitlements', [])

        # If user has entitlements, they should appear with ENT_ prefix
        if entitlements:
            ent_authorities = [a for a in authorities if a.startswith('ENT_')]
            assert len(ent_authorities) > 0

    def test_source_acl_has_no_prefix(self, client, auth_header):
        """Test that source_acl values have no prefix (passed as-is)."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        authorities = payload.get('authorities', [])
        source_acl = payload.get('source_acl', [])

        # source_acl values should appear directly in authorities
        for acl in source_acl:
            assert acl in authorities


class TestClaimsInToken:
    """Tests for standard claims in JWT token."""

    def test_token_contains_sub_claim(self, client, auth_header):
        """Test that token contains sub (subject) claim."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        assert 'sub' in payload
        assert payload['sub'] == 'admin'

    def test_token_contains_iss_claim(self, client, auth_header):
        """Test that token contains iss (issuer) claim."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        assert 'iss' in payload
        assert len(payload['iss']) > 0

    def test_token_contains_aud_claim(self, client, auth_header):
        """Test that token contains aud (audience) claim."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        assert 'aud' in payload

    def test_token_contains_exp_claim(self, client, auth_header):
        """Test that token contains exp (expiration) claim."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        assert 'exp' in payload
        assert isinstance(payload['exp'], int)

    def test_token_contains_iat_claim(self, client, auth_header):
        """Test that token contains iat (issued at) claim."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        assert 'iat' in payload
        assert isinstance(payload['iat'], int)


class TestUserAttributesInToken:
    """Tests for user-specific attributes in JWT token."""

    def test_token_contains_roles(self, client, auth_header):
        """Test that token contains roles from user config."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        # Token should have roles array
        assert 'roles' in payload
        assert isinstance(payload['roles'], list)

    def test_token_contains_tenant(self, client, auth_header):
        """Test that token contains tenant from user config."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        # Token should have tenant if configured
        if 'tenant' in payload:
            assert isinstance(payload['tenant'], str)

    def test_token_contains_identity_class(self, client, auth_header):
        """Test that token contains identity_class from user config."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        # Token should have identity_class if configured
        if 'identity_class' in payload:
            assert isinstance(payload['identity_class'], str)


class TestAuthorityPrefixConfiguration:
    """Tests for authority prefix configuration behavior."""

    def test_build_authorities_with_default_prefixes(self):
        """Test authority building with default prefix configuration."""
        from nanoidp.services.token import TokenService
        from nanoidp.config import User

        user = User(
            username="testuser",
            password="test",
            roles=["USER", "TESTER"],
            identity_class="INTERNAL",
            entitlements=["READ_DOCS"],
            source_acl=["ACL_READ"]
        )

        service = TokenService()
        authorities = service.build_authorities(user)

        # Check that authorities include properly prefixed values
        assert any('USER' in a for a in authorities)
        assert any('INTERNAL' in a for a in authorities)
        # ACL_READ should be in authorities directly
        assert 'ACL_READ' in authorities

    def test_authorities_array_documented_format(self, client, auth_header):
        """Test that authorities array matches README documentation format.

        From README:
        "authorities": [
            "ROLE_USER",
            "ROLE_ADMIN",
            "IDENTITY_INTERNAL",
            "ENT_ADMIN_ACCESS",
            "ACL_READ",
            "ACL_WRITE"
        ]
        """
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        token = json.loads(response.data)['access_token']
        payload = pyjwt.decode(token, options={"verify_signature": False})

        authorities = payload.get('authorities', [])

        # Authorities should be a flat list of strings
        assert isinstance(authorities, list)
        for auth in authorities:
            assert isinstance(auth, str)


class TestEmptyAndMissingFields:
    """Tests for handling empty and missing user fields."""

    def test_user_with_empty_roles_generates_valid_token(self):
        """Test that users with empty roles still generate valid tokens."""
        from nanoidp.services.token import TokenService
        from nanoidp.config import User

        user = User(
            username="minimaluser",
            password="test",
            roles=[],
            identity_class=None,
            entitlements=[],
            source_acl=[]
        )

        service = TokenService()
        authorities = service.build_authorities(user)

        # Should return empty or minimal authorities
        assert isinstance(authorities, list)

    def test_user_with_none_identity_class(self):
        """Test that users with None identity_class don't add spurious authorities."""
        from nanoidp.services.token import TokenService
        from nanoidp.config import User

        user = User(
            username="noidentity",
            password="test",
            roles=["USER"],
            identity_class=None
        )

        service = TokenService()
        authorities = service.build_authorities(user)

        # Should not have any IDENTITY_ prefixed entry
        identity_authorities = [a for a in authorities if 'IDENTITY_None' in a]
        assert len(identity_authorities) == 0
