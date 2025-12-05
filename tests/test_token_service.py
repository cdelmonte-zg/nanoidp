"""
Unit tests for the Token Service.
Tests JWT token creation, authorities building, and token validation.
"""

import pytest
import jwt as pyjwt
from datetime import datetime, timezone

from nanoidp.services.token import TokenService, get_token_service
from nanoidp.config import User


class TestTokenCreation:
    """Tests for JWT token creation."""

    @pytest.fixture
    def token_service(self, app):
        """Get token service instance."""
        with app.app_context():
            return get_token_service()

    @pytest.fixture
    def basic_user(self):
        """Create a basic user for testing."""
        return User(
            username="testuser",
            password="testpass",
            email="test@example.org",
            roles=["USER"],
            tenant="default",
        )

    def test_create_token_returns_dict(self, token_service, basic_user, app):
        """Test that create_token returns a dictionary."""
        with app.app_context():
            result = token_service.create_token(basic_user)

        assert isinstance(result, dict)

    def test_create_token_has_required_fields(self, token_service, basic_user, app):
        """Test that token response has all required fields."""
        with app.app_context():
            result = token_service.create_token(basic_user)

        assert "access_token" in result
        assert "token_type" in result
        assert "expires_in" in result
        assert "refresh_token" in result
        assert "scope" in result

    def test_create_token_type_is_bearer(self, token_service, basic_user, app):
        """Test that token_type is Bearer."""
        with app.app_context():
            result = token_service.create_token(basic_user)

        assert result["token_type"] == "Bearer"

    def test_create_token_has_jti(self, token_service, basic_user, app):
        """Test that access token has a JTI (JWT ID)."""
        with app.app_context():
            result = token_service.create_token(basic_user)

        # Decode token to check for JTI
        decoded = pyjwt.decode(
            result["access_token"],
            options={"verify_signature": False}
        )

        assert "jti" in decoded
        assert isinstance(decoded["jti"], str)
        assert len(decoded["jti"]) > 0

    def test_create_token_jti_unique(self, token_service, basic_user, app):
        """Test that each token has a unique JTI."""
        jtis = set()

        with app.app_context():
            for _ in range(10):
                result = token_service.create_token(basic_user)
                decoded = pyjwt.decode(
                    result["access_token"],
                    options={"verify_signature": False}
                )
                jtis.add(decoded["jti"])

        assert len(jtis) == 10  # All unique

    def test_create_token_contains_subject(self, token_service, basic_user, app):
        """Test that token contains the correct subject (username)."""
        with app.app_context():
            result = token_service.create_token(basic_user)

        decoded = pyjwt.decode(
            result["access_token"],
            options={"verify_signature": False}
        )

        assert decoded["sub"] == "testuser"

    def test_create_token_contains_roles(self, token_service, basic_user, app):
        """Test that token contains user roles."""
        with app.app_context():
            result = token_service.create_token(basic_user)

        decoded = pyjwt.decode(
            result["access_token"],
            options={"verify_signature": False}
        )

        assert "roles" in decoded
        assert decoded["roles"] == ["USER"]

    def test_create_token_contains_tenant(self, token_service, basic_user, app):
        """Test that token contains tenant."""
        with app.app_context():
            result = token_service.create_token(basic_user)

        decoded = pyjwt.decode(
            result["access_token"],
            options={"verify_signature": False}
        )

        assert "tenant" in decoded
        assert decoded["tenant"] == "default"

    def test_create_token_custom_expiry(self, token_service, basic_user, app):
        """Test that custom expiry is respected."""
        with app.app_context():
            result = token_service.create_token(basic_user, exp_minutes=30)

        assert result["expires_in"] == 30 * 60  # 30 minutes in seconds

    def test_create_token_extra_claims(self, token_service, basic_user, app):
        """Test that extra claims are included in token."""
        with app.app_context():
            result = token_service.create_token(
                basic_user,
                extra_claims={"custom_claim": "custom_value"}
            )

        decoded = pyjwt.decode(
            result["access_token"],
            options={"verify_signature": False}
        )

        assert "custom_claim" in decoded
        assert decoded["custom_claim"] == "custom_value"

    def test_refresh_token_is_different(self, token_service, basic_user, app):
        """Test that refresh token is different from access token."""
        with app.app_context():
            result = token_service.create_token(basic_user)

        assert result["access_token"] != result["refresh_token"]

    def test_refresh_token_has_token_type(self, token_service, basic_user, app):
        """Test that refresh token has token_type claim."""
        with app.app_context():
            result = token_service.create_token(basic_user)

        decoded = pyjwt.decode(
            result["refresh_token"],
            options={"verify_signature": False}
        )

        assert decoded["token_type"] == "refresh"


class TestAuthoritiesBuilding:
    """Tests for building authorities from user attributes."""

    @pytest.fixture
    def token_service(self, app):
        """Get token service instance."""
        with app.app_context():
            return get_token_service()

    def test_build_authorities_with_roles(self, token_service, app):
        """Test that roles are converted to authorities with ROLE_ prefix."""
        user = User(
            username="test",
            password="test",
            roles=["ADMIN", "user"],
            tenant="default",
        )

        with app.app_context():
            authorities = token_service.build_authorities(user)

        assert "ROLE_ADMIN" in authorities
        assert "ROLE_USER" in authorities  # Uppercased

    def test_build_authorities_with_identity_class(self, token_service, app):
        """Test that identity_class is converted to authority."""
        user = User(
            username="test",
            password="test",
            roles=[],
            tenant="default",
            identity_class="INTERNAL",
        )

        with app.app_context():
            authorities = token_service.build_authorities(user)

        assert "IDENTITY_INTERNAL" in authorities

    def test_build_authorities_with_entitlements(self, token_service, app):
        """Test that entitlements are converted to authorities with ENT_ prefix."""
        user = User(
            username="test",
            password="test",
            roles=[],
            tenant="default",
            entitlements=["READ_DATA", "WRITE_DATA"],
        )

        with app.app_context():
            authorities = token_service.build_authorities(user)

        assert "ENT_READ_DATA" in authorities
        assert "ENT_WRITE_DATA" in authorities

    def test_build_authorities_with_source_acl(self, token_service, app):
        """Test that source_acl entries are added without prefix."""
        user = User(
            username="test",
            password="test",
            roles=[],
            tenant="default",
            source_acl=["ACL_READ", "ACL_WRITE"],
        )

        with app.app_context():
            authorities = token_service.build_authorities(user)

        assert "ACL_READ" in authorities
        assert "ACL_WRITE" in authorities

    def test_build_authorities_combined(self, token_service, app):
        """Test authorities with all types combined."""
        user = User(
            username="test",
            password="test",
            roles=["ADMIN"],
            tenant="default",
            identity_class="EXTERNAL",
            entitlements=["ACCESS"],
            source_acl=["ACL_TEST"],
        )

        with app.app_context():
            authorities = token_service.build_authorities(user)

        assert "ROLE_ADMIN" in authorities
        assert "IDENTITY_EXTERNAL" in authorities
        assert "ENT_ACCESS" in authorities
        assert "ACL_TEST" in authorities

    def test_build_authorities_empty_user(self, token_service, app):
        """Test authorities with minimal user (no roles, etc.)."""
        user = User(
            username="test",
            password="test",
            roles=[],
            tenant="default",
        )

        with app.app_context():
            authorities = token_service.build_authorities(user)

        assert authorities == []


class TestTokenInclusion:
    """Tests for token claim inclusion."""

    @pytest.fixture
    def token_service(self, app):
        """Get token service instance."""
        with app.app_context():
            return get_token_service()

    def test_token_includes_authorities(self, token_service, app):
        """Test that authorities are included in token."""
        user = User(
            username="test",
            password="test",
            roles=["ADMIN"],
            tenant="default",
        )

        with app.app_context():
            result = token_service.create_token(user)

        decoded = pyjwt.decode(
            result["access_token"],
            options={"verify_signature": False}
        )

        assert "authorities" in decoded
        assert "ROLE_ADMIN" in decoded["authorities"]

    def test_token_includes_identity_class(self, token_service, app):
        """Test that identity_class is included in token claims."""
        user = User(
            username="test",
            password="test",
            roles=[],
            tenant="default",
            identity_class="PARTNER",
        )

        with app.app_context():
            result = token_service.create_token(user)

        decoded = pyjwt.decode(
            result["access_token"],
            options={"verify_signature": False}
        )

        assert "identity_class" in decoded
        assert decoded["identity_class"] == "PARTNER"

    def test_token_includes_entitlements(self, token_service, app):
        """Test that entitlements are included in token claims."""
        user = User(
            username="test",
            password="test",
            roles=[],
            tenant="default",
            entitlements=["FEATURE_X"],
        )

        with app.app_context():
            result = token_service.create_token(user)

        decoded = pyjwt.decode(
            result["access_token"],
            options={"verify_signature": False}
        )

        assert "entitlements" in decoded
        assert "FEATURE_X" in decoded["entitlements"]

    def test_token_includes_source_acl(self, token_service, app):
        """Test that source_acl is included in token claims."""
        user = User(
            username="test",
            password="test",
            roles=[],
            tenant="default",
            source_acl=["ACL_DOCS"],
        )

        with app.app_context():
            result = token_service.create_token(user)

        decoded = pyjwt.decode(
            result["access_token"],
            options={"verify_signature": False}
        )

        assert "source_acl" in decoded
        assert "ACL_DOCS" in decoded["source_acl"]

    def test_token_includes_custom_attributes(self, token_service, app):
        """Test that custom attributes are included in token claims."""
        user = User(
            username="test",
            password="test",
            roles=[],
            tenant="default",
            attributes={"department": "Engineering", "level": 5},
        )

        with app.app_context():
            result = token_service.create_token(user)

        decoded = pyjwt.decode(
            result["access_token"],
            options={"verify_signature": False}
        )

        assert "attributes" in decoded
        assert decoded["attributes"]["department"] == "Engineering"
        assert decoded["attributes"]["level"] == 5


class TestGlobalTokenService:
    """Tests for the global token service singleton."""

    def test_get_token_service_returns_instance(self, app):
        """Test that get_token_service returns a TokenService."""
        with app.app_context():
            service = get_token_service()

        assert isinstance(service, TokenService)
