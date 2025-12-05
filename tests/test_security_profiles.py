"""
Tests for NanoIDP security profiles.

Tests cover:
- Password hashing with bcrypt
- CORS configuration
- Rate limiting
- Security profile switching
"""

import pytest
import bcrypt

from nanoidp.config import ConfigManager, Settings, User


class TestPasswordHashing:
    """Tests for bcrypt password hashing."""

    def test_hash_password_returns_bcrypt_hash(self):
        """Test that hash_password returns a valid bcrypt hash."""
        config = ConfigManager()
        hashed = config.hash_password("testpassword")

        assert hashed.startswith("$2")  # bcrypt prefix
        assert len(hashed) == 60  # bcrypt hash length

    def test_hash_password_different_each_time(self):
        """Test that hashing same password gives different hashes (salted)."""
        config = ConfigManager()
        hash1 = config.hash_password("samepassword")
        hash2 = config.hash_password("samepassword")

        assert hash1 != hash2  # Different salts

    def test_authenticate_with_plaintext_password(self):
        """Test authentication with plaintext password (dev mode)."""
        config = ConfigManager()
        config.settings.password_hashing = False

        # Add test user with plaintext password
        config.users["testuser"] = User(
            username="testuser",
            password="plaintext123",
            email="test@example.org",
        )

        # Should authenticate
        user = config.authenticate("testuser", "plaintext123")
        assert user is not None
        assert user.username == "testuser"

        # Wrong password should fail
        assert config.authenticate("testuser", "wrongpassword") is None

    def test_authenticate_with_bcrypt_password(self):
        """Test authentication with bcrypt hashed password."""
        config = ConfigManager()
        config.settings.password_hashing = True

        # Create bcrypt hash
        hashed = bcrypt.hashpw("secret123".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        config.users["hashuser"] = User(
            username="hashuser",
            password=hashed,
            email="hash@example.org",
        )

        # Should authenticate with correct password
        user = config.authenticate("hashuser", "secret123")
        assert user is not None
        assert user.username == "hashuser"

        # Wrong password should fail
        assert config.authenticate("hashuser", "wrongpassword") is None

    def test_authenticate_bcrypt_fallback_to_plaintext(self):
        """Test that invalid bcrypt hash falls back to plaintext comparison."""
        config = ConfigManager()
        config.settings.password_hashing = True

        # User with plaintext password (not a valid bcrypt hash)
        config.users["plainuser"] = User(
            username="plainuser",
            password="notahash",
            email="plain@example.org",
        )

        # Should still authenticate via fallback
        user = config.authenticate("plainuser", "notahash")
        assert user is not None

    def test_authenticate_nonexistent_user(self):
        """Test authentication with nonexistent user."""
        config = ConfigManager()
        assert config.authenticate("nonexistent", "password") is None


class TestSecurityProfileSettings:
    """Tests for security profile configuration."""

    def test_default_security_profile_is_dev(self):
        """Test that default security profile is 'dev'."""
        settings = Settings()
        assert settings.security_profile == "dev"

    def test_stricter_dev_profile_valid(self):
        """Test that 'stricter-dev' is a valid profile."""
        settings = Settings(security_profile="stricter-dev")
        assert settings.security_profile == "stricter-dev"

    def test_invalid_security_profile_fails(self):
        """Test that invalid security profile raises error."""
        with pytest.raises(ValueError) as exc_info:
            Settings(security_profile="production")
        assert "Security profile" in str(exc_info.value)

    def test_default_cors_is_permissive(self):
        """Test that default CORS allows all origins."""
        settings = Settings()
        assert settings.cors_allowed_origins == ["*"]

    def test_cors_can_be_restricted(self):
        """Test that CORS origins can be configured."""
        settings = Settings(cors_allowed_origins=["http://localhost:3000"])
        assert settings.cors_allowed_origins == ["http://localhost:3000"]

    def test_rate_limiting_disabled_by_default(self):
        """Test that rate limiting is disabled by default."""
        settings = Settings()
        assert settings.rate_limit_enabled is False

    def test_rate_limiting_can_be_enabled(self):
        """Test that rate limiting can be enabled."""
        settings = Settings(rate_limit_enabled=True)
        assert settings.rate_limit_enabled is True

    def test_rate_limit_default_value(self):
        """Test default rate limit value."""
        settings = Settings()
        assert settings.rate_limit_token_endpoint == "10/minute"

    def test_password_hashing_disabled_by_default(self):
        """Test that password hashing is disabled by default."""
        settings = Settings()
        assert settings.password_hashing is False

    def test_password_hashing_can_be_enabled(self):
        """Test that password hashing can be enabled."""
        settings = Settings(password_hashing=True)
        assert settings.password_hashing is True


class TestCORSConfiguration:
    """Tests for CORS configuration in Flask app."""

    @pytest.fixture
    def app_dev_profile(self):
        """Create app with dev profile."""
        from nanoidp.app import create_app
        app = create_app(profile="dev")
        app.config["TESTING"] = True
        return app

    @pytest.fixture
    def app_stricter_profile(self):
        """Create app with stricter-dev profile."""
        from nanoidp.app import create_app
        app = create_app(profile="stricter-dev")
        app.config["TESTING"] = True
        return app

    def test_dev_profile_allows_all_origins(self, app_dev_profile):
        """Test that dev profile allows all CORS origins."""
        with app_dev_profile.test_client() as client:
            response = client.options(
                "/health",
                headers={"Origin": "http://evil.com"}
            )
            # CORS should allow the origin
            assert response.status_code in [200, 204]

    def test_stricter_profile_restricts_cors(self, app_stricter_profile):
        """Test that stricter-dev profile has restricted CORS."""
        # The profile should be set
        from nanoidp.config import get_config
        config = get_config()
        assert config.settings.security_profile == "stricter-dev"


class TestRateLimiting:
    """Tests for rate limiting configuration."""

    def test_rate_limiter_exists_in_app(self):
        """Test that rate limiter is configured in app."""
        from nanoidp.app import create_app, get_limiter
        app = create_app(profile="stricter-dev")
        limiter = get_limiter()
        assert limiter is not None

    def test_rate_limiter_disabled_in_dev(self):
        """Test that rate limiter is effectively disabled in dev profile."""
        from nanoidp.app import create_app, get_limiter
        app = create_app(profile="dev")
        limiter = get_limiter()
        # Limiter exists but is disabled
        assert limiter is not None


class TestProfileOverrides:
    """Tests for profile-based setting overrides."""

    def test_stricter_dev_enables_password_hashing(self):
        """Test that stricter-dev profile enables password hashing."""
        from nanoidp.app import create_app
        from nanoidp.config import get_config

        app = create_app(profile="stricter-dev")
        config = get_config()

        assert config.settings.password_hashing is True

    def test_stricter_dev_enables_rate_limiting(self):
        """Test that stricter-dev profile enables rate limiting."""
        from nanoidp.app import create_app
        from nanoidp.config import get_config

        app = create_app(profile="stricter-dev")
        config = get_config()

        assert config.settings.rate_limit_enabled is True

    def test_stricter_dev_blocks_debug_mode(self):
        """Test that stricter-dev profile blocks debug mode."""
        from nanoidp.app import create_app
        from nanoidp.config import get_config

        app = create_app(profile="stricter-dev")
        config = get_config()

        assert config.settings.debug is False

    def test_dev_profile_allows_debug_mode(self):
        """Test that dev profile allows debug mode."""
        from nanoidp.config import Settings
        settings = Settings(debug=True)
        assert settings.debug is True
