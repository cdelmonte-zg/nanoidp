"""
Unit tests for the Configuration Manager.
Tests user management, client management, and authentication.
"""

import pytest

from nanoidp.config import (
    ConfigManager,
    User,
    OAuthClient,
    Settings,
    get_config,
)


class TestUserManagement:
    """Tests for user management functionality."""

    def test_get_user_exists(self, app):
        """Test getting an existing user."""
        with app.app_context():
            config = get_config()
            user = config.get_user("admin")

        assert user is not None
        assert user.username == "admin"

    def test_get_user_not_exists(self, app):
        """Test getting a non-existent user returns None."""
        with app.app_context():
            config = get_config()
            user = config.get_user("nonexistent-user")

        assert user is None

    def test_user_has_required_fields(self, app):
        """Test that user objects have all required fields."""
        with app.app_context():
            config = get_config()
            user = config.get_user("admin")

        assert hasattr(user, "username")
        assert hasattr(user, "password")
        assert hasattr(user, "email")
        assert hasattr(user, "roles")
        assert hasattr(user, "tenant")

    def test_user_optional_fields(self, app):
        """Test that user objects have optional fields."""
        with app.app_context():
            config = get_config()
            user = config.get_user("admin")

        assert hasattr(user, "identity_class")
        assert hasattr(user, "entitlements")
        assert hasattr(user, "source_acl")
        assert hasattr(user, "attributes")


class TestUserAuthentication:
    """Tests for user authentication."""

    def test_authenticate_valid_credentials(self, app):
        """Test authentication with valid credentials."""
        with app.app_context():
            config = get_config()
            user = config.authenticate("admin", "admin")

        assert user is not None
        assert user.username == "admin"

    def test_authenticate_invalid_password(self, app):
        """Test authentication with wrong password."""
        with app.app_context():
            config = get_config()
            user = config.authenticate("admin", "wrong-password")

        assert user is None

    def test_authenticate_invalid_username(self, app):
        """Test authentication with non-existent user."""
        with app.app_context():
            config = get_config()
            user = config.authenticate("nonexistent", "password")

        assert user is None

    def test_authenticate_empty_credentials(self, app):
        """Test authentication with empty credentials."""
        with app.app_context():
            config = get_config()

        user = config.authenticate("", "")
        assert user is None


class TestClientManagement:
    """Tests for OAuth client management."""

    def test_check_client_valid(self, app):
        """Test checking valid client credentials."""
        with app.app_context():
            config = get_config()
            result = config.check_client("demo-client", "demo-secret")

        assert result is True

    def test_check_client_invalid_secret(self, app):
        """Test checking client with wrong secret."""
        with app.app_context():
            config = get_config()
            result = config.check_client("demo-client", "wrong-secret")

        assert result is False

    def test_check_client_invalid_id(self, app):
        """Test checking non-existent client."""
        with app.app_context():
            config = get_config()
            result = config.check_client("nonexistent-client", "any-secret")

        assert result is False

    def test_get_client_exists(self, app):
        """Test getting an existing client."""
        with app.app_context():
            config = get_config()
            client = config.get_client("demo-client")

        assert client is not None
        assert client.client_id == "demo-client"

    def test_get_client_not_exists(self, app):
        """Test getting a non-existent client returns None."""
        with app.app_context():
            config = get_config()
            client = config.get_client("nonexistent-client")

        assert client is None


class TestSettings:
    """Tests for settings configuration."""

    def test_settings_has_issuer(self, app):
        """Test that settings has issuer URL."""
        with app.app_context():
            config = get_config()

        assert config.settings.issuer is not None
        assert config.settings.issuer.startswith("http")

    def test_settings_has_audience(self, app):
        """Test that settings has audience."""
        with app.app_context():
            config = get_config()

        assert config.settings.audience is not None

    def test_settings_has_token_expiry(self, app):
        """Test that settings has token expiry in minutes."""
        with app.app_context():
            config = get_config()

        assert config.settings.token_expiry_minutes > 0

    def test_settings_has_clients(self, app):
        """Test that settings has OAuth clients configured."""
        with app.app_context():
            config = get_config()

        assert len(config.settings.clients) > 0

    def test_settings_has_authority_prefixes(self, app):
        """Test that settings has authority prefixes."""
        with app.app_context():
            config = get_config()

        prefixes = config.settings.authority_prefixes
        assert "roles" in prefixes
        assert "identity_class" in prefixes
        assert "entitlements" in prefixes


class TestDefaultUser:
    """Tests for default user configuration."""

    def test_default_user_is_set(self, app):
        """Test that default_user is configured."""
        with app.app_context():
            config = get_config()

        assert config.default_user is not None
        assert len(config.default_user) > 0

    def test_default_user_exists(self, app):
        """Test that default_user refers to an existing user."""
        with app.app_context():
            config = get_config()
            user = config.get_user(config.default_user)

        assert user is not None


class TestUserDataclass:
    """Tests for the User dataclass."""

    def test_user_creation_minimal(self):
        """Test creating a user with minimal fields."""
        user = User(
            username="test",
            password="pass",
            roles=["USER"],
            tenant="default",
        )

        assert user.username == "test"
        assert user.password == "pass"
        assert user.roles == ["USER"]
        assert user.tenant == "default"

    def test_user_creation_full(self):
        """Test creating a user with all fields."""
        user = User(
            username="test",
            password="pass",
            email="test@example.org",
            roles=["ADMIN"],
            tenant="corp",
            identity_class="INTERNAL",
            entitlements=["ACCESS"],
            source_acl=["ACL_READ"],
            attributes={"level": 5},
        )

        assert user.email == "test@example.org"
        assert user.identity_class == "INTERNAL"
        assert user.entitlements == ["ACCESS"]
        assert user.source_acl == ["ACL_READ"]
        assert user.attributes == {"level": 5}

    def test_user_default_email(self):
        """Test that default email is empty string."""
        user = User(
            username="john",
            password="pass",
            roles=[],
            tenant="default",
        )

        assert user.email == ""  # Default is empty string

    def test_user_default_empty_lists(self):
        """Test that optional list fields default to empty."""
        user = User(
            username="test",
            password="pass",
            roles=[],
            tenant="default",
        )

        assert user.entitlements == []
        assert user.source_acl == []
        assert user.attributes == {}


class TestOAuthClientDataclass:
    """Tests for the OAuthClient dataclass."""

    def test_client_creation(self):
        """Test creating an OAuth client."""
        client = OAuthClient(
            client_id="my-app",
            client_secret="my-secret",
        )

        assert client.client_id == "my-app"
        assert client.client_secret == "my-secret"

    def test_client_with_description(self):
        """Test creating a client with description."""
        client = OAuthClient(
            client_id="my-app",
            client_secret="my-secret",
            description="My Application",
        )

        assert client.description == "My Application"

    def test_client_default_description(self):
        """Test that description defaults to empty string."""
        client = OAuthClient(
            client_id="my-app",
            client_secret="my-secret",
        )

        assert client.description == ""


class TestGlobalConfig:
    """Tests for the global configuration singleton."""

    def test_get_config_returns_instance(self, app):
        """Test that get_config returns a ConfigManager."""
        with app.app_context():
            config = get_config()

        assert isinstance(config, ConfigManager)

    def test_get_config_singleton(self, app):
        """Test that get_config returns the same instance."""
        with app.app_context():
            config1 = get_config()
            config2 = get_config()

        assert config1 is config2


class TestUserPydanticValidation:
    """Tests for User Pydantic validation."""

    def test_user_empty_username_fails(self):
        """Test that empty username raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            User(username="", password="pass")

        assert "username" in str(exc_info.value)

    def test_user_empty_password_fails(self):
        """Test that empty password raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            User(username="test", password="")

        assert "password" in str(exc_info.value)

    def test_user_invalid_email_fails(self):
        """Test that invalid email raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            User(username="test", password="pass", email="invalid-no-at-sign")

        assert "email" in str(exc_info.value).lower()

    def test_user_valid_email_passes(self):
        """Test that valid email is accepted."""
        user = User(username="test", password="pass", email="test@example.com")
        assert user.email == "test@example.com"

    def test_user_empty_email_passes(self):
        """Test that empty email is accepted (optional field)."""
        user = User(username="test", password="pass", email="")
        assert user.email == ""

    def test_user_to_dict_works(self):
        """Test that to_dict returns expected dictionary."""
        user = User(
            username="test",
            password="pass",
            email="test@example.com",
            roles=["ADMIN"],
            tenant="corp",
        )
        result = user.to_dict()

        assert result["username"] == "test"
        assert result["email"] == "test@example.com"
        assert result["roles"] == ["ADMIN"]
        assert result["tenant"] == "corp"
        assert "password" not in result  # Password should not be in to_dict


class TestOAuthClientPydanticValidation:
    """Tests for OAuthClient Pydantic validation."""

    def test_client_empty_id_fails(self):
        """Test that empty client_id raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            OAuthClient(client_id="", client_secret="secret")

        assert "client_id" in str(exc_info.value)

    def test_client_empty_secret_fails(self):
        """Test that empty client_secret raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            OAuthClient(client_id="my-app", client_secret="")

        assert "client_secret" in str(exc_info.value)

    def test_client_valid_creation(self):
        """Test that valid client is created successfully."""
        client = OAuthClient(
            client_id="my-app",
            client_secret="my-secret",
            description="Test app",
        )
        assert client.client_id == "my-app"
        assert client.client_secret == "my-secret"
        assert client.description == "Test app"


class TestSettingsPydanticValidation:
    """Tests for Settings Pydantic validation."""

    def test_settings_invalid_port_too_low(self):
        """Test that port < 1 raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            Settings(port=0)

        assert "port" in str(exc_info.value)

    def test_settings_invalid_port_too_high(self):
        """Test that port > 65535 raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            Settings(port=99999)

        assert "port" in str(exc_info.value)

    def test_settings_valid_port(self):
        """Test that valid port is accepted."""
        settings = Settings(port=8080)
        assert settings.port == 8080

    def test_settings_invalid_issuer_not_url(self):
        """Test that non-URL issuer raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            Settings(issuer="not-a-url")

        assert "issuer" in str(exc_info.value).lower()

    def test_settings_issuer_trailing_slash_normalized(self):
        """Test that trailing slash is removed from issuer."""
        settings = Settings(issuer="http://localhost:8000/")
        assert settings.issuer == "http://localhost:8000"

    def test_settings_invalid_token_expiry_zero(self):
        """Test that token_expiry_minutes = 0 raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            Settings(token_expiry_minutes=0)

        assert "token_expiry" in str(exc_info.value)

    def test_settings_invalid_token_expiry_too_high(self):
        """Test that token_expiry_minutes > 1440 raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            Settings(token_expiry_minutes=1441)

        assert "token_expiry" in str(exc_info.value)

    def test_settings_valid_token_expiry(self):
        """Test that valid token_expiry is accepted."""
        settings = Settings(token_expiry_minutes=120)
        assert settings.token_expiry_minutes == 120

    def test_settings_invalid_log_level(self):
        """Test that invalid log_level raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            Settings(log_level="INVALID")

        assert "log_level" in str(exc_info.value).lower()

    def test_settings_log_level_normalized_uppercase(self):
        """Test that log_level is normalized to uppercase."""
        settings = Settings(log_level="debug")
        assert settings.log_level == "DEBUG"

    def test_settings_valid_log_levels(self):
        """Test that all valid log levels are accepted."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            settings = Settings(log_level=level)
            assert settings.log_level == level

    def test_settings_empty_audience_fails(self):
        """Test that empty audience raises ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            Settings(audience="")

        assert "audience" in str(exc_info.value)

    def test_settings_default_values(self):
        """Test that Settings has sensible defaults."""
        settings = Settings()

        assert settings.host == "0.0.0.0"
        assert settings.port == 8000
        assert settings.debug is False
        assert settings.issuer == "http://localhost:8000"
        assert settings.audience == "default"
        assert settings.token_expiry_minutes == 60
        assert settings.jwt_algorithm == "RS256"
        assert settings.log_level == "INFO"
