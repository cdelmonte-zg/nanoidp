"""
Unit tests for NanoIDP typed exceptions.
"""

import pytest

from nanoidp.exceptions import (
    # Base
    NanoIDPError,
    # Authentication
    AuthenticationError,
    InvalidCredentialsError,
    UserNotFoundError,
    # Client
    ClientError,
    ClientNotFoundError,
    InvalidClientCredentialsError,
    # Token
    TokenError,
    InvalidTokenError,
    ExpiredTokenError,
    RevokedTokenError,
    # Auth Code
    AuthCodeError,
    InvalidAuthCodeError,
    ExpiredAuthCodeError,
    PKCEValidationError,
    # Configuration
    ConfigurationError,
    ConfigFileNotFoundError,
    InvalidConfigurationError,
    # Grant
    GrantError,
    UnsupportedGrantTypeError,
    InvalidGrantError,
    # SAML
    SAMLError,
    InvalidSAMLRequestError,
    SAMLSignatureError,
)


class TestBaseException:
    """Tests for NanoIDPError base class."""

    def test_base_exception_message(self):
        """Test that base exception has message."""
        exc = NanoIDPError("Something went wrong")
        assert exc.message == "Something went wrong"
        assert str(exc) == "Something went wrong"

    def test_base_exception_code(self):
        """Test that base exception has error code."""
        exc = NanoIDPError("Error", code="CUSTOM_CODE")
        assert exc.code == "CUSTOM_CODE"

    def test_base_exception_default_code(self):
        """Test default error code."""
        exc = NanoIDPError("Error")
        assert exc.code == "NANOIDP_ERROR"

    def test_exception_is_catchable(self):
        """Test that exceptions can be caught."""
        with pytest.raises(NanoIDPError):
            raise NanoIDPError("Test error")


class TestAuthenticationErrors:
    """Tests for authentication-related exceptions."""

    def test_invalid_credentials_error(self):
        """Test InvalidCredentialsError."""
        exc = InvalidCredentialsError()
        assert "Invalid" in exc.message
        assert exc.code == "INVALID_CREDENTIALS"

    def test_invalid_credentials_custom_message(self):
        """Test InvalidCredentialsError with custom message."""
        exc = InvalidCredentialsError("Wrong password")
        assert exc.message == "Wrong password"

    def test_user_not_found_error(self):
        """Test UserNotFoundError."""
        exc = UserNotFoundError("john")
        assert "john" in exc.message
        assert exc.username == "john"
        assert exc.code == "USER_NOT_FOUND"

    def test_authentication_error_inheritance(self):
        """Test that auth errors inherit from AuthenticationError."""
        exc = InvalidCredentialsError()
        assert isinstance(exc, AuthenticationError)
        assert isinstance(exc, NanoIDPError)


class TestClientErrors:
    """Tests for OAuth client-related exceptions."""

    def test_client_not_found_error(self):
        """Test ClientNotFoundError."""
        exc = ClientNotFoundError("my-app")
        assert "my-app" in exc.message
        assert exc.client_id == "my-app"
        assert exc.code == "CLIENT_NOT_FOUND"

    def test_invalid_client_credentials_error(self):
        """Test InvalidClientCredentialsError."""
        exc = InvalidClientCredentialsError("my-app")
        assert "my-app" in exc.message
        assert exc.client_id == "my-app"
        assert exc.code == "INVALID_CLIENT_CREDENTIALS"

    def test_client_error_inheritance(self):
        """Test that client errors inherit from ClientError."""
        exc = ClientNotFoundError("test")
        assert isinstance(exc, ClientError)
        assert isinstance(exc, NanoIDPError)


class TestTokenErrors:
    """Tests for token-related exceptions."""

    def test_invalid_token_error(self):
        """Test InvalidTokenError."""
        exc = InvalidTokenError()
        assert exc.code == "INVALID_TOKEN"

    def test_expired_token_error(self):
        """Test ExpiredTokenError."""
        exc = ExpiredTokenError()
        assert "expired" in exc.message.lower()
        assert exc.code == "EXPIRED_TOKEN"

    def test_revoked_token_error(self):
        """Test RevokedTokenError."""
        exc = RevokedTokenError()
        assert "revoked" in exc.message.lower()
        assert exc.code == "REVOKED_TOKEN"

    def test_token_error_inheritance(self):
        """Test that token errors inherit from TokenError."""
        exc = InvalidTokenError()
        assert isinstance(exc, TokenError)
        assert isinstance(exc, NanoIDPError)


class TestAuthCodeErrors:
    """Tests for authorization code exceptions."""

    def test_invalid_auth_code_error(self):
        """Test InvalidAuthCodeError."""
        exc = InvalidAuthCodeError()
        assert exc.code == "INVALID_AUTH_CODE"

    def test_expired_auth_code_error(self):
        """Test ExpiredAuthCodeError."""
        exc = ExpiredAuthCodeError()
        assert "expired" in exc.message.lower()
        assert exc.code == "EXPIRED_AUTH_CODE"

    def test_pkce_validation_error(self):
        """Test PKCEValidationError."""
        exc = PKCEValidationError()
        assert "PKCE" in exc.message
        assert exc.code == "PKCE_VALIDATION_FAILED"

    def test_pkce_custom_message(self):
        """Test PKCEValidationError with custom message."""
        exc = PKCEValidationError("Invalid code_verifier")
        assert exc.message == "Invalid code_verifier"

    def test_auth_code_error_inheritance(self):
        """Test that auth code errors inherit from AuthCodeError."""
        exc = PKCEValidationError()
        assert isinstance(exc, AuthCodeError)
        assert isinstance(exc, NanoIDPError)


class TestConfigurationErrors:
    """Tests for configuration exceptions."""

    def test_config_file_not_found_error(self):
        """Test ConfigFileNotFoundError."""
        exc = ConfigFileNotFoundError("/path/to/config.yaml")
        assert "/path/to/config.yaml" in exc.message
        assert exc.file_path == "/path/to/config.yaml"
        assert exc.code == "CONFIG_FILE_NOT_FOUND"

    def test_invalid_configuration_error(self):
        """Test InvalidConfigurationError."""
        exc = InvalidConfigurationError("Invalid port number", field="port")
        assert "Invalid port" in exc.message
        assert exc.field == "port"
        assert exc.code == "INVALID_CONFIGURATION"

    def test_configuration_error_inheritance(self):
        """Test that config errors inherit from ConfigurationError."""
        exc = ConfigFileNotFoundError("test")
        assert isinstance(exc, ConfigurationError)
        assert isinstance(exc, NanoIDPError)


class TestGrantErrors:
    """Tests for OAuth2 grant exceptions."""

    def test_unsupported_grant_type_error(self):
        """Test UnsupportedGrantTypeError."""
        exc = UnsupportedGrantTypeError("implicit")
        assert "implicit" in exc.message
        assert exc.grant_type == "implicit"
        assert exc.code == "UNSUPPORTED_GRANT_TYPE"

    def test_invalid_grant_error(self):
        """Test InvalidGrantError."""
        exc = InvalidGrantError()
        assert exc.code == "INVALID_GRANT"

    def test_grant_error_inheritance(self):
        """Test that grant errors inherit from GrantError."""
        exc = InvalidGrantError()
        assert isinstance(exc, GrantError)
        assert isinstance(exc, NanoIDPError)


class TestSAMLErrors:
    """Tests for SAML exceptions."""

    def test_invalid_saml_request_error(self):
        """Test InvalidSAMLRequestError."""
        exc = InvalidSAMLRequestError()
        assert exc.code == "INVALID_SAML_REQUEST"

    def test_saml_signature_error(self):
        """Test SAMLSignatureError."""
        exc = SAMLSignatureError()
        assert "signature" in exc.message.lower()
        assert exc.code == "SAML_SIGNATURE_ERROR"

    def test_saml_error_inheritance(self):
        """Test that SAML errors inherit from SAMLError."""
        exc = InvalidSAMLRequestError()
        assert isinstance(exc, SAMLError)
        assert isinstance(exc, NanoIDPError)


class TestExceptionHierarchy:
    """Tests for exception hierarchy and catch-all behavior."""

    def test_catch_all_with_base_class(self):
        """Test that all exceptions can be caught with NanoIDPError."""
        exceptions = [
            InvalidCredentialsError(),
            UserNotFoundError("test"),
            ClientNotFoundError("test"),
            InvalidTokenError(),
            PKCEValidationError(),
            ConfigFileNotFoundError("test"),
            UnsupportedGrantTypeError("test"),
            InvalidSAMLRequestError(),
        ]

        for exc in exceptions:
            assert isinstance(exc, NanoIDPError)

    def test_specific_catch(self):
        """Test that specific exceptions can be caught separately."""
        def raise_auth_error():
            raise InvalidCredentialsError()

        def raise_token_error():
            raise ExpiredTokenError()

        # AuthenticationError should catch InvalidCredentialsError
        with pytest.raises(AuthenticationError):
            raise_auth_error()

        # TokenError should catch ExpiredTokenError
        with pytest.raises(TokenError):
            raise_token_error()

        # But AuthenticationError should NOT catch TokenError
        with pytest.raises(TokenError):
            try:
                raise_token_error()
            except AuthenticationError:
                pytest.fail("TokenError should not be caught by AuthenticationError")
