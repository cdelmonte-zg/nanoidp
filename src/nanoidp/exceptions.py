"""
Typed exceptions for NanoIDP.
Provides clear, specific error handling across the application.
"""


class NanoIDPError(Exception):
    """Base exception for all NanoIDP errors."""

    def __init__(self, message: str, code: str = "NANOIDP_ERROR"):
        self.message = message
        self.code = code
        super().__init__(message)


# Authentication Errors
class AuthenticationError(NanoIDPError):
    """Base class for authentication-related errors."""

    def __init__(self, message: str, code: str = "AUTH_ERROR"):
        super().__init__(message, code)


class InvalidCredentialsError(AuthenticationError):
    """Raised when username/password credentials are invalid."""

    def __init__(self, message: str = "Invalid username or password"):
        super().__init__(message, "INVALID_CREDENTIALS")


class UserNotFoundError(AuthenticationError):
    """Raised when a user is not found."""

    def __init__(self, username: str):
        super().__init__(f"User not found: {username}", "USER_NOT_FOUND")
        self.username = username


# Client Errors
class ClientError(NanoIDPError):
    """Base class for OAuth client-related errors."""

    def __init__(self, message: str, code: str = "CLIENT_ERROR"):
        super().__init__(message, code)


class ClientNotFoundError(ClientError):
    """Raised when an OAuth client is not found."""

    def __init__(self, client_id: str):
        super().__init__(f"Client not found: {client_id}", "CLIENT_NOT_FOUND")
        self.client_id = client_id


class InvalidClientCredentialsError(ClientError):
    """Raised when client credentials are invalid."""

    def __init__(self, client_id: str):
        super().__init__(
            f"Invalid credentials for client: {client_id}",
            "INVALID_CLIENT_CREDENTIALS"
        )
        self.client_id = client_id


# Token Errors
class TokenError(NanoIDPError):
    """Base class for token-related errors."""

    def __init__(self, message: str, code: str = "TOKEN_ERROR"):
        super().__init__(message, code)


class InvalidTokenError(TokenError):
    """Raised when a token is invalid or malformed."""

    def __init__(self, message: str = "Invalid token"):
        super().__init__(message, "INVALID_TOKEN")


class ExpiredTokenError(TokenError):
    """Raised when a token has expired."""

    def __init__(self, message: str = "Token has expired"):
        super().__init__(message, "EXPIRED_TOKEN")


class RevokedTokenError(TokenError):
    """Raised when a token has been revoked."""

    def __init__(self, message: str = "Token has been revoked"):
        super().__init__(message, "REVOKED_TOKEN")


# Authorization Code Errors
class AuthCodeError(NanoIDPError):
    """Base class for authorization code errors."""

    def __init__(self, message: str, code: str = "AUTH_CODE_ERROR"):
        super().__init__(message, code)


class InvalidAuthCodeError(AuthCodeError):
    """Raised when an authorization code is invalid."""

    def __init__(self, message: str = "Invalid authorization code"):
        super().__init__(message, "INVALID_AUTH_CODE")


class ExpiredAuthCodeError(AuthCodeError):
    """Raised when an authorization code has expired."""

    def __init__(self, message: str = "Authorization code has expired"):
        super().__init__(message, "EXPIRED_AUTH_CODE")


class PKCEValidationError(AuthCodeError):
    """Raised when PKCE code_verifier validation fails."""

    def __init__(self, message: str = "PKCE validation failed"):
        super().__init__(message, "PKCE_VALIDATION_FAILED")


# Configuration Errors
class ConfigurationError(NanoIDPError):
    """Base class for configuration-related errors."""

    def __init__(self, message: str, code: str = "CONFIG_ERROR"):
        super().__init__(message, code)


class ConfigFileNotFoundError(ConfigurationError):
    """Raised when a configuration file is not found."""

    def __init__(self, file_path: str):
        super().__init__(
            f"Configuration file not found: {file_path}",
            "CONFIG_FILE_NOT_FOUND"
        )
        self.file_path = file_path


class InvalidConfigurationError(ConfigurationError):
    """Raised when configuration is invalid."""

    def __init__(self, message: str, field: str = None):
        super().__init__(message, "INVALID_CONFIGURATION")
        self.field = field


# OAuth2 Grant Errors
class GrantError(NanoIDPError):
    """Base class for OAuth2 grant errors."""

    def __init__(self, message: str, code: str = "GRANT_ERROR"):
        super().__init__(message, code)


class UnsupportedGrantTypeError(GrantError):
    """Raised when an unsupported grant type is requested."""

    def __init__(self, grant_type: str):
        super().__init__(
            f"Unsupported grant type: {grant_type}",
            "UNSUPPORTED_GRANT_TYPE"
        )
        self.grant_type = grant_type


class InvalidGrantError(GrantError):
    """Raised when a grant is invalid."""

    def __init__(self, message: str = "Invalid grant"):
        super().__init__(message, "INVALID_GRANT")


# SAML Errors
class SAMLError(NanoIDPError):
    """Base class for SAML-related errors."""

    def __init__(self, message: str, code: str = "SAML_ERROR"):
        super().__init__(message, code)


class InvalidSAMLRequestError(SAMLError):
    """Raised when a SAML request is invalid."""

    def __init__(self, message: str = "Invalid SAML request"):
        super().__init__(message, "INVALID_SAML_REQUEST")


class SAMLSignatureError(SAMLError):
    """Raised when SAML signature validation fails."""

    def __init__(self, message: str = "SAML signature validation failed"):
        super().__init__(message, "SAML_SIGNATURE_ERROR")
