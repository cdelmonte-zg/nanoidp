"""
Unit tests for the Authorization Code service.
Tests PKCE verification, code creation, and code consumption.
"""

import pytest
import hashlib
import base64
import secrets
from datetime import datetime, timedelta, timezone

from nanoidp.services.auth_code import (
    AuthCodeStore,
    AuthorizationCode,
    get_auth_code_store,
)


class TestPKCEVerification:
    """Tests for PKCE (Proof Key for Code Exchange) verification."""

    def test_pkce_plain_method_valid(self):
        """Test PKCE verification with plain method - valid verifier."""
        store = AuthCodeStore()
        code_verifier = "test_verifier_string"
        code_challenge = "test_verifier_string"  # Same for plain

        result = store._verify_pkce(code_verifier, code_challenge, "plain")
        assert result is True

    def test_pkce_plain_method_invalid(self):
        """Test PKCE verification with plain method - invalid verifier."""
        store = AuthCodeStore()
        code_verifier = "wrong_verifier"
        code_challenge = "correct_challenge"

        result = store._verify_pkce(code_verifier, code_challenge, "plain")
        assert result is False

    def test_pkce_s256_method_valid(self):
        """Test PKCE verification with S256 method - valid verifier."""
        store = AuthCodeStore()
        code_verifier = secrets.token_urlsafe(32)

        # Generate challenge: BASE64URL(SHA256(verifier))
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        result = store._verify_pkce(code_verifier, code_challenge, "S256")
        assert result is True

    def test_pkce_s256_method_invalid(self):
        """Test PKCE verification with S256 method - invalid verifier."""
        store = AuthCodeStore()
        code_verifier = "wrong_verifier"
        code_challenge = "some_challenge"

        result = store._verify_pkce(code_verifier, code_challenge, "S256")
        assert result is False

    def test_pkce_none_method_uses_plain(self):
        """Test that None method defaults to plain comparison."""
        store = AuthCodeStore()
        code_verifier = "test_string"
        code_challenge = "test_string"

        result = store._verify_pkce(code_verifier, code_challenge, None)
        assert result is True

    def test_pkce_unknown_method_fails(self):
        """Test that unknown PKCE methods fail verification."""
        store = AuthCodeStore()
        result = store._verify_pkce("verifier", "challenge", "unknown_method")
        assert result is False


class TestAuthorizationCodeCreation:
    """Tests for authorization code creation."""

    def test_create_code_returns_string(self):
        """Test that create_code returns a non-empty string."""
        store = AuthCodeStore()
        code = store.create_code(
            client_id="test-client",
            redirect_uri="http://localhost/callback",
            username="test-user",
        )

        assert isinstance(code, str)
        assert len(code) > 0

    def test_create_code_unique(self):
        """Test that each created code is unique."""
        store = AuthCodeStore()
        codes = set()

        for _ in range(100):
            code = store.create_code(
                client_id="test-client",
                redirect_uri="http://localhost/callback",
                username="test-user",
            )
            codes.add(code)

        assert len(codes) == 100  # All unique

    def test_create_code_stores_all_parameters(self):
        """Test that all parameters are stored correctly."""
        store = AuthCodeStore()
        code = store.create_code(
            client_id="my-client",
            redirect_uri="http://example.com/callback",
            username="john",
            scope="openid profile",
            code_challenge="challenge123",
            code_challenge_method="S256",
            nonce="nonce456",
            state="state789",
        )

        auth_code = store.get_code_info(code)

        assert auth_code is not None
        assert auth_code.client_id == "my-client"
        assert auth_code.redirect_uri == "http://example.com/callback"
        assert auth_code.username == "john"
        assert auth_code.scope == "openid profile"
        assert auth_code.code_challenge == "challenge123"
        assert auth_code.code_challenge_method == "S256"
        assert auth_code.nonce == "nonce456"
        assert auth_code.state == "state789"
        assert auth_code.used is False

    def test_create_code_default_scope(self):
        """Test that default scope is 'openid'."""
        store = AuthCodeStore()
        code = store.create_code(
            client_id="test-client",
            redirect_uri="http://localhost/callback",
            username="test-user",
        )

        auth_code = store.get_code_info(code)
        assert auth_code.scope == "openid"


class TestAuthorizationCodeConsumption:
    """Tests for authorization code consumption."""

    def test_consume_code_success(self):
        """Test successful code consumption."""
        store = AuthCodeStore()
        code = store.create_code(
            client_id="test-client",
            redirect_uri="http://localhost/callback",
            username="test-user",
        )

        auth_code = store.consume_code(
            code=code,
            client_id="test-client",
            redirect_uri="http://localhost/callback",
        )

        assert auth_code is not None
        assert auth_code.username == "test-user"
        assert auth_code.used is True

    def test_consume_code_invalid_code(self):
        """Test that invalid codes return None."""
        store = AuthCodeStore()

        auth_code = store.consume_code(
            code="invalid-code",
            client_id="test-client",
            redirect_uri="http://localhost/callback",
        )

        assert auth_code is None

    def test_consume_code_wrong_client_id(self):
        """Test that wrong client_id fails."""
        store = AuthCodeStore()
        code = store.create_code(
            client_id="correct-client",
            redirect_uri="http://localhost/callback",
            username="test-user",
        )

        auth_code = store.consume_code(
            code=code,
            client_id="wrong-client",
            redirect_uri="http://localhost/callback",
        )

        assert auth_code is None

    def test_consume_code_wrong_redirect_uri(self):
        """Test that wrong redirect_uri fails."""
        store = AuthCodeStore()
        code = store.create_code(
            client_id="test-client",
            redirect_uri="http://correct.com/callback",
            username="test-user",
        )

        auth_code = store.consume_code(
            code=code,
            client_id="test-client",
            redirect_uri="http://wrong.com/callback",
        )

        assert auth_code is None

    def test_consume_code_one_time_use(self):
        """Test that codes can only be consumed once."""
        store = AuthCodeStore()
        code = store.create_code(
            client_id="test-client",
            redirect_uri="http://localhost/callback",
            username="test-user",
        )

        # First consumption should succeed
        first_result = store.consume_code(
            code=code,
            client_id="test-client",
            redirect_uri="http://localhost/callback",
        )
        assert first_result is not None

        # Second consumption should fail
        second_result = store.consume_code(
            code=code,
            client_id="test-client",
            redirect_uri="http://localhost/callback",
        )
        assert second_result is None

    def test_consume_code_pkce_required_when_challenge_present(self):
        """Test that code_verifier is required when code was created with code_challenge."""
        store = AuthCodeStore()

        # Generate valid PKCE
        verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        code = store.create_code(
            client_id="test-client",
            redirect_uri="http://localhost/callback",
            username="test-user",
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        # Without verifier should fail
        auth_code = store.consume_code(
            code=code,
            client_id="test-client",
            redirect_uri="http://localhost/callback",
        )
        assert auth_code is None

    def test_consume_code_pkce_valid_verifier(self):
        """Test successful consumption with valid PKCE verifier."""
        store = AuthCodeStore()

        # Generate valid PKCE
        verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        code = store.create_code(
            client_id="test-client",
            redirect_uri="http://localhost/callback",
            username="test-user",
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        # With valid verifier should succeed
        auth_code = store.consume_code(
            code=code,
            client_id="test-client",
            redirect_uri="http://localhost/callback",
            code_verifier=verifier,
        )
        assert auth_code is not None
        assert auth_code.username == "test-user"

    def test_consume_code_pkce_invalid_verifier(self):
        """Test that invalid PKCE verifier fails."""
        store = AuthCodeStore()

        code = store.create_code(
            client_id="test-client",
            redirect_uri="http://localhost/callback",
            username="test-user",
            code_challenge="valid_challenge",
            code_challenge_method="S256",
        )

        # With wrong verifier should fail
        auth_code = store.consume_code(
            code=code,
            client_id="test-client",
            redirect_uri="http://localhost/callback",
            code_verifier="wrong_verifier",
        )
        assert auth_code is None


class TestAuthorizationCodeExpiration:
    """Tests for authorization code expiration."""

    def test_code_has_expiration(self):
        """Test that codes have an expiration time set."""
        store = AuthCodeStore()
        code = store.create_code(
            client_id="test-client",
            redirect_uri="http://localhost/callback",
            username="test-user",
        )

        auth_code = store.get_code_info(code)
        assert auth_code.expires_at is not None
        assert auth_code.expires_at > datetime.now(timezone.utc)

    def test_expired_code_cannot_be_consumed(self):
        """Test that expired codes cannot be consumed."""
        store = AuthCodeStore()
        code = store.create_code(
            client_id="test-client",
            redirect_uri="http://localhost/callback",
            username="test-user",
        )

        # Manually expire the code
        auth_code = store._codes[code]
        auth_code.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)

        # Try to consume expired code
        result = store.consume_code(
            code=code,
            client_id="test-client",
            redirect_uri="http://localhost/callback",
        )
        assert result is None


class TestGlobalAuthCodeStore:
    """Tests for the global auth code store singleton."""

    def test_get_auth_code_store_returns_instance(self):
        """Test that get_auth_code_store returns an AuthCodeStore."""
        store = get_auth_code_store()
        assert isinstance(store, AuthCodeStore)

    def test_get_auth_code_store_singleton(self):
        """Test that get_auth_code_store returns the same instance."""
        store1 = get_auth_code_store()
        store2 = get_auth_code_store()
        assert store1 is store2
