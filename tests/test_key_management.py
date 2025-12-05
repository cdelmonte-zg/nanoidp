"""
Tests for NanoIDP key management.

Tests cover:
- External PEM key import
- JWKS with multiple keys
- Key rotation
"""

import os
import tempfile
import pytest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    PublicFormat,
)

from nanoidp.services.crypto import CryptoService, init_crypto_service, get_crypto_service
import nanoidp.services.crypto as crypto_module
import nanoidp.config as config_module


@pytest.fixture(autouse=True, scope="module")
def reset_singletons_for_module():
    """Reset service singletons before and after this test module.

    This prevents key rotation tests from affecting other tests.
    """
    # Reset before module starts
    crypto_module._crypto_service = None
    config_module._config = None
    yield
    # Reset after module ends
    crypto_module._crypto_service = None
    config_module._config = None


@pytest.fixture(autouse=True, scope="function")
def reset_singletons_after_test():
    """Reset service singletons after each test.

    This prevents individual tests from affecting each other.
    """
    yield
    # Reset the global crypto service singleton
    crypto_module._crypto_service = None
    # Reset the global config singleton too
    config_module._config = None


def generate_test_keypair(keys_dir: Path):
    """Generate a test RSA key pair and save to files."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    priv_path = keys_dir / "test_private.pem"
    pub_path = keys_dir / "test_public.pem"

    with open(priv_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )

    with open(pub_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return str(priv_path), str(pub_path)


class TestExternalKeyImport:
    """Tests for importing external PEM keys."""

    def test_load_external_keys_success(self):
        """Test loading external PEM keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            keys_dir = Path(tmpdir) / "keys"
            keys_dir.mkdir()

            # Generate external keys
            priv_path, pub_path = generate_test_keypair(keys_dir)

            # Create crypto service with external keys
            crypto = CryptoService(
                keys_dir=str(keys_dir),
                external_private_key=priv_path,
                external_public_key=pub_path,
                external_key_id="external-key-123",
            )

            assert crypto.kid == "external-key-123"
            assert len(crypto.priv_pem) > 0
            assert len(crypto.pub_pem) > 0

    def test_load_external_keys_generates_kid_if_not_provided(self):
        """Test that KID is auto-generated if not provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            keys_dir = Path(tmpdir) / "keys"
            keys_dir.mkdir()

            priv_path, pub_path = generate_test_keypair(keys_dir)

            crypto = CryptoService(
                keys_dir=str(keys_dir),
                external_private_key=priv_path,
                external_public_key=pub_path,
            )

            assert crypto.kid is not None
            assert len(crypto.kid) > 0

    def test_load_external_keys_missing_private_key(self):
        """Test error when private key file is missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            keys_dir = Path(tmpdir) / "keys"
            keys_dir.mkdir()

            _, pub_path = generate_test_keypair(keys_dir)

            with pytest.raises(FileNotFoundError):
                CryptoService(
                    keys_dir=str(keys_dir),
                    external_private_key="/nonexistent/private.pem",
                    external_public_key=pub_path,
                )

    def test_load_external_keys_missing_public_key(self):
        """Test error when public key file is missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            keys_dir = Path(tmpdir) / "keys"
            keys_dir.mkdir()

            priv_path, _ = generate_test_keypair(keys_dir)

            with pytest.raises(FileNotFoundError):
                CryptoService(
                    keys_dir=str(keys_dir),
                    external_private_key=priv_path,
                    external_public_key="/nonexistent/public.pem",
                )

    def test_external_keys_can_sign_jwt(self):
        """Test that external keys can be used to sign JWTs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            keys_dir = Path(tmpdir) / "keys"
            keys_dir.mkdir()

            priv_path, pub_path = generate_test_keypair(keys_dir)

            crypto = CryptoService(
                keys_dir=str(keys_dir),
                external_private_key=priv_path,
                external_public_key=pub_path,
            )

            token = crypto.create_jwt(
                sub="testuser",
                issuer="http://test",
                audience="test-app",
            )

            assert token is not None
            assert len(token.split(".")) == 3  # JWT has 3 parts


class TestJWKSMultipleKeys:
    """Tests for JWKS with multiple keys."""

    def test_get_jwks_returns_keys_array(self):
        """Test that get_jwks returns a dict with keys array."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir)
            jwks = crypto.get_jwks()

            assert "keys" in jwks
            assert isinstance(jwks["keys"], list)
            assert len(jwks["keys"]) >= 1

    def test_get_jwks_active_key_first(self):
        """Test that active key is first in JWKS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir)
            jwks = crypto.get_jwks()

            first_key = jwks["keys"][0]
            assert first_key["kid"] == crypto.kid

    def test_get_jwk_returns_single_key(self):
        """Test that get_jwk returns single active key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir)
            jwk = crypto.get_jwk()

            assert jwk["kid"] == crypto.kid
            assert jwk["kty"] == "RSA"
            assert jwk["use"] == "sig"
            assert jwk["alg"] == "RS256"

    def test_jwks_key_has_required_fields(self):
        """Test that JWKS keys have all required fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir)
            jwks = crypto.get_jwks()

            for key in jwks["keys"]:
                assert "kty" in key
                assert "kid" in key
                assert "use" in key
                assert "alg" in key
                assert "n" in key  # RSA modulus
                assert "e" in key  # RSA exponent


class TestKeyRotation:
    """Tests for key rotation functionality."""

    def test_rotate_keys_returns_info(self):
        """Test that rotate_keys returns rotation info."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir)
            old_kid = crypto.kid

            result = crypto.rotate_keys()

            assert "old_kid" in result
            assert "new_kid" in result
            assert "previous_keys_count" in result
            assert "rotated_at" in result
            assert result["old_kid"] == old_kid
            assert result["new_kid"] != old_kid

    def test_rotate_keys_changes_active_kid(self):
        """Test that rotation changes the active key ID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir)
            old_kid = crypto.kid

            crypto.rotate_keys()

            assert crypto.kid != old_kid

    def test_rotate_keys_preserves_previous_key(self):
        """Test that rotation preserves the previous key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir)
            old_kid = crypto.kid

            crypto.rotate_keys()

            # Previous key should be in the list
            assert len(crypto.previous_keys) == 1
            assert crypto.previous_keys[0].kid == old_kid

    def test_rotate_keys_previous_key_in_jwks(self):
        """Test that previous key appears in JWKS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir)
            old_kid = crypto.kid

            crypto.rotate_keys()
            jwks = crypto.get_jwks()

            kids = [key["kid"] for key in jwks["keys"]]
            assert old_kid in kids
            assert crypto.kid in kids

    def test_rotate_keys_respects_max_previous_keys(self):
        """Test that rotation respects max_previous_keys limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir, max_previous_keys=2)

            # Rotate 4 times
            for _ in range(4):
                crypto.rotate_keys()

            # Should only keep 2 previous keys
            assert len(crypto.previous_keys) == 2

    def test_rotate_keys_jwks_count_limited(self):
        """Test that JWKS key count is limited by max_previous_keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir, max_previous_keys=2)

            # Rotate 5 times
            for _ in range(5):
                crypto.rotate_keys()

            jwks = crypto.get_jwks()
            # 1 active + 2 previous = 3 keys max
            assert len(jwks["keys"]) == 3

    def test_regenerate_keys_calls_rotate(self):
        """Test that regenerate_keys calls rotate_keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir)
            old_kid = crypto.kid

            result = crypto.regenerate_keys()

            assert result["old_kid"] == old_kid
            assert crypto.kid != old_kid

    def test_rotation_saves_metadata(self):
        """Test that rotation saves keys.json metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir)
            crypto.rotate_keys()

            metadata_path = Path(tmpdir) / "keys.json"
            assert metadata_path.exists()

    def test_rotation_saves_previous_key_file(self):
        """Test that rotation saves previous key to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto = CryptoService(keys_dir=tmpdir)
            old_kid = crypto.kid

            crypto.rotate_keys()

            prev_dir = Path(tmpdir) / "previous"
            prev_key_file = prev_dir / f"{old_kid}_public.pem"
            assert prev_key_file.exists()


class TestKeyRotationAPI:
    """Tests for key rotation API endpoint.

    These tests use a temporary config directory to avoid modifying
    the actual keys used by other tests.
    """

    @pytest.fixture
    def temp_config_dir(self):
        """Create a temporary config directory with necessary files."""
        import shutil
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_config = Path(tmpdir) / "config"
            temp_config.mkdir()

            # Copy default config files
            src_config = Path("./config")
            if (src_config / "users.yaml").exists():
                shutil.copy(src_config / "users.yaml", temp_config / "users.yaml")
            if (src_config / "settings.yaml").exists():
                # Copy settings but modify keys_dir to use temp directory
                import yaml
                with open(src_config / "settings.yaml") as f:
                    settings = yaml.safe_load(f) or {}
                settings.setdefault("jwt", {})["keys_dir"] = str(temp_config / "keys")
                with open(temp_config / "settings.yaml", "w") as f:
                    yaml.dump(settings, f)

            # Create keys directory
            (temp_config / "keys").mkdir()

            yield str(temp_config)

    @pytest.fixture
    def client(self, temp_config_dir, monkeypatch):
        """Create test client using temporary config."""
        from nanoidp.app import create_app
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", temp_config_dir)
        # Reset singletons to pick up new config
        crypto_module._crypto_service = None
        config_module._config = None
        app = create_app()
        app.config["TESTING"] = True
        return app.test_client()

    def test_keys_rotate_endpoint_exists(self, client):
        """Test that /api/keys/rotate endpoint exists."""
        response = client.post("/api/keys/rotate")
        assert response.status_code == 200

    def test_keys_rotate_returns_rotation_info(self, client):
        """Test that rotation endpoint returns info."""
        response = client.post("/api/keys/rotate")
        data = response.get_json()

        assert data["success"] is True
        assert "old_kid" in data
        assert "new_kid" in data
        assert data["old_kid"] != data["new_kid"]

    def test_keys_info_endpoint_exists(self, client):
        """Test that /api/keys/info endpoint exists."""
        response = client.get("/api/keys/info")
        assert response.status_code == 200

    def test_keys_info_returns_key_info(self, client):
        """Test that keys info endpoint returns key information."""
        response = client.get("/api/keys/info")
        data = response.get_json()

        assert "active_kid" in data
        assert "previous_keys_count" in data
        assert "previous_kids" in data
        assert "max_previous_keys" in data

    def test_jwks_endpoint_returns_multiple_keys_after_rotation(self, client):
        """Test that JWKS includes previous keys after rotation."""
        # Get initial JWKS and the active key
        response1 = client.get("/.well-known/jwks.json")
        initial_jwks = response1.get_json()
        initial_kids = {key["kid"] for key in initial_jwks["keys"]}

        # Rotate keys
        rotate_response = client.post("/api/keys/rotate")
        rotate_data = rotate_response.get_json()
        new_kid = rotate_data["new_kid"]
        old_kid = rotate_data["old_kid"]

        # Get JWKS after rotation
        response2 = client.get("/.well-known/jwks.json")
        new_jwks = response2.get_json()
        new_kids = {key["kid"] for key in new_jwks["keys"]}

        # New key should be in JWKS
        assert new_kid in new_kids
        # Old key should still be in JWKS (for token validation)
        assert old_kid in new_kids
