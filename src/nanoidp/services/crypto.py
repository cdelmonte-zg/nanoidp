"""
Cryptographic services for JWT and SAML signing.

Supports:
- Auto-generated RSA keys
- External PEM key import
- Key rotation with multiple keys in JWKS
"""

import json
import shutil
import uuid
import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    PublicFormat,
)
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

import jwt

logger = logging.getLogger(__name__)


@dataclass
class KeyInfo:
    """Information about a cryptographic key."""
    kid: str
    pub_pem: bytes
    priv_pem: Optional[bytes] = None  # Only active key has private key
    is_active: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CryptoService:
    """Handles cryptographic operations for JWT and SAML."""

    def __init__(
        self,
        keys_dir: str = "./keys",
        external_private_key: Optional[str] = None,
        external_public_key: Optional[str] = None,
        external_key_id: Optional[str] = None,
        max_previous_keys: int = 2,
    ):
        self.keys_dir = Path(keys_dir)
        self.max_previous_keys = max_previous_keys

        # Active key (used for signing)
        self.priv_pem: bytes = b""
        self.pub_pem: bytes = b""
        self.kid: str = ""
        self.cert_pem: bytes = b""

        # Previous keys (for token validation during rotation)
        self.previous_keys: List[KeyInfo] = []

        # External key configuration
        self._external_private_key = external_private_key
        self._external_public_key = external_public_key
        self._external_key_id = external_key_id

        self._ensure_keys()

    def _ensure_keys(self):
        """Ensure RSA keys and certificate exist."""
        self.keys_dir.mkdir(parents=True, exist_ok=True)

        # Check for external keys first
        if self._external_private_key and self._external_public_key:
            self._load_external_keys()
            return

        priv_path = self.keys_dir / "rsa_private.pem"
        pub_path = self.keys_dir / "rsa_public.pem"
        kid_path = self.keys_dir / "kid.txt"
        cert_path = self.keys_dir / "idp-cert.pem"
        keys_meta_path = self.keys_dir / "keys.json"

        new_generated = False

        if not (priv_path.exists() and pub_path.exists() and kid_path.exists()):
            logger.info("Generating new RSA key pair...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            kid = uuid.uuid4().hex

            with open(priv_path, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=NoEncryption(),
                    )
                )

            public_key = private_key.public_key()
            with open(pub_path, "wb") as f:
                f.write(
                    public_key.public_bytes(
                        encoding=Encoding.PEM,
                        format=PublicFormat.SubjectPublicKeyInfo,
                    )
                )

            with open(kid_path, "w") as f:
                f.write(kid)

            new_generated = True
            logger.info(f"Generated new key pair with KID: {kid}")

        # Load keys
        with open(priv_path, "rb") as f:
            self.priv_pem = f.read()
        with open(pub_path, "rb") as f:
            self.pub_pem = f.read()
        with open(kid_path, "r") as f:
            self.kid = f.read().strip()

        # Load previous keys from metadata
        self._load_previous_keys(keys_meta_path)

        # Generate X.509 certificate if missing
        if not cert_path.exists() or new_generated:
            self._generate_certificate(cert_path)

        with open(cert_path, "rb") as f:
            self.cert_pem = f.read()

    def _load_external_keys(self):
        """Load external PEM keys instead of generating new ones."""
        logger.info(f"Loading external keys from {self._external_private_key}")

        priv_path = Path(self._external_private_key)
        pub_path = Path(self._external_public_key)

        if not priv_path.exists():
            raise FileNotFoundError(f"External private key not found: {priv_path}")
        if not pub_path.exists():
            raise FileNotFoundError(f"External public key not found: {pub_path}")

        with open(priv_path, "rb") as f:
            self.priv_pem = f.read()
        with open(pub_path, "rb") as f:
            self.pub_pem = f.read()

        # Validate keys are valid RSA
        try:
            serialization.load_pem_private_key(self.priv_pem, password=None)
            serialization.load_pem_public_key(self.pub_pem)
        except Exception as e:
            raise ValueError(f"Invalid PEM key format: {e}")

        self.kid = self._external_key_id or uuid.uuid4().hex
        logger.info(f"Loaded external keys with KID: {self.kid}")

        # Generate certificate for SAML
        cert_path = self.keys_dir / "idp-cert.pem"
        self._generate_certificate(cert_path)
        with open(cert_path, "rb") as f:
            self.cert_pem = f.read()

    def _load_previous_keys(self, keys_meta_path: Path):
        """Load previous keys from metadata file."""
        if not keys_meta_path.exists():
            return

        try:
            with open(keys_meta_path, "r") as f:
                metadata = json.load(f)

            previous_dir = self.keys_dir / "previous"
            for key_info in metadata.get("previous_keys", []):
                kid = key_info.get("kid")
                pub_file = previous_dir / f"{kid}_public.pem"
                if pub_file.exists():
                    with open(pub_file, "rb") as f:
                        pub_pem = f.read()
                    self.previous_keys.append(KeyInfo(
                        kid=kid,
                        pub_pem=pub_pem,
                        is_active=False,
                        created_at=key_info.get("created_at", ""),
                    ))
            logger.info(f"Loaded {len(self.previous_keys)} previous keys for JWKS")
        except Exception as e:
            logger.warning(f"Failed to load previous keys: {e}")

    def _save_keys_metadata(self):
        """Save keys metadata to file."""
        keys_meta_path = self.keys_dir / "keys.json"
        metadata = {
            "active_kid": self.kid,
            "previous_keys": [
                {"kid": k.kid, "created_at": k.created_at}
                for k in self.previous_keys
            ],
        }
        with open(keys_meta_path, "w") as f:
            json.dump(metadata, f, indent=2)

    def _generate_certificate(self, cert_path: Path):
        """Generate a self-signed X.509 certificate."""
        logger.info("Generating self-signed certificate...")

        private_key = serialization.load_pem_private_key(self.priv_pem, password=None)
        public_key = serialization.load_pem_public_key(self.pub_pem)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NanoIDP"),
                x509.NameAttribute(NameOID.COMMON_NAME, "NanoIDP Self-Signed"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(days=1))
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))

        logger.info("Certificate generated successfully")

    def _pem_to_jwk(self, pub_pem: bytes, kid: str) -> Dict[str, Any]:
        """Convert a PEM public key to JWK format."""
        public_key = serialization.load_pem_public_key(
            pub_pem, backend=default_backend()
        )

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Public key is not RSA")

        numbers = public_key.public_numbers()

        def b64url_uint(i: int) -> str:
            b = i.to_bytes((i.bit_length() + 7) // 8, "big")
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

        return {
            "kty": "RSA",
            "use": "sig",
            "kid": kid,
            "alg": "RS256",
            "n": b64url_uint(numbers.n),
            "e": b64url_uint(numbers.e),
        }

    def get_jwk(self) -> Dict[str, Any]:
        """Get the active public key as a JWK."""
        return self._pem_to_jwk(self.pub_pem, self.kid)

    def get_jwks(self) -> Dict[str, Any]:
        """Get JWKS with all keys (active + previous for rotation support)."""
        keys = [self._pem_to_jwk(self.pub_pem, self.kid)]

        # Add previous keys for token validation during rotation
        for prev_key in self.previous_keys:
            try:
                keys.append(self._pem_to_jwk(prev_key.pub_pem, prev_key.kid))
            except Exception as e:
                logger.warning(f"Failed to add previous key {prev_key.kid} to JWKS: {e}")

        return {"keys": keys}

    def create_jwt(
        self,
        sub: str,
        issuer: str,
        audience: str,
        roles: list = None,
        tenant: str = None,
        extra: dict = None,
        exp_minutes: int = 60,
    ) -> str:
        """Create a signed JWT token."""
        now = datetime.now(timezone.utc)
        payload = {
            "jti": str(uuid.uuid4()),  # JWT ID for revocation support
            "iss": issuer,
            "sub": sub,
            "aud": audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=exp_minutes)).timestamp()),
        }

        if roles:
            payload["roles"] = roles
        if tenant:
            payload["tenant"] = tenant
        if extra and isinstance(extra, dict):
            payload.update(extra)

        headers = {"kid": self.kid, "alg": "RS256", "typ": "JWT"}
        token = jwt.encode(payload, self.priv_pem, algorithm="RS256", headers=headers)
        return token

    def verify_jwt(self, token: str, audience: str) -> Dict[str, Any]:
        """Verify and decode a JWT token."""
        try:
            # Use public key for verification
            payload = jwt.decode(
                token,
                self.pub_pem,
                algorithms=["RS256"],
                audience=audience,
                options={"verify_signature": True},
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")

    def get_certificate_base64(self) -> str:
        """Get the certificate in base64 format (without headers)."""
        lines = self.cert_pem.decode().splitlines()
        b64_lines = [line for line in lines if "-----" not in line]
        return "".join(b64_lines)

    def rotate_keys(self) -> Dict[str, Any]:
        """Rotate keys: move current active key to previous, generate new active key.

        Returns:
            Dictionary with old_kid, new_kid, and rotation details.
        """
        old_kid = self.kid

        # Move current active key to previous (only public key)
        previous_dir = self.keys_dir / "previous"
        previous_dir.mkdir(parents=True, exist_ok=True)

        # Save current public key to previous directory
        prev_pub_file = previous_dir / f"{old_kid}_public.pem"
        with open(prev_pub_file, "wb") as f:
            f.write(self.pub_pem)

        # Add to previous keys list
        self.previous_keys.insert(0, KeyInfo(
            kid=old_kid,
            pub_pem=self.pub_pem,
            is_active=False,
        ))

        # Prune old keys if exceeding max_previous_keys
        while len(self.previous_keys) > self.max_previous_keys:
            removed_key = self.previous_keys.pop()
            old_pub_file = previous_dir / f"{removed_key.kid}_public.pem"
            if old_pub_file.exists():
                old_pub_file.unlink()
            logger.info(f"Removed old key {removed_key.kid} from rotation")

        # Generate new keys
        priv_path = self.keys_dir / "rsa_private.pem"
        pub_path = self.keys_dir / "rsa_public.pem"
        kid_path = self.keys_dir / "kid.txt"
        cert_path = self.keys_dir / "idp-cert.pem"

        logger.info("Generating new RSA key pair for rotation...")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        new_kid = uuid.uuid4().hex

        # Write private key
        with open(priv_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption(),
                )
            )

        # Write public key
        public_key = private_key.public_key()
        with open(pub_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo,
                )
            )

        # Write KID
        with open(kid_path, "w") as f:
            f.write(new_kid)

        # Reload keys into memory
        with open(priv_path, "rb") as f:
            self.priv_pem = f.read()
        with open(pub_path, "rb") as f:
            self.pub_pem = f.read()
        self.kid = new_kid

        # Generate new certificate
        self._generate_certificate(cert_path)
        with open(cert_path, "rb") as f:
            self.cert_pem = f.read()

        # Save metadata
        self._save_keys_metadata()

        logger.info(f"Key rotation complete: {old_kid} → {new_kid}")

        return {
            "old_kid": old_kid,
            "new_kid": new_kid,
            "previous_keys_count": len(self.previous_keys),
            "rotated_at": datetime.now(timezone.utc).isoformat(),
        }

    def regenerate_keys(self):
        """Regenerate RSA keys and certificate (legacy method, calls rotate_keys)."""
        return self.rotate_keys()


# Global crypto service instance
_crypto_service: Optional[CryptoService] = None


def get_crypto_service(keys_dir: str = "./keys") -> CryptoService:
    """Get or create the global crypto service."""
    global _crypto_service
    if _crypto_service is None:
        _crypto_service = CryptoService(keys_dir)
    return _crypto_service


def init_crypto_service(
    keys_dir: str,
    external_private_key: Optional[str] = None,
    external_public_key: Optional[str] = None,
    external_key_id: Optional[str] = None,
    max_previous_keys: int = 2,
) -> CryptoService:
    """Initialize the global crypto service.

    Args:
        keys_dir: Directory for storing generated keys
        external_private_key: Path to external private PEM key (optional)
        external_public_key: Path to external public PEM key (optional)
        external_key_id: Key ID for external keys (optional)
        max_previous_keys: Maximum number of previous keys to keep in JWKS
    """
    global _crypto_service
    _crypto_service = CryptoService(
        keys_dir=keys_dir,
        external_private_key=external_private_key,
        external_public_key=external_public_key,
        external_key_id=external_key_id,
        max_previous_keys=max_previous_keys,
    )
    return _crypto_service
