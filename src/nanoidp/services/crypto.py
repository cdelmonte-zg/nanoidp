"""
Cryptographic services for JWT and SAML signing.

Supports:
- Auto-generated RSA keys
- External PEM key import
- Key rotation with multiple keys in JWKS
"""

import base64
import hashlib
import json
import logging
import os
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509.oid import NameOID

from ..config import Settings, get_config

logger = logging.getLogger(__name__)


@dataclass
class KeyInfo:
    """Information about a cryptographic key."""
    kid: str
    pub_pem: bytes
    priv_pem: Optional[bytes] = None  # Only active key has private key
    is_active: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ExternalKeysNotRotatable(ValueError):
    """Rotation was requested for operator-provided signing keys (#358)."""


def _signing_inputs(
    keys_dir: str,
    external_private_key: Optional[str],
    external_public_key: Optional[str],
    external_key_id: Optional[str],
    max_previous_keys: int,
) -> Tuple[Any, ...]:
    return (
        str(Path(keys_dir)),
        external_private_key,
        external_public_key,
        external_key_id,
        max_previous_keys,
    )


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
        # What this service was built from (see signing_inputs()).
        self.inputs = _signing_inputs(
            keys_dir, external_private_key, external_public_key, external_key_id, max_previous_keys
        )

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

    @property
    def uses_external_keys(self) -> bool:
        """True when this service signs with operator-provided PEM keys
        rather than keys_dir-generated ones."""
        return bool(self._external_private_key and self._external_public_key)

    def _ensure_keys(self) -> None:
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

        # Generate the X.509 certificate if missing, or if it does not belong
        # to the signing key (a certificate left behind by another key would
        # make every SAML signature fail verification against the metadata).
        if new_generated or not self._certificate_matches(cert_path):
            self._generate_certificate(cert_path)

        with open(cert_path, "rb") as f:
            self.cert_pem = f.read()

    def _load_external_keys(self) -> None:
        """Load external PEM keys instead of generating new ones."""
        if self._external_private_key is None or self._external_public_key is None:
            raise ValueError("External key paths not configured")
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
            private_key = serialization.load_pem_private_key(self.priv_pem, password=None)
            public_key = serialization.load_pem_public_key(self.pub_pem)
        except Exception as e:
            raise ValueError(f"Invalid PEM key format: {e}") from e
        if not isinstance(private_key, rsa.RSAPrivateKey) or not isinstance(
            public_key, rsa.RSAPublicKey
        ):
            raise ValueError("External keys must be RSA keys")
        # Two valid keys from different pairs would sign tokens with one key
        # while the JWKS serves the other (#358).
        if private_key.public_key().public_numbers() != public_key.public_numbers():
            raise ValueError(
                f"External public key {pub_path} does not belong to the private key {priv_path}"
            )

        # Without a configured kid, the RFC 7638 thumbprint: the same key
        # pair has the same kid across restarts and reloads.
        self.kid = self._external_key_id or self._jwk_thumbprint(self.pub_pem)
        logger.info(f"Loaded external keys with KID: {self.kid}")

        # The SAML certificate for this key, in a file of its own (#358): never
        # the generated keys' idp-cert.pem, which a later configuration without
        # external keys signs against, and stable across restarts for SPs that
        # pin it. Named by the public key's thumbprint, not the kid, which the
        # operator may reuse for another key.
        cert_path = self.keys_dir / f"external-cert-{self._jwk_thumbprint(self.pub_pem)}.pem"
        if not self._certificate_matches(cert_path):
            self._generate_certificate(cert_path)
        with open(cert_path, "rb") as f:
            self.cert_pem = f.read()

    def _load_previous_keys(self, keys_meta_path: Path) -> None:
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
        # The retention applies as soon as the service is built, not only at
        # the next rotation (#358): keys.json lists the newest first. Only the
        # served list is trimmed; rotate_keys removes the files.
        del self.previous_keys[self.max_previous_keys:]

    def _save_keys_metadata(self) -> None:
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

    def _certificate_matches(self, cert_path: Path) -> bool:
        """Whether ``cert_path`` holds a certificate for the signing key."""
        try:
            certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
            signing = serialization.load_pem_public_key(self.pub_pem)
            return bool(certificate.public_key().public_numbers() == signing.public_numbers())  # type: ignore[union-attr]
        except (OSError, ValueError, AttributeError):
            return False

    def _generate_certificate(self, cert_path: Path) -> None:
        """Generate a self-signed X.509 certificate."""
        logger.info("Generating self-signed certificate...")

        private_key = serialization.load_pem_private_key(self.priv_pem, password=None)
        public_key = serialization.load_pem_public_key(self.pub_pem)
        # The loaders return a union over every supported key algorithm, but
        # nanoidp keys are always RSA - and CertificateBuilder rejects e.g. DH
        # keys, so narrow before use.
        if not isinstance(private_key, rsa.RSAPrivateKey) or not isinstance(
            public_key, rsa.RSAPublicKey
        ):
            raise ValueError("Certificate generation requires RSA keys")

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
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Written beside the target and moved into place, so a reader never
        # sees a partly written certificate.
        with tempfile.NamedTemporaryFile(dir=cert_path.parent, delete=False) as tmp:
            tmp.write(cert.public_bytes(Encoding.PEM))
        os.chmod(tmp.name, 0o644)  # a certificate is public
        os.replace(tmp.name, cert_path)

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

    def _jwk_thumbprint(self, pub_pem: bytes) -> str:
        """RFC 7638 JWK thumbprint (SHA-256) of an RSA public key."""
        jwk = self._pem_to_jwk(pub_pem, kid="")
        members = json.dumps(
            {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]}, separators=(",", ":"), sort_keys=True
        )
        digest = hashlib.sha256(members.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

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
        audience: Union[str, List[str]],
        roles: Optional[List[str]] = None,
        tenant: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
        exp_minutes: int = 60,
        nonce: Optional[str] = None
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
        if nonce is not None:
            payload["nonce"] = nonce

        headers = {"kid": self.kid, "alg": "RS256", "typ": "JWT"}
        token = jwt.encode(payload, self.priv_pem, algorithm="RS256", headers=headers)
        return token

    def verify_jwt(
        self, token: str, audience: Optional[Union[str, List[str]]]
    ) -> Dict[str, Any]:
        """Verify a JWT acceptable as a NANOIDP token - not any valid RS256
        JWT.

        The ``exp`` claim is REQUIRED (#306). That is nanoidp's token-profile
        policy, not a JWT-spec requirement (RFC 7519 leaves exp optional):
        OIDC Core requires exp on ID Tokens and RFC 9068 requires it on JWT
        access tokens, ``create_jwt`` has always stamped one on everything
        nanoidp mints, and a token accepted here must have a finite lifetime
        - an eternal bearer token would let an integration test pass against
        nanoidp and fail against any real IdP. Only hand-crafted tokens
        signed with the nanoidp key ever lacked it. No other claim is
        required here; widening the enforced profile (iss, iat, jti, ...)
        is a separate discussion.

        ``audience`` accepts a list as well as a string (PyJWT semantics:
        the token is valid if its ``aud`` matches any of the values), so ID
        Tokens carrying an array ``aud`` can be verified too.

        ``audience=None`` verifies signature and expiry but NOT the audience
        (#187): nanoidp's own token-facing endpoints (/introspect, /userinfo,
        /revoke) must accept an access token whose ``aud`` is an RFC 8707
        resource, not ``oauth.audience`` - the issuer can serve a token it
        signed regardless of who it was audienced to, and the id/refresh type
        guard is ``token_use``, not the audience (RFC 7662, issue #34).
        """
        try:
            # Use public key for verification
            payload = jwt.decode(
                token,
                self.pub_pem,
                algorithms=["RS256"],
                audience=audience,
                options={
                    "verify_signature": True,
                    "verify_aud": audience is not None,
                    "require": ["exp"],
                },
            )
            return payload
        except jwt.ExpiredSignatureError as e:
            raise ValueError("Token has expired") from e
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}") from e

    def get_certificate_base64(self) -> str:
        """Get the certificate in base64 format (without headers)."""
        lines = self.cert_pem.decode().splitlines()
        b64_lines = [line for line in lines if "-----" not in line]
        return "".join(b64_lines)

    def rotate_keys(self) -> Dict[str, Any]:
        """Rotate keys: move current active key to previous, generate new active key.

        Returns:
            Dictionary with old_kid, new_kid, and rotation details.

        Raises:
            ExternalKeysNotRotatable: the service signs with operator-provided
                keys, which only the operator replaces.
        """
        if self.uses_external_keys:
            raise ExternalKeysNotRotatable(
                "The signing keys come from jwt.external_keys: to change them, point it "
                "at a new key pair and reload (a key replaced at the same paths is read "
                "at the next start)"
            )
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

    def regenerate_keys(self) -> Dict[str, Any]:
        """Regenerate RSA keys and certificate (legacy method, calls rotate_keys)."""
        return self.rotate_keys()


# The signing service of this process. Published by the configuration's
# activation step (#359), never rebuilt behind it by a reader.
_crypto_service: Optional[CryptoService] = None
_crypto_service_lock = threading.Lock()


def signing_inputs(settings: Settings) -> Tuple[Any, ...]:
    """Every setting a CryptoService is built from.

    Two configurations with equal inputs share one signing service; any
    difference, including ``max_previous_keys``, means a new one.
    """
    return _signing_inputs(
        settings.keys_dir,
        settings.external_private_key,
        settings.external_public_key,
        settings.external_key_id,
        settings.max_previous_keys,
    )


def prepare_crypto_service(settings: Settings) -> CryptoService:
    """The signing service a candidate configuration needs, built but not
    published.

    Returns the published service itself when the candidate's inputs are
    unchanged, so an unrelated reload neither rebuilds it nor touches its
    keys. Otherwise constructs a new one, which creates ``keys_dir`` and
    generates keys there if none exist, or loads the external keys; any
    failure raises, and the caller rejects the configuration.
    """
    published = _crypto_service
    if published is not None and published.inputs == signing_inputs(settings):
        return published
    return CryptoService(
        keys_dir=settings.keys_dir,
        external_private_key=settings.external_private_key,
        external_public_key=settings.external_public_key,
        external_key_id=settings.external_key_id,
        max_previous_keys=settings.max_previous_keys,
    )


def publish_crypto_service(service: CryptoService) -> None:
    """Make ``service`` the one every reader gets from get_crypto_service()."""
    global _crypto_service
    with _crypto_service_lock:
        _crypto_service = service


def activate_crypto_service(settings: Settings) -> Callable[[], None]:
    """The configuration activation step for the signing service (#359).

    Handed to ``init_config(activate=...)`` by the process composition: the
    load prepares the candidate's service before it commits anything, and
    calls the returned function to publish it once nothing can fail any
    more.
    """
    try:
        service = prepare_crypto_service(settings)
    except Exception as exc:
        raise ValueError(
            f"JWT signing configuration cannot be activated ({type(exc).__name__}: {exc})"
        ) from exc
    return lambda: publish_crypto_service(service)


def get_crypto_service() -> CryptoService:
    """The published signing service.

    Readers that also use settings read them first and this second: the
    activation publishes the service before the settings, so a request can
    pair older settings with a newer service, never newer settings with an
    older one.

    A process whose configuration was loaded without the activation step
    (a ConfigManager built directly, as tests do) gets a service built
    from the current settings on first use.
    """
    global _crypto_service
    service = _crypto_service
    if service is not None:
        return service
    settings = get_config().settings
    with _crypto_service_lock:
        service = _crypto_service
        if service is None:
            service = prepare_crypto_service(settings)
            _crypto_service = service
        return service
