"""
Cryptographic services for JWT and SAML signing.

Supports:
- Auto-generated RSA keys
- External PEM key import
- Key rotation with multiple keys in JWKS
"""

import base64
import dataclasses
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
from . import key_directory

logger = logging.getLogger(__name__)


@dataclass
class KeyInfo:
    """Information about a cryptographic key."""
    kid: str
    pub_pem: bytes
    priv_pem: Optional[bytes] = None  # Only active key has private key
    is_active: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# Fixed text, returned as is by every surface that refuses the rotation.
EXTERNAL_KEYS_NOT_ROTATABLE = (
    "The signing keys come from jwt.external_keys: to change them, point it at a new "
    "key pair and reload (a key replaced at the same paths is read at the next start)"
)


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

        # Generated keys are state several processes may share (#420): what
        # is loaded is a whole bundle, the one the marker names, under the
        # directory's lock. The key itself is generated outside it (it takes
        # a tenth of a second or more), and only by whoever found nothing.
        with key_directory.locked(self.keys_dir):
            bundle = key_directory.load(self.keys_dir)
        if bundle is None:
            logger.info("Generating new RSA key pair...")
            candidate = self._new_bundle(previous=())
            with key_directory.locked(self.keys_dir):
                # Look again: another process may have won in the meantime,
                # and then its bundle is the one, whole.
                bundle = key_directory.load(self.keys_dir)
                if bundle is None:
                    key_directory.publish_first(self.keys_dir, candidate)
                    bundle = candidate
                    logger.info(f"Generated new key pair with KID: {bundle.kid}")
        self._adopt(bundle)

        # Generate the X.509 certificate if missing, or if it does not belong
        # to the signing key (a certificate left behind by another key would
        # make every SAML signature fail verification against the metadata).
        if not self._certificate_matches(self.cert_pem):
            certificate = self._certificate_for(self.priv_pem, self.pub_pem)
            with key_directory.locked(self.keys_dir):
                if key_directory.active_kid(self.keys_dir) == self.kid:
                    key_directory.replace_certificate(self.keys_dir, certificate)
            self.cert_pem = certificate

    def _adopt(self, bundle: "key_directory.Bundle") -> None:
        """Sign and verify with ``bundle`` from here on."""
        self.priv_pem = bundle.private_pem
        self.pub_pem = bundle.public_pem
        self.kid = bundle.kid
        self.cert_pem = bundle.certificate_pem
        # The retention applies as soon as the service is built, not only at
        # the next rotation (#358): keys.json lists the newest first. Only the
        # served list is trimmed: the public-key files of keys dropped here
        # stay on disk, unserved, and the next rotation rewrites keys.json
        # with the retained set.
        self.previous_keys = [
            KeyInfo(kid=key.kid, pub_pem=key.public_pem, is_active=False, created_at=key.created_at)
            for key in bundle.previous[: self.max_previous_keys]
        ]
        logger.info(f"Loaded {len(self.previous_keys)} previous keys for JWKS")

    def _new_bundle(self, previous: Tuple["key_directory.PreviousKey", ...]) -> "key_directory.Bundle":
        """A fresh key pair with its certificate, as a bundle nobody has
        published yet."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        return key_directory.Bundle(
            kid=uuid.uuid4().hex,
            private_pem=private_pem,
            public_pem=public_pem,
            certificate_pem=self._certificate_for(private_pem, public_pem),
            previous=previous,
        )

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

    def _certificate_matches(self, certificate: Union[Path, bytes]) -> bool:
        """Whether ``certificate`` (a file, or its bytes) is one for the
        signing key."""
        try:
            data = certificate.read_bytes() if isinstance(certificate, Path) else certificate
            loaded = x509.load_pem_x509_certificate(data)
            signing = serialization.load_pem_public_key(self.pub_pem)
            return bool(loaded.public_key().public_numbers() == signing.public_numbers())  # type: ignore[union-attr]
        except (OSError, ValueError, AttributeError):
            return False

    @staticmethod
    def _certificate_for(private_pem: bytes, public_pem: bytes) -> bytes:
        """A self-signed X.509 certificate for that key pair, as PEM."""
        logger.info("Generating self-signed certificate...")

        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = serialization.load_pem_public_key(public_pem)
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
        return cert.public_bytes(Encoding.PEM)

    def _generate_certificate(self, cert_path: Path) -> None:
        """Write a certificate for the signing key to ``cert_path`` (the
        external keys' own file, #358; the generated keys' certificate is
        part of their bundle)."""
        certificate = self._certificate_for(self.priv_pem, self.pub_pem)
        # Written beside the target and moved into place, so a reader never
        # sees a partly written certificate.
        with tempfile.NamedTemporaryFile(dir=cert_path.parent, delete=False) as tmp:
            tmp.write(certificate)
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
            raise ExternalKeysNotRotatable(EXTERNAL_KEYS_NOT_ROTATABLE)
        # The key is generated before the directory is locked: it takes a
        # tenth of a second or more, and the lock is everybody's (#420).
        logger.info("Generating new RSA key pair for rotation...")
        fresh = self._new_bundle(previous=())
        with key_directory.locked(self.keys_dir):
            # What is rotated is what is published, which is this service's
            # own bundle unless another process rotated since it was loaded:
            # then that one becomes the previous key, as it should.
            old = key_directory.load(self.keys_dir)
            if old is None:
                raise RuntimeError(f"No published signing keys in {self.keys_dir} to rotate")
            retired = key_directory.PreviousKey(
                kid=old.kid,
                public_pem=old.public_pem,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            new = dataclasses.replace(fresh, previous=((retired,) + old.previous)[: self.max_previous_keys])
            for dropped in ((retired,) + old.previous)[self.max_previous_keys :]:
                logger.info(f"Removed old key {dropped.kid} from rotation")
            key_directory.rotate(self.keys_dir, new)
        old_kid = old.kid
        new_kid = new.kid
        self._adopt(new)

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
