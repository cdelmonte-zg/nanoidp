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
import threading
import time
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


@dataclass(frozen=True)
class SigningKeys:
    """What a service signs and verifies with, as one value (#420).

    Replaced whole, never changed: a rotation, or the adoption of a peer's,
    assigns a new one, so a reader that takes it once cannot find the kid of
    one key next to the private key of another. Before #420 that did not
    matter much, since every token was checked against the active key
    whatever it named; with verification by kid, a token minted under one
    key's name and signed with the other would be refused for good.
    """

    kid: str
    priv_pem: bytes
    pub_pem: bytes
    cert_pem: bytes
    previous_keys: Tuple[KeyInfo, ...] = ()


_NO_KEYS = SigningKeys(kid="", priv_pem=b"", pub_pem=b"", cert_pem=b"")


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
        self._configure(keys_dir, external_private_key, external_public_key, external_key_id, max_previous_keys)
        self._ensure_keys()

    def _configure(
        self,
        keys_dir: str,
        external_private_key: Optional[str],
        external_public_key: Optional[str],
        external_key_id: Optional[str],
        max_previous_keys: int,
    ) -> None:
        self.keys_dir = Path(keys_dir)
        self.max_previous_keys = max_previous_keys
        # What this service was built from (see signing_inputs()).
        self.inputs = _signing_inputs(
            keys_dir, external_private_key, external_public_key, external_key_id, max_previous_keys
        )
        # The active key, its certificate and the previous keys kept, as one
        # value (see SigningKeys).
        self._keys: SigningKeys = _NO_KEYS
        # External key configuration
        self._external_private_key = external_private_key
        self._external_public_key = external_public_key
        self._external_key_id = external_key_id
        # What the marker looked like when it was last read, and what it
        # said (see _published_kid): identity of the file -> kid.
        self._marker: Optional[Tuple[Tuple[int, int, int], Optional[str]]] = None

    @property
    def keys(self) -> SigningKeys:
        """The keys, taken once: for a reader that needs more than one of
        them (SAML signs with the private key and sends the certificate)."""
        return self._keys

    @property
    def kid(self) -> str:
        return self._keys.kid

    @property
    def priv_pem(self) -> bytes:
        return self._keys.priv_pem

    @property
    def pub_pem(self) -> bytes:
        return self._keys.pub_pem

    @property
    def cert_pem(self) -> bytes:
        return self._keys.cert_pem

    @property
    def previous_keys(self) -> Tuple[KeyInfo, ...]:
        return self._keys.previous_keys

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
        bundle = key_directory.load_published(self.keys_dir)
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
        self._repair_certificate()

    def _repair_certificate(self) -> None:
        """Install the X.509 certificate if missing, or if it does not belong
        to the signing key (a certificate left behind by another key would
        make every SAML signature fail verification against the metadata)."""
        if not self._certificate_matches(self.cert_pem):
            self._with_certificate(self._install_certificate(key_directory.CERTIFICATE, self._published_certificate))

    def _with_certificate(self, certificate: bytes) -> None:
        self._keys = dataclasses.replace(self._keys, cert_pem=certificate)

    def _published_certificate(self) -> bytes:
        """The certificate of the bundle that is published, for
        ``_install_certificate``: called under the lock. If a peer rotated
        while this service was making a certificate for the key it had
        loaded, the published bundle is the one to sign with, and it is
        adopted here, with whatever certificate it has."""
        published = key_directory.load(self.keys_dir)
        if published is None:
            return b""
        if published.kid != self.kid:
            logger.info(f"The signing keys were rotated to {published.kid} while this service started: adopting them")
            self._adopt(published)
        return published.certificate_pem

    def _adopt(self, bundle: "key_directory.Bundle") -> None:
        """Sign and verify with ``bundle`` from here on: one assignment, so
        that no reader finds part of it."""
        # The retention applies as soon as the service is built, not only at
        # the next rotation (#358): keys.json lists the newest first. Only the
        # served list is trimmed: the public-key files of keys dropped here
        # stay on disk, unserved, and the next rotation rewrites keys.json
        # with the retained set.
        previous = tuple(
            KeyInfo(kid=key.kid, pub_pem=key.public_pem, is_active=False, created_at=key.created_at)
            for key in bundle.previous[: self.max_previous_keys]
        )
        self._keys = SigningKeys(
            kid=bundle.kid,
            priv_pem=bundle.private_pem,
            pub_pem=bundle.public_pem,
            cert_pem=bundle.certificate_pem,
            previous_keys=previous,
        )
        logger.info(f"Loaded {len(previous)} previous keys for JWKS")

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
            priv_pem = f.read()
        with open(pub_path, "rb") as f:
            pub_pem = f.read()

        # Validate keys are valid RSA
        try:
            private_key = serialization.load_pem_private_key(priv_pem, password=None)
            public_key = serialization.load_pem_public_key(pub_pem)
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
        kid = self._external_key_id or self._jwk_thumbprint(pub_pem)
        self._keys = SigningKeys(kid=kid, priv_pem=priv_pem, pub_pem=pub_pem, cert_pem=b"")
        logger.info(f"Loaded external keys with KID: {kid}")

        # The SAML certificate for this key, in a file of its own (#358): never
        # the generated keys' idp-cert.pem, which a later configuration without
        # external keys signs against, and stable across restarts for SPs that
        # pin it. Named by the public key's thumbprint, not the kid, which the
        # operator may reuse for another key.
        cert_path = self.keys_dir / f"external-cert-{self._jwk_thumbprint(pub_pem)}.pem"
        self._with_certificate(self._read_certificate(cert_path))
        if not self._certificate_matches(self.cert_pem):
            self._with_certificate(self._install_certificate(cert_path.name, lambda: self._read_certificate(cert_path)))

    @staticmethod
    def _read_certificate(cert_path: Path) -> bytes:
        try:
            return cert_path.read_bytes()
        except OSError:
            return b""

    def _install_certificate(self, name: str, published: Callable[[], bytes]) -> bytes:
        """A certificate for the signing key, under ``name`` in the keys
        directory: made outside the directory's lock, installed under it
        after looking again. A peer may have installed one meanwhile, and
        then that is the one: no marker moves for a certificate, so two
        processes that each installed their own would never find out. In a
        directory this process cannot write it keeps its own, unsaved."""
        made_for = self._keys
        certificate = self._certificate_for(made_for.priv_pem, made_for.pub_pem)
        try:
            with key_directory.locked(self.keys_dir):
                theirs = published()
                if self._certificate_matches(theirs):
                    return theirs
                if self._keys.kid != made_for.kid:
                    # Looking again adopted a bundle a peer had rotated to,
                    # and its certificate is no good either: the one made
                    # above is for a key that is no longer the signing key.
                    now = self._keys
                    certificate = self._certificate_for(now.priv_pem, now.pub_pem)
                key_directory.replace_certificate(self.keys_dir, certificate, name)
        except key_directory.LockNamespaceUnavailable:
            logger.warning(f"{self.keys_dir} is not writable: the SAML certificate was not saved")
        return certificate

    def _certificate_matches(self, certificate: bytes) -> bool:
        """Whether ``certificate`` is one for the signing key."""
        try:
            loaded = x509.load_pem_x509_certificate(certificate)
            signing = serialization.load_pem_public_key(self.pub_pem)
            return bool(loaded.public_key().public_numbers() == signing.public_numbers())  # type: ignore[union-attr]
        except (ValueError, AttributeError):
            return False

    def _as_bundle(self) -> "key_directory.Bundle":
        """What this service signs and verifies with, as a bundle."""
        keys = self._keys
        return key_directory.Bundle(
            kid=keys.kid,
            private_pem=keys.priv_pem,
            public_pem=keys.pub_pem,
            certificate_pem=keys.cert_pem,
            previous=tuple(
                key_directory.PreviousKey(kid=key.kid, public_pem=key.pub_pem, created_at=key.created_at)
                for key in keys.previous_keys
            ),
        )

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
        keys = self._keys
        return self._pem_to_jwk(keys.pub_pem, keys.kid)

    def get_jwks(self) -> Dict[str, Any]:
        """Get JWKS with all keys (active + previous for rotation support)."""
        snapshot = self._keys
        keys = [self._pem_to_jwk(snapshot.pub_pem, snapshot.kid)]

        # Add previous keys for token validation during rotation
        for prev_key in snapshot.previous_keys:
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

        # The kid and the key it names, taken together (see SigningKeys).
        keys = self._keys
        headers = {"kid": keys.kid, "alg": "RS256", "typ": "JWT"}
        token = jwt.encode(payload, keys.priv_pem, algorithm="RS256", headers=headers)
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
            # Verified against the key the token names, among the ones this
            # service keeps (#420): the JWKS publishes the previous keys so
            # that tokens signed with them stay valid, and that has to hold
            # for nanoidp's own endpoints too.
            payload = jwt.decode(
                token,
                self._verification_key(jwt.get_unverified_header(token).get("kid"), self._keys),
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

    def _verification_key(self, kid: Any, keys: SigningKeys) -> bytes:
        """The public key a token is checked against, by the ``kid`` of its
        header, among ``keys``. The kid chooses the key and vouches for
        nothing: the signature is still checked against it.

            no kid                   the active key, as it has always been
            the active kid           the active key
            a previous kid kept      that key (no more of them than
                                     ``max_previous_keys``, as in the JWKS)
            anything else            not a key of this service's

        External keys have no history: one key, whatever kid it has been
        published under. The operator may change ``external_key_id`` for
        the same pair (#358 made the thumbprint the default), and what was
        signed with that key stays valid, as it always has.
        """
        if self.uses_external_keys:
            return keys.pub_pem
        if kid is None or kid == "" or kid == keys.kid:
            return keys.pub_pem
        for previous in keys.previous_keys:
            if kid == previous.kid:
                return previous.pub_pem
        raise jwt.InvalidTokenError("the key it names is not one of this issuer's keys")

    def reloaded(self) -> Optional["CryptoService"]:
        """A service built as this one was, from the bundle the keys
        directory publishes now: what a process adopts when a peer rotated
        (#420). None when nothing whole is published.

        It loads and nothing else. The constructor would generate a key pair
        where it finds none, which is right for a process that is starting
        and wrong for one that is running: a marker with no key behind it
        (edited, restored, or its keys removed) would have the next request
        replace the signing key and every previous one with it.
        """
        bundle = key_directory.load_published(self.keys_dir)
        if bundle is None:
            return None
        fresh = object.__new__(CryptoService)
        fresh._configure(
            str(self.keys_dir),
            self._external_private_key,
            self._external_public_key,
            self._external_key_id,
            self.max_previous_keys,
        )
        fresh._adopt(bundle)
        fresh._repair_certificate()
        return fresh

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
            # And when nothing is published any more (the directory was
            # emptied under a running service), what this service signs with
            # is what is retired, as it always was: a rotation puts the
            # directory right instead of failing on it.
            old = key_directory.load(self.keys_dir) or self._as_bundle()
            retired = key_directory.PreviousKey(
                kid=old.kid,
                public_pem=old.public_pem,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            new = dataclasses.replace(fresh, previous=((retired,) + old.previous)[: self.max_previous_keys])
            for dropped in ((retired,) + old.previous)[self.max_previous_keys :]:
                logger.info(f"Removed old key {dropped.kid} from rotation")
            key_directory.rotate(self.keys_dir, new)
            # Adopted before the directory's lock is let go: a thread of this
            # process that sees the new marker and wants to load it waits for
            # that lock, and by then this service has the new keys, so that
            # nobody loads and publishes a second service for this rotation.
            self._adopt(new)
        old_kid = old.kid
        new_kid = new.kid

        logger.info(f"Key rotation complete: {old_kid} → {new_kid}")

        return {
            "old_kid": old_kid,
            "new_kid": new_kid,
            "previous_keys_count": len(new.previous),
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


# Noticing a peer's rotation (#420). The refresh has a lock of its own: the
# one services are published under is never held while the directory's lock
# is waited for, so a stuck peer does not hold up a publication (which the
# configuration's activation makes while it holds its own lock).
_refresh_lock = threading.Lock()
# While a refresh runs, since when (monotonic); read without a lock.
_refresh_started: Optional[float] = None
# The last refresh that failed: for which kid, and when (monotonic).
_refresh_failed: Optional[Tuple[str, float]] = None
# How long a request waits for another's refresh, counted from when that
# refresh began: loading a bundle takes milliseconds, and a refresh older
# than this is one that is stuck, which nobody else waits for.
_REFRESH_WAIT_SECONDS = 0.5
# How long after a failed refresh the next one is not tried. Meanwhile the
# key in hand is used, which is as correct as it was a moment ago.
_REFRESH_RETRY_SECONDS = 5.0


def _published_kid(service: CryptoService) -> Optional[str]:
    """What the directory's marker says, looked at as cheaply as it can be:
    a ``stat``, and a read only when the file is not the one read last
    (``os.replace`` makes a new file, so a rotation always shows). None when
    nothing is published; any other error is raised, not taken for "no
    rotation"."""
    marker = service.keys_dir / key_directory.MARKER
    try:
        found = os.stat(marker)
    except FileNotFoundError:
        return None
    identity = (found.st_ino, found.st_mtime_ns, found.st_size)
    seen = service._marker
    # No inode number (some filesystems report 0): the times and the size
    # are not enough on their own, every kid has the same length.
    if found.st_ino and seen is not None and seen[0] == identity:
        return seen[1]
    kid = key_directory.active_kid(service.keys_dir)
    service._marker = (identity, kid)
    return kid


def _fresh(service: CryptoService) -> CryptoService:
    """``service``, or the one that replaces it because another process
    rotated the generated keys (#420).

    The ONE place a peer's rotation is noticed: every reader of the keys
    comes through ``get_crypto_service()``, JWT and JWKS and SAML and the
    key information, so none of them has a freshness of its own.

    The marker is looked at without a lock (see ``_published_kid``). Only
    when it names another key than the one in hand is the bundle loaded,
    whole, under the directory's lock. A signature that saw OLD just before
    a peer committed NEW is correct: OLD becomes a previous key and stays
    verifiable. A NEW service is published and the one in hand is left as it
    is, so that a request that already holds it keeps a whole one.
    """
    global _refresh_started, _refresh_failed
    if service.uses_external_keys:
        return service  # not generated, not rotated, not in the directory's marker
    try:
        published = _published_kid(service)
    except OSError as failure:
        # EMFILE, EIO, EACCES: which key is published cannot be told, which
        # is not the same as "the same one", and is said.
        logger.warning(f"The signing keys' marker in {service.keys_dir} cannot be read: {failure}")
        return service
    if published is None or published == service.kid:
        # No marker says that nothing is published, not that something else
        # is: a directory emptied under a running service is not a rotation.
        return service
    started = _refresh_started
    wait = _REFRESH_WAIT_SECONDS - (time.monotonic() - started) if started is not None else _REFRESH_WAIT_SECONDS
    if wait <= 0 or not _refresh_lock.acquire(timeout=wait):
        return _crypto_service or service  # another request is refreshing, or is stuck at it
    try:
        _refresh_started = time.monotonic()
        current = _crypto_service or service
        if current is not service:
            # Another service was published since the marker was read: a
            # request that refreshed first, or a reload of the configuration
            # (external keys, another keys directory). What was read is
            # about ``service``'s directory and says nothing about this one,
            # which the next look checks on its own terms.
            return current
        if current.kid == published:
            return current  # this process rotated meanwhile
        failed = _refresh_failed
        if failed is not None and failed[0] == published and time.monotonic() - failed[1] < _REFRESH_RETRY_SECONDS:
            return current
        seen = current.kid
        try:
            refreshed = current.reloaded()
        except Exception as failure:
            _refresh_failed = (published, time.monotonic())
            logger.warning(f"The signing keys were rotated to {published} and could not be loaded yet: {failure}")
            return current
        if refreshed is None:
            _refresh_failed = (published, time.monotonic())
            logger.warning(
                f"The signing keys' marker in {current.keys_dir} names {published}, and no key is there: "
                "signing on with the one in hand"
            )
            return current
        _refresh_failed = None
        return _publish_refreshed(current, refreshed, seen)
    finally:
        _refresh_started = None
        _refresh_lock.release()


def _publish_refreshed(current: CryptoService, refreshed: CryptoService, seen: str) -> CryptoService:
    """Publish ``refreshed`` in place of ``current``, unless the world moved
    while it was loaded: ``current`` caught up by itself, or another service
    was published (a reload of the configuration), whose inputs are the ones
    that count.

    ``seen`` is the kid ``current`` had when the refresh began. Only this
    process's own rotation changes it, and a rotation retires what is
    published, so a ``current`` whose kid moved while the bundle was being
    loaded has keys newer than the ones loaded: publishing them would have
    the process sign with a key already retired.
    """
    global _crypto_service
    with _crypto_service_lock:
        if current.kid != seen or current.kid == refreshed.kid:
            return current
        if _crypto_service is not None and _crypto_service is not current:
            return _crypto_service
        logger.info(f"The signing keys were rotated by another process: {current.kid} -> {refreshed.kid}")
        _crypto_service = refreshed
        return refreshed


def get_crypto_service() -> CryptoService:
    """The published signing service.

    Readers that also use settings read them first and this second: the
    activation publishes the service before the settings, so a request can
    pair older settings with a newer service, never newer settings with an
    older one.

    With generated keys, the service returned is the one for the key that
    is published now: see ``_fresh``.

    A process whose configuration was loaded without the activation step
    (a ConfigManager built directly, as tests do) gets a service built
    from the current settings on first use.
    """
    global _crypto_service
    service = _crypto_service
    if service is not None:
        return _fresh(service)
    settings = get_config().settings
    with _crypto_service_lock:
        service = _crypto_service
        if service is None:
            service = prepare_crypto_service(settings)
            _crypto_service = service
        return service
