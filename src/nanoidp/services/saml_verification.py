"""
AuthnRequest signature verification (issue #69).

Opt-in via ``saml.want_authn_requests_signed``: SPs that sign their requests
can test that nanoidp actually validates the signatures, under both bindings:

- **HTTP-Redirect** (SAML 2.0 Bindings §3.4.4.1): the signature covers the
  URL-encoded query fragment ``SAMLRequest=...[&RelayState=...]&SigAlg=...``
  exactly as transmitted, so verification works on the *raw* query string -
  re-encoding the values would break it.
- **HTTP-POST** (SAML 2.0 Core §5): an enveloped ``ds:Signature`` inside the
  AuthnRequest XML, verified with signxml against the registered
  certificates. XML always passes through ``secure_fromstring`` semantics
  upstream (XXE-safe); signxml gets the raw bytes and applies its own
  hardened parsing.

SP certificates are PEM files listed in ``saml.sp_certificates``; a request
verifies if any registered certificate validates it.
"""

import base64
import logging
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_pem_x509_certificate

from ..exceptions import SAMLSignatureError

logger = logging.getLogger(__name__)

# SigAlg URIs (RFC 4051 / xmldsig) accepted for the Redirect binding. SHA-1 is
# obsolete but kept for legacy SPs - this is a dev tool and the point is
# exercising the SP's actual configuration.
_REDIRECT_SIG_ALGS: Dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": hashes.SHA256,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": hashes.SHA512,
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1": hashes.SHA1,
}


def load_sp_certificates(paths: List[str]) -> List[bytes]:
    """Read the registered SP certificate PEMs; unreadable paths are skipped
    with a warning (a missing file must not take the whole IdP down)."""
    certs: List[bytes] = []
    for path in paths:
        try:
            with open(path, "rb") as f:
                certs.append(f.read())
        except OSError as e:
            logger.warning(f"SP certificate '{path}' could not be read: {e}")
    return certs


def _raw_query_params(raw_query: str) -> List[Tuple[str, str]]:
    """Split a raw query string into (name, raw_value) pairs WITHOUT decoding
    the values - the Redirect-binding signature covers the transmitted bytes."""
    pairs: List[Tuple[str, str]] = []
    for chunk in raw_query.split("&"):
        if not chunk:
            continue
        name, _, raw_value = chunk.partition("=")
        pairs.append((name, raw_value))
    return pairs


def verify_redirect_signature(raw_query: str, cert_pems: List[bytes]) -> None:
    """Verify an HTTP-Redirect binding signature (Bindings §3.4.4.1).

    Raises SAMLSignatureError when the request is unsigned, uses an
    unsupported SigAlg, or no registered certificate validates it.
    """
    params = dict(_raw_query_params(raw_query))
    if "Signature" not in params or "SigAlg" not in params:
        raise SAMLSignatureError(
            "AuthnRequest is not signed (Signature/SigAlg query parameters "
            "required by want_authn_requests_signed)"
        )

    sig_alg = unquote(params["SigAlg"])
    hash_cls = _REDIRECT_SIG_ALGS.get(sig_alg)
    if hash_cls is None:
        raise SAMLSignatureError(f"Unsupported SigAlg: {sig_alg}")

    try:
        signature = base64.b64decode(unquote(params["Signature"]), validate=True)
    except Exception as e:
        raise SAMLSignatureError(f"Malformed Signature parameter: {e}") from e

    # The signed octet string is the URL-encoded fragment in transmission
    # order, Signature excluded (Bindings §3.4.4.1).
    ordered = [
        f"{name}={raw_value}"
        for name, raw_value in _raw_query_params(raw_query)
        if name in ("SAMLRequest", "RelayState", "SigAlg")
    ]
    signed_octets = "&".join(ordered).encode("utf-8")

    if not cert_pems:
        raise SAMLSignatureError(
            "want_authn_requests_signed is enabled but no saml.sp_certificates "
            "are registered"
        )

    last_error: Optional[Exception] = None
    for pem in cert_pems:
        try:
            public_key = load_pem_x509_certificate(pem).public_key()
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise SAMLSignatureError("SP certificate does not carry an RSA key")
            public_key.verify(signature, signed_octets, padding.PKCS1v15(), hash_cls())
            return
        except Exception as e:  # try the next registered certificate
            last_error = e
    raise SAMLSignatureError(
        f"Redirect-binding signature did not verify against any registered "
        f"SP certificate: {last_error}"
    )


def verify_post_signature(xml_bytes: bytes, cert_pems: List[bytes]) -> None:
    """Verify an enveloped XML signature on an AuthnRequest (Core §5).

    Raises SAMLSignatureError when the document is unsigned or no registered
    certificate validates it.
    """
    # Imported lazily: signxml is heavyweight and this only runs when the
    # opt-in verification is enabled.
    from signxml import XMLVerifier

    if b"Signature" not in xml_bytes:
        raise SAMLSignatureError(
            "AuthnRequest carries no XML signature "
            "(required by want_authn_requests_signed)"
        )
    if not cert_pems:
        raise SAMLSignatureError(
            "want_authn_requests_signed is enabled but no saml.sp_certificates "
            "are registered"
        )

    last_error: Optional[Exception] = None
    for pem in cert_pems:
        try:
            XMLVerifier().verify(xml_bytes, x509_cert=pem.decode("ascii"))
            return
        except Exception as e:
            last_error = e
    raise SAMLSignatureError(
        f"POST-binding XML signature did not verify against any registered "
        f"SP certificate: {last_error}"
    )
