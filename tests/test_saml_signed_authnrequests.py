"""
Tests for opt-in AuthnRequest signature verification (issue #69).

With ``saml.want_authn_requests_signed`` on, nanoidp verifies:
- HTTP-Redirect binding: the query-string signature over the URL-encoded
  ``SAMLRequest[&RelayState]&SigAlg`` fragment (SAML 2.0 Bindings §3.4.4.1);
- HTTP-POST binding: the enveloped ``ds:Signature`` (SAML 2.0 Core §5);
against the certificates registered in ``saml.sp_certificates``. Default is
off (principle 3), and the metadata advertises ``WantAuthnRequestsSigned``
if and only if enforcement is on (principle 2).
"""

import base64
import datetime
import zlib
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, methods

from nanoidp.config import get_config

RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

AUTHN_REQUEST = (
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_sig-test-1" '
    'Version="2.0" IssueInstant="2026-01-01T00:00:00Z" '
    'AssertionConsumerServiceURL="http://localhost:8080/login/saml2/sso/nanoidp">'
    "<saml:Issuer>signed-sp</saml:Issuer></samlp:AuthnRequest>"
).encode()


def _make_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "signed-sp")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


SP_KEY, SP_CERT = _make_keypair()
OTHER_KEY, OTHER_CERT = _make_keypair()


def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@pytest.fixture
def signed_mode(app, tmp_path):
    """Enable verification with the SP certificate registered."""
    cert_path = tmp_path / "sp-cert.pem"
    cert_path.write_bytes(_pem(SP_CERT))
    with app.app_context():
        settings = get_config().settings
        settings.saml_want_authn_requests_signed = True
        settings.saml_sp_certificates = [str(cert_path)]
    yield settings
    settings.saml_want_authn_requests_signed = False
    settings.saml_sp_certificates = []


def _redirect_query(key=SP_KEY, relay_state="RS", sig_alg=RSA_SHA256, tamper=False):
    """Build a signed HTTP-Redirect query string (Bindings §3.4.4.1)."""
    deflated = zlib.compress(AUTHN_REQUEST, 9)[2:-4]
    b64 = base64.b64encode(deflated).decode()
    parts = [f"SAMLRequest={quote(b64, safe='')}"]
    if relay_state is not None:
        parts.append(f"RelayState={quote(relay_state, safe='')}")
    parts.append(f"SigAlg={quote(sig_alg, safe='')}")
    signed_octets = "&".join(parts).encode()
    signature = key.sign(signed_octets, padding.PKCS1v15(), hashes.SHA256())
    if tamper:
        # a different (but well-formed) request after signing
        other = zlib.compress(AUTHN_REQUEST.replace(b"_sig-test-1", b"_evil"), 9)[2:-4]
        parts[0] = f"SAMLRequest={quote(base64.b64encode(other).decode(), safe='')}"
    return "&".join(parts) + f"&Signature={quote(base64.b64encode(signature).decode(), safe='')}"


def _signed_post_request(key=SP_KEY, cert=SP_CERT, tamper=False) -> str:
    """Build a base64 POST-binding AuthnRequest with an enveloped signature."""
    root = etree.fromstring(AUTHN_REQUEST)
    signed = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
    ).sign(root, key=_key_pem(key), cert=_pem(cert).decode())
    xml = etree.tostring(signed)
    if tamper:
        xml = xml.replace(b"signed-sp", b"evil-sp")
    return base64.b64encode(xml).decode()


class TestRedirectBinding:
    def test_signed_request_accepted(self, client, signed_mode):
        r = client.get(f"/saml/sso?{_redirect_query()}")
        assert r.status_code == 200
        assert b"username" in r.data  # login form

    def test_signed_without_relay_state_accepted(self, client, signed_mode):
        r = client.get(f"/saml/sso?{_redirect_query(relay_state=None)}")
        assert r.status_code == 200

    def test_unsigned_request_rejected(self, client, signed_mode):
        deflated = zlib.compress(AUTHN_REQUEST, 9)[2:-4]
        b64 = quote(base64.b64encode(deflated).decode(), safe="")
        r = client.get(f"/saml/sso?SAMLRequest={b64}")
        assert r.status_code == 400
        assert b"not signed" in r.data

    def test_tampered_request_rejected(self, client, signed_mode):
        r = client.get(f"/saml/sso?{_redirect_query(tamper=True)}")
        assert r.status_code == 400

    def test_wrong_key_rejected(self, client, signed_mode):
        r = client.get(f"/saml/sso?{_redirect_query(key=OTHER_KEY)}")
        assert r.status_code == 400

    def test_unsupported_sigalg_rejected(self, client, signed_mode):
        r = client.get(
            f"/saml/sso?{_redirect_query(sig_alg='http://example.com/fake-alg')}"
        )
        assert r.status_code == 400
        assert b"Unsupported SigAlg" in r.data

    def test_no_registered_certificates_fails_closed(self, client, signed_mode):
        signed_mode.saml_sp_certificates = []
        r = client.get(f"/saml/sso?{_redirect_query()}")
        assert r.status_code == 400


class TestPostBinding:
    def test_signed_request_accepted(self, client, signed_mode):
        r = client.post("/saml/sso", data={"SAMLRequest": _signed_post_request()})
        assert r.status_code == 200
        assert b"username" in r.data

    def test_full_login_flow_with_signed_request(self, client, signed_mode):
        """The login leg re-verifies the embedded signature and issues the
        SAML response."""
        r = client.post(
            "/saml/sso",
            data={
                "SAMLRequest": _signed_post_request(),
                "saml_original_verb": "POST",
                "username": "admin",
                "password": "admin",
            },
        )
        assert r.status_code == 200
        assert b"SAMLResponse" in r.data

    def test_unsigned_request_rejected(self, client, signed_mode):
        r = client.post(
            "/saml/sso",
            data={"SAMLRequest": base64.b64encode(AUTHN_REQUEST).decode()},
        )
        assert r.status_code == 400
        assert b"no XML signature" in r.data

    def test_tampered_request_rejected(self, client, signed_mode):
        r = client.post(
            "/saml/sso", data={"SAMLRequest": _signed_post_request(tamper=True)}
        )
        assert r.status_code == 400

    def test_wrong_key_rejected(self, client, signed_mode):
        r = client.post(
            "/saml/sso",
            data={"SAMLRequest": _signed_post_request(key=OTHER_KEY, cert=OTHER_CERT)},
        )
        assert r.status_code == 400


class TestRedirectLegBinding:
    """The Redirect login leg is bound server-side (#69 review): a POST with
    saml_original_verb=GET is only admitted for values byte-identical to a
    request this session already verified — hidden form fields alone are
    client-controlled and must not bypass enforcement."""

    def _unsigned_b64(self, request_id: bytes = b"_sig-test-1") -> str:
        deflated = zlib.compress(AUTHN_REQUEST.replace(b"_sig-test-1", request_id), 9)[2:-4]
        return base64.b64encode(deflated).decode()

    def test_forged_get_leg_without_prior_verification_fails_closed(
        self, client, signed_mode
    ):
        """Login-continuation forgery: no verified GET ever happened."""
        r = client.post(
            "/saml/sso",
            data={
                "SAMLRequest": self._unsigned_b64(),
                "saml_original_verb": "GET",
                "username": "admin",
                "password": "admin",
            },
        )
        assert r.status_code == 400
        assert b"signature-verified request" in r.data

    def test_forged_get_leg_with_authenticated_session_fails_closed(
        self, client, signed_mode
    ):
        """Already-authenticated bypass: session user set, still no verified
        Redirect request bound — must not proceed to response generation."""
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        r = client.post(
            "/saml/sso",
            data={"SAMLRequest": self._unsigned_b64(), "saml_original_verb": "GET"},
        )
        assert r.status_code == 400
        assert b"SAMLResponse" not in r.data

    def test_get_leg_with_different_request_than_verified_rejected(
        self, client, signed_mode
    ):
        """A verified GET binds THAT request; swapping in another on the login
        leg is rejected."""
        query = _redirect_query()
        assert client.get(f"/saml/sso?{query}").status_code == 200
        r = client.post(
            "/saml/sso",
            data={
                "SAMLRequest": self._unsigned_b64(b"_other"),
                "RelayState": "RS",
                "saml_original_verb": "GET",
                "username": "admin",
                "password": "admin",
            },
        )
        assert r.status_code == 400

    def test_legitimate_redirect_login_flow_completes(self, client, signed_mode):
        """Verified GET, then the login leg with byte-identical values issues
        the SAML response."""
        query = _redirect_query()
        assert client.get(f"/saml/sso?{query}").status_code == 200
        # the exact SAMLRequest value the form carries (decoded from the query)
        deflated = zlib.compress(AUTHN_REQUEST, 9)[2:-4]
        same_b64 = base64.b64encode(deflated).decode()
        r = client.post(
            "/saml/sso",
            data={
                "SAMLRequest": same_b64,
                "RelayState": "RS",
                "saml_original_verb": "GET",
                "username": "admin",
                "password": "admin",
            },
        )
        assert r.status_code == 200
        assert b"SAMLResponse" in r.data


class TestDefaultsAndMetadata:
    def test_default_off_keeps_unsigned_requests_working(self, client):
        deflated = zlib.compress(AUTHN_REQUEST, 9)[2:-4]
        b64 = quote(base64.b64encode(deflated).decode(), safe="")
        r = client.get(f"/saml/sso?SAMLRequest={b64}")
        assert r.status_code == 200

    def test_metadata_omits_flag_by_default(self, client):
        r = client.get("/saml/metadata")
        assert b"WantAuthnRequestsSigned" not in r.data

    def test_metadata_advertises_flag_when_enforced(self, client, signed_mode):
        r = client.get("/saml/metadata")
        assert b'WantAuthnRequestsSigned="true"' in r.data


class TestPersistence:
    def test_settings_round_trip(self, tmp_path):
        from nanoidp.config import ConfigManager

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.yaml").write_text(
            "oauth:\n"
            '  issuer: "http://localhost:8000"\n'
            "saml:\n"
            "  want_authn_requests_signed: true\n"
            "  sp_certificates:\n"
            '    - "/certs/sp.pem"\n'
        )
        (config_dir / "users.yaml").write_text(
            'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
        )
        manager = ConfigManager(str(config_dir))
        assert manager.settings.saml_want_authn_requests_signed is True
        assert manager.settings.saml_sp_certificates == ["/certs/sp.pem"]

        manager.save()
        reloaded = ConfigManager(str(config_dir))
        assert reloaded.settings.saml_want_authn_requests_signed is True
        assert reloaded.settings.saml_sp_certificates == ["/certs/sp.pem"]
