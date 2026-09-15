"""jwt.external_keys and jwt.max_previous_keys reach the signing service (#358).

Both were documented and never read by the loader. They are signing inputs:
the activation step of #359 builds the signing service from them on every
load, rejects a configuration that cannot be used, and reuses the running
service while they are unchanged.
"""

import asyncio
import base64
import hashlib
import json
import shutil
from pathlib import Path

import jwt
import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from nanoidp.app import create_app
from nanoidp.config import ConfigurationRejected, get_config
from nanoidp.services.crypto import get_crypto_service

_REPO = Path(__file__).resolve().parent.parent
_AUTH = {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}


def _write_pair(directory: Path, name: str) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = directory / f"{name}.key.pem"
    public = directory / f"{name}.pub.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private, public


def _thumbprint(public: Path) -> str:
    numbers = serialization.load_pem_public_key(public.read_bytes()).public_numbers()

    def b64(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    members = f'{{"e":"{b64(numbers.e)}","kty":"RSA","n":"{b64(numbers.n)}"}}'
    return base64.urlsafe_b64encode(hashlib.sha256(members.encode()).digest()).rstrip(b"=").decode()


def _config_dir(tmp_path: Path, jwt_section: dict) -> Path:
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    _set_jwt(config_dir, {"keys_dir": str(tmp_path / "keys"), **jwt_section})
    return config_dir


def _set_jwt(config_dir: Path, jwt_section: dict) -> None:
    settings = config_dir / "settings.yaml"
    doc = yaml.safe_load(settings.read_text())
    doc["jwt"] = {"algorithm": "RS256", **jwt_section}
    settings.write_text(yaml.safe_dump(doc))


def _external(private: Path, public: Path, kid=None) -> dict:
    block = {"private_key": str(private), "public_key": str(public)}
    if kid is not None:
        block["kid"] = kid
    return {"external_keys": block}


def _app(config_dir: Path):
    app = create_app(str(config_dir))
    app.config["TESTING"] = True
    return app.test_client()


def _token(client) -> str:
    response = client.post(
        "/token",
        data={"grant_type": "password", "username": "admin", "password": "admin"},
        headers=_AUTH,
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()["access_token"]


class TestExternalKeys:
    def test_tokens_are_signed_with_the_configured_key_and_the_jwks_serves_it(self, tmp_path):
        private, public = _write_pair(tmp_path / "operator", "signing")
        client = _app(_config_dir(tmp_path, _external(private, public, kid="op-key")))

        token = _token(client)

        assert jwt.get_unverified_header(token)["kid"] == "op-key"
        claims = jwt.decode(
            token,
            serialization.load_pem_public_key(public.read_bytes()),
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        assert claims["sub"] == "admin"
        served = client.get("/.well-known/jwks.json").get_json()["keys"]
        assert [key["kid"] for key in served] == ["op-key"]
        # No generated pair takes over the configured one.
        assert not (tmp_path / "keys" / "rsa_private.pem").exists()

    def test_placeholders_are_expanded_in_the_key_paths(self, tmp_path, monkeypatch):
        private, public = _write_pair(tmp_path / "operator", "signing")
        monkeypatch.setenv("NANOIDP_TEST_KEY_DIR", str(tmp_path / "operator"))
        config_dir = _config_dir(
            tmp_path,
            {
                "external_keys": {
                    "private_key": "${NANOIDP_TEST_KEY_DIR}/signing.key.pem",
                    "public_key": "${NANOIDP_TEST_KEY_DIR}/signing.pub.pem",
                    "kid": "op-key",
                }
            },
        )

        assert jwt.get_unverified_header(_token(_app(config_dir)))["kid"] == "op-key"

    def test_without_kid_the_kid_is_the_rfc7638_thumbprint_and_stable(self, tmp_path):
        private, public = _write_pair(tmp_path / "operator", "signing")
        config_dir = _config_dir(tmp_path, _external(private, public))

        first = jwt.get_unverified_header(_token(_app(config_dir)))["kid"]
        # A fresh process state: the service is built again from the files.
        import nanoidp.services.crypto as crypto_module

        crypto_module._crypto_service = None
        second = jwt.get_unverified_header(_token(_app(config_dir)))["kid"]

        assert first == second == _thumbprint(public)

    def test_a_mismatched_pair_is_rejected_at_startup(self, tmp_path):
        private, _ = _write_pair(tmp_path / "operator", "a")
        _, other_public = _write_pair(tmp_path / "operator", "b")

        with pytest.raises(ConfigurationRejected, match="does not belong") as excinfo:
            create_app(str(_config_dir(tmp_path, _external(private, other_public))))
        assert excinfo.value.kind == "activation"

    def test_a_mismatched_pair_is_rejected_at_reload_and_the_running_key_stays(self, tmp_path):
        private, public = _write_pair(tmp_path / "operator", "a")
        _, other_public = _write_pair(tmp_path / "operator", "b")
        config_dir = _config_dir(tmp_path, _external(private, public, kid="op-key"))
        client = _app(config_dir)

        _set_jwt(
            config_dir,
            {"keys_dir": str(tmp_path / "keys"), **_external(private, other_public, kid="op-key-2")},
        )
        response = client.post("/api/config/reload")

        assert response.status_code == 422
        assert response.get_json()["kind"] == "activation"
        assert "does not belong" in response.get_json()["error"]
        assert jwt.get_unverified_header(_token(client))["kid"] == "op-key"

    @pytest.mark.parametrize("problem", ["missing", "malformed"])
    def test_an_unusable_key_file_is_rejected(self, tmp_path, problem):
        private, public = _write_pair(tmp_path / "operator", "signing")
        if problem == "missing":
            public.unlink()
        else:
            public.write_text("not a pem\n")

        with pytest.raises(ConfigurationRejected) as excinfo:
            create_app(str(_config_dir(tmp_path, _external(private, public))))
        assert excinfo.value.kind == "activation"

    @pytest.mark.parametrize("given", ["private_key", "public_key"])
    def test_the_two_paths_are_given_together(self, tmp_path, given):
        private, public = _write_pair(tmp_path / "operator", "signing")
        block = {"private_key": str(private), "public_key": str(public)}
        config_dir = _config_dir(tmp_path, {"external_keys": {given: block[given]}})

        with pytest.raises(ConfigurationRejected) as excinfo:
            create_app(str(config_dir))
        assert excinfo.value.kind == "invalid"

    def test_changing_the_external_keys_on_reload_publishes_a_new_service(self, tmp_path):
        first_private, first_public = _write_pair(tmp_path / "operator", "a")
        second_private, second_public = _write_pair(tmp_path / "operator", "b")
        config_dir = _config_dir(tmp_path, _external(first_private, first_public, kid="first"))
        client = _app(config_dir)
        running = get_crypto_service()

        _set_jwt(
            config_dir,
            {"keys_dir": str(tmp_path / "keys"), **_external(second_private, second_public, kid="second")},
        )
        assert client.post("/api/config/reload").status_code == 200

        assert get_crypto_service() is not running
        assert jwt.get_unverified_header(_token(client))["kid"] == "second"

    def test_ui_and_mcp_saves_keep_the_signing_settings(self, tmp_path, mcp_call_tool):
        from nanoidp.services.yaml_writer import get_yaml_writer

        private, public = _write_pair(tmp_path / "operator", "signing")
        config_dir = _config_dir(
            tmp_path, {**_external(private, public, kid="op-key"), "max_previous_keys": 4}
        )
        client = _app(config_dir)

        get_yaml_writer().update_login_settings(mode="password")
        saved = json.loads(asyncio.run(mcp_call_tool("save_config", {})).content[0].text)
        assert saved["success"] is True

        written = yaml.safe_load((config_dir / "settings.yaml").read_text())["jwt"]
        assert written["external_keys"]["kid"] == "op-key"
        assert written["max_previous_keys"] == 4
        assert client.post("/api/config/reload").status_code == 200
        assert jwt.get_unverified_header(_token(client))["kid"] == "op-key"

    def test_a_key_replaced_at_the_same_paths_is_not_reloaded(self, tmp_path):
        """The signing service is identified by its configuration inputs, not
        by file contents: the documented way to change external keys is a new
        path (or kid) and a reload; a key replaced in place is read at the
        next start."""
        private, public = _write_pair(tmp_path / "operator", "signing")
        config_dir = _config_dir(tmp_path, _external(private, public, kid="op-key"))
        client = _app(config_dir)
        running = get_crypto_service()
        replacement_private, replacement_public = _write_pair(tmp_path / "replacement", "signing")
        shutil.copy(replacement_private, private)
        shutil.copy(replacement_public, public)

        assert client.post("/api/config/reload").status_code == 200

        assert get_crypto_service() is running

    def test_rotation_is_refused_and_the_key_files_are_untouched(self, tmp_path, mcp_call_tool):
        private, public = _write_pair(tmp_path / "operator", "signing")
        client = _app(_config_dir(tmp_path, _external(private, public, kid="op-key")))
        before = (private.read_bytes(), public.read_bytes())

        api = client.post("/api/keys/rotate")
        mcp = json.loads(asyncio.run(mcp_call_tool("rotate_keys", {})).content[0].text)
        ui = client.post("/keys/regenerate", follow_redirects=True)

        assert api.status_code == 409 and api.get_json()["success"] is False
        assert mcp["success"] is False and "jwt.external_keys" in mcp["error"]
        assert "jwt.external_keys" in ui.get_data(as_text=True)
        assert (private.read_bytes(), public.read_bytes()) == before
        assert jwt.get_unverified_header(_token(client))["kid"] == "op-key"
        assert not (tmp_path / "keys" / "previous").exists()

    def test_the_mcp_server_signs_with_the_configured_key(self, tmp_path, monkeypatch, mcp_call_tool):
        private, public = _write_pair(tmp_path / "operator", "signing")
        config_dir = _config_dir(tmp_path, _external(private, public, kid="op-key"))
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))

        result = json.loads(
            asyncio.run(mcp_call_tool("generate_token", {"username": "admin"})).content[0].text
        )

        assert jwt.get_unverified_header(result["access_token"])["kid"] == "op-key"
        assert get_config().settings.external_key_id == "op-key"


def _signed_saml_response_verifies_against_the_metadata(client) -> bool:
    """Sign a SAML Response and verify it with the certificate the SAML
    metadata publishes, as an SP would."""
    from lxml import etree
    from signxml import XMLVerifier

    from nanoidp.routes.saml import _build_saml_response

    namespaces = {
        "md": "urn:oasis:names:tc:SAML:2.0:metadata",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    }
    metadata = etree.fromstring(client.get("/saml/metadata").data)
    certificate_b64 = metadata.find(
        ".//md:KeyDescriptor[@use='signing']//ds:X509Certificate", namespaces
    ).text.strip()
    certificate = (
        "-----BEGIN CERTIFICATE-----\n" + certificate_b64 + "\n-----END CERTIFICATE-----\n"
    )
    xml = _build_saml_response(
        acs_url="http://sp.example.com/acs",
        issuer="http://localhost:8000/saml",
        audience="http://sp.example.com",
        name_id="admin",
        attributes={},
        sign=True,
    )
    try:
        XMLVerifier().verify(xml, x509_cert=certificate)
    except Exception:
        return False
    return True


class TestSigningCertificate:
    """The SAML certificate always belongs to the key that signs (#358 review)."""

    def test_switching_to_external_keys_and_back_keeps_saml_signatures_verifiable(self, tmp_path):
        private, public = _write_pair(tmp_path / "operator", "signing")
        config_dir = _config_dir(tmp_path, {})
        client = _app(config_dir)
        generated_certificate = (tmp_path / "keys" / "idp-cert.pem").read_bytes()
        assert _signed_saml_response_verifies_against_the_metadata(client)

        _set_jwt(config_dir, {"keys_dir": str(tmp_path / "keys"), **_external(private, public)})
        assert client.post("/api/config/reload").status_code == 200
        assert _signed_saml_response_verifies_against_the_metadata(client)
        # The external key's certificate lives in a file of its own.
        assert (tmp_path / "keys" / "idp-cert.pem").read_bytes() == generated_certificate

        _set_jwt(config_dir, {"keys_dir": str(tmp_path / "keys")})
        assert client.post("/api/config/reload").status_code == 200
        assert _signed_saml_response_verifies_against_the_metadata(client)

    def test_the_external_key_certificate_is_stable_across_starts(self, tmp_path):
        import nanoidp.services.crypto as crypto_module

        private, public = _write_pair(tmp_path / "operator", "signing")
        config_dir = _config_dir(tmp_path, _external(private, public))
        _app(config_dir)
        first = get_crypto_service().cert_pem
        crypto_module._crypto_service = None
        _app(config_dir)

        assert get_crypto_service().cert_pem == first

    def test_a_certificate_of_another_key_is_replaced(self, tmp_path):
        from cryptography import x509

        client = _app(_config_dir(tmp_path, {}))
        import nanoidp.services.crypto as crypto_module

        foreign = tmp_path / "foreign"
        crypto_module.CryptoService(str(foreign))
        shutil.copy(foreign / "idp-cert.pem", tmp_path / "keys" / "idp-cert.pem")
        crypto_module._crypto_service = None
        client = _app(_config_dir(tmp_path / "again", {"keys_dir": str(tmp_path / "keys")}))

        service = get_crypto_service()
        certificate = x509.load_pem_x509_certificate((tmp_path / "keys" / "idp-cert.pem").read_bytes())
        signing = serialization.load_pem_private_key(service.priv_pem, None).public_key()
        assert certificate.public_key().public_numbers() == signing.public_numbers()
        assert _signed_saml_response_verifies_against_the_metadata(client)

    def test_a_rejected_reload_leaves_the_certificate_files_alone(self, tmp_path):
        private, public = _write_pair(tmp_path / "operator", "signing")
        config_dir = _config_dir(tmp_path, {})
        client = _app(config_dir)
        before = sorted((path.name, path.read_bytes()) for path in (tmp_path / "keys").glob("*cert*.pem"))

        settings = config_dir / "settings.yaml"
        doc = yaml.safe_load(settings.read_text())
        doc["jwt"] = {"algorithm": "RS256", "keys_dir": str(tmp_path / "keys"), **_external(private, public)}
        doc["hooks"] = {"strict": True}
        doc["plugins"] = {"missing": {}}
        settings.write_text(yaml.safe_dump(doc))
        assert client.post("/api/config/reload").status_code == 503

        assert _signed_saml_response_verifies_against_the_metadata(client)
        assert get_crypto_service().uses_external_keys is False
        idp_cert = (tmp_path / "keys" / "idp-cert.pem").read_bytes()
        assert ("idp-cert.pem", idp_cert) in before


class TestMaxPreviousKeys:
    def test_lowering_the_retention_on_reload_trims_the_jwks(self, tmp_path):
        config_dir = _config_dir(tmp_path, {"max_previous_keys": 3})
        client = _app(config_dir)
        for _ in range(3):
            assert client.post("/api/keys/rotate").status_code == 200
        assert len(client.get("/.well-known/jwks.json").get_json()["keys"]) == 4

        _set_jwt(config_dir, {"keys_dir": str(tmp_path / "keys"), "max_previous_keys": 1})
        assert client.post("/api/config/reload").status_code == 200

        info = client.get("/api/keys/info").get_json()
        assert info["previous_keys_count"] == 1
        assert len(client.get("/.well-known/jwks.json").get_json()["keys"]) == 2


    def test_the_configured_retention_bounds_the_jwks_after_rotations(self, tmp_path):
        client = _app(_config_dir(tmp_path, {"max_previous_keys": 1}))
        for _ in range(3):
            assert client.post("/api/keys/rotate").status_code == 200

        info = client.get("/api/keys/info").get_json()
        assert info["max_previous_keys"] == 1
        assert info["previous_keys_count"] == 1
        assert len(client.get("/.well-known/jwks.json").get_json()["keys"]) == 2

    def test_changing_the_retention_on_reload_publishes_a_new_service(self, tmp_path):
        config_dir = _config_dir(tmp_path, {"max_previous_keys": 1})
        client = _app(config_dir)
        running = get_crypto_service()

        _set_jwt(config_dir, {"keys_dir": str(tmp_path / "keys"), "max_previous_keys": 4})
        assert client.post("/api/config/reload").status_code == 200

        assert get_crypto_service() is not running
        assert client.get("/api/keys/info").get_json()["max_previous_keys"] == 4

    @pytest.mark.parametrize("value", [-1, 11])
    def test_out_of_bounds_retention_is_rejected(self, tmp_path, value):
        with pytest.raises(ConfigurationRejected) as excinfo:
            create_app(str(_config_dir(tmp_path, {"max_previous_keys": value})))
        assert excinfo.value.kind == "invalid"
