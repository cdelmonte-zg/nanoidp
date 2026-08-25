"""
/sso rejects a request with nowhere to send the assertion (#227).

An AuthnRequest without AssertionConsumerServiceURL, against a config
whose saml.default_acs_url is blank, used to reach the success path with
an empty ACS: the None arm (the latent html.escape(None) 500 surfaced by
#223's typing) became unreachable once the document models gave
default_acs_url a non-None default (#175), but an explicit
default_acs_url: "" is a valid str and rendered an auto-submit form
posting to action="" - the IdP's own page. Both arms are now a clean 400
naming the two missing sources, with a failed saml_request audit entry.
"""

import base64
import shutil
import zlib
from pathlib import Path

import pytest
import yaml

from nanoidp.app import create_app

_REPO_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


def _authn_request_without_acs():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_no_acs_req"
    Version="2.0"
    IssueInstant="2025-01-01T00:00:00Z">
    <saml:Issuer>http://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>"""
    compressed = zlib.compress(xml.encode("utf-8"))[2:-4]
    return base64.b64encode(compressed).decode("ascii")


@pytest.fixture
def acs_less_client(tmp_path):
    """An app whose config BLANKS saml.default_acs_url.

    Merely omitting the key is not enough: the document models give
    default_acs_url a non-None default (#175), so the explicit empty
    string is the one reachable "no default configured" state.
    """
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO_CONFIG_DIR / name, cfg / name)
    data = yaml.safe_load((cfg / "settings.yaml").read_text())
    data["saml"]["default_acs_url"] = ""
    data.setdefault("jwt", {})["keys_dir"] = str(tmp_path / "keys")
    (cfg / "settings.yaml").write_text(yaml.safe_dump(data))
    app = create_app(config_dir=str(cfg))
    app.config["TESTING"] = True
    return app.test_client()


class TestSsoWithoutAnyAcsUrl:
    def _login(self, client):
        client.post("/login", data={"username": "admin", "password": "admin"})

    def test_rejects_with_400_naming_both_missing_sources(self, acs_less_client):
        from nanoidp.services import get_audit_log

        self._login(acs_less_client)
        resp = acs_less_client.get(
            "/saml/sso", query_string={"SAMLRequest": _authn_request_without_acs()}
        )
        assert resp.status_code == 400
        assert b"AssertionConsumerServiceURL" in resp.data
        assert b"default_acs_url" in resp.data
        entries = get_audit_log().get_entries(limit=5, event_type="saml_request")
        assert any(e.get("status") == "failed" for e in entries)

    def test_default_acs_url_still_rescues_an_acs_less_request(self, client):
        """Control: the shipped preset HAS default_acs_url, so the same
        request succeeds there - the rejection is only for the double-miss."""
        self._login(client)
        resp = client.get(
            "/saml/sso", query_string={"SAMLRequest": _authn_request_without_acs()}
        )
        assert resp.status_code == 200
        assert b"SAMLResponse" in resp.data
