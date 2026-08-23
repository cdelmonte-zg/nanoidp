"""
#181: saml.entity_id / saml.sso_url follow the effective issuer when unset.

Absent from settings.yaml means "derived": <effective issuer>/saml and
<effective issuer>/saml/sso, where the effective issuer honours
issuer_from_request exactly like OIDC discovery. An explicit value wins. One
helper (routes/_issuer.py) feeds metadata, the <Issuer> of responses and
assertions, /api/config, the UI and the MCP settings tools, so they cannot
disagree (SAML 2.0 Metadata 2.3.2: entityID is the value used as <Issuer>,
Core 2.2.5).
"""

import base64
import re

import pytest
import yaml
from lxml import etree

from nanoidp.app import create_app
from nanoidp.config import ConfigManager, get_config, init_config
from nanoidp.mcp_server import _execute_tool
from nanoidp.models import Settings
from nanoidp.serialization import apply_settings_document
from nanoidp.services.yaml_writer import YamlWriter

MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
SAMLP = "{urn:oasis:names:tc:SAML:2.0:protocol}"
SAML = "{urn:oasis:names:tc:SAML:2.0:assertion}"


def _config_dir(tmp_path, saml=None, issuer="http://localhost:8000", issuer_from_request=False):
    settings = {
        "server": {"host": "127.0.0.1", "port": 8000},
        "oauth": {
            "issuer": issuer,
            "issuer_from_request": issuer_from_request,
            "clients": [{"client_id": "demo-client", "client_secret": "demo-secret"}],
        },
        "saml": {"sign_responses": False, **(saml or {})},
    }
    (tmp_path / "settings.yaml").write_text(yaml.safe_dump(settings))
    (tmp_path / "users.yaml").write_text(
        yaml.safe_dump({"users": {"admin": {"password": "admin"}}, "default_user": "admin"})
    )
    return str(tmp_path)


@pytest.fixture
def make_app(tmp_path, monkeypatch):
    # The YamlWriter singleton is created against the first config dir it
    # sees and never reset between tests; point it at this test's dir.
    import nanoidp.services.yaml_writer as yw

    monkeypatch.setattr(yw, "_yaml_writer", None)

    def _make(**kwargs):
        app = create_app(config_dir=_config_dir(tmp_path, **kwargs))
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret-key"
        return app

    return _make


def _authn_request(acs_url="http://sp.example.com/acs", request_id="_req1"):
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'ID="{request_id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" '
        f'AssertionConsumerServiceURL="{acs_url}"/>'
    )
    return base64.b64encode(xml.encode()).decode()


def _metadata(client, host=None):
    headers = {"Host": host} if host else {}
    resp = client.get("/saml/metadata", headers=headers)
    assert resp.status_code == 200
    root = etree.fromstring(resp.data)
    locations = {el.get("Location") for el in root.iter(f"{MD}SingleSignOnService")}
    return root.get("entityID"), locations


def _sso_response(client, host=None):
    # The test client's cookie jar is domain-bound, so the login session must
    # be created under the same base_url the request is sent with.
    base_url = f"http://{host}/" if host else "http://localhost/"
    with client.session_transaction(base_url=base_url) as sess:
        sess["user"] = "admin"
    resp = client.post("/saml/sso", data={"SAMLRequest": _authn_request()}, base_url=base_url)
    assert resp.status_code == 200
    match = re.search(r'name="SAMLResponse"\s+value="([^"]+)"', resp.data.decode())
    assert match
    return etree.fromstring(base64.b64decode(match.group(1)))


class TestModelDerivation:
    def test_defaults_are_unset(self):
        s = Settings()
        assert s.saml_entity_id is None
        assert s.saml_sso_url is None

    def test_derived_from_issuer(self):
        s = Settings(issuer="https://idp.example.test/")
        assert s.resolve_saml_entity_id(s.issuer) == "https://idp.example.test/saml"
        assert s.resolve_saml_sso_url(s.issuer) == "https://idp.example.test/saml/sso"

    def test_explicit_wins(self):
        s = Settings(saml_entity_id="urn:idp:fixed", saml_sso_url="https://fixed/sso")
        assert s.resolve_saml_entity_id("http://other") == "urn:idp:fixed"
        assert s.resolve_saml_sso_url("http://other") == "https://fixed/sso"

    def test_default_derivation_matches_previous_defaults(self):
        """Absent keys must behave exactly as the old hard-coded defaults did."""
        s = Settings()
        assert s.resolve_saml_entity_id(s.issuer) == "http://localhost:8000/saml"
        assert s.resolve_saml_sso_url(s.issuer) == "http://localhost:8000/saml/sso"


class TestLoader:
    def test_absent_loads_as_none(self, tmp_path):
        config = ConfigManager(_config_dir(tmp_path))
        assert config.settings.saml_entity_id is None
        assert config.settings.saml_sso_url is None

    def test_blank_loads_as_none(self, tmp_path):
        config = ConfigManager(_config_dir(tmp_path, saml={"entity_id": "", "sso_url": ""}))
        assert config.settings.saml_entity_id is None
        assert config.settings.saml_sso_url is None

    def test_explicit_loads_verbatim(self, tmp_path):
        config = ConfigManager(
            _config_dir(tmp_path, saml={"entity_id": "urn:idp:x", "sso_url": "https://x/sso"})
        )
        assert config.settings.saml_entity_id == "urn:idp:x"
        assert config.settings.saml_sso_url == "https://x/sso"

    def test_env_placeholder_still_expands(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAML_ENTITY_ID", "urn:from:env")
        config = ConfigManager(_config_dir(tmp_path, saml={"entity_id": "${SAML_ENTITY_ID}"}))
        assert config.settings.saml_entity_id == "urn:from:env"


class TestMetadataAndIssuerConsistency:
    def test_static_issuer_derivation(self, make_app):
        client = make_app(issuer="http://idp.local:8000").test_client()
        entity_id, locations = _metadata(client)
        assert entity_id == "http://idp.local:8000/saml"
        assert locations == {"http://idp.local:8000/saml/sso"}

    def test_static_issuer_ignores_host_header(self, make_app):
        client = make_app(issuer="http://idp.local:8000").test_client()
        entity_id, _ = _metadata(client, host="evil.example:9")
        assert entity_id == "http://idp.local:8000/saml"

    def test_issuer_from_request_reflects_host(self, make_app):
        client = make_app(issuer_from_request=True).test_client()
        entity_id, locations = _metadata(client, host="nanoidp:9900")
        assert entity_id == "http://nanoidp:9900/saml"
        assert locations == {"http://nanoidp:9900/saml/sso"}
        # and OIDC discovery on the same Host agrees
        disc = client.get("/.well-known/openid-configuration", headers={"Host": "nanoidp:9900"})
        assert disc.get_json()["issuer"] == "http://nanoidp:9900"

    def test_explicit_values_do_not_follow_request(self, make_app):
        client = make_app(
            issuer_from_request=True,
            saml={"entity_id": "urn:idp:fixed", "sso_url": "https://fixed.example/sso"},
        ).test_client()
        entity_id, locations = _metadata(client, host="nanoidp:9900")
        assert entity_id == "urn:idp:fixed"
        assert locations == {"https://fixed.example/sso"}

    def test_response_and_assertion_issuer_match_metadata(self, make_app):
        client = make_app(issuer_from_request=True).test_client()
        entity_id, _ = _metadata(client, host="nanoidp:9900")
        root = _sso_response(client, host="nanoidp:9900")
        response_issuer = root.find(f"{SAML}Issuer").text
        assertion_issuer = root.find(f"{SAML}Assertion/{SAML}Issuer").text
        assert response_issuer == assertion_issuer == entity_id == "http://nanoidp:9900/saml"

    def test_response_issuer_uses_explicit_entity_id(self, make_app):
        client = make_app(saml={"entity_id": "urn:idp:fixed"}).test_client()
        root = _sso_response(client)
        assert root.find(f"{SAML}Issuer").text == "urn:idp:fixed"

    def test_api_config_reports_effective_and_derived(self, make_app):
        client = make_app(issuer_from_request=True).test_client()
        saml = client.get("/api/config", headers={"Host": "nanoidp:9900"}).get_json()["saml"]
        assert saml["entity_id"] == "http://nanoidp:9900/saml"
        assert saml["entity_id_derived"] is True
        assert saml["sso_url"] == "http://nanoidp:9900/saml/sso"
        assert saml["sso_url_derived"] is True

    def test_api_config_reports_explicit(self, make_app):
        client = make_app(saml={"entity_id": "urn:idp:fixed"}).test_client()
        saml = client.get("/api/config").get_json()["saml"]
        assert saml["entity_id"] == "urn:idp:fixed"
        assert saml["entity_id_derived"] is False
        assert saml["sso_url_derived"] is True


class TestWriter:
    def test_derived_values_are_never_persisted(self, tmp_path):
        config = init_config(_config_dir(tmp_path))
        config.save()
        saml = yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]
        assert "entity_id" not in saml
        assert "sso_url" not in saml

    def test_explicit_values_are_preserved(self, tmp_path):
        config = init_config(_config_dir(tmp_path, saml={"entity_id": "urn:idp:x"}))
        config.save()
        saml = yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]
        assert saml["entity_id"] == "urn:idp:x"
        assert "sso_url" not in saml

    def test_clearing_removes_key(self, tmp_path):
        config = init_config(_config_dir(tmp_path, saml={"entity_id": "urn:idp:x"}))
        config.settings.saml_entity_id = None
        config.save()
        saml = yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]
        assert "entity_id" not in saml

    def test_apply_settings_document_pops_absent(self):
        document = {"saml": {"entity_id": "urn:old", "sso_url": "https://old/sso"}}
        apply_settings_document(document, Settings())
        assert "entity_id" not in document["saml"]
        assert "sso_url" not in document["saml"]

    def test_yaml_writer_blank_clears_and_value_sets(self, tmp_path):
        init_config(_config_dir(tmp_path, saml={"entity_id": "urn:idp:x"}))
        writer = YamlWriter(str(tmp_path))
        writer.update_saml_settings(entity_id="", sso_url="https://new/sso")
        saml = yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]
        assert "entity_id" not in saml
        assert saml["sso_url"] == "https://new/sso"
        assert get_config().settings.saml_entity_id is None
        assert get_config().settings.saml_sso_url == "https://new/sso"

    def test_yaml_writer_none_leaves_untouched(self, tmp_path):
        init_config(_config_dir(tmp_path, saml={"entity_id": "urn:idp:x"}))
        YamlWriter(str(tmp_path)).update_saml_settings(sign_responses=True)
        saml = yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]
        assert saml["entity_id"] == "urn:idp:x"


class TestUiForm:
    def test_settings_page_shows_effective_as_placeholder(self, make_app):
        client = make_app(issuer="http://idp.local:8000").test_client()
        html = client.get("/settings").data.decode()
        assert 'placeholder="http://idp.local:8000/saml"' in html
        assert 'name="saml_entity_id"' in html
        # derived -> the input itself is empty, the placeholder carries the value
        assert re.search(r'name="saml_entity_id"\s+value=""', html)

    def test_settings_page_shows_explicit_as_value(self, make_app):
        client = make_app(saml={"entity_id": "urn:idp:x"}).test_client()
        html = client.get("/settings").data.decode()
        assert re.search(r'name="saml_entity_id"\s+value="urn:idp:x"', html)

    def test_blank_post_keeps_derived(self, make_app, tmp_path):
        client = make_app().test_client()
        client.post("/settings", data={"saml_entity_id": "", "saml_sso_url": ""})
        saml = yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]
        assert "entity_id" not in saml and "sso_url" not in saml
        assert get_config().settings.saml_entity_id is None

    def test_blank_post_clears_explicit(self, make_app, tmp_path):
        client = make_app(saml={"entity_id": "urn:idp:x"}).test_client()
        client.post("/settings", data={"saml_entity_id": ""})
        assert "entity_id" not in yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]
        assert get_config().settings.saml_entity_id is None

    def test_absent_field_leaves_explicit(self, make_app, tmp_path):
        client = make_app(saml={"entity_id": "urn:idp:x"}).test_client()
        client.post("/settings", data={"audience": "other"})
        assert yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]["entity_id"] == "urn:idp:x"

    def test_post_sets_explicit(self, make_app, tmp_path):
        client = make_app().test_client()
        client.post("/settings", data={"saml_entity_id": "urn:idp:new"})
        assert yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]["entity_id"] == "urn:idp:new"
        assert get_config().settings.saml_entity_id == "urn:idp:new"

    def test_dashboard_shows_effective_entity_id(self, make_app):
        client = make_app(issuer="http://idp.local:8000").test_client()
        assert "http://idp.local:8000/saml" in client.get("/").data.decode()


class TestMcp:
    @pytest.mark.asyncio
    async def test_get_settings_reports_effective_against_fixed_issuer(self, tmp_path):
        config = ConfigManager(_config_dir(tmp_path, issuer="http://idp.local:8000", issuer_from_request=True))
        result = await _execute_tool("get_settings", {}, config)
        assert result["saml"]["entity_id"] == "http://idp.local:8000/saml"
        assert result["saml"]["entity_id_derived"] is True
        assert result["saml"]["sso_url"] == "http://idp.local:8000/saml/sso"
        assert result["saml"]["sso_url_derived"] is True

    @pytest.mark.asyncio
    async def test_update_settings_sets_and_clears(self, tmp_path):
        config = ConfigManager(_config_dir(tmp_path))
        result = await _execute_tool(
            "update_settings", {"saml_entity_id": "urn:idp:mcp", "saml_sso_url": "https://mcp/sso"}, config
        )
        assert result["success"] is True
        assert set(result["updated_fields"]) >= {"saml_entity_id", "saml_sso_url"}
        assert config.settings.saml_entity_id == "urn:idp:mcp"
        got = await _execute_tool("get_settings", {}, config)
        assert got["saml"]["entity_id"] == "urn:idp:mcp"
        assert got["saml"]["entity_id_derived"] is False

        await _execute_tool("update_settings", {"saml_entity_id": "", "saml_sso_url": ""}, config)
        assert config.settings.saml_entity_id is None
        assert config.settings.saml_sso_url is None
        got = await _execute_tool("get_settings", {}, config)
        assert got["saml"]["entity_id_derived"] is True

    def test_update_settings_schema_declares_fields(self):
        from nanoidp.mcp_server import _TOOLS

        tool = next(t for t in _TOOLS if t.name == "update_settings")
        props = tool.input_schema["properties"]
        assert "saml_entity_id" in props and "saml_sso_url" in props

