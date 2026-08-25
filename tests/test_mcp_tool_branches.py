"""
Branch coverage for the _tool_* MCP handlers (#222).

mcp_server.py sat at 75% statement coverage: the wire-level tests proved
the dispatch and guard machinery, but most handlers' domain-failure
branches (user/client already exists, not found) and several whole happy
paths (get_user, delete_user, list_clients, decode/verify token,
reload_config, update_settings' field branches, save_config) had no test
at all. Everything here drives the real protocol path through the
in-memory MCP client (conftest.call_mcp_tool), asserting the
{"success": False, ...} / is_error contract the module docstring pins.
"""

import json

import pytest
import yaml

from nanoidp.config import ConfigManager


@pytest.fixture
def mcp_config(tmp_path, monkeypatch):
    """A ConfigManager on its own config dir, installed as the MCP singleton.

    Mirrors the pattern of tests/test_mcp.py: the MCP server keeps its own
    config global, so tests install theirs and clear the gate env vars.
    keys_dir points into tmp_path because generate_token/rotate_keys build
    a real crypto service.
    """
    import nanoidp.mcp_server as mcp

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    settings = {
        "server": {"host": "127.0.0.1", "port": 8000},
        "oauth": {
            "issuer": "http://localhost:8000",
            "audience": "test-aud",
            "clients": [
                {
                    "client_id": "branch-client",
                    "client_secret": "branch-secret",
                    "description": "seed client",
                    "redirect_uris": ["https://app.example/cb"],
                    "allowed_scopes": ["openid", "profile"],
                }
            ],
        },
        "jwt": {"keys_dir": str(tmp_path / "keys")},
    }
    (config_dir / "settings.yaml").write_text(yaml.safe_dump(settings))
    (config_dir / "users.yaml").write_text(
        'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
    )

    config = ConfigManager(str(config_dir))
    monkeypatch.setattr(mcp, "_config", config)
    monkeypatch.setattr(mcp, "_readonly_mode", False)
    monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)
    monkeypatch.delenv("NANOIDP_MANAGEMENT_SECRET", raising=False)
    # generate_token goes through get_token_service(), which builds from the
    # GLOBAL config discovery, not from mcp_server's own ConfigManager (the
    # same global-vs-own coupling family as #176's B5 finding, latent in
    # production because both usually resolve the same directory). Point the
    # discovery at this test's directory so the two agree here too - and so
    # the token service can never touch the repo's ./keys.
    monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))
    return config


def _payload(result):
    return json.loads(result.content[0].text)


class TestUserToolBranches:
    @pytest.mark.asyncio
    async def test_get_user_found_and_missing(self, mcp_config, mcp_call_tool):
        found = _payload(await mcp_call_tool("get_user", {"username": "admin"}))
        assert found["found"] is True
        assert found["user"]["username"] == "admin"

        missing_result = await mcp_call_tool("get_user", {"username": "ghost"})
        missing = _payload(missing_result)
        assert missing["found"] is False
        assert missing["username"] == "ghost"

    @pytest.mark.asyncio
    async def test_create_user_duplicate_fails_without_overwrite(self, mcp_config, mcp_call_tool):
        result = await mcp_call_tool(
            "create_user", {"username": "admin", "password": "hacked"}
        )
        assert result.is_error is True
        payload = _payload(result)
        assert payload["success"] is False
        assert "already exists" in payload["error"]
        assert mcp_config.get_user("admin").password == "admin"

    @pytest.mark.asyncio
    async def test_update_user_missing_and_field_branches(self, mcp_config, mcp_call_tool):
        missing = await mcp_call_tool("update_user", {"username": "ghost", "email": "x@x"})
        assert missing.is_error is True
        assert "not found" in _payload(missing)["error"]

        updated = _payload(
            await mcp_call_tool(
                "update_user",
                {
                    "username": "admin",
                    "password": "newpw",
                    "email": "admin@new.example",
                    "roles": ["ops", "dev"],
                    "groups": ["team-a"],
                    "tenant": "acme",
                    "identity_class": "INTERNAL",
                    "entitlements": ["E1"],
                    "source_acl": ["svc-a"],
                },
            )
        )
        assert updated["success"] is True
        user = mcp_config.get_user("admin")
        assert user.password == "newpw"
        assert user.email == "admin@new.example"
        assert user.roles == ["ops", "dev"]
        assert user.groups == ["team-a"]
        assert user.tenant == "acme"
        assert user.entitlements == ["E1"]
        assert user.source_acl == ["svc-a"]

    @pytest.mark.asyncio
    async def test_delete_user_success_and_missing(self, mcp_config, mcp_call_tool):
        _payload(await mcp_call_tool("create_user", {"username": "todelete", "password": "x"}))
        deleted = _payload(await mcp_call_tool("delete_user", {"username": "todelete"}))
        assert deleted["success"] is True
        assert mcp_config.get_user("todelete") is None

        missing = await mcp_call_tool("delete_user", {"username": "todelete"})
        assert missing.is_error is True
        assert "not found" in _payload(missing)["error"]


class TestTokenToolBranches:
    @pytest.mark.asyncio
    async def test_generate_decode_and_verify_roundtrip(self, mcp_config, mcp_call_tool):
        generated = _payload(
            await mcp_call_tool("generate_token", {"username": "admin"})
        )
        token = generated["access_token"]

        decoded = _payload(await mcp_call_tool("decode_token", {"token": token}))
        assert decoded["claims"]["sub"] == "admin"

        verified = _payload(await mcp_call_tool("verify_token", {"token": token}))
        assert verified["valid"] is True
        assert verified["claims"]["sub"] == "admin"

    @pytest.mark.asyncio
    async def test_generate_token_unknown_user_fails(self, mcp_config, mcp_call_tool):
        result = await mcp_call_tool("generate_token", {"username": "ghost"})
        assert result.is_error is True
        assert "not found" in _payload(result)["error"]

    @pytest.mark.asyncio
    async def test_decode_token_garbage_is_a_clean_failure(self, mcp_config, mcp_call_tool):
        result = await mcp_call_tool("decode_token", {"token": "not-a-jwt"})
        assert result.is_error is True
        assert "Failed to decode token" in _payload(result)["error"]

    @pytest.mark.asyncio
    async def test_verify_token_garbage_is_invalid_not_a_crash(self, mcp_config, mcp_call_tool):
        result = await mcp_call_tool("verify_token", {"token": "not-a-jwt"})
        payload = _payload(result)
        assert payload.get("valid") is not True


class TestClientToolBranches:
    @pytest.mark.asyncio
    async def test_list_and_get_client(self, mcp_config, mcp_call_tool):
        listed = _payload(await mcp_call_tool("list_clients", {}))
        assert any(c["client_id"] == "branch-client" for c in listed["clients"])

        found = _payload(await mcp_call_tool("get_client", {"client_id": "branch-client"}))
        assert found["found"] is True
        assert found["client"]["allowed_scopes"] == ["openid", "profile"]

        missing = _payload(await mcp_call_tool("get_client", {"client_id": "ghost"}))
        assert missing["found"] is False

    @pytest.mark.asyncio
    async def test_create_client_duplicate_fails(self, mcp_config, mcp_call_tool):
        result = await mcp_call_tool(
            "create_client", {"client_id": "branch-client", "client_secret": "other"}
        )
        assert result.is_error is True
        assert "already exists" in _payload(result)["error"]
        assert mcp_config.get_client("branch-client").client_secret == "branch-secret"

    @pytest.mark.asyncio
    async def test_update_client_missing_and_field_branches(self, mcp_config, mcp_call_tool):
        missing = await mcp_call_tool("update_client", {"client_id": "ghost", "description": "x"})
        assert missing.is_error is True
        assert "not found" in _payload(missing)["error"]

        updated = _payload(
            await mcp_call_tool(
                "update_client",
                {
                    "client_id": "branch-client",
                    "client_secret": "rotated",
                    "description": "edited",
                    "additional_audiences": ["aud-x"],
                    "redirect_uris": ["https://other.example/cb"],
                    "allowed_scopes": ["openid"],
                    "background_color": "#112233",
                    "header_color": "#445566",
                    "footer_color": "#778899",
                    "show_client_id": True,
                    "show_description": True,
                },
            )
        )
        assert updated["success"] is True
        client = mcp_config.get_client("branch-client")
        assert client.client_secret == "rotated"
        assert client.description == "edited"
        assert client.additional_audiences == ["aud-x"]
        assert client.redirect_uris == ["https://other.example/cb"]
        assert client.allowed_scopes == ["openid"]
        assert client.background_color == "#112233"
        assert client.header_color == "#445566"
        assert client.footer_color == "#778899"
        assert client.show_client_id is True
        assert client.show_description is True

    @pytest.mark.asyncio
    async def test_delete_client_success_and_missing(self, mcp_config, mcp_call_tool):
        deleted = _payload(await mcp_call_tool("delete_client", {"client_id": "branch-client"}))
        assert deleted["success"] is True
        assert mcp_config.get_client("branch-client") is None

        missing = await mcp_call_tool("delete_client", {"client_id": "branch-client"})
        assert missing.is_error is True
        assert "not found" in _payload(missing)["error"]


class TestConfigToolBranches:
    @pytest.mark.asyncio
    async def test_reload_config_succeeds(self, mcp_config, mcp_call_tool):
        payload = _payload(await mcp_call_tool("reload_config", {}))
        assert payload["success"] is True

    @pytest.mark.asyncio
    async def test_update_settings_field_branches(self, mcp_config, mcp_call_tool):
        payload = _payload(
            await mcp_call_tool(
                "update_settings",
                {
                    "issuer": "http://idp.example:9000",
                    "issuer_from_request": True,
                    "issuer_allowlist": ["http://idp.example:9000"],
                    "device_verification_base_url": "http://idp.example:9000",
                    "issuer_from_proxy_headers": True,
                    "audience": "new-aud",
                    "token_expiry_minutes": 12,
                    "saml_entity_id": "http://idp.example:9000/saml/metadata",
                    "saml_sso_url": "http://idp.example:9000/saml/sso",
                    "saml_sign_responses": False,
                    "saml_export_roles": True,
                    "saml_export_groups": True,
                    "saml_roles_attr_name": "memberOf",
                    "saml_groups_attr_name": "memberOf",
                    "saml_c14n_algorithm": "c14n",
                    "saml_want_authn_requests_signed": False,
                    "saml_sp_certificates": [],
                    "strict_saml_binding": True,
                    "verbose_logging": False,
                    "refresh_token_rotation": True,
                    "require_pkce": True,
                },
            )
        )
        assert payload["success"] is True
        settings = mcp_config.settings
        assert settings.issuer == "http://idp.example:9000"
        assert settings.audience == "new-aud"
        assert settings.token_expiry_minutes == 12
        assert settings.require_pkce is True
        assert settings.refresh_token_rotation is True
        assert settings.verbose_logging is False
        assert settings.saml_roles_attr_name == "memberOf"
        assert settings.strict_saml_binding is True

    @pytest.mark.asyncio
    async def test_save_config_writes_yaml(self, mcp_config, mcp_call_tool):
        _payload(await mcp_call_tool("update_settings", {"audience": "saved-aud"}))
        payload = _payload(await mcp_call_tool("save_config", {}))
        assert payload["success"] is True
        saved = yaml.safe_load((mcp_config.config_dir / "settings.yaml").read_text())
        assert saved["oauth"]["audience"] == "saved-aud"

    @pytest.mark.asyncio
    async def test_save_config_failure_is_a_clean_error(
        self, mcp_config, mcp_call_tool, monkeypatch
    ):
        def _failing_save():
            raise OSError("disk full")

        monkeypatch.setattr(mcp_config, "save", _failing_save)
        result = await mcp_call_tool("save_config", {})
        assert result.is_error is True
        payload = _payload(result)
        assert payload["success"] is False
        assert "Failed to save config" in payload["error"]

    @pytest.mark.asyncio
    async def test_get_jwks_serves_the_active_key(self, mcp_config, mcp_call_tool):
        jwks = _payload(await mcp_call_tool("get_jwks", {}))
        assert jwks["keys"]
        info = _payload(await mcp_call_tool("get_keys_info", {}))
        assert any(k["kid"] == info["active_kid"] for k in jwks["keys"])

    @pytest.mark.asyncio
    async def test_keys_info_and_rotation(self, mcp_config, mcp_call_tool):
        info = _payload(await mcp_call_tool("get_keys_info", {}))
        kid_before = info["active_kid"]

        rotated = _payload(await mcp_call_tool("rotate_keys", {}))
        assert rotated["success"] is True
        assert rotated["new_kid"] != kid_before


class TestDispatchGuards:
    @pytest.mark.asyncio
    async def test_readonly_mode_rejects_mutating_tool(
        self, mcp_config, mcp_call_tool, monkeypatch
    ):
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_readonly_mode", True)
        result = await mcp_call_tool("create_user", {"username": "x", "password": "y"})
        assert result.is_error is True
        payload = _payload(result)
        assert payload["code"] == "MCP_READONLY_MODE"
        assert mcp_config.get_user("x") is None

    @pytest.mark.asyncio
    async def test_execute_tool_unknown_name_raises(self, mcp_config):
        """The dispatcher's unreachable-on-protocol-path contract: a direct
        mis-call raises instead of returning a divergent error shape."""
        from nanoidp.mcp_server import _execute_tool

        with pytest.raises(ValueError, match="Unknown tool"):
            await _execute_tool("no-such-tool", {}, mcp_config)
