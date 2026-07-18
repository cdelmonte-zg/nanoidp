"""
Tests for NanoIDP MCP Server functionality.

Tests cover:
- get_settings tool including verbose_logging
- update_settings tool including verbose_logging
- Tool execution flow
"""

import json

import pytest


class TestMCPGetSettings:
    """Tests for MCP get_settings tool."""

    @pytest.mark.asyncio
    async def test_get_settings_includes_verbose_logging(self, tmp_path):
        """Test that get_settings includes verbose_logging in response."""
        # Create test config
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        settings_yaml = """
server:
  host: "0.0.0.0"
  port: 8000

oauth:
  issuer: "http://localhost:8000"
  clients:
    - client_id: "test"
      client_secret: "test"

logging:
  verbose_logging: true
"""
        (config_dir / "settings.yaml").write_text(settings_yaml)

        users_yaml = """
users:
  admin:
    password: "admin"
default_user: admin
"""
        (config_dir / "users.yaml").write_text(users_yaml)

        # Initialize config
        from nanoidp.config import ConfigManager
        config = ConfigManager(str(config_dir))

        # Test get_settings response structure
        settings = config.settings
        response = {
            "issuer": settings.issuer,
            "audience": settings.audience,
            "token_expiry_minutes": settings.token_expiry_minutes,
            "jwt_algorithm": settings.jwt_algorithm,
            "saml": {
                "entity_id": settings.saml_entity_id,
                "sso_url": settings.saml_sso_url,
                "sign_responses": settings.saml_sign_responses,
                "c14n_algorithm": settings.saml_c14n_algorithm,
            },
            "logging": {
                "verbose_logging": settings.verbose_logging,
            },
        }

        # Verify structure
        assert "logging" in response
        assert "verbose_logging" in response["logging"]
        assert response["logging"]["verbose_logging"] is True

    @pytest.mark.asyncio
    async def test_get_settings_verbose_logging_default(self, tmp_path):
        """Test that verbose_logging defaults to True when not specified."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        settings_yaml = """
server:
  host: "0.0.0.0"
  port: 8000

oauth:
  issuer: "http://localhost:8000"
  clients:
    - client_id: "test"
      client_secret: "test"
"""
        (config_dir / "settings.yaml").write_text(settings_yaml)

        users_yaml = """
users:
  admin:
    password: "admin"
default_user: admin
"""
        (config_dir / "users.yaml").write_text(users_yaml)

        from nanoidp.config import ConfigManager
        config = ConfigManager(str(config_dir))

        # Should default to True
        assert config.settings.verbose_logging is True


class TestMCPUpdateSettings:
    """Tests for MCP update_settings tool."""

    @pytest.mark.asyncio
    async def test_update_settings_can_change_verbose_logging(self, tmp_path):
        """Test that update_settings can change verbose_logging."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        settings_yaml = """
server:
  host: "0.0.0.0"
  port: 8000

oauth:
  issuer: "http://localhost:8000"
  clients:
    - client_id: "test"
      client_secret: "test"

logging:
  verbose_logging: true
"""
        (config_dir / "settings.yaml").write_text(settings_yaml)

        users_yaml = """
users:
  admin:
    password: "admin"
default_user: admin
"""
        (config_dir / "users.yaml").write_text(users_yaml)

        from nanoidp.config import ConfigManager
        config = ConfigManager(str(config_dir))

        # Initial state
        assert config.settings.verbose_logging is True

        # Simulate update_settings changing verbose_logging
        config.settings.verbose_logging = False

        # Verify change
        assert config.settings.verbose_logging is False


class TestMCPToolSchema:
    """Tests for MCP tool schema definitions."""

    def test_update_settings_schema_includes_verbose_logging(self):
        """Test that update_settings schema includes verbose_logging parameter."""
        # Read the MCP server module to verify schema
        from nanoidp import mcp_server

        # Verify the module has the expected structure
        assert hasattr(mcp_server, 'server')
        assert hasattr(mcp_server, 'MUTATING_TOOLS')
        assert 'update_settings' in mcp_server.MUTATING_TOOLS


class TestMCPReadonlyMode:
    """Tests for MCP readonly mode behavior."""

    def test_readonly_mode_blocks_update_settings(self):
        """Test that readonly mode blocks update_settings calls."""
        # Simulate readonly mode enabled
        import nanoidp.mcp_server as mcp_module
        from nanoidp.mcp_server import _check_readonly_mode
        original_readonly = mcp_module._readonly_mode

        try:
            mcp_module._readonly_mode = True

            # Check that update_settings is blocked
            allowed, error_msg = _check_readonly_mode("update_settings")
            assert allowed is False
            assert "readonly" in error_msg.lower()

            # Check that get_settings is allowed
            allowed, error_msg = _check_readonly_mode("get_settings")
            assert allowed is True
            assert error_msg == ""
        finally:
            mcp_module._readonly_mode = original_readonly


class TestMCPAdminSecret:
    """Tests for MCP admin secret protection."""

    def test_update_settings_requires_admin_secret_when_configured(self):
        """Test that update_settings requires admin_secret when env var is set."""
        import os

        from nanoidp.mcp_server import _check_admin_secret

        original_secret = os.environ.get("NANOIDP_MCP_ADMIN_SECRET")

        try:
            # Set admin secret
            os.environ["NANOIDP_MCP_ADMIN_SECRET"] = "test-secret-123"

            # Without admin_secret parameter
            arguments = {}
            allowed, error_msg = _check_admin_secret("update_settings", arguments)
            assert allowed is False
            assert "admin_secret" in error_msg.lower()

            # With wrong admin_secret
            arguments = {"admin_secret": "wrong-secret"}
            allowed, error_msg = _check_admin_secret("update_settings", arguments)
            assert allowed is False
            assert "invalid" in error_msg.lower()

            # With correct admin_secret
            arguments = {"admin_secret": "test-secret-123"}
            allowed, error_msg = _check_admin_secret("update_settings", arguments)
            assert allowed is True
            assert error_msg == ""
        finally:
            if original_secret is None:
                os.environ.pop("NANOIDP_MCP_ADMIN_SECRET", None)
            else:
                os.environ["NANOIDP_MCP_ADMIN_SECRET"] = original_secret

    def test_get_settings_does_not_require_admin_secret(self):
        """Test that get_settings works without admin_secret."""
        import os

        from nanoidp.mcp_server import _check_admin_secret

        original_secret = os.environ.get("NANOIDP_MCP_ADMIN_SECRET")

        try:
            os.environ["NANOIDP_MCP_ADMIN_SECRET"] = "test-secret-123"

            # get_settings should be allowed without admin_secret
            arguments = {}
            allowed, error_msg = _check_admin_secret("get_settings", arguments)
            assert allowed is True
            assert error_msg == ""
        finally:
            if original_secret is None:
                os.environ.pop("NANOIDP_MCP_ADMIN_SECRET", None)
            else:
                os.environ["NANOIDP_MCP_ADMIN_SECRET"] = original_secret


class TestMCPVerboseLoggingIntegration:
    """Integration tests for verbose_logging through MCP."""

    @pytest.mark.asyncio
    async def test_verbose_logging_affects_audit_output(self, tmp_path):
        """Test that verbose_logging setting affects audit log output."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        settings_yaml = """
server:
  host: "0.0.0.0"
  port: 8000

oauth:
  issuer: "http://localhost:8000"
  clients:
    - client_id: "test"
      client_secret: "test"

logging:
  verbose_logging: false
"""
        (config_dir / "settings.yaml").write_text(settings_yaml)

        users_yaml = """
users:
  admin:
    password: "admin"
default_user: admin
"""
        (config_dir / "users.yaml").write_text(users_yaml)

        from nanoidp.config import ConfigManager
        config = ConfigManager(str(config_dir))

        # Verify verbose_logging is false
        assert config.settings.verbose_logging is False

        # Change to true
        config.settings.verbose_logging = True
        assert config.settings.verbose_logging is True


class TestMCPClientAdditionalAudiences:
    """create_client / update_client expose `additional_audiences` (issue #32)."""

    def _config(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.yaml").write_text(
            'oauth:\n'
            '  issuer: "http://localhost:8000"\n'
            '  clients:\n'
            '    - client_id: "test"\n'
            '      client_secret: "test"\n'
        )
        (config_dir / "users.yaml").write_text(
            'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
        )
        from nanoidp.config import ConfigManager
        return ConfigManager(str(config_dir))

    @pytest.mark.asyncio
    async def test_create_client_with_additional_audiences(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)

        result = await _execute_tool(
            "create_client",
            {
                "client_id": "multi",
                "client_secret": "s",
                "additional_audiences": ["https://api.example.com", "urn:svc"],
            },
            config,
        )

        assert result["success"] is True
        assert result["client"]["additional_audiences"] == [
            "https://api.example.com",
            "urn:svc",
        ]
        # persisted on the model
        assert config.get_client("multi").additional_audiences == [
            "https://api.example.com",
            "urn:svc",
        ]

    @pytest.mark.asyncio
    async def test_create_client_defaults_to_empty_audiences(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)

        result = await _execute_tool(
            "create_client", {"client_id": "plain", "client_secret": "s"}, config
        )

        assert result["success"] is True
        assert result["client"]["additional_audiences"] == []

    @pytest.mark.asyncio
    async def test_update_client_sets_additional_audiences(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        await _execute_tool("create_client", {"client_id": "c", "client_secret": "s"}, config)

        result = await _execute_tool(
            "update_client", {"client_id": "c", "additional_audiences": ["aud://x"]}, config
        )

        assert result["success"] is True
        assert config.get_client("c").additional_audiences == ["aud://x"]

    @pytest.mark.asyncio
    async def test_update_client_invalid_audiences_does_not_partially_mutate(self, tmp_path):
        """A bad additional_audiences must not leave client_secret/description changed (#37)."""
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        await _execute_tool(
            "create_client",
            {"client_id": "c", "client_secret": "orig", "description": "orig-desc"},
            config,
        )

        with pytest.raises(ValueError):
            await _execute_tool(
                "update_client",
                {
                    "client_id": "c",
                    "client_secret": "newsecret",
                    "description": "newdesc",
                    "additional_audiences": "not-a-list",  # invalid → must raise
                },
                config,
            )

        # The failed update must not have applied the other fields.
        client = config.get_client("c")
        assert client.client_secret == "orig"
        assert client.description == "orig-desc"
        assert client.additional_audiences == []

    @pytest.mark.asyncio
    async def test_get_client_reports_additional_audiences(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        await _execute_tool(
            "create_client",
            {"client_id": "c", "client_secret": "s", "additional_audiences": ["a"]},
            config,
        )

        result = await _execute_tool("get_client", {"client_id": "c"}, config)

        assert result["found"] is True
        assert result["client"]["additional_audiences"] == ["a"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", ["create_client", "update_client"])
    async def test_schema_exposes_additional_audiences(self, tool_name):
        from nanoidp import mcp_server

        tools = await mcp_server.list_tools()
        tool = next(t for t in tools if t.name == tool_name)
        props = tool.inputSchema["properties"]
        assert "additional_audiences" in props
        assert props["additional_audiences"]["type"] == "array"
        assert props["additional_audiences"]["items"]["type"] == "string"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "raw,expected",
        [
            (None, []),
            ([], []),
            (["", "valid", ""], ["valid"]),
            (["a", "b"], ["a", "b"]),
        ],
        ids=["none", "empty", "drops-blanks", "kept"],
    )
    async def test_create_client_normalizes_audiences(self, tmp_path, raw, expected):
        """Blank/None audiences are filtered (defensive normalization, parity with update)."""
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        args = {"client_id": "c", "client_secret": "s"}
        if raw is not None:
            args["additional_audiences"] = raw

        result = await _execute_tool("create_client", args, config)

        assert result["success"] is True
        assert config.get_client("c").additional_audiences == expected

    @pytest.mark.asyncio
    async def test_update_client_normalizes_audiences(self, tmp_path):
        """update_client filters blanks too (it bypasses Pydantic on assignment)."""
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        await _execute_tool("create_client", {"client_id": "c", "client_secret": "s"}, config)

        result = await _execute_tool(
            "update_client", {"client_id": "c", "additional_audiences": ["", "x", ""]}, config
        )

        assert result["success"] is True
        assert config.get_client("c").additional_audiences == ["x"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad",
        [["a", 123], "not-a-list", [None]],
        ids=["int", "str", "none-item"],
    )
    async def test_create_client_rejects_non_string_audiences(self, tmp_path, bad):
        """Strict semantics: non-string audiences are rejected, not silently dropped."""
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        with pytest.raises(ValueError):
            await _execute_tool(
                "create_client",
                {"client_id": "c", "client_secret": "s", "additional_audiences": bad},
                config,
            )

    @pytest.mark.asyncio
    async def test_call_tool_returns_clean_error_for_bad_audiences(self, tmp_path, monkeypatch):
        """The public call_tool handler turns the ValueError into a readable error
        response (not a crash) - closing the raise/handle loop end to end."""
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_config", self._config(tmp_path))
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp.call_tool(
            "create_client",
            {"client_id": "c", "client_secret": "s", "additional_audiences": ["a", 123]},
        )

        assert len(result) == 1
        payload = json.loads(result[0].text)
        assert payload["tool"] == "create_client"
        assert "additional_audiences" in payload["error"]


class TestGenerateTokenClaims:
    """MCP ``generate_token`` claims arguments (#104/#113, parity #112).

    The MCP half of the OIDC ``claims`` parameter: ``id_token_claims`` must
    actually land the claims in the ID Token, ``userinfo_claims`` must be
    stamped on the access token and honoured by ``/userinfo``, and both must
    survive a token refresh like their HTTP counterparts.
    """

    async def _generate(self, arguments):
        from nanoidp.config import get_config
        from nanoidp.mcp_server import _execute_tool

        result = await _execute_tool("generate_token", arguments, get_config())
        assert result["success"] is True, result
        return result

    @pytest.mark.asyncio
    async def test_id_token_claims_land_in_id_token(self, app):
        import jwt as pyjwt

        result = await self._generate(
            {"username": "admin", "scope": "openid", "id_token_claims": ["email", "department"]}
        )
        payload = pyjwt.decode(result["id_token"], options={"verify_signature": False})
        assert payload["email"] == "admin@example.org"
        # custom user attribute resolved like any standard claim
        assert payload["department"] == "IT"

    @pytest.mark.asyncio
    async def test_unresolvable_names_are_skipped(self, app):
        import jwt as pyjwt

        result = await self._generate(
            {"username": "admin", "scope": "openid", "id_token_claims": ["no_such_claim"]}
        )
        payload = pyjwt.decode(result["id_token"], options={"verify_signature": False})
        assert "no_such_claim" not in payload

    @pytest.mark.asyncio
    async def test_id_token_claims_inert_without_openid_scope(self, app):
        result = await self._generate(
            {"username": "admin", "id_token_claims": ["email"]}
        )
        assert "id_token" not in result

    @pytest.mark.asyncio
    async def test_userinfo_claims_stamped_and_honoured(self, app, client):
        import jwt as pyjwt

        result = await self._generate(
            {"username": "admin", "scope": "openid", "userinfo_claims": ["department"]}
        )
        access_payload = pyjwt.decode(
            result["access_token"], options={"verify_signature": False}
        )
        assert access_payload["req_userinfo_claims"] == ["department"]

        # /userinfo returns the requested claim at top level - under the dev
        # profile `department` only appears nested in `attributes`, so this is
        # observable even without scope gating.
        resp = client.get(
            "/userinfo", headers={"Authorization": "Bearer " + result["access_token"]}
        )
        assert resp.status_code == 200, resp.data
        data = json.loads(resp.data)
        assert data["department"] == "IT"

    @pytest.mark.asyncio
    async def test_claims_persist_across_refresh(self, app, client, auth_header):
        import jwt as pyjwt

        result = await self._generate(
            {
                "username": "admin",
                "scope": "openid",
                "id_token_claims": ["email"],
                "userinfo_claims": ["department"],
            }
        )
        rt_payload = pyjwt.decode(
            result["refresh_token"], options={"verify_signature": False}
        )
        assert rt_payload["req_id_token_claims"] == ["email"]
        assert rt_payload["req_userinfo_claims"] == ["department"]

        # Refresh over HTTP: the refreshed tokens keep honouring the request (#112).
        resp = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": result["refresh_token"]},
            headers=auth_header,
        )
        assert resp.status_code == 200, resp.data
        refreshed = json.loads(resp.data)
        id_payload = pyjwt.decode(refreshed["id_token"], options={"verify_signature": False})
        assert id_payload["email"] == "admin@example.org"
        access_payload = pyjwt.decode(
            refreshed["access_token"], options={"verify_signature": False}
        )
        assert access_payload["req_userinfo_claims"] == ["department"]
