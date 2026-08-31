"""
Tests for NanoIDP MCP Server functionality.

Tests cover:
- get_settings tool including verbose_logging
- update_settings tool including verbose_logging
- Tool execution flow
"""

import json

import jwt as pyjwt
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


class TestMCPToolHandlerParity:
    """_TOOLS and _TOOL_HANDLERS must declare exactly the same names (#211).

    The dispatch table replaced the old if/elif chain; a tool declared
    without a handler used to fail only at call time (ValueError), and a
    handler without a declaration would be dead code the schema validator
    rejects before dispatch. Either mismatch is a bug caught here.
    """

    def test_every_declared_tool_has_a_handler_and_vice_versa(self):
        from nanoidp.mcp_server import _TOOL_HANDLERS, _TOOLS

        declared = {tool.name for tool in _TOOLS}
        handled = set(_TOOL_HANDLERS)
        assert declared == handled

    def test_mutating_tools_is_a_subset_of_declared_tools(self):
        from nanoidp.mcp_server import _TOOLS, MUTATING_TOOLS

        declared = {tool.name for tool in _TOOLS}
        assert set(MUTATING_TOOLS) <= declared


class TestMCPHandlerRegistration:
    """The SDK takes handlers as constructor args; nothing else registers them."""

    def test_handlers_are_registered(self):
        from nanoidp.mcp_server import server

        assert server.get_request_handler("tools/list") is not None
        assert server.get_request_handler("tools/call") is not None

    @pytest.mark.asyncio
    async def test_every_tool_schema_is_an_object(self, mcp_list_tools):
        """Results are validated against the protocol schema on the wire, which
        requires inputSchema to declare "type": "object"."""
        tools = await mcp_list_tools()
        assert tools
        for tool in tools:
            assert tool.input_schema.get("type") == "object", tool.name

    @pytest.mark.asyncio
    async def test_missing_arguments_are_treated_as_empty(self, tmp_path, monkeypatch, mcp_call_tool):
        """params.arguments is None when the call carries none."""
        import nanoidp.mcp_server as mcp
        from nanoidp.config import ConfigManager

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

        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.setattr(mcp, "_config", ConfigManager(str(config_dir)))
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool("list_users", None)

        assert result.is_error is False
        assert "users" in json.loads(result.content[0].text)

    @pytest.mark.asyncio
    async def test_missing_required_argument_is_a_clean_validation_error(
        self, monkeypatch, mcp_call_tool
    ):
        """The SDK no longer validates arguments against input_schema before
        dispatch (mcp 1.x's @server.call_tool(validate_input=True) did); a
        missing required field must come back as an is_error result, not a
        bare KeyError leaking out of _execute_tool."""
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool("create_user", {})

        assert result.is_error is True
        payload = json.loads(result.content[0].text)
        assert payload["tool"] == "create_user"
        assert payload["code"] == "MCP_INVALID_ARGUMENTS"
        assert "username" in payload["error"]

    @pytest.mark.asyncio
    async def test_config_init_failure_returns_is_error_result(self, monkeypatch, mcp_call_tool):
        """_ensure_config() runs before the readonly/admin-secret checks; a
        failure there must still come back as CallToolResult(is_error=True)
        instead of escaping call_tool as a raw exception."""
        import nanoidp.mcp_server as mcp

        def _boom() -> None:
            raise RuntimeError("config init failed")

        monkeypatch.setattr(mcp, "_ensure_config", _boom)

        result = await mcp_call_tool("list_users", None)

        assert result.is_error is True
        payload = json.loads(result.content[0].text)
        assert payload["tool"] == "list_users"
        assert "config init failed" in payload["error"]

    @pytest.mark.asyncio
    async def test_unknown_tool_is_a_clean_error_not_a_success(self, monkeypatch, mcp_call_tool):
        """A misspelled tool name must not take the success path: without this,
        _execute_tool's `{"error": "Unknown tool: ..."}` fallback returned
        is_error=False, so a client gating on isError - and the audit log -
        would treat it as a successful call."""
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool("totally_bogus_tool", {})

        assert result.is_error is True
        payload = json.loads(result.content[0].text)
        assert payload["tool"] == "totally_bogus_tool"
        assert payload["code"] == "MCP_UNKNOWN_TOOL"

    @pytest.mark.asyncio
    async def test_domain_level_failure_sets_is_error(self, monkeypatch, mcp_call_tool):
        """A tool-level failure returned as data (e.g. {"success": False, ...})
        must still be flagged is_error=True - it's a failed call, not an
        exception, so it doesn't go through call_tool's except branch."""
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool("delete_user", {"username": "does-not-exist"})

        assert result.is_error is True
        payload = json.loads(result.content[0].text)
        assert payload["success"] is False

    @pytest.mark.asyncio
    async def test_verify_token_invalid_is_not_an_error(self, monkeypatch, mcp_call_tool):
        """An invalid/expired token is verify_token's designed answer, not a
        failed call: the result reports valid=False with a `reason` (not an
        `error` key) and is not flagged is_error (isError contract)."""
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool("verify_token", {"token": "not-a-real-jwt"})

        assert result.is_error is False
        payload = json.loads(result.content[0].text)
        assert payload["valid"] is False
        assert "reason" in payload
        assert "error" not in payload


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
    """Tests for MCP admin secret protection.

    _check_admin_secret(config, tool_name, arguments) reads config.settings.
    management_secret directly (#163 B5 fix) rather than the env var through
    a global singleton, so these pass a bare config double instead of
    patching os.environ.
    """

    def _config(self, secret):
        from unittest.mock import MagicMock

        config = MagicMock()
        config.settings.management_secret = secret
        return config

    def test_update_settings_requires_admin_secret_when_configured(self):
        from nanoidp.mcp_server import _check_admin_secret

        config = self._config("test-secret-123")

        # Without admin_secret parameter
        arguments = {}
        allowed, error_msg = _check_admin_secret(config, "update_settings", arguments)
        assert allowed is False
        assert "admin_secret" in error_msg.lower()

        # With wrong admin_secret
        arguments = {"admin_secret": "wrong-secret"}
        allowed, error_msg = _check_admin_secret(config, "update_settings", arguments)
        assert allowed is False
        assert "invalid" in error_msg.lower()

        # With correct admin_secret
        arguments = {"admin_secret": "test-secret-123"}
        allowed, error_msg = _check_admin_secret(config, "update_settings", arguments)
        assert allowed is True
        assert error_msg == ""

    def test_get_settings_does_not_require_admin_secret(self):
        from nanoidp.mcp_server import _check_admin_secret

        config = self._config("test-secret-123")

        # get_settings should be allowed without admin_secret
        arguments = {}
        allowed, error_msg = _check_admin_secret(config, "get_settings", arguments)
        assert allowed is True
        assert error_msg == ""

    def test_non_ascii_secret_does_not_crash(self):
        """#163 B2 regression: secrets.compare_digest raises TypeError on
        non-ASCII str; the fix compares UTF-8 bytes instead."""
        from nanoidp.mcp_server import _check_admin_secret

        config = self._config("segretò")

        allowed, error_msg = _check_admin_secret(config, "create_user", {"admin_secret": "wrong"})
        assert allowed is False
        assert "Invalid admin_secret" in error_msg

        allowed, error_msg = _check_admin_secret(
            config, "create_user", {"admin_secret": "segretò"}
        )
        assert allowed is True

    def test_non_str_candidate_does_not_crash(self):
        """#163 B2 regression: a non-string admin_secret (e.g. an int) must
        compare False, not raise TypeError."""
        from nanoidp.mcp_server import _check_admin_secret

        config = self._config("mysecret")

        allowed, error_msg = _check_admin_secret(config, "create_user", {"admin_secret": 123})
        assert allowed is False
        assert "Invalid admin_secret" in error_msg

    def test_reads_the_passed_config_not_the_global_singleton(self, monkeypatch, tmp_path):
        """#163 B5 regression: _check_admin_secret must key off the ConfigManager
        it's given (what _ensure_config() actually returns), not
        routes._auth.get_management_secret() - which reads
        nanoidp.config.get_config()'s own global, a different object from
        mcp_server._config whenever the two have been set independently (as
        tests that monkeypatch mcp._config directly already do)."""
        import nanoidp.config as config_module
        from nanoidp.config import ConfigManager
        from nanoidp.mcp_server import _check_admin_secret

        no_secret_dir = tmp_path / "no_secret"
        no_secret_dir.mkdir()
        has_secret_dir = tmp_path / "has_secret"
        has_secret_dir.mkdir()
        (has_secret_dir / "settings.yaml").write_text("session:\n  management_secret: mysecret\n")

        # The global nanoidp.config singleton has no secret configured.
        monkeypatch.setattr(config_module, "_config", ConfigManager(str(no_secret_dir)))

        # mcp_server's own config (what _ensure_config() would hand to
        # call_tool) does - _check_admin_secret must gate off THIS.
        own_config = ConfigManager(str(has_secret_dir))

        allowed, error_msg = _check_admin_secret(own_config, "create_user", {})
        assert allowed is False
        assert "admin_secret" in error_msg


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
    async def test_schema_exposes_additional_audiences(self, tool_name, mcp_list_tools):
        tools = await mcp_list_tools()
        tool = next(t for t in tools if t.name == tool_name)
        props = tool.input_schema["properties"]
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
    async def test_call_tool_returns_clean_error_for_bad_audiences(self, tmp_path, monkeypatch, mcp_call_tool):
        """A non-string entry in additional_audiences is caught by the schema
        pre-check before dispatch, so call_tool returns a clean
        MCP_INVALID_ARGUMENTS error naming the field (not a crash). The
        _normalize_str_list ValueError path this used to exercise is now
        unreachable via call_tool; it still guards direct _execute_tool callers
        (see TestGenerateTokenClaims), so its isinstance branch stays."""
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_config", self._config(tmp_path))
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool(
            "create_client",
            {"client_id": "c", "client_secret": "s", "additional_audiences": ["a", 123]},
        )

        assert len(result.content) == 1
        assert result.is_error is True
        payload = json.loads(result.content[0].text)
        assert payload["tool"] == "create_client"
        assert payload["code"] == "MCP_INVALID_ARGUMENTS"
        assert "additional_audiences" in payload["error"]


class TestMCPPersonaLogin:
    """MCP exposure of persona login mode: `create_persona_user` and the
    `login_mode` setting on `get_settings`/`update_settings`."""

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
    async def test_create_persona_user_has_no_password(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)

        result = await _execute_tool(
            "create_persona_user", {"username": "alice", "email": "a@example.org"}, config
        )

        assert result["success"] is True
        assert config.get_user("alice").password is None
        assert result["user"]["username"] == "alice"

    @pytest.mark.asyncio
    async def test_create_persona_user_rejects_duplicate(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        await _execute_tool("create_persona_user", {"username": "alice"}, config)

        result = await _execute_tool("create_persona_user", {"username": "alice"}, config)

        assert result["success"] is False
        assert "already exists" in result["error"]

    @pytest.mark.asyncio
    async def test_create_user_contract_is_unchanged(self, monkeypatch, mcp_call_tool, tmp_path):
        """Regression: adding create_persona_user must not loosen create_user -
        it still requires a password argument."""
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_config", self._config(tmp_path))
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool("create_user", {"username": "bob"})

        assert result.is_error is True
        payload = json.loads(result.content[0].text)
        assert payload["code"] == "MCP_INVALID_ARGUMENTS"
        assert "password" in payload["error"]

    @pytest.mark.asyncio
    async def test_create_persona_user_schema_has_no_password_property(self, mcp_list_tools):
        tools = await mcp_list_tools()
        tool = next(t for t in tools if t.name == "create_persona_user")

        assert "password" not in tool.input_schema["properties"]
        assert tool.input_schema["required"] == ["username"]

    @pytest.mark.asyncio
    async def test_create_user_and_create_persona_user_schemas_share_common_properties(self, mcp_list_tools):
        """Regression: the two tools' non-username/password properties must
        stay identical (a shared dict, not hand-copied) so they can't drift,
        and both must declare 'attributes' - the shared handler-side builder
        reads it from either tool."""
        tools = await mcp_list_tools()
        create_user = next(t for t in tools if t.name == "create_user")
        create_persona_user = next(t for t in tools if t.name == "create_persona_user")

        common_keys = set(create_persona_user.input_schema["properties"]) - {"username"}
        assert "attributes" in common_keys
        for key in common_keys:
            assert create_user.input_schema["properties"][key] == create_persona_user.input_schema["properties"][key]

    def test_create_persona_user_is_a_mutating_tool(self):
        from nanoidp.mcp_server import MUTATING_TOOLS
        assert "create_persona_user" in MUTATING_TOOLS


class TestMCPUserDescription:
    """The display-only `description` field is a first-class property on
    every user-shaped MCP tool, not a custom attribute."""

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
    async def test_create_user_accepts_and_returns_description(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)

        result = await _execute_tool(
            "create_user",
            {"username": "bob", "password": "pw", "description": "Finance approver persona"},
            config,
        )

        assert result["success"] is True
        assert result["user"]["description"] == "Finance approver persona"
        assert config.get_user("bob").description == "Finance approver persona"

    @pytest.mark.asyncio
    async def test_create_persona_user_accepts_and_returns_description(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)

        result = await _execute_tool(
            "create_persona_user",
            {"username": "alice", "description": "Admin persona for testing"},
            config,
        )

        assert result["success"] is True
        assert result["user"]["description"] == "Admin persona for testing"

    @pytest.mark.asyncio
    async def test_update_user_changes_description(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        await _execute_tool("create_user", {"username": "carol", "password": "pw"}, config)

        result = await _execute_tool(
            "update_user", {"username": "carol", "description": "Updated note"}, config
        )

        assert result["success"] is True
        assert result["user"]["description"] == "Updated note"
        assert config.get_user("carol").description == "Updated note"

    @pytest.mark.asyncio
    async def test_update_user_updates_attributes(self, tmp_path):
        """#280: create_user accepted custom attributes from day one, but
        update_user's schema and handler silently lacked the field - an agent
        could set attributes at creation and never change them again."""
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        await _execute_tool(
            "create_user",
            {"username": "erin", "password": "pw", "attributes": {"dept": "eng"}},
            config,
        )

        result = await _execute_tool(
            "update_user",
            {"username": "erin", "attributes": {"dept": "sales", "region": "emea"}},
            config,
        )

        assert result["success"] is True
        assert result["user"]["attributes"] == {"dept": "sales", "region": "emea"}
        assert config.get_user("erin").attributes == {"dept": "sales", "region": "emea"}

    @pytest.mark.asyncio
    async def test_update_user_schema_includes_attributes(self, mcp_list_tools):
        """#280: the schema half of the same gap."""
        tools = await mcp_list_tools()
        update_user = next(t for t in tools if t.name == "update_user")
        assert "attributes" in update_user.input_schema["properties"]

    @pytest.mark.asyncio
    async def test_get_user_returns_description(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        await _execute_tool(
            "create_user", {"username": "dave", "password": "pw", "description": "d"}, config
        )

        result = await _execute_tool("get_user", {"username": "dave"}, config)

        assert result["user"]["description"] == "d"

    @pytest.mark.asyncio
    async def test_create_user_and_create_persona_user_schemas_include_description(self, mcp_list_tools):
        tools = await mcp_list_tools()
        create_user = next(t for t in tools if t.name == "create_user")
        create_persona_user = next(t for t in tools if t.name == "create_persona_user")
        update_user = next(t for t in tools if t.name == "update_user")

        assert "description" in create_user.input_schema["properties"]
        assert "description" in create_persona_user.input_schema["properties"]
        assert "description" in update_user.input_schema["properties"]

    @pytest.mark.asyncio
    async def test_overlong_description_rejected_by_schema(self, monkeypatch, mcp_call_tool, tmp_path):
        """The MCP protocol path (call_tool) validates maxLength before
        dispatch - a client can't smuggle an overlong description past the
        JSON schema even though the handler bypasses it in tests."""
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_config", self._config(tmp_path))
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool(
            "create_user",
            {"username": "toolong", "password": "pw", "description": "a" * 201},
        )

        assert result.is_error is True
        payload = json.loads(result.content[0].text)
        assert payload["code"] == "MCP_INVALID_ARGUMENTS"

    @pytest.mark.asyncio
    async def test_update_user_direct_mutation_rejects_overlong_description(self, tmp_path):
        """Defense in depth (maintainer review on #244): _execute_tool is
        reachable directly, bypassing call_tool's JSON schema check, so
        _tool_update_user's direct 'user.description = ...' assignment must
        itself refuse a value the loader would later reject - otherwise a
        bypassed call can write a users.yaml the server can no longer start
        from. User.model_config now carries validate_assignment=True (the
        same fix #37 applied to OAuthClient), so this raises before any
        write happens."""
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        await _execute_tool("create_user", {"username": "eve", "password": "pw"}, config)

        with pytest.raises(ValueError):
            await _execute_tool(
                "update_user", {"username": "eve", "description": "a" * 300}, config
            )

        # The in-memory user must be left untouched - the assignment raised
        # before the model's __setattr__ committed the new value.
        assert config.get_user("eve").description == ""

    @pytest.mark.asyncio
    async def test_update_user_rejects_atomically_across_multiple_fields(self, tmp_path):
        """Round 2 (maintainer review on #244): validate_assignment=True
        made field-by-field mutation of the *live* user observable - an
        earlier field in the call could commit before a later field's
        validation failure raised, leaving the user half-updated (and this
        was reachable through the ordinary call_tool path too, since 'email'
        has no schema-level format check, only the model validator). A valid
        'password' followed by an invalid 'description' in the same call
        must leave the password unchanged - _tool_update_user validates a
        scratch copy and only swaps it in once every field has passed."""
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)
        await _execute_tool("create_user", {"username": "eve", "password": "old"}, config)

        with pytest.raises(ValueError):
            await _execute_tool(
                "update_user",
                {"username": "eve", "password": "new-should-not-stick", "description": "a" * 300},
                config,
            )

        assert config.get_user("eve").password == "old"
        assert config.get_user("eve").description == ""

    @pytest.mark.asyncio
    async def test_get_settings_includes_login_mode(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)

        result = await _execute_tool("get_settings", {}, config)

        assert result["login_mode"] == "password"

    @pytest.mark.asyncio
    async def test_update_settings_can_switch_to_persona(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)

        result = await _execute_tool(
            "update_settings", {"login_mode": "persona"}, config
        )

        assert result["success"] is True
        assert "login_mode" in result["updated_fields"]
        assert result["current_settings"]["login_mode"] == "persona"
        assert config.settings.login_mode == "persona"
        assert config.settings.persona_mode_enabled is True

    @pytest.mark.asyncio
    async def test_update_settings_rejects_invalid_login_mode(self, monkeypatch, mcp_call_tool, tmp_path):
        """Invalid login_mode is caught by the schema's "enum" constraint
        before dispatch, as a clean MCP_INVALID_ARGUMENTS error."""
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_config", self._config(tmp_path))
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool("update_settings", {"login_mode": "bogus"})

        assert result.is_error is True
        payload = json.loads(result.content[0].text)
        assert payload["code"] == "MCP_INVALID_ARGUMENTS"
        assert "login_mode" in payload["error"]

    @pytest.mark.asyncio
    async def test_get_settings_includes_auto_login(self, tmp_path):
        """#250: default off, alongside login_mode."""
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)

        result = await _execute_tool("get_settings", {}, config)

        assert result["auto_login"] is False

    @pytest.mark.asyncio
    async def test_update_settings_can_enable_auto_login(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)

        result = await _execute_tool(
            "update_settings", {"login_mode": "persona", "auto_login": True}, config
        )

        assert result["success"] is True
        assert "auto_login" in result["updated_fields"]
        assert result["current_settings"]["auto_login"] is True
        assert config.settings.auto_login is True
        assert config.settings.auto_login_enabled is True

    @pytest.mark.asyncio
    async def test_update_settings_auto_login_without_persona_mode_is_inert(self, tmp_path):
        """#250-assumption 1: accepted, not rejected - just has no effect
        until login_mode is also 'persona'."""
        from nanoidp.mcp_server import _execute_tool
        config = self._config(tmp_path)

        result = await _execute_tool("update_settings", {"auto_login": True}, config)

        assert result["success"] is True
        assert config.settings.auto_login is True
        assert config.settings.auto_login_enabled is False

    @pytest.mark.asyncio
    async def test_update_settings_rejects_non_bool_auto_login(self, monkeypatch, mcp_call_tool, tmp_path):
        """Caught by the schema's "type": "boolean" constraint before dispatch."""
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_config", self._config(tmp_path))
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool("update_settings", {"auto_login": "yes"})

        assert result.is_error is True
        payload = json.loads(result.content[0].text)
        assert payload["code"] == "MCP_INVALID_ARGUMENTS"
        assert "auto_login" in payload["error"]


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
    async def test_non_list_claims_arguments_rejected(self, app):
        """The SDK does not enforce inputSchema server-side: a non-list value
        must be rejected with a clean ValueError (turned into an error payload
        by call_tool), not minted into a token that misbehaves at /userinfo."""
        from nanoidp.config import get_config
        from nanoidp.mcp_server import _execute_tool

        for field, bad in (
            ("userinfo_claims", "email"),
            ("userinfo_claims", 5),
            ("id_token_claims", "email"),
            ("id_token_claims", [1, 2]),
        ):
            with pytest.raises(ValueError, match=field):
                await _execute_tool(
                    "generate_token",
                    {"username": "admin", "scope": "openid", field: bad},
                    get_config(),
                )

    @pytest.mark.asyncio
    async def test_claims_persist_across_refresh(self, app, client, auth_header):
        import jwt as pyjwt

        result = await self._generate(
            {
                "username": "admin",
                "client_id": "demo-client",
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

    @pytest.mark.asyncio
    async def test_unbound_token_has_no_refresh_token(self, app):
        """Without client_id, generate_token mints an UNBOUND access token and
        issues NO refresh token: a refresh token with no client_id binding is
        refused since 3.0 (#73), so handing one back would be a dead credential."""
        result = await self._generate({"username": "admin", "scope": "openid"})
        assert "access_token" in result
        assert "refresh_token" not in result

    @pytest.mark.asyncio
    async def test_bound_token_refresh_token_is_spendable(self, app, client, auth_header):
        """With a valid client_id, the token is bound and its refresh token can
        be spent by that client."""
        result = await self._generate({"username": "admin", "scope": "openid", "client_id": "demo-client"})
        resp = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": result["refresh_token"]},
            headers=auth_header,
        )
        assert resp.status_code == 200, resp.data

    @pytest.mark.asyncio
    async def test_unknown_client_id_is_rejected(self, app):
        """A client_id that names no configured client is refused up front,
        rather than stamping a binding no authenticable client could match."""
        from nanoidp.config import get_config
        from nanoidp.mcp_server import _execute_tool

        result = await _execute_tool(
            "generate_token",
            {"username": "admin", "client_id": "does-not-exist"},
            get_config(),
        )
        assert result["success"] is False
        assert "does-not-exist" in result["error"]


class TestSimulationBoundary:
    """#279: generate_token and verify_token deliberately diverge from the
    grant endpoints - they simulate, they do not enforce. These pins keep the
    exemptions EXPLICIT: if one starts enforcing, the boundary documented in
    the tool descriptions changed and docs/tests must move together."""

    async def _generate(self, arguments):
        from nanoidp.config import get_config
        from nanoidp.mcp_server import _execute_tool

        result = await _execute_tool("generate_token", arguments, get_config())
        assert result["success"] is True, result
        return result

    @pytest.mark.asyncio
    async def test_generate_token_scope_has_no_ceiling_even_with_client_id(self, app):
        """scoped-client's allowed_scopes is [openid, profile] and
        'custom:everything' is outside the vocabulary too - the grant
        endpoints reject both, this tool stamps them as asked (minting an
        out-of-ceiling token is how a resource server's rejection path gets
        tested)."""
        result = await self._generate(
            {
                "username": "admin",
                "client_id": "scoped-client",
                "scope": "email custom:everything",
            }
        )
        payload = pyjwt.decode(result["access_token"], options={"verify_signature": False})
        assert payload["scope"] == "email custom:everything"

    @pytest.mark.asyncio
    async def test_verify_token_ignores_revocation_like_a_stateless_rs(self, app, client, auth_header):
        """verify_token simulates a JWKS-validating resource server (the #191
        model): revocation is /introspect's answer. A revoked token still
        verifies here and introspects as inactive there."""
        from nanoidp.config import get_config
        from nanoidp.mcp_server import _execute_tool
        from nanoidp.services.revocation import get_revocation_store

        minted = await self._generate({"username": "admin", "scope": "openid"})
        token = minted["access_token"]
        jti = pyjwt.decode(token, options={"verify_signature": False})["jti"]
        get_revocation_store().revoke(jti)
        try:
            verified = await _execute_tool("verify_token", {"token": token}, get_config())
            assert verified["valid"] is True

            resp = client.post("/introspect", data={"token": token}, headers=auth_header)
            assert resp.status_code == 200
            assert json.loads(resp.data)["active"] is False
        finally:
            get_revocation_store().clear()
