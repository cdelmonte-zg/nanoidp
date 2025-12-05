"""
Tests for NanoIDP MCP server security.

Tests cover:
- MCP admin secret protection
- MCP audit logging
- Blocking mutating operations without secret
"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

# Import MCP security functions
from nanoidp.mcp_server import (
    _check_admin_secret,
    _log_mcp_tool,
    MUTATING_TOOLS,
)


class TestMutatingToolsDefinition:
    """Tests for MUTATING_TOOLS definition."""

    def test_mutating_tools_includes_user_operations(self):
        """Test that user operations are in MUTATING_TOOLS."""
        assert "create_user" in MUTATING_TOOLS
        assert "update_user" in MUTATING_TOOLS
        assert "delete_user" in MUTATING_TOOLS

    def test_mutating_tools_includes_client_operations(self):
        """Test that client operations are in MUTATING_TOOLS."""
        assert "create_client" in MUTATING_TOOLS
        assert "update_client" in MUTATING_TOOLS
        assert "delete_client" in MUTATING_TOOLS

    def test_mutating_tools_includes_token_generation(self):
        """Test that token generation is in MUTATING_TOOLS."""
        assert "generate_token" in MUTATING_TOOLS

    def test_mutating_tools_includes_settings_operations(self):
        """Test that settings operations are in MUTATING_TOOLS."""
        assert "update_settings" in MUTATING_TOOLS
        assert "save_config" in MUTATING_TOOLS

    def test_read_only_tools_not_in_mutating(self):
        """Test that read-only tools are not in MUTATING_TOOLS."""
        read_only_tools = [
            "list_users",
            "get_user",
            "list_clients",
            "get_client",
            "get_settings",
            "get_oidc_discovery",
            "get_jwks",
            "decode_token",
            "verify_token",
            "reload_config",
        ]
        for tool in read_only_tools:
            assert tool not in MUTATING_TOOLS


class TestAdminSecretCheck:
    """Tests for _check_admin_secret function."""

    def test_no_secret_configured_allows_all(self):
        """Test that without secret configured, all operations are allowed."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove any existing secret
            os.environ.pop("NANOIDP_MCP_ADMIN_SECRET", None)

            allowed, error = _check_admin_secret("create_user", {})
            assert allowed is True
            assert error == ""

    def test_read_only_tool_allowed_without_secret(self):
        """Test that read-only tools don't need secret."""
        with patch.dict(os.environ, {"NANOIDP_MCP_ADMIN_SECRET": "mysecret"}):
            allowed, error = _check_admin_secret("list_users", {})
            assert allowed is True
            assert error == ""

    def test_mutating_tool_blocked_without_secret(self):
        """Test that mutating tools are blocked when secret is configured but not provided."""
        with patch.dict(os.environ, {"NANOIDP_MCP_ADMIN_SECRET": "mysecret"}):
            allowed, error = _check_admin_secret("create_user", {})
            assert allowed is False
            assert "NANOIDP_MCP_ADMIN_SECRET" in error
            assert "create_user" in error

    def test_mutating_tool_allowed_with_correct_secret(self):
        """Test that mutating tools are allowed with correct secret."""
        with patch.dict(os.environ, {"NANOIDP_MCP_ADMIN_SECRET": "mysecret"}):
            arguments = {"admin_secret": "mysecret", "username": "test"}
            allowed, error = _check_admin_secret("create_user", arguments)
            assert allowed is True
            assert error == ""
            # Secret should be removed from arguments
            assert "admin_secret" not in arguments

    def test_mutating_tool_blocked_with_wrong_secret(self):
        """Test that mutating tools are blocked with wrong secret."""
        with patch.dict(os.environ, {"NANOIDP_MCP_ADMIN_SECRET": "mysecret"}):
            arguments = {"admin_secret": "wrongsecret"}
            allowed, error = _check_admin_secret("create_user", arguments)
            assert allowed is False
            assert "Invalid admin_secret" in error

    def test_secret_removed_from_arguments(self):
        """Test that admin_secret is removed from arguments after check."""
        with patch.dict(os.environ, {"NANOIDP_MCP_ADMIN_SECRET": "mysecret"}):
            arguments = {"admin_secret": "mysecret", "username": "test", "password": "pass"}
            _check_admin_secret("create_user", arguments)
            assert "admin_secret" not in arguments
            assert "username" in arguments
            assert "password" in arguments

    @pytest.mark.parametrize("tool_name", list(MUTATING_TOOLS))
    def test_all_mutating_tools_require_secret(self, tool_name):
        """Test that all mutating tools require secret when configured."""
        with patch.dict(os.environ, {"NANOIDP_MCP_ADMIN_SECRET": "secret123"}):
            allowed, error = _check_admin_secret(tool_name, {})
            assert allowed is False
            assert tool_name in error


class TestMCPAuditLogging:
    """Tests for MCP audit logging."""

    def test_log_mcp_tool_success(self):
        """Test logging successful MCP tool call."""
        with patch("nanoidp.mcp_server.get_audit_log") as mock_get_audit:
            mock_audit = MagicMock()
            mock_get_audit.return_value = mock_audit

            _log_mcp_tool("list_users", success=True, details={"tool": "list_users"})

            mock_audit.log.assert_called_once()
            call_kwargs = mock_audit.log.call_args[1]
            assert call_kwargs["event_type"] == "mcp_tool"
            assert call_kwargs["method"] == "list_users"
            assert call_kwargs["status"] == "success"

    def test_log_mcp_tool_error(self):
        """Test logging failed MCP tool call."""
        with patch("nanoidp.mcp_server.get_audit_log") as mock_get_audit:
            mock_audit = MagicMock()
            mock_get_audit.return_value = mock_audit

            _log_mcp_tool("create_user", success=False, details={"error": "access denied"})

            mock_audit.log.assert_called_once()
            call_kwargs = mock_audit.log.call_args[1]
            assert call_kwargs["status"] == "error"

    def test_log_mcp_tool_handles_exception(self):
        """Test that logging handles exceptions gracefully."""
        with patch("nanoidp.mcp_server.get_audit_log") as mock_get_audit:
            mock_get_audit.side_effect = Exception("Audit service unavailable")

            # Should not raise exception
            _log_mcp_tool("list_users", success=True)


class TestMCPSecurityIntegration:
    """Integration tests for MCP security."""

    @pytest.fixture
    def mock_config(self):
        """Mock the config for MCP tests."""
        with patch("nanoidp.mcp_server._ensure_config") as mock:
            config = MagicMock()
            config.users = {}
            config.settings.clients = []
            config.settings.issuer = "http://localhost:8000"
            config.settings.audience = "test"
            config.settings.token_expiry_minutes = 60
            config.settings.keys_dir = "./keys"
            mock.return_value = config
            yield config

    @pytest.mark.asyncio
    async def test_call_tool_blocks_mutating_without_secret(self, mock_config):
        """Test that call_tool blocks mutating operations without secret."""
        from nanoidp.mcp_server import call_tool

        with patch.dict(os.environ, {"NANOIDP_MCP_ADMIN_SECRET": "secret123"}):
            with patch("nanoidp.mcp_server._log_mcp_tool"):
                result = await call_tool("create_user", {"username": "test", "password": "pass"})

                assert len(result) == 1
                content = json.loads(result[0].text)
                assert "error" in content
                assert content["code"] == "MCP_ADMIN_SECRET_REQUIRED"

    @pytest.mark.asyncio
    async def test_call_tool_allows_read_only_with_secret_configured(self, mock_config):
        """Test that read-only tools work even with secret configured."""
        from nanoidp.mcp_server import call_tool

        with patch.dict(os.environ, {"NANOIDP_MCP_ADMIN_SECRET": "secret123"}):
            with patch("nanoidp.mcp_server._log_mcp_tool"):
                result = await call_tool("list_users", {})

                assert len(result) == 1
                content = json.loads(result[0].text)
                # Should not be an error
                assert "code" not in content or content.get("code") != "MCP_ADMIN_SECRET_REQUIRED"

    @pytest.mark.asyncio
    async def test_call_tool_logs_all_calls(self, mock_config):
        """Test that all tool calls are logged."""
        from nanoidp.mcp_server import call_tool

        with patch("nanoidp.mcp_server._log_mcp_tool") as mock_log:
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("NANOIDP_MCP_ADMIN_SECRET", None)

                await call_tool("list_users", {})

                mock_log.assert_called()


class TestMCPReadonlyMode:
    """Tests for MCP readonly mode."""

    def test_check_readonly_mode_disabled_allows_all(self):
        """Test that readonly mode disabled allows all tools."""
        from nanoidp.mcp_server import _check_readonly_mode
        import nanoidp.mcp_server as mcp

        # Ensure readonly mode is off
        original_value = mcp._readonly_mode
        mcp._readonly_mode = False

        try:
            allowed, error = _check_readonly_mode("create_user")
            assert allowed is True
            assert error == ""

            allowed, error = _check_readonly_mode("list_users")
            assert allowed is True
        finally:
            mcp._readonly_mode = original_value

    def test_check_readonly_mode_blocks_mutating_tools(self):
        """Test that readonly mode blocks mutating tools."""
        from nanoidp.mcp_server import _check_readonly_mode
        import nanoidp.mcp_server as mcp

        original_value = mcp._readonly_mode
        mcp._readonly_mode = True

        try:
            allowed, error = _check_readonly_mode("create_user")
            assert allowed is False
            assert "readonly mode" in error.lower()
            assert "create_user" in error
        finally:
            mcp._readonly_mode = original_value

    def test_check_readonly_mode_allows_read_only_tools(self):
        """Test that readonly mode allows read-only tools."""
        from nanoidp.mcp_server import _check_readonly_mode
        import nanoidp.mcp_server as mcp

        original_value = mcp._readonly_mode
        mcp._readonly_mode = True

        try:
            allowed, error = _check_readonly_mode("list_users")
            assert allowed is True
            assert error == ""

            allowed, error = _check_readonly_mode("get_user")
            assert allowed is True

            allowed, error = _check_readonly_mode("decode_token")
            assert allowed is True
        finally:
            mcp._readonly_mode = original_value

    @pytest.mark.parametrize("tool_name", list(MUTATING_TOOLS))
    def test_all_mutating_tools_blocked_in_readonly(self, tool_name):
        """Test that all mutating tools are blocked in readonly mode."""
        from nanoidp.mcp_server import _check_readonly_mode
        import nanoidp.mcp_server as mcp

        original_value = mcp._readonly_mode
        mcp._readonly_mode = True

        try:
            allowed, error = _check_readonly_mode(tool_name)
            assert allowed is False
            assert tool_name in error
        finally:
            mcp._readonly_mode = original_value


class TestMCPSecurityDocumentation:
    """Tests to verify security documentation is accurate."""

    def test_mutating_tools_count(self):
        """Test that we have the expected number of mutating tools."""
        # From README: create_user, update_user, delete_user,
        #              create_client, update_client, delete_client,
        #              generate_token, update_settings, save_config
        expected_count = 9
        assert len(MUTATING_TOOLS) == expected_count

    def test_mcp_server_has_security_docstring(self):
        """Test that mcp_server module has security documentation."""
        import nanoidp.mcp_server as mcp
        assert "Security" in mcp.__doc__ or "security" in mcp.__doc__.lower()
        assert "NANOIDP_MCP_ADMIN_SECRET" in mcp.__doc__

    def test_mcp_server_docstring_mentions_readonly(self):
        """Test that mcp_server module mentions readonly mode."""
        import nanoidp.mcp_server as mcp
        assert "readonly" in mcp.__doc__.lower() or "NANOIDP_MCP_READONLY" in mcp.__doc__
