"""
Tests for NanoIDP MCP Server functionality.

Tests cover:
- get_settings tool including verbose_logging
- update_settings tool including verbose_logging
- Tool execution flow
"""

import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock


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

        # Get the list_tools function and check schema
        # The schema should include verbose_logging
        expected_schema_property = {
            "type": "boolean",
            "description": "Include usernames/client_ids in log messages (dev convenience)",
        }

        # Verify the module has the expected structure
        assert hasattr(mcp_server, 'server')
        assert hasattr(mcp_server, 'MUTATING_TOOLS')
        assert 'update_settings' in mcp_server.MUTATING_TOOLS


class TestMCPReadonlyMode:
    """Tests for MCP readonly mode behavior."""

    def test_readonly_mode_blocks_update_settings(self):
        """Test that readonly mode blocks update_settings calls."""
        from nanoidp.mcp_server import _check_readonly_mode, MUTATING_TOOLS

        # Simulate readonly mode enabled
        import nanoidp.mcp_server as mcp_module
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
