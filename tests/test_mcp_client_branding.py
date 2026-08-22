"""Tests for MCP create_client/update_client exposing branding fields (#150)."""

import pytest


def _config(tmp_path):
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


class TestMCPClientBrandingFields:
    """create_client / update_client expose branding fields (issue #150)."""

    @pytest.mark.asyncio
    async def test_create_client_with_branding_fields(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = _config(tmp_path)

        result = await _execute_tool(
            "create_client",
            {
                "client_id": "branded",
                "client_secret": "s",
                "background_color": "#1a1a2e",
                "header_color": "#0d6efd",
                "footer_color": "#ffffff",
                "show_client_id": False,
                "show_description": True,
            },
            config,
        )

        assert result["success"] is True
        assert result["client"]["background_color"] == "#1a1a2e"
        assert result["client"]["header_color"] == "#0d6efd"
        assert result["client"]["footer_color"] == "#ffffff"
        assert result["client"]["show_client_id"] is False
        assert result["client"]["show_description"] is True

        client = config.get_client("branded")
        assert client.background_color == "#1a1a2e"
        assert client.show_client_id is False

    @pytest.mark.asyncio
    async def test_create_client_defaults_branding_to_none_and_defaults(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = _config(tmp_path)

        result = await _execute_tool(
            "create_client", {"client_id": "plain", "client_secret": "s"}, config
        )

        assert result["success"] is True
        assert result["client"]["background_color"] is None
        assert result["client"]["header_color"] is None
        assert result["client"]["footer_color"] is None
        assert result["client"]["show_client_id"] is True
        assert result["client"]["show_description"] is False

    @pytest.mark.asyncio
    async def test_create_client_rejects_invalid_hex_color(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = _config(tmp_path)

        with pytest.raises(ValueError):
            await _execute_tool(
                "create_client",
                {"client_id": "bad", "client_secret": "s", "background_color": "not-a-color"},
                config,
            )

        assert config.get_client("bad") is None

    @pytest.mark.asyncio
    async def test_update_client_sets_branding_fields(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = _config(tmp_path)
        await _execute_tool("create_client", {"client_id": "c", "client_secret": "s"}, config)

        result = await _execute_tool(
            "update_client",
            {
                "client_id": "c",
                "background_color": "#123456",
                "show_description": True,
            },
            config,
        )

        assert result["success"] is True
        client = config.get_client("c")
        assert client.background_color == "#123456"
        assert client.show_description is True

    @pytest.mark.asyncio
    async def test_update_client_clears_color_with_empty_string(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = _config(tmp_path)
        await _execute_tool(
            "create_client",
            {"client_id": "c", "client_secret": "s", "background_color": "#123456"},
            config,
        )

        result = await _execute_tool(
            "update_client", {"client_id": "c", "background_color": ""}, config
        )

        assert result["success"] is True
        assert config.get_client("c").background_color is None

    @pytest.mark.asyncio
    async def test_update_client_invalid_color_does_not_partially_mutate(self, tmp_path):
        """A bad color must not leave client_secret/description/other colors changed (#37/#150)."""
        from nanoidp.mcp_server import _execute_tool
        config = _config(tmp_path)
        await _execute_tool(
            "create_client",
            {
                "client_id": "c",
                "client_secret": "orig",
                "description": "orig-desc",
                "header_color": "#111111",
            },
            config,
        )

        with pytest.raises(ValueError):
            await _execute_tool(
                "update_client",
                {
                    "client_id": "c",
                    "client_secret": "newsecret",
                    "description": "newdesc",
                    "header_color": "#222222",
                    "background_color": "not-a-color",  # invalid -> must raise
                },
                config,
            )

        client = config.get_client("c")
        assert client.client_secret == "orig"
        assert client.description == "orig-desc"
        assert client.header_color == "#111111"
        assert client.background_color is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", ["create_client", "update_client"])
    async def test_schema_exposes_branding_fields(self, tool_name, mcp_list_tools):
        tools = await mcp_list_tools()
        tool = next(t for t in tools if t.name == tool_name)
        props = tool.input_schema["properties"]
        for field in (
            "background_color",
            "header_color",
            "footer_color",
        ):
            assert props[field]["type"] == "string"
        for field in ("show_client_id", "show_description"):
            assert props[field]["type"] == "boolean"

    @pytest.mark.asyncio
    async def test_get_client_reports_branding_fields(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool
        config = _config(tmp_path)
        await _execute_tool(
            "create_client",
            {"client_id": "c", "client_secret": "s", "footer_color": "#abcdef"},
            config,
        )

        result = await _execute_tool("get_client", {"client_id": "c"}, config)

        assert result["found"] is True
        assert result["client"]["footer_color"] == "#abcdef"
