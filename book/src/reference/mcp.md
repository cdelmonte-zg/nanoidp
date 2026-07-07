# MCP server

NanoIDP includes an MCP (Model Context Protocol) server for integration
with Claude Code and other MCP-compatible tools. For a hands-on tour —
prompts, workflows, end-to-end examples — see
[MCP with Claude Code](../guides/MCP_WORKFLOW.md). For the admin secret,
readonly mode, and the exposure warnings, see the
[Security guide](../guides/SECURITY.md#mcp-server-security).

## Available tools

| Tool | Description |
|------|-------------|
| `list_users` | List all configured users |
| `get_user` | Get details of a specific user |
| `create_user` | Create a new user |
| `update_user` | Update an existing user (password, email, roles, …) |
| `delete_user` | Delete a user |
| `generate_token` | Generate OAuth2 tokens for a user (pass `scope` with `openid` to also get an ID Token) |
| `decode_token` | Decode JWT token (without verification) |
| `verify_token` | Verify JWT token signature and expiration |
| `list_clients` | List OAuth clients |
| `get_client` | Get client details |
| `create_client` | Create a new OAuth client |
| `update_client` | Update an existing OAuth client |
| `delete_client` | Delete an OAuth client |
| `get_settings` | Get current IdP settings |
| `update_settings` | Update IdP settings |
| `save_config` | Persist the current configuration to the YAML files |
| `reload_config` | Reload configuration from files |
| `get_oidc_discovery` | Get OIDC discovery document (same document as `/.well-known/openid-configuration`) |
| `get_jwks` | Get JSON Web Key Set |
| `get_audit_log` | Get audit log entries (filter by limit, event type, username) |
| `get_audit_stats` | Get audit statistics |
| `clear_audit_log` | Clear the audit log |
| `get_keys_info` | Get signing key info (active kid, previous keys) |
| `rotate_keys` | Rotate signing keys (old key stays valid for verification) |

## Claude Code configuration

Add to your project's `.claude/settings.json`:

```json
{
  "mcpServers": {
    "nanoidp": {
      "command": "python",
      "args": ["-m", "nanoidp.mcp_server"],
      "env": {
        "NANOIDP_CONFIG_DIR": "./config"
      }
    }
  }
}
```

Or if NanoIDP is installed globally:

```json
{
  "mcpServers": {
    "nanoidp": {
      "command": "nanoidp-mcp",
      "env": {
        "NANOIDP_CONFIG_DIR": "/path/to/config"
      }
    }
  }
}
```

## Claude Desktop configuration

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "nanoidp": {
      "command": "nanoidp-mcp",
      "env": {
        "NANOIDP_CONFIG_DIR": "/path/to/nanoidp/config"
      }
    }
  }
}
```

## Running standalone

```bash
# Run MCP server directly
python -m nanoidp.mcp_server
```

All MCP tool calls are logged to the audit log.
