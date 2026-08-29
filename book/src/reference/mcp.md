# MCP server

NanoIDP includes an MCP (Model Context Protocol) server for integration
with Claude Code and other MCP-compatible tools. For a hands-on tour with
prompts, workflows, and end-to-end examples, see
[MCP with Claude Code](../guides/MCP_WORKFLOW.md). For the admin secret,
readonly mode, and the exposure warnings, see the
[Security guide](../guides/SECURITY.md#mcp-server-security).

## Available tools

| Tool | Description |
|------|-------------|
| `list_users` | List all configured users |
| `get_user` | Get details of a specific user |
| `create_user` | Create a new user |
| `create_persona_user` | Create a password-less user for persona login mode (local dev/testing convenience) |
| `update_user` | Update an existing user (password, email, roles, …) |
| `delete_user` | Delete a user |
| `generate_token` | Generate OAuth2 tokens for a user (pass `scope` with `openid` to also get an ID Token; `id_token_claims`/`userinfo_claims` mirror the OIDC `claims` request parameter; `resource` binds the access token `aud` to an RFC 8707 resource, #187) |
| `decode_token` | Decode JWT token (without verification) |
| `verify_token` | Verify JWT token signature and expiration (pass `audience` to also require the token's `aud` to match, simulating a resource server; omit it to accept a resource-bound token and read its claims, #187) |
| `list_clients` | List OAuth clients |
| `get_client` | Get client details |
| `create_client` | Create a new OAuth client |
| `update_client` | Update an existing OAuth client |
| `delete_client` | Delete an OAuth client |
| `get_settings` | Get current IdP settings |
| `update_settings` | Update IdP settings |
| `save_config` | Persist the current configuration to the YAML files, optionally guarded by `expected_users_revision` / `expected_settings_revision` (see below) |
| `reload_config` | Reload configuration from files (the response carries fresh `users_revision` / `settings_revision`) |
| `validate_config` | Lint the running config directory without starting or executing anything (no hook, no plugin): `{valid, findings}` |
| `get_oidc_discovery` | Get OIDC discovery document (same document as `/.well-known/openid-configuration`) |
| `get_jwks` | Get JSON Web Key Set |
| `get_audit_log` | Get audit log entries (filter by limit, event type, username) |
| `get_audit_stats` | Get audit statistics |
| `clear_audit_log` | Clear the audit log |
| `get_keys_info` | Get signing key info (active kid, previous keys) |
| `rotate_keys` | Rotate signing keys (old key stays valid for verification) |

## Conflict-checked saves

The declared configuration can have several writers at once: the web UI,
another agent, or a second nanoidp process (a Flask server and a
`nanoidp-mcp` companion) on the same directory. To catch a concurrent
change instead of silently overwriting it, the read tools return the
revision of the file the runtime was loaded from - `list_users` and
`get_user` carry `users_revision`; `list_clients`, `get_client` and
`get_settings` carry `settings_revision` - and `save_config` accepts them
back as `expected_users_revision` / `expected_settings_revision`. A save
whose revision no longer matches the file is refused with
`{"success": false, "kind": "conflict"}` before anything is written: call
`reload_config`, reapply the change on the fresh state, and save again
with the revisions from its response.

`save_config` always writes both files, so there are exactly two modes.
Omitting both revisions keeps the save unconditional (last write wins),
same as before. Supplying either revision makes the whole save
conflict-checked: the omitted one defaults to the revision this runtime
was loaded from, so a save guarded on `users.yaml` cannot silently
overwrite a `settings.yaml` another writer changed in the meantime, or
vice versa - there is no mode where one file is guarded and the other is
overwritten from a stale snapshot.

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
