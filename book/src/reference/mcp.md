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
| `generate_token` | Generate OAuth2 tokens for a user (pass `scope` with `openid` to also get an ID Token; `id_token_claims`/`userinfo_claims` mirror the OIDC `claims` request parameter; `resource` binds the access token `aud` to an RFC 8707 resource, #187; `client_id` (must name a real client) binds the token and issues a refresh token spendable by it - omit for an unbound access token with no refresh token, #73) |
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

## Tool arguments and the domain models

An argument that carries the value of a configuration field takes its shape
from that field: type, enum, bounds, length, pattern and item type come from
the model the server validates against. `username` and `client_id` carry
`minLength`, `token_expiry_minutes` its range, and `token_endpoint_auth_method`,
`layout`, `login_mode` and `saml_c14n_algorithm` their closed sets.

A field's shape is not the whole of what the server accepts: a rule that
reads more than one field, or a format a JSON Schema keyword cannot state,
stays with the model and answers from the handler - `create_user` still
rejects `email: "nope"`, and a confidential client without a secret is still
refused after dispatch.

The tool keeps what is its own: the description of the argument, what the
operation requires (`update_user` patches a user, so only `username` is
required) and a wider vocabulary where it has one - an empty
`client_secret`, `background_color`, `header_color` or `footer_color` means
"none" or "clear it", and an empty `get_audit_log` `username` means "no
filter", so the handler answers those rather than the schema. An argument
that is not a field's value at all keeps its own shape: `verify_token`'s
`audience` is the audience the caller wants a token tested against, not the
IdP's configured one.

One consequence for a client: an argument the schema can now reject comes
back as a dispatch refusal, `{"error", "code": "MCP_INVALID_ARGUMENTS",
"tool"}` with `isError`, where it used to reach the tool. What the tool
answered varied - `delete_user` reported `{"success": false}`, `get_user`
reported `{"found": false}`, `create_user` returned the raw validation text,
and `update_settings` applied an out-of-range `token_expiry_minutes` and
reported success, because it writes its arguments onto a model without
`validate_assignment`. The two layers are the ones CONTRIBUTING describes
under "Error surfaces"; only the boundary between them moved.

## The MCP server and a running nanoidp server

`nanoidp-mcp` (or `python -m nanoidp.mcp_server`) is its own process. It
loads its own copy of the configuration from `NANOIDP_CONFIG_DIR` and does
not talk to a nanoidp server started separately on the same directory. What
the tools change, and who sees it:

- `create_*`, `update_*`, `delete_*` and `update_settings` change the MCP
  server's in-memory copy only. The tools answering from that copy see the
  change immediately: `list_users`, `get_user`, and `generate_token` for a
  user created a moment ago. Tokens are signed with the keys in `keys_dir`,
  so a resource server that validates against the running server's JWKS
  accepts them.
- A running nanoidp server does not see the change. A user created through
  MCP cannot log in there, and the password grant answers `invalid_grant`,
  until `save_config` writes the YAML files **and** that server reloads
  them (`POST /api/config/reload`, or a restart). The server does not watch
  the files. Once saved, the change is declared configuration like any
  other entry.
- `reload_config` rebuilds the MCP server's copy from the files, dropping
  every change not saved yet. `save_config` writes the whole copy: every
  pending user, client and setting at once, not only the last change.
- `get_audit_log`, `get_audit_stats` and `clear_audit_log` act on the MCP
  server's own audit log. The events of a running nanoidp server are in
  that server's `/api/audit`.

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
