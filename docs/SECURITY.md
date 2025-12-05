# NanoIDP Security Guide

## Overview

NanoIDP is a **development and testing tool** designed for local development environments, integration testing, and CI/CD pipelines.

**WARNING: Do NOT use NanoIDP in production environments.**

By design, NanoIDP prioritizes developer convenience over security hardening. It is intended to help developers test OAuth2/OIDC and SAML integrations without the complexity of production identity providers.

---

## Security Profiles

NanoIDP supports two security profiles to balance convenience with basic security controls:

| Profile | Description |
|---------|-------------|
| `dev` (default) | Maximum convenience for development: plaintext passwords, permissive CORS, no rate limiting |
| `stricter-dev` | Semi-hardened mode: bcrypt passwords, restricted CORS, rate limiting, debug mode blocked |

### Usage

```bash
# Run with default dev profile
python -m nanoidp

# Run with stricter-dev profile
python -m nanoidp --profile stricter-dev
```

### Feature Comparison

| Feature | `dev` | `stricter-dev` |
|---------|-------|----------------|
| Password storage | Plaintext | bcrypt hash |
| CORS | `*` (all origins) | localhost only |
| Rate limiting | None | 10 req/min on `/token` |
| Debug mode | Allowed | Blocked |

---

## Key Management

NanoIDP uses RSA keys for JWT signing. Keys can be auto-generated, imported from external files, or rotated dynamically.

### Auto-generated Keys

By default, NanoIDP generates RSA keys on first startup and stores them in the `keys/` directory:

```
config/
└── keys/
    ├── private.pem      # RSA private key (signing)
    ├── public.pem       # RSA public key (verification)
    └── kid.txt          # Key ID
```

### External Keys

You can use your own RSA keys instead of auto-generated ones:

```yaml
# settings.yaml
jwt:
  external_keys:
    private_key: /path/to/private.pem
    public_key: /path/to/public.pem
    kid: "my-custom-key-id"
```

Requirements:
- Private key: PEM format, PKCS8 encoding
- Public key: PEM format, SubjectPublicKeyInfo encoding
- Key ID (optional): If not provided, one is generated from the key fingerprint

### Key Rotation

NanoIDP supports key rotation with multiple keys in JWKS for seamless token validation during rotation periods.

#### API Endpoints

```bash
# Rotate keys (generates new key, preserves old for validation)
curl -X POST http://localhost:8000/api/keys/rotate

# Get key information
curl http://localhost:8000/api/keys/info
```

#### How It Works

1. **Rotation**: New key pair generated, old key moved to "previous" list
2. **JWKS**: Returns both active and previous keys (configurable via `max_previous_keys`, default 2)
3. **Signing**: New tokens signed with the active key
4. **Validation**: Tokens signed with previous keys remain valid until those keys are rotated out

#### Configuration

```yaml
# settings.yaml
jwt:
  max_previous_keys: 2  # Number of previous keys to keep in JWKS
```

---

## MCP Server Security

The MCP (Model Context Protocol) server provides integration with Claude Code and other MCP-compatible tools.

### Security Warning

The MCP server exposes powerful administrative tools and should ONLY be used:
- Locally on developer machines
- In isolated development environments
- **Never** exposed to network access

### Mutating Tools

The following MCP tools modify configuration and require extra caution:

| Tool | Description |
|------|-------------|
| `create_user` | Create a new user |
| `update_user` | Modify user attributes |
| `delete_user` | Remove a user |
| `create_client` | Create OAuth client |
| `update_client` | Modify client settings |
| `delete_client` | Remove OAuth client |
| `generate_token` | Generate access tokens |
| `update_settings` | Modify IdP settings |
| `save_config` | Persist configuration changes |

### Admin Secret Protection

When `NANOIDP_MCP_ADMIN_SECRET` is set, mutating operations require the secret:

```json
{
  "mcpServers": {
    "nanoidp": {
      "command": "nanoidp-mcp",
      "env": {
        "NANOIDP_CONFIG_DIR": "./config",
        "NANOIDP_MCP_ADMIN_SECRET": "your-secret-here"
      }
    }
  }
}
```

Mutating tool calls without the correct secret will be rejected.

### Readonly Mode

To completely disable mutating tools:

```bash
# Via CLI flag
nanoidp-mcp --readonly

# Via environment variable
NANOIDP_MCP_READONLY=true nanoidp-mcp
```

In Claude Code settings:

```json
{
  "mcpServers": {
    "nanoidp": {
      "command": "nanoidp-mcp",
      "args": ["--readonly"],
      "env": {
        "NANOIDP_CONFIG_DIR": "./config"
      }
    }
  }
}
```

Use readonly mode when you only need introspection (listing users, decoding tokens, viewing settings) but want to prevent accidental modifications.

### Audit Logging

All MCP tool calls are logged to the audit log, including:
- Tool name
- Parameters (secrets redacted)
- Timestamp
- Result status

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NANOIDP_CONFIG_DIR` | Configuration directory path | `./config` |
| `NANOIDP_MCP_ADMIN_SECRET` | Secret required for mutating MCP operations | (none) |
| `NANOIDP_MCP_READONLY` | Disable mutating MCP tools when set to `true` | `false` |
| `PORT` | Server port | `8000` |

---

## Best Practices

1. **Use stricter-dev profile** when sharing the instance with team members
2. **Enable readonly mode** for MCP when only introspection is needed
3. **Set MCP admin secret** if multiple developers share the same NanoIDP instance
4. **Rotate keys periodically** to test token validation with multiple keys
5. **Never expose NanoIDP to public networks** - it's designed for local/isolated use only

---

## Related Documentation

- [MCP Workflow](MCP_WORKFLOW.md) - Detailed Claude Code integration examples
- [README](../README.md) - Installation and configuration
