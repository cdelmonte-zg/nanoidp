# NanoIDP

[![Tests](https://github.com/cdelmonte-zg/nanoidp/actions/workflows/tests.yml/badge.svg)](https://github.com/cdelmonte-zg/nanoidp/actions/workflows/tests.yml)

A lightweight, configurable Identity Provider for development and testing. Supports OAuth2/OIDC and SAML 2.0 protocols with a full-featured web UI for configuration.

## Features

- **OAuth2 / OIDC** - Full OAuth2 implementation with Authorization Code, Password, Client Credentials, Refresh Token, and Device Authorization grants
- **PKCE Support** - Proof Key for Code Exchange (RFC 7636) with S256 and plain methods
- **Token Management** - Introspection (RFC 7662) and Revocation (RFC 7009) endpoints
- **OIDC Logout** - End Session endpoint for RP-initiated logout
- **Device Flow** - Device Authorization Grant (RFC 8628) for CLI/IoT applications
- **SAML 2.0** - SSO and AttributeQuery endpoints with configurable signed assertions
- **MCP Server** - Model Context Protocol integration for Claude Code
- **Web UI** - Full configuration interface for users, clients, settings, and more
- **YAML Configuration** - File-based configuration, no database required
- **Attribute-based Access Control** - Flexible authority prefixes and claims mapping
- **Audit Logging** - Track all authentication events
- **Docker Support** - Ready to deploy with Docker/Docker Compose

## Installation

### From PyPI

```bash
pip install nanoidp
```

### From Source

```bash
git clone https://github.com/cdelmonte-zg/nanoidp.git
cd nanoidp
pip install .
```

### For Development

```bash
git clone https://github.com/cdelmonte-zg/nanoidp.git
cd nanoidp
pip install -e ".[dev]"
```

## Quick Start

### Initialize Configuration (Recommended for pip install)

When installing via pip, use the `init` command to create a configuration directory:

```bash
# Create config in ./config (default)
python -m nanoidp init

# Or specify a custom path
python -m nanoidp init ./my-idp-config

# Then start with that config
python -m nanoidp --config ./my-idp-config
```

This creates:
- `users.yaml` - User definitions
- `settings.yaml` - OAuth/SAML settings
- `keys/` - Directory for RSA keys (auto-generated on startup)

### Interactive Wizard

For a guided setup:

```bash
python -m nanoidp wizard
```

The wizard guides you through:
- Server configuration (host, port, issuer)
- OAuth client setup
- Admin user creation
- Token settings

### Run the Server

```bash
# Run with default config (./config)
python -m nanoidp

# With custom config directory
python -m nanoidp --config /path/to/config

# Using environment variable
NANOIDP_CONFIG_DIR=/path/to/config python -m nanoidp

# With options
python -m nanoidp --port 8080 --debug
```

### Using Docker

```bash
docker-compose up -d
```

The server will be available at `http://localhost:8000`

## Web Interface

Access the admin UI at `http://localhost:8000`:

- **Dashboard** - Overview and quick stats
- **Users** - Create, edit, delete users
- **OAuth Clients** - Manage OAuth2 client credentials
- **Settings** - Configure IdP settings (issuer, audience, SAML)
- **Keys & Certs** - View and regenerate RSA keys
- **Claims** - Configure authority prefix mappings
- **Audit Log** - View and export authentication events
- **Token Tester** - Generate and inspect tokens

## Configuration

### Users (`config/users.yaml`)

```yaml
users:
  admin:
    password: "admin"
    email: "admin@example.org"
    identity_class: "INTERNAL"
    entitlements:
      - "ADMIN_ACCESS"
      - "USER_MANAGEMENT"
    roles:
      - "USER"
      - "ADMIN"
    tenant: "default"
    source_acl:
      - "ACL_READ"
      - "ACL_WRITE"

default_user: "admin"
```

### Settings (`config/settings.yaml`)

```yaml
server:
  host: "0.0.0.0"
  port: 8000

oauth:
  issuer: "http://localhost:8000"
  audience: "my-app"
  token_expiry_minutes: 60
  clients:
    - client_id: "demo-client"
      client_secret: "demo-secret"
      description: "Default demo client"

saml:
  entity_id: "http://localhost:8000/saml"
  sso_url: "http://localhost:8000/saml/sso"
  default_acs_url: "http://localhost:8080/login/saml2/sso/nanoidp"
  sign_responses: true  # Set to false for testing unsigned SAML flows

authority_prefixes:
  roles: "ROLE_"
  identity_class: "IDENTITY_"
  entitlements: "ENT_"

logging:
  verbose_logging: true  # Include usernames/client_ids in logs (default: true)
```

### Logging Configuration

NanoIDP logs all authentication events to both the audit log (viewable in the Web UI) and standard output.

```yaml
logging:
  level: INFO              # DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_token_requests: true # Log token endpoint requests
  log_saml_requests: true  # Log SAML endpoint requests
  verbose_logging: true    # Include usernames/client_ids in log messages
```

**Verbose Logging** (`verbose_logging: true`, default):
- Log messages include user and client identifiers for debugging
- Example: `[login] POST /token - success (user: admin) (client: demo-client)`

**Non-Verbose Logging** (`verbose_logging: false`):
- Log messages omit sensitive identifiers
- Example: `[login] POST /token - success`

Set `verbose_logging: false` if you're concerned about PII in log files, though for a dev tool this is typically not an issue.

## API Endpoints

### OAuth2 / OIDC

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /.well-known/jwks.json` | JSON Web Key Set |
| `GET /authorize` | Authorization endpoint (login page) |
| `POST /token` | Token endpoint |
| `GET/POST /userinfo` | UserInfo endpoint |
| `POST /introspect` | Token Introspection (RFC 7662) |
| `POST /revoke` | Token Revocation (RFC 7009) |
| `GET/POST /logout` | OIDC End Session / Logout |
| `POST /device_authorization` | Device Authorization (RFC 8628) |
| `GET/POST /device` | Device verification page |

### SAML

| Endpoint | Description |
|----------|-------------|
| `GET /saml/metadata` | IdP Metadata |
| `GET/POST /saml/sso` | Single Sign-On (supports both HTTP-POST and HTTP-Redirect bindings) |
| `POST /saml/attribute-query` | Attribute Query |

#### SAML Bindings

NanoIDP supports both standard SAML 2.0 bindings for the SSO endpoint:

| Binding | HTTP Method | SAMLRequest Encoding |
|---------|-------------|---------------------|
| HTTP-POST | POST | Base64 only (uncompressed) |
| HTTP-Redirect | GET | DEFLATE compressed + Base64 |

Both bindings are advertised in the SAML metadata (`/saml/metadata`).

#### Strict Binding Mode

By default, NanoIDP operates in **lenient mode** for developer convenience, accepting GET requests with uncompressed SAMLRequest data (non-compliant but useful for debugging).

To enforce strict SAML 2.0 binding compliance:

**Via configuration file (`settings.yaml`):**

```yaml
saml:
  strict_binding: true  # Reject GET with uncompressed data
```

**Via Web UI:**

1. Go to `http://localhost:8000/settings`
2. In the SAML Settings section, toggle **"Strict SAML Binding"**
3. Click **Save Settings**

| Mode | GET with uncompressed data | GET with DEFLATE | POST uncompressed |
|------|---------------------------|------------------|-------------------|
| Lenient (default) | Accepted | Accepted | Accepted |
| Strict | **Rejected (400)** | Accepted | Accepted |

#### SAML Response Signing

By default, NanoIDP signs all SAML responses with an XML digital signature. You can disable signing for testing scenarios that require unsigned SAML flows:

**Via configuration file (`settings.yaml`):**

```yaml
saml:
  sign_responses: false  # Disable SAML response signing
```

**Via Web UI:**

1. Go to `http://localhost:8000/settings`
2. In the SAML Settings section, toggle **"Sign SAML Responses"**
3. Click **Save Settings**

When `sign_responses: true` (default), responses include:
- `<ds:Signature>` element with RSA-SHA256 signature
- `<ds:X509Certificate>` with the IdP certificate

When `sign_responses: false`, responses are sent without any signature elements.

#### XML Canonicalization Algorithm

By default, NanoIDP uses **Exclusive C14N** for XML canonicalization, which is the standard for SAML signatures and compatible with most modern SAML implementations. You can configure the algorithm based on your SP requirements:

**Via configuration file (`settings.yaml`):**

```yaml
saml:
  c14n_algorithm: exc_c14n  # Default: Exclusive C14N 1.0 (standard for SAML)
  # c14n_algorithm: c14n    # C14N 1.0
  # c14n_algorithm: c14n11  # C14N 1.1
```

**Via Web UI:**

1. Go to `http://localhost:8000/settings`
2. In the SAML Settings section, select the **Canonicalization Algorithm** from the dropdown
3. Click **Save Settings**

| Value | Algorithm | Use Case |
|-------|-----------|----------|
| `exc_c14n` (default) | Exclusive C14N 1.0 | Standard for SAML, handles namespace isolation |
| `c14n` | C14N 1.0 | Legacy SAML implementations |
| `c14n11` | C14N 1.1 | Newer implementations |

**Why Exclusive C14N is the default:**

Exclusive C14N is recommended by the SAML 2.0 specification because it only includes namespaces actually used in the signed element. This is important when SPs extract the `<Assertion>` element from the `<Response>` to verify the signature independently. With standard C14N, the signature includes parent namespaces that break when the Assertion is extracted.

### REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check |
| `GET /api/users` | List users |
| `GET /api/users/{username}` | Get user details |
| `POST /api/users/{username}/token` | Generate token |
| `GET /api/audit` | Get audit log |
| `POST /api/config/reload` | Reload configuration |
| `POST /api/keys/rotate` | Rotate cryptographic keys |
| `GET /api/keys/info` | Get key information |

## Token Request Examples

### Password Grant

```bash
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=password&username=admin&password=admin'
```

### Client Credentials Grant

```bash
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=client_credentials'
```

### Refresh Token

```bash
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN'
```

### Device Authorization Flow

```bash
# 1. Request device code
curl -X POST 'http://localhost:8000/device_authorization' \
  -u 'demo-client:demo-secret' \
  -d 'scope=openid'

# Response:
# {
#   "device_code": "...",
#   "user_code": "ABCD1234",
#   "verification_uri": "http://localhost:8000/device",
#   "expires_in": 600
# }

# 2. User visits verification_uri and enters user_code

# 3. Poll for token
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=YOUR_DEVICE_CODE'
```

### Token Introspection

```bash
curl -X POST 'http://localhost:8000/introspect' \
  -u 'demo-client:demo-secret' \
  -d 'token=YOUR_ACCESS_TOKEN'
```

### Token Revocation

```bash
curl -X POST 'http://localhost:8000/revoke' \
  -u 'demo-client:demo-secret' \
  -d 'token=YOUR_ACCESS_TOKEN'
```

## JWT Token Structure

```json
{
  "iss": "http://localhost:8000",
  "sub": "admin",
  "aud": "my-app",
  "iat": 1704100000,
  "exp": 1704103600,
  "roles": ["USER", "ADMIN"],
  "tenant": "default",
  "identity_class": "INTERNAL",
  "entitlements": ["ADMIN_ACCESS", "USER_MANAGEMENT"],
  "authorities": [
    "ROLE_USER",
    "ROLE_ADMIN",
    "IDENTITY_INTERNAL",
    "ENT_ADMIN_ACCESS",
    "ENT_USER_MANAGEMENT",
    "ACL_READ",
    "ACL_WRITE"
  ]
}
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run in development mode
python -m nanoidp --debug
```

### End-to-End Test Agent

NanoIDP includes a comprehensive test agent that validates all functionality:

```bash
# Run against local server (default: http://localhost:8000)
python examples/test_agent.py

# Run against custom URL
python examples/test_agent.py --url http://localhost:9000

# Verbose output
python examples/test_agent.py --verbose

# JSON output
python examples/test_agent.py --json
```

The test agent covers:
- **Core**: Health check, OIDC discovery
- **OAuth2/OIDC**: All grant types, token introspection, revocation, logout
- **SAML 2.0**: Metadata, SSO (POST/Redirect bindings), Attribute Query, signing config
- **Key Management**: Key info, rotation, post-rotation token validation
- **REST API**: Users, config, audit log

## MCP Server (Model Context Protocol)

NanoIDP includes an MCP server for integration with Claude Code and other MCP-compatible tools.

### Available Tools

| Tool | Description |
|------|-------------|
| `list_users` | List all configured users |
| `get_user` | Get details of a specific user |
| `create_user` | Create a new user |
| `delete_user` | Delete a user |
| `generate_token` | Generate OAuth2 access token for a user |
| `decode_token` | Decode JWT token (without verification) |
| `verify_token` | Verify JWT token signature and expiration |
| `list_clients` | List OAuth clients |
| `get_client` | Get client details |
| `get_settings` | Get current IdP settings |
| `reload_config` | Reload configuration from files |
| `get_oidc_discovery` | Get OIDC discovery document |
| `get_jwks` | Get JSON Web Key Set |

### Claude Code CLI Configuration

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

### Claude Desktop Configuration

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

### Running Standalone

```bash
# Run MCP server directly
python -m nanoidp.mcp_server
```

## Security

This is a **development/testing tool** and should NOT be used in production environments.

### Security Measures

While NanoIDP is designed for development, it still implements basic security protections:

| Protection | Description |
|------------|-------------|
| **XXE Prevention** | XML parsing uses secure lxml configuration with entity expansion disabled |
| **XSS Prevention** | User-controlled values in SAML responses are HTML-escaped |
| **JWT Signature Verification** | All tokens are verified using RS256 signatures |
| **PKCE Support** | Prevents authorization code interception attacks |

**Note:** As a dev tool, NanoIDP intentionally allows:
- Open redirects (any `post_logout_redirect_uri` accepted)
- Plaintext passwords in config files (convenience over security)
- Permissive CORS by default

These trade-offs prioritize developer convenience over production-grade security.

### Security Profiles

NanoIDP supports two security profiles:

| Profile | Description |
|---------|-------------|
| `dev` (default) | Maximum convenience for development: plaintext passwords, permissive CORS, no rate limiting |
| `stricter-dev` | Semi-hardened mode: bcrypt passwords, restricted CORS, rate limiting, debug mode blocked |

```bash
# Run with stricter-dev profile
python -m nanoidp --profile stricter-dev
```

**Feature comparison:**

| Feature | `dev` | `stricter-dev` |
|---------|-------|----------------|
| Password storage | Plaintext | bcrypt hash |
| CORS | `*` (all origins) | localhost only |
| Rate limiting | None | 10 req/min on `/token` |
| Debug mode | Allowed | Blocked |

### Key Management

#### External Keys

You can use your own RSA keys instead of auto-generated ones:

```yaml
# settings.yaml
jwt:
  external_keys:
    private_key: /path/to/private.pem
    public_key: /path/to/public.pem
    kid: "my-custom-key-id"
```

#### Key Rotation

NanoIDP supports key rotation with multiple keys in JWKS for seamless token validation during rotation:

```bash
# Rotate keys via API
curl -X POST http://localhost:8000/api/keys/rotate

# Get key information
curl http://localhost:8000/api/keys/info
```

The JWKS endpoint (`/.well-known/jwks.json`) returns both the active key and previous keys (up to `max_previous_keys`, default 2) for validation of tokens signed with older keys.

### MCP Server Security

The MCP server exposes powerful administrative tools and should ONLY be used:
- Locally on developer machines
- In isolated development environments
- Never exposed to network access

**Mutating tools** (those that modify configuration):
- `create_user`, `update_user`, `delete_user`
- `create_client`, `update_client`, `delete_client`
- `generate_token`, `update_settings`, `save_config`

#### Admin Secret Protection

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

#### Readonly Mode

To completely disable mutating tools (create, update, delete, generate):

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

All MCP tool calls are logged to the audit log.

For detailed usage examples with Claude Code, see [docs/MCP_WORKFLOW.md](docs/MCP_WORKFLOW.md).

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NANOIDP_CONFIG_DIR` | Configuration directory | `./config` |
| `NANOIDP_MCP_ADMIN_SECRET` | Secret required for mutating MCP operations | (none) |
| `NANOIDP_MCP_READONLY` | Disable mutating MCP tools when set to `true` | `false` |
| `PORT` | Server port | `8000` |

## Releasing

NanoIDP uses GitHub Actions with PyPI Trusted Publishing for automated releases.

### Release Process

```bash
# 1. Update version in pyproject.toml
# 2. Update CHANGELOG.md
# 3. Commit changes
git add -A && git commit -m "Release v1.0.1"

# 4. Create and push tag
git tag v1.0.1
git push origin main --tags
```

The workflow automatically:
1. Runs all tests
2. Builds the package
3. Publishes to TestPyPI
4. Publishes to PyPI (only for non-prerelease tags)

### Pre-release Testing

For testing releases before publishing to PyPI:

```bash
# Create a pre-release tag (only publishes to TestPyPI)
git tag v1.0.1-rc1
git push origin v1.0.1-rc1

# Install from TestPyPI to verify
pip install -i https://test.pypi.org/simple/ nanoidp==1.0.1rc1
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.


## ❤️ Support NanoIDP

NanoIDP is maintained as an open-source project.

If it helps you test OAuth2, OpenID Connect, or SAML flows,
you can support its development here:

- 💖 GitHub Sponsors: https://github.com/sponsors/cdelmonte-zg
- ☕ Buy Me a Coffee: https://buymeacoffee.com/nanoidp
