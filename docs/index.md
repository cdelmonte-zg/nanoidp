# NanoIDP Documentation

A lightweight Identity Provider for development and testing, supporting OAuth2/OIDC and SAML 2.0.

---

## Quick Links

| Document | Description |
|----------|-------------|
| [README](../README.md) | Installation, quick start, API reference, configuration |
| [Security Guide](SECURITY.md) | Security profiles, key management, MCP security |
| [MCP Workflow](MCP_WORKFLOW.md) | Claude Code integration and IDE workflow examples |
| [Implementation Notes](IMPLEMENTATION.md) | Architecture and design decisions |
| [Changelog](CHANGES.md) | Version history and changes |

---

## Topics by Category

### Getting Started

- **Installation**: PyPI, source, Docker - see [README](../README.md#installation)
- **Quick Start**: `python -m nanoidp init` and `python -m nanoidp` - see [README](../README.md#quick-start)
- **Interactive Wizard**: `python -m nanoidp wizard` for guided setup
- **Configuration**: `users.yaml` and `settings.yaml` - see [README](../README.md#configuration)

### Authentication Protocols

#### OAuth2 / OIDC
- Authorization Code Grant (with PKCE support)
- Password Grant
- Client Credentials Grant
- Refresh Token Grant
- Device Authorization Grant (RFC 8628)
- Token Introspection (RFC 7662)
- Token Revocation (RFC 7009)
- OIDC Discovery (`/.well-known/openid-configuration`)
- JWKS (`/.well-known/jwks.json`)

#### SAML 2.0
- IdP Metadata (`/saml/metadata`)
- Single Sign-On (`/saml/sso`)
- Attribute Query (`/saml/attribute-query`)

### Security

- **Security Profiles**: `dev` vs `stricter-dev` - see [Security Guide](SECURITY.md#security-profiles)
- **Key Management**: Auto-generated, external, rotation - see [Security Guide](SECURITY.md#key-management)
- **MCP Security**: Admin secret, readonly mode - see [Security Guide](SECURITY.md#mcp-server-security)

### Integration

- **MCP Server**: Claude Code and Claude Desktop integration - see [MCP Workflow](MCP_WORKFLOW.md)
- **REST API**: User management, token generation, audit logs - see [README](../README.md#rest-api)
- **Web UI**: Admin interface at `http://localhost:8000`

### Development

- **Running Tests**: `pytest` - 419 tests covering OAuth, SAML, security edge cases
- **Contributing**: See [CONTRIBUTING.md](../CONTRIBUTING.md)

---

## API Endpoints Overview

### OAuth2 / OIDC Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OIDC Discovery |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |
| `/authorize` | GET | Authorization (login page) |
| `/token` | POST | Token endpoint |
| `/userinfo` | GET/POST | UserInfo endpoint |
| `/introspect` | POST | Token Introspection |
| `/revoke` | POST | Token Revocation |
| `/logout` | GET/POST | OIDC End Session |
| `/device_authorization` | POST | Device Authorization |
| `/device` | GET/POST | Device verification |

### SAML Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/saml/metadata` | GET | IdP Metadata XML |
| `/saml/sso` | POST | Single Sign-On |
| `/saml/attribute-query` | POST | Attribute Query |

### Management API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/users` | GET | List users |
| `/api/users/{username}` | GET | Get user details |
| `/api/users/{username}/token` | POST | Generate token |
| `/api/audit` | GET | Audit log |
| `/api/config/reload` | POST | Reload configuration |
| `/api/keys/rotate` | POST | Rotate keys |
| `/api/keys/info` | GET | Key information |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NANOIDP_CONFIG_DIR` | Configuration directory | `./config` |
| `NANOIDP_MCP_ADMIN_SECRET` | MCP admin secret | (none) |
| `NANOIDP_MCP_READONLY` | Disable MCP mutations | `false` |
| `PORT` | Server port | `8000` |
