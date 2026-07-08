<p align="center">
  <img src="docs/images/Gnome%20guardian%20of%20digital%20identity.png" alt="NanoIDP" width="200">
</p>

<h1 align="center">NanoIDP</h1>

<p align="center">
  <a href="https://github.com/cdelmonte-zg/nanoidp/actions/workflows/tests.yml"><img src="https://github.com/cdelmonte-zg/nanoidp/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
</p>

<p align="center">
  A lightweight, configurable Identity Provider for development and testing.<br>
  Supports OAuth2/OIDC and SAML 2.0 protocols with a full-featured web UI for configuration.
</p>

<p align="center">
  📖 <a href="https://cdelmonte-zg.github.io/nanoidp/"><b>Documentation</b></a>
</p>

> Design principles, non-goals and medium-term direction live in [VISION.md](VISION.md).

## Features

- **OAuth2 / OIDC** - OAuth2/OIDC support for development and integration testing: Authorization Code, Password, Client Credentials, Refresh Token, and Device Authorization grants
- **PKCE Support** - Proof Key for Code Exchange (RFC 7636) with S256 and plain methods
- **Security Profiles** - `stricter-dev` (runtime hardening) and `oauth21` (draft OAuth 2.1 protocol strictness: PKCE-only S256, rotation, no password grant, registered redirect URIs)
- **Token Management** - Introspection (RFC 7662) and Revocation (RFC 7009) endpoints
- **OIDC Logout** - End Session endpoint for RP-initiated logout
- **Device Flow** - Device Authorization Grant (RFC 8628) for CLI/IoT applications
- **SAML 2.0** - SSO and AttributeQuery endpoints with configurable signed assertions and opt-in verification of signed AuthnRequests
- **MCP Server** - Model Context Protocol integration for Claude Code
- **Web UI** - Full configuration interface for users, clients, settings, and more
- **YAML Configuration** - File-based configuration, no database required
- **Attribute-based Access Control** - Flexible authority prefixes and claims mapping
- **Audit Logging** - Track all authentication events
- **Docker Support** - Ready to deploy with Docker/Docker Compose

## Quick Start

```bash
pip install nanoidp

python -m nanoidp init    # create ./config (users, settings, keys)
python -m nanoidp         # serve on http://localhost:8000
```

Get a first token:

```bash
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=password&username=admin&password=admin&scope=openid'
```

The admin UI runs at `http://localhost:8000`. Prefer Docker?

```bash
docker run --rm -p 8000:8000 \
  -v $(pwd)/config:/app/config \
  ghcr.io/cdelmonte-zg/nanoidp:latest
```

Full walkthrough (wizard, custom config paths, docker-compose):
[Install](https://cdelmonte-zg.github.io/nanoidp/getting-started/install.html)
and [Quickstart](https://cdelmonte-zg.github.io/nanoidp/getting-started/quickstart.html).

## Documentation

The full documentation lives at
**<https://cdelmonte-zg.github.io/nanoidp/>**:

- [Requesting tokens](https://cdelmonte-zg.github.io/nanoidp/guides/token-requests.html) - curl examples for every grant, introspection, revocation
- [MCP with Claude Code](https://cdelmonte-zg.github.io/nanoidp/guides/MCP_WORKFLOW.html) - drive NanoIDP from an agent
- [Security guide](https://cdelmonte-zg.github.io/nanoidp/guides/SECURITY.html) - profiles, key management, MCP hardening
- [Configuration](https://cdelmonte-zg.github.io/nanoidp/reference/configuration.html) - `users.yaml`, `settings.yaml`, logging
- [Endpoints](https://cdelmonte-zg.github.io/nanoidp/reference/endpoints.html) - OAuth2/OIDC, SAML, REST API
- [Tokens and claims](https://cdelmonte-zg.github.io/nanoidp/reference/tokens.html) - token structure and `aud` semantics
- [SAML options](https://cdelmonte-zg.github.io/nanoidp/reference/saml.html) - bindings, strict mode, signing, canonicalization
- [MCP server](https://cdelmonte-zg.github.io/nanoidp/reference/mcp.html) - all tools and Claude Code/Desktop setup

## Security

NanoIDP is a **development/testing tool** and must NOT be used in
production. Defaults favor convenience (plaintext passwords in config,
permissive CORS, open redirects); hardening is opt-in via the
`stricter-dev` (runtime) and `oauth21` (draft OAuth 2.1 protocol
strictness) profiles and explicit settings. The
[Security guide](https://cdelmonte-zg.github.io/nanoidp/guides/SECURITY.html)
draws the line precisely.

## Development

```bash
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the
end-to-end test agent, code quality tooling, and the release process.

## License

MIT License - see [LICENSE](LICENSE) for details.

## ❤️ Support NanoIDP

NanoIDP is maintained as an open-source project.

If it helps you test OAuth2, OpenID Connect, or SAML flows,
you can support its development here:

- 💖 GitHub Sponsors: https://github.com/sponsors/cdelmonte-zg
- ☕ Buy Me a Coffee: https://buymeacoffee.com/nanoidp
