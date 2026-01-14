# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-01-14

### Added
- Configurable `verbose_logging` setting to control sensitive data in logs
- `verbose_logging` exposed in MCP `get_settings` and `update_settings` tools
- `logging.verbose_logging` exposed in REST API `/api/config` endpoint
- MCP tests (`tests/test_mcp.py`) with 8 tests for MCP functionality
- Verbose logging test in E2E test agent

### Changed
- Replaced deprecated `defusedxml.lxml` with native lxml secure parser for XXE protection
- Added `html.escape` for XSS prevention in SAML responses
- Audit logging now respects `verbose_logging` setting (usernames/client_ids only when enabled)

### Security
- XXE (XML External Entity) protection using secure lxml parser configuration
- XSS prevention in SAML response forms
- Configurable sensitive data logging (verbose_logging defaults to true for dev convenience)

## [1.1.1] - 2026-01-14

### Added
- Configurable XML canonicalization algorithm via `saml.c14n_algorithm` setting

## [1.1.0] - 2026-01-14

### Added
- Configurable SAML response signing via `saml.sign_responses` setting
- UI toggle for SAML signing in Settings page (`/settings`)
- `sign_responses` exposed in `/api/config` endpoint
- Test agent (`examples/test_agent.py`) for comprehensive endpoint testing

### Changed
- SAML SSO and AttributeQuery endpoints now respect `sign_responses` configuration
- Changed default XML canonicalization to C14N 1.0 for pysaml2 compatibility
- Updated documentation with SAML signing configuration instructions

## [1.0.0] - 2025-12-04

### Added
- Initial release
- OAuth2/OIDC support (Authorization Code, Password, Client Credentials, Refresh Token, Device Flow)
- PKCE support (S256 and plain methods)
- Token Introspection (RFC 7662) and Revocation (RFC 7009)
- OIDC Logout / End Session endpoint
- Device Authorization Grant (RFC 8628)
- SAML 2.0 SSO and AttributeQuery endpoints with signed assertions
- MCP Server integration for Claude Code
- Web UI for configuration (users, clients, settings, keys, audit log)
- YAML-based configuration
- Attribute-based access control with configurable authority prefixes
- Audit logging
- Docker support
- Security profiles (`dev` and `stricter-dev`)
- Key rotation with JWKS support for multiple keys
- External key import support

[1.2.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/cdelmonte-zg/nanoidp/releases/tag/v1.0.0
