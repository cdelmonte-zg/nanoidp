# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CI now type-checks `src/` with **mypy** (#55), with a documented
  gradual-adoption baseline in `pyproject.toml` (`check_untyped_defs`,
  `no_implicit_optional`, missing-stub imports ignored). All 40 baseline
  errors were fixed: implicit-`Optional` parameter defaults, heterogeneous
  dicts annotated `Dict[str, Any]`, `check_client` accepts `Optional`
  credentials and fails closed, RSA key narrowing in cert generation,
  signxml certificate passed as PEM string, and `_get_c14n_algorithm`
  raises instead of returning `None` when signxml is missing. The baseline
  also surfaced the broken `nanoidp-mcp` entrypoint fixed in #57.

### Fixed
- Review follow-ups of the 2026-06-11 merge block (#56):
  - **Refresh tokens are bound to their client**: the issuing `client_id` is
    persisted in the refresh token claims and the refresh grant rejects any
    other client (RFC 9700 §4.14) — which also guarantees the refreshed ID
    Token keeps the original `aud` (OIDC Core §12.2). Tokens minted before
    the claim existed keep working.
  - **Rotation is atomic and revokes families on reuse**: the revocation
    check and the claim of the consumed token now happen in one critical
    section, so two concurrent refreshes of the same token can no longer
    both succeed. Each grant starts a refresh-token family (`rt_family`
    claim, stable across rotations); reusing an already-consumed token
    revokes the whole family, including the live descendant (RFC 9700
    §4.14.2).
  - **PKCE `plain` can no longer slip through stricter-dev by omitting the
    method**: per RFC 7636 §4.3 an absent `code_challenge_method` defaults
    to `plain`; the method is now normalized before validation, and unknown
    methods are rejected at the authorization endpoint (§4.4.1).
  - **`require_pkce` is persisted**: it is now read from and written to
    `settings.yaml` (oauth section), so `update_settings` → `save_config` →
    `reload_config` no longer silently reverts it.
  - **The token response reports the scope actually granted** (RFC 6749
    §5.1) instead of a hardcoded `"openid"`; when no scope was involved the
    parameter is omitted, and a narrowed refresh reports the narrowed scope.
- The `nanoidp-mcp` stdio entrypoint crashed at startup ("a coroutine was
  expected"): `stdio_server()` is an async context manager yielding the
  message streams, not a coroutine. Found by the mypy baseline being
  prepared for #55; verified with a JSON-RPC initialize handshake.
- The token endpoint validates `exp` and `extra` before the grant dispatch:
  with rotation enabled, a malformed value can no longer consume the refresh
  token without delivering its replacement (the last tradeoff noted in the
  #56 review), and a non-numeric `exp` now returns a proper 400 instead of
  an unhandled `ValueError` (500).

### Added
- Optional **refresh token rotation** (#46): with `oauth.refresh_token_rotation: true`
  (default off), each refresh invalidates the consumed refresh token, so its
  reuse fails with 401 — lets clients test rotation and reuse-detection
  handling (OAuth 2.0 Security BCP §4.14.2). Revocation happens only after the
  replacement is issued, and explicitly revoked refresh tokens are now also
  rejected by the refresh grant.
- **PKCE enforcement** (#47): new `require_pkce` setting (enabled by the
  `stricter-dev` profile) rejects `/authorize` requests without a
  `code_challenge`; `stricter-dev` also rejects `code_challenge_method=plain`
  and discovery only advertises `S256` there. Default profile unchanged.
- **MCP audit & key tools** (#48): `get_audit_log`, `get_audit_stats`,
  `clear_audit_log`, `get_keys_info` and `rotate_keys` mirror the HTTP API,
  so agent workflows can inspect what the IdP recorded and exercise JWKS
  refresh handling. `clear_audit_log`/`rotate_keys` count as mutating tools
  (admin secret / readonly rules apply). MCP `get_settings`/`update_settings`
  now expose `refresh_token_rotation` and `require_pkce`.

### Changed
- CI now runs `ruff check .` before the tests (#45), and the codebase is
  lint-clean: 153 findings fixed (#49) — deprecated `datetime.utcnow()`
  replaced (removes 80 DeprecationWarnings), unused imports/variables
  dropped, imports sorted and moved to module level, `Optional[...]` type
  hints in the crypto service, `verify_jwt` accepts an array audience,
  exceptions re-raised with `from e`.
- ID Tokens now carry `auth_time` and `at_hash` (#42). `auth_time` reflects
  when the end-user actually authenticated: the login page for the
  authorization code flow, the `/device` verification for the device flow,
  the request itself for the password grant — and it is preserved unchanged
  across refreshes (OIDC Core §12.2), carried in the refresh token claims
  like the scope (#39). `at_hash` binds the ID Token to the access token
  issued alongside it (left half of SHA-256, base64url — §3.1.3.6).
  Discovery `claims_supported` now also advertises `auth_time`, `nonce` and
  `at_hash`.

### Fixed
- Thread-safety hardening for shared in-memory state (#43): the
  authorization code store now performs its check-then-mark sequence under a
  lock (one-time use can no longer be defeated by concurrent redemptions),
  device codes are claimed/transitioned atomically and pruned when expired,
  and the lazily-created service singletons (config, token, crypto, audit,
  auth codes) use double-checked locking so concurrent first access creates
  exactly one instance.
- The MCP `get_oidc_discovery` tool now returns the exact same document as the
  HTTP `/.well-known/openid-configuration` endpoint (#40). Both build it via a
  new shared helper (`services.discovery.build_discovery_document`), so the
  MCP tool now advertises `claims_supported` (including `azp`),
  `response_types_supported`, `id_token_signing_alg_values_supported`,
  `code_challenge_methods_supported` and the endpoint auth methods — and the
  two documents can no longer drift apart.
- Discovery no longer advertises the `token` response type (#41): the implicit
  flow was never implemented (`/authorize` only accepts `response_type=code`)
  and is deprecated by the OAuth 2.0 Security BCP, so advertising it misled
  clients. `response_types_supported` is now `["code"]`.

### Documentation
- The MCP tools table in the README now lists all 19 tools (#44): it was
  missing `create_client`, `update_client`, `delete_client`, `update_user`,
  `update_settings` and `save_config`. (`docs/MCP_WORKFLOW.md` was already
  complete.)

### Added
- The **refresh_token** grant now re-issues an ID Token when the original grant
  included the `openid` scope (OIDC Core §12.2, #39). The granted scope is
  persisted in the refresh token claims and recovered on refresh; a `scope`
  form parameter may narrow, but never broaden, the original grant (RFC 6749
  §6 — broadening is rejected with `400`). The refreshed ID Token carries no
  `nonce` (it binds the original authentication request). Refresh tokens minted
  before this change have no persisted scope and keep the old behavior.
- The MCP `generate_token` tool accepts an optional `scope` argument and
  returns an `id_token` when `openid` is included, matching the HTTP token
  endpoint.

## [2.1.0] - 2026-05-26

### Added
- ID Tokens are now issued for the **password** and **device** (RFC 8628) grants
  when `openid` scope is requested, not just `authorization_code` (#36). These
  grants authenticate an end-user, so an ID Token is meaningful; `client_credentials`
  still never emits one (no end-user).

### Fixed
- Friendlier loading of client `additional_audiences` from `settings.yaml` (#35):
  a scalar value (`additional_audiences: api://x`) is coerced to a one-element list,
  and an unsupported shape (e.g. a non-string item) now fails with a clear,
  client-scoped error instead of an opaque Pydantic `ValidationError` at startup.
- Minor hardening/polish from the #32 review (#37): `OAuthClient` now validates on
  direct attribute assignment (`validate_assignment`), discovery advertises `azp` in
  `claims_supported`, and the MCP `_normalize_audiences` rejects falsy non-list inputs
  instead of silently returning an empty list.

### Security
- Harden the ID Token vs access-token boundary (#34). The resource audience
  (`oauth.audience`) is now filtered out of the ID Token `aud` even if a client
  lists it in `additional_audiences`, and every token carries a `token_use`
  marker (`access` / `id` / `refresh`). `/userinfo` rejects tokens marked as ID or
  refresh tokens and `/introspect` reports ID Tokens as inactive, so an ID Token can
  no longer be spent as an access token. (Refresh tokens stay introspectable per
  RFC 7662.)

## [2.0.0] - 2026-05-25

### Changed
- **ID Token `aud`** now contains the requesting client's `client_id`, as required by
  OpenID Connect Core 1.0 §2 (was previously the static `oauth.audience`). This makes
  it possible to test multiple clients and brings nanoidp in line with the OIDC spec.
  - **Breaking:** relying parties that validated the ID Token `aud` against the old
    static `oauth.audience` value must now expect their own `client_id`.
  - The **access token** `aud` is unchanged and still reflects `oauth.audience`
    (the resource audience, per RFC 9068 §2.2).

### Added
- `additional_audiences` per-client setting: extra audiences appended to the ID Token
  `aud`. If this produces more than one distinct audience value, `aud` is emitted as an
  array and nanoidp also emits `azp` equal to the `client_id`, so clients can test
  authorized-party handling.

## [1.4.0] - 2026-04-28

### Added
- Environment variable substitution in `settings.yaml` using `${NAME}` / `${NAME:default}` syntax
- `PORT` env var honoured in the Docker image via shell expansion in `CMD`

## [1.3.3] - 2026-04-22
  
### Fixed
- Return `id_token` in /token response for Authorization Code Flow when `openid` scope is requested, as required by OIDC Core spec (Section 3.1.3.3)
- Include `nonce` claim in `id_token` when provided by the client

### Changed
- Use `pyproject.toml` as single source of truth for version number
- Remove outdated version label from Dockerfile

## [1.3.2] - 2026-03-27

### Fixed
- Token endpoint now rejects requests when `client_id` cannot be determined from either the request body or the `Authorization` header
- Token endpoint now rejects requests where `client_id` in the body conflicts with the authenticated client in the `Authorization` header

### Added
- Tests for client_id mismatch and missing client_id edge cases

## [1.3.1] - 2026-03-26

### Fixed
- Allow authorization code flow without `Authorization` header for PKCE public clients (RFC 6749 §2.1)
  - Libraries like authlib send `client_id` in the request body instead of the header when no client secret exists
  - Auth header validation is now only enforced for grant types other than `authorization_code`

### Added
- Test for PKCE plain flow without auth header (`test_pkce_plain_flow_no_auth_header`)

## [1.3.0] - 2026-03-25

### Added
- GitHub Actions workflow to build and publish Docker images to GitHub Container Registry (GHCR)
  - Triggered on version tags (`v*`), builds multi-platform images (`linux/amd64`, `linux/arm64`)
  - `latest` tag published only for non-prerelease versions
- Docker usage instructions in README (`docker pull` and `docker run` examples)

### Changed
- Dockerfile healthcheck switched from Python `urllib` to `curl` for Podman compatibility and reduced overhead
- Updated `actions/checkout` from v4 to v6 in publish workflow

## [1.2.3] - 2026-03-03

### Fixed
- Dockerfile and docker-compose.yml: replaced `curl` with Python's `urllib` for healthcheck — avoids adding `curl` as a system dependency in the image

### Docs
- Added mascotte/logo images to the project

## [1.2.2] - 2026-01-19

### Added
- New `strict_saml_binding` setting to enforce SAML 2.0 binding compliance
  - When `false` (default): lenient mode accepts GET with uncompressed data (useful for debugging)
  - When `true`: strict mode rejects non-compliant requests per SAML spec
- Setting exposed in UI (Settings page), REST API (`/api/config`), and MCP server
- Exclusive C14N (`exc_c14n`) is now the default XML canonicalization algorithm
  - Standard for SAML 2.0 signatures, handles namespace isolation correctly
  - Available algorithms: `exc_c14n` (Exclusive C14N 1.0, default), `c14n` (C14N 1.0), `c14n11` (C14N 1.1)
- UI select dropdown for C14N algorithm in Settings page
- `strict_saml_binding` and `verbose_logging` now persist correctly on save/reload
- Comprehensive E2E test coverage for all SAML flows in `test_agent.py`:
  - `test_saml_metadata_bindings` - verifies both HTTP-POST and HTTP-Redirect advertised
  - `test_saml_sso_post_binding` - SP-initiated SSO with HTTP-POST (InResponseTo verification)
  - `test_saml_sso_redirect_binding` - SP-initiated SSO with HTTP-Redirect (InResponseTo verification)
  - `test_saml_idp_initiated_not_supported` - documents IdP-initiated SSO is not supported
  - `test_saml_strict_binding_mode` - tests strict/lenient binding behavior
  - `test_saml_attribute_query_verification` - verifies actual attributes returned
- Unit tests for inline login flow (`test_inline_login_flow_preserves_post/redirect_binding`)
- Unit test for strict mode + inline login (`test_strict_mode_inline_login_preserves_redirect_binding`)
- Unit test for Exclusive C14N configuration (`test_c14n_algorithm_configurable_to_exclusive`)

### Fixed
- SAML SSO now correctly handles both HTTP-POST and HTTP-Redirect bindings
- Parser always tries DEFLATE decompression first, falls back to raw XML (handles all edge cases)
- Strict mode now works with inline login by passing original HTTP verb via hidden field
  - Fixes: GET compressed → login form → POST would fail in strict mode
  - Stateless: no server-side session needed, works in CI/CD pipelines
- Explicit `|e` escape filter in login template hidden fields (XSS defense-in-depth)
- Normalized `original_verb` handling (uppercase, validated to GET/POST)
- Quick-fill username buttons use `tojson` filter to handle special characters safely

## [1.2.1] - 2026-01-16

### Fixed
- SAML SSO now correctly handles HTTP-POST binding (uncompressed SAMLRequest)
- Previously, `_parse_saml_request` unconditionally attempted DEFLATE decompression, causing parsing to fail for POST requests
- Now uses HTTP method to determine binding type: GET = HTTP-Redirect (compressed), POST = HTTP-POST (uncompressed)

### Changed
- E2E test agent now verifies actual SAML parsing (InResponseTo matching) instead of just endpoint availability
- Added separate tests for HTTP-POST and HTTP-Redirect bindings in `test_agent.py`

### Changed (Architecture)
- **Inline login for SAML SSO**: `/saml/sso` now shows login form directly instead of redirecting to `/login`
  - This preserves SAML binding context naturally (no redirect = no method change)
  - Follows the pattern used by Keycloak and other IdPs
  - Removes the complex edge cases caused by redirect-based login
- `/login` endpoint simplified - now only used for direct web UI access, not SAML flows
- Login form now posts to current URL (no hardcoded action) - works for both `/login` and `/saml/sso`

### Changed
- SAML metadata now advertises both HTTP-POST and HTTP-Redirect bindings for SingleSignOnService
- Audit stats now track SAML SSO and Attribute Query separately (`saml_sso_requests`, `saml_attribute_queries`)
- Dashboard shows combined SAML total with SSO/AttrQuery breakdown
- E2E test agent expanded to 35 tests (was 28), now covering all SAML flows with parsing verification

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
- Changed default XML canonicalization to C14N 1.0 for maximum compatibility
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

[1.4.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.3...v1.4.0
[1.3.3]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.3...v1.3.0
[1.2.3]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/cdelmonte-zg/nanoidp/releases/tag/v1.0.0
