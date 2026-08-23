# NanoIDP Security Guide

## Overview

NanoIDP is a **development and testing tool** designed for local development environments, integration testing, and CI/CD pipelines.

**WARNING: Do NOT use NanoIDP in production environments.**

By design, NanoIDP prioritizes developer convenience over security hardening. It is intended to help developers test OAuth2/OIDC and SAML integrations without the complexity of production identity providers.

---

## Network Binding

NanoIDP binds to `127.0.0.1` (loopback only) by default, so out of the box it is reachable only from the local machine.

This matters because the management API (`/api/*`) is **unauthenticated by design** (see [MCP Server Security](#mcp-server-security) for the equivalent concern on the MCP side). Those endpoints can mint a validly signed access token for any user, including `admin`, rotate the signing keys, and clear the audit log. Loopback binding keeps that surface off the network.

### Exposing on a network

If you deliberately need NanoIDP reachable from other hosts or containers, set the host explicitly:

```bash
# CLI flag
python -m nanoidp --host 0.0.0.0

# or in settings.yaml
server:
  host: "0.0.0.0"
```

The bundled Docker image already sets `--host 0.0.0.0`, because inside a container the isolation boundary is the container network rather than the host loopback. When you bind to all interfaces, NanoIDP logs a startup warning, since the unauthenticated management API then becomes reachable by any host that can route to the port. Only do this on a trusted, isolated network.

---

## Config UI Login Gate

`/login` and `/logout` exist on the web UI, but by default they don't gate
anything - every dashboard page (users, clients, settings, keys, claims,
audit log, token tester) is reachable without a session, same as the rest of
the unauthenticated management surface described above. `require_ui_login`
makes `/login` real:

```yaml
session:
  require_ui_login: true   # default: false
```

| Setting | Behavior |
|---------|----------|
| `false` (default) | The config web UI is unauthenticated, like today |
| `true` | Every web UI page except `/login` itself redirects to `/login` until a session exists |

**What it does not protect**: the separate management API (`/api/*`) stays
unauthenticated regardless of this setting - it's a distinct Flask blueprint
that a UI-only login gate structurally cannot reach. If you enable
`require_ui_login` because the dashboard is reachable by more than just you,
also keep `/api/*` off the network (see [Network Binding](#network-binding)
above) or in front of your own auth layer; this setting does nothing for it.

**Persona mode interaction**: logging in via `/login` or via the SAML SSO
inline login at `/saml/sso` both satisfy this gate - they authenticate
through the same `interactive_authenticate()` call and set the same session.
If [Persona Login Mode](#persona-login-mode) is also enabled
(`login.mode: persona`), that call is identity selection only, with no
credential check. In that combination, `require_ui_login` confirms a user
was picked from a list, not that anyone was verified - it is not protection
against anyone who can reach the port.

**YAML-only**: like `secret_key` and `security_profile`, this is not exposed
on the Settings page or the MCP `update_settings` tool. It's a fixed operator
decision about the trust boundary of the surface itself, not something meant
to be flipped from inside the surface it protects.

---

## Security Profiles

NanoIDP supports three security profiles to balance convenience with basic security controls:

| Profile | Description |
|---------|-------------|
| `dev` (default) | Maximum convenience for development: plaintext passwords, permissive CORS, no rate limiting |
| `stricter-dev` | Semi-hardened runtime: bcrypt passwords, restricted CORS, rate limiting, debug mode blocked |
| `oauth21` | Draft OAuth 2.1 protocol strictness (#68): PKCE required (S256 only), refresh token rotation on, password grant removed, registered redirect URIs mandatory at `/authorize` |

`stricter-dev` hardens the *runtime*; `oauth21` hardens the *protocol*. They are deliberately orthogonal. The discovery document always reflects the active profile: under `oauth21`, `password` disappears from `grant_types_supported` and `code_challenge_methods_supported` is `["S256"]`.

### Usage

```bash
# Run with default dev profile
python -m nanoidp

# Run with stricter-dev profile
python -m nanoidp --profile stricter-dev

# Run with draft OAuth 2.1 protocol strictness
python -m nanoidp --profile oauth21
```

`--profile` is a per-run override: when given (any of the three values,
including an explicit `dev`) it wins over `security_profile` in
`settings.yaml`, is never written back to the file, and is re-applied after
every configuration reload, including the reload that follows each web UI or
MCP save. The `stricter-dev` runtime hardening (`require_pkce`,
`password_hashing`, `rate_limit_enabled`, debug off) is derived from the
effective profile on every reload the same way, whether the profile came from
the flag or from YAML. `GET /api/config` reports the effective profile,
whether it came from an override, and the derived values (#172).

### Feature Comparison

| Feature | `dev` | `stricter-dev` | `oauth21` |
|---------|-------|----------------|-----------|
| Password storage | Plaintext | bcrypt hash | Plaintext |
| CORS | `*` (all origins) | localhost only | `*` (all origins) |
| Rate limiting | None | 10 req/min on `/token` | None |
| Debug mode | Allowed | Blocked | Allowed |
| PKCE | Optional | Required, S256 only | Required, S256 only |
| Refresh token rotation | Setting (`off`) | Setting (`off`) | Forced on |
| `password` grant | Enabled | Enabled | Removed (and not advertised) |
| Redirect URIs at `/authorize` | Any valid URI, or exact match if registered | Same as `dev` | Registration mandatory, exact match |

### Invalid bcrypt hash fallback

When `password_hashing` is on, a stored `users.yaml` password that isn't a
valid bcrypt hash is *not* rejected by default - `authenticate()` catches the
format error and falls back to a plain string comparison, only logging a
warning. This exists so turning on `stricter-dev`/`password_hashing` doesn't
immediately lock out every user until each one is manually re-hashed.

To close that gap, opt in to:

```yaml
session:
  enforce_password_check: true   # default: false
```

With this on, a user whose `users.yaml` password isn't already a bcrypt hash
simply can't log in - no plaintext fallback, no warning-and-continue. Has no
effect when `password_hashing` is off (that path is intentionally plaintext,
dev mode). Like `secret_key` and `require_ui_login`, this is YAML-only - not
on the Settings page or the MCP `update_settings` tool.

---

## Persona Login Mode

Interactive logins can optionally skip password prompts entirely and let you sign in by picking a configured user from a list - handy for local testing when you just want to switch between users quickly, without looking up passwords.

Opt-in and off by default:

```yaml
login:
  mode: persona   # default: password
```

| Mode | Behavior |
|------|----------|
| `password` (default) | Interactive logins require the configured password |
| `persona` | Interactive logins list the configured users; sign in by selecting one, no password prompt |

**Where it applies**: every interactive login surface - the nanoidp dashboard's `/login`, OIDC's `/authorize`, SAML's `/saml/sso`, and the device authorization flow's `/device` verification page.

**Where it doesn't apply**: the OAuth2 `password` grant (`grant_type=password` at `/token`) is unaffected either way - it's a machine-to-machine credential exchange, not an interactive login. A user with no `password` configured (see below) simply can never authenticate through it, in either mode.

**Password-less users**: `password` is optional on a user in `users.yaml`. A user without one can only sign in via persona mode - they're rejected by password-mode login and the OAuth password grant alike.

```yaml
users:
  admin:
    password: "admin"          # still works with either login mode
  alice:
    email: "alice@example.org" # no password: persona-mode only
```

**SAML detail**: a persona login can't claim `AuthnContextClassRef: PasswordProtectedTransport`, since no password was used - NanoIDP emits `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified` instead for sessions authenticated this way.

**Orthogonal to security profiles**: `login.mode` and `security_profile` are independent settings. `security_profile` governs OAuth/SAML protocol strictness; `login.mode` only changes how the interactive login UI authenticates the resource owner. Persona mode works the same under any profile.

Like the rest of NanoIDP, this is a local development/testing convenience - it is never intended as an authentication mode for a deployed environment.

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

## Hooks and Plugins

`hooks:` (shell commands run before a configuration load, after a
configuration save and after an audit event) and `plugins:` (Python
packages loaded from the `nanoidp.plugins` entry-point group) extend
nanoidp from outside the core; see the
[Extending nanoidp](https://cdelmonte-zg.github.io/nanoidp/guides/extending.html)
guide. Two facts matter here:

- A Python plugin runs with the process's privileges. Installing one is a
  trust decision like any other dependency.
- A shell hook runs whatever the YAML says, through the shell, with
  nanoidp's environment. `settings.yaml` and `bootstrap.yaml` are
  operator-owned by definition, the same trust boundary as `secret_key`
  and `management_secret`, which is why hooks and plugins are YAML-only:
  the web UI and the MCP `update_settings` tool report them and cannot
  change them. A configuration surface that could set a command would be a
  remote-execution primitive.

Hooks never run on the protocol path and cannot fail a request: an
`on_audit_event` failure is counted and logged, never propagated.

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
| `create_persona_user` | Create a password-less user (persona login mode) |
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

## Multi-hostname Issuer (`issuer_from_request`)

`oauth.issuer_from_request` (off by default) reflects each request's own
Host header as the discovery `issuer`, token `iss`, and device flow
`verification_uri`, so the same NanoIDP can be reached under more than one
hostname (e.g. a Docker Compose service name vs. `localhost`) without a
discovery/token issuer mismatch.

**Trust caveats:**
- The Host header is trusted as-is unless `oauth.issuer_allowlist` is set to
  a non-empty list of allowed origins; a non-matching Host then falls back to
  the fixed `issuer` instead. Only enable `issuer_from_request` without an
  allowlist on trusted networks.
- Behind a TLS-terminating reverse proxy, also enable
  `oauth.issuer_from_proxy_headers` so `request.scheme`/`host_url` reflect
  `X-Forwarded-Proto`/`X-Forwarded-Host` instead of the proxy's own HTTP
  connection - this only changes the derived issuer when `issuer_from_request`
  is also on (it always affects rate-limit client IP attribution regardless).
  Only enable this when NanoIDP sits directly behind exactly one trusted proxy
  - these headers are otherwise spoofable by any client.
- By default, the device flow's `verification_uri` reflects whichever Host
  called `/device_authorization`. If that caller is a backend/container
  (e.g. `Host: nanoidp:9900`) rather than the end user's own browser, the
  returned URL may not be reachable from the user's machine. Set
  `oauth.device_verification_base_url` to a fixed, human-reachable URL (e.g.
  `https://idp.example.com`) to pin `verification_uri` regardless of the
  calling Host; discovery's `issuer` and a token's `iss` are unaffected and
  keep following the request that fetched/requested them.

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
5. **Keep the default `127.0.0.1` binding** unless you specifically need network access; only override it on a trusted, isolated network (see [Network Binding](#network-binding))
6. **Never expose NanoIDP to public networks**: it's designed for local/isolated use only

---

## Related Documentation

- [MCP Workflow](MCP_WORKFLOW.md) - Detailed Claude Code integration examples
- [README](https://github.com/cdelmonte-zg/nanoidp#readme) - Installation and configuration
