# Configuration

NanoIDP is configured through two YAML files in the config directory
(`./config` by default, `--config` or `NANOIDP_CONFIG_DIR` to change it).
Everything below can also be managed from the web UI at
`http://localhost:8000`:

- **Dashboard**: overview and quick stats
- **Users**: create, edit, delete users
- **OAuth Clients**: manage OAuth2 client credentials
- **Settings**: configure IdP settings (issuer, audience, SAML)
- **Keys & Certs**: view and regenerate RSA keys
- **Claims**: configure authority prefix mappings
- **Audit Log**: view and export authentication events
- **Token Tester**: generate and inspect tokens

## Users (`config/users.yaml`)

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
    groups:
      - "ADMINISTRATORS"
      - "EVERYONE"
    tenant: "default"
    source_acl:
      - "ACL_READ"
      - "ACL_WRITE"

default_user: "admin"
```

How these attributes end up in tokens, including the `authority_prefixes`
mapping below, is described in [Tokens and claims](tokens.md).

## Login mode (persona login)

`password` is optional on a user - a user without one can only sign in via
[persona login mode](../guides/SECURITY.md#persona-login-mode), a local
dev/testing convenience (off by default) that lets every interactive login
surface (`/login`, `/authorize`, `/saml/sso`, `/device`) authenticate by
selecting a configured user instead of typing a password:

```yaml
# settings.yaml
login:
  mode: persona   # default: password
```

```yaml
# users.yaml
users:
  admin:
    password: "admin"          # still works with either login mode
  alice:
    email: "alice@example.org" # no password: persona-mode only
```

See the [Security guide](../guides/SECURITY.md#persona-login-mode) for the
full contract, including why the OAuth `password` grant is unaffected and
the SAML `AuthnContextClassRef` detail.

## Settings (`config/settings.yaml`)

```yaml
server:
  host: "127.0.0.1"        # loopback by default; set 0.0.0.0 to expose on a network
  port: 8000

oauth:
  issuer: "http://localhost:8000"
  issuer_from_request: false    # true: derive issuer/iss/verification_uri from
                                 # each request's own Host header instead of the
                                 # fixed issuer above - lets the same NanoIDP be
                                 # reachable under more than one hostname (e.g. a
                                 # Docker Compose service name vs. localhost) without
                                 # a discovery/token issuer mismatch. MCP tools have
                                 # no request of their own and always report the
                                 # fixed issuer.
  issuer_allowlist: []          # origins allowed to be reflected by issuer_from_request,
                                 # e.g. ["http://localhost:8000", "http://nanoidp:9900"].
                                 # Empty (default) allows any Host header; a non-matching
                                 # Host falls back to the fixed issuer above.
  device_verification_base_url: null  # fixed, human-reachable URL (e.g.
                                 # "https://idp.example.com") for the device flow's
                                 # verification_uri, overriding issuer_from_request's
                                 # derivation there - use this when a backend/container
                                 # calls /device_authorization so the returned URL is
                                 # still one a human's browser can open. Discovery's
                                 # issuer and a token's iss are unaffected.
  issuer_from_proxy_headers: false  # true: trust X-Forwarded-Proto/Host/For from a
                                 # single reverse-proxy hop in front of NanoIDP
                                 # (applies werkzeug's ProxyFix). Only affects the
                                 # issuer_from_request derivation above - has no
                                 # visible effect unless that's also on - but always
                                 # affects rate-limit client IP attribution. Only
                                 # enable behind exactly one trusted proxy - these
                                 # headers are otherwise spoofable.
  audience: "my-app"            # access token "aud" (resource audience, RFC 9068)
  token_expiry_minutes: 60
  refresh_token_rotation: false # true: each refresh invalidates the used refresh token
  clients:
    - client_id: "demo-client"
      client_secret: "demo-secret"
      description: "Default demo client"
    - client_id: "multi-aud-client"
      client_secret: "secret"
      description: "Client whose ID Token carries extra audiences"
      additional_audiences:     # optional; makes the ID Token "aud" an array
        - "https://api.example.com"
        - "urn:service:billing"
    - client_id: "registered-client"
      client_secret: "secret"
      description: "Client whose redirect_uri is pinned"
      redirect_uris:            # optional; when set, /authorize enforces
        - "http://localhost:3000/callback"  # exact string matching
    - client_id: "branded-client"
      client_secret: "secret"
      description: "Demo client with custom login page branding"
      background_color: "#2c3e50"  # optional; hex only, behind the login card
      header_color: "#3498db"      # optional; hex only, the card's header band
      footer_color: "#e8f4f8"      # optional; hex only, the card's footer band
      show_client_id: true         # optional; default true
      show_description: true       # optional; default false
  # logos_dir: "./static/logos"    # optional; defaults to src/nanoidp/static/logos

saml:
  entity_id: "http://localhost:8000/saml"
  sso_url: "http://localhost:8000/saml/sso"
  default_acs_url: "http://localhost:8080/login/saml2/sso/nanoidp"
  sign_responses: true  # Set to false for testing unsigned SAML flows
  want_authn_requests_signed: false  # verify AuthnRequest signatures (see SAML options)
  # sp_certificates:                 # PEM files, required when the above is true
  #   - /path/to/sp-cert.pem
  export_roles: false        # include the user's roles as a SAML attribute
  export_groups: false       # include the user's groups as a SAML attribute
  roles_attr_name: "roles"   # attribute name used when export_roles is on
  groups_attr_name: "groups" # attribute name used when export_groups is on

# Optional; also settable at startup with --profile, which wins over this value
# for that run only (any of the three, including an explicit dev), is never
# written back here and survives every reload (#172)
# security_profile: oauth21   # dev (default) | stricter-dev | oauth21

# Optional; local dev/testing convenience, off by default - see "Login mode" above
# login:
#   mode: persona   # password (default) | persona

authority_prefixes:
  roles: "ROLE_"
  groups: "GROUP_"
  identity_class: "IDENTITY_"
  entitlements: "ENT_"

# Optional; the identity-class values selectable when editing a user
# (web UI and user forms). Defaults to the four values below.
allowed_identity_classes:
  - "INTERNAL"
  - "EXTERNAL"
  - "PARTNER"
  - "SERVICE"

logging:
  verbose_logging: true  # Include usernames/client_ids in logs (default: true)
```

**Registered redirect URIs**: a client with a non-empty `redirect_uris`
list gets exact-string matching on `/authorize` (RFC 6749 §3.1.2.3,
OAuth 2.1 §4.1.1): no prefix, host or path normalization, and a mismatch
is answered with `400 invalid_request` directly, never by redirecting to
the unvalidated URI (§3.1.2.4). Clients without the field keep accepting
any syntactically valid URI, the permissive dev default.

**Login page branding**: for demos and prototyping, a client can show its
`client_id` and `description` on the `/authorize` login page and use custom
colors, so testers can see which application they're signing in to. All
fields are optional and safe by construction: colors must be a plain
`#rrggbb` hex string (validated on save, rejected otherwise), never raw CSS
or markup, and a logo is a local file, never a remote URL. To add a logo,
drop an image at `<logos_dir>/<client_id>.{svg,png,jpg,jpeg,webp}` (default
`logos_dir`: `src/nanoidp/static/logos`, overridable via `oauth.logos_dir`);
it's picked up by filename, no config entry needed.

To preview a client's branded login page, open `/authorize` with its
`client_id` and a `redirect_uri` (any syntactically valid URL works unless
the client has `redirect_uris` pinned - see above):

```text
http://localhost:8000/authorize?response_type=code&client_id=branded-client&redirect_uri=http://localhost:3000/callback
```

The page won't complete the flow (there's no app listening at
`redirect_uri` to receive the code), but it renders the branding, which is
all a visual check needs. This only affects `/authorize`; the dashboard's
own `/login` and the SAML SSO login page are unbranded.

The SAML options (`strict_binding`, `sign_responses`, `c14n_algorithm`)
are covered in detail in [SAML options](saml.md). Security-related
settings are covered in the [Security guide](../guides/SECURITY.md):
profiles, `require_pkce`, key management, `jwt.external_keys`, and the
config UI's opt-in [login gate](../guides/SECURITY.md#config-ui-login-gate)
(`session.require_ui_login`), and the invalid-bcrypt-hash
[fallback removal](../guides/SECURITY.md#invalid-bcrypt-hash-fallback)
(`session.enforce_password_check`).

## Logging

NanoIDP logs all authentication events to both the audit log (viewable in
the web UI) and standard output.

```yaml
logging:
  level: INFO              # DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_token_requests: true # Log token endpoint requests
  log_saml_requests: true  # Log SAML endpoint requests
  verbose_logging: true    # Include usernames/client_ids in log messages
```

**Verbose logging** (`verbose_logging: true`, default):

- Log messages include user and client identifiers for debugging
- Example: `[login] POST /token - success (user: admin) (client: demo-client)`

**Non-verbose logging** (`verbose_logging: false`):

- Log messages omit sensitive identifiers
- Example: `[login] POST /token - success`

Set `verbose_logging: false` if you're concerned about PII in log files,
though for a dev tool this is typically not an issue.

## Environment variables

The environment variables (`NANOIDP_CONFIG_DIR`, `NANOIDP_MCP_ADMIN_SECRET`,
`NANOIDP_MCP_READONLY`, `PORT`) are listed in the
[Security guide](../guides/SECURITY.md#environment-variables).
