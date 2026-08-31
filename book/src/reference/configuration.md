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

## Config schema version

Both files may declare, at the top level, the schema version they follow:

```yaml
config_version: 1
```

The version belongs to the configuration directory's contract as a whole,
not to one file: `settings.yaml` and `users.yaml` declare the same number
(a mismatch refuses to start), each file is checked independently against
the version the running release supports, and a future bump applies to both files together with one loader
migration. The value must be a literal integer; it is checked before
`${VAR}` placeholders are expanded, so `config_version: ${CONFIG_VERSION:1}`
is rejected like any non-integer.

The contract is a single integer, not semver:

- **Absent means 1.** Existing files need no change; `nanoidp init` and the
  wizard write the key into the files they create, and saves from the web UI
  or the MCP server preserve it if present and never add it.
- **Unknown keys are reported.** A key nanoidp does not know (a typo such
  as `oauth.isuer`) is logged as a warning with its path and ignored; the
  file still loads, unless the directory is validated strictly (see
  [Validating your configuration](#validating-your-configuration)). Inside a
  user entry, unknown keys become that user's `attributes`, as they always
  have.
- **Optional additions never bump it.** New optional keys with defaults keep
  the version; only renames, removals or semantic changes of existing keys
  do, and such a bump ships with a migration step in the loader.
- **A newer version than the running release understands is refused at
  startup** with a message naming the file, the value found and the
  supported version, as is any value that is not a positive integer.

`GET /api/config` and the MCP `get_settings` tool report the effective
`config_version`, so external tools and agents know which contract to target.
The CHANGELOG carries a "Config schema" section whenever it changes.

### The generated schema artifact

The machine-readable form of the contract lives in the repository at
[`docs/schema/config.v1.json`](https://github.com/cdelmonte-zg/nanoidp/blob/main/docs/schema/config.v1.json):
one standalone JSON Schema per file, under the keys `settings`, `users` and
`bootstrap`, next to the `config_version` they describe. Point an editor's
YAML-schema support at the entry matching the file to get completion and
typo detection while writing it.

It is generated, never hand-written - that is the whole point, since a
hand-written schema would be one more place the contract could disagree
with itself:

```bash
nanoidp config-schema                 # the full document, on stdout
nanoidp config-schema --file users    # one file's schema
nanoidp config-schema --write         # regenerate docs/schema/config.v1.json
```

`--write` targets a path inside the repository and therefore works from a
source checkout only; from an installed package, redirect stdout instead. A
test fails when the committed file no longer matches the models, with the
command to run.

One thing the schema cannot express: a `${VAR}` placeholder is a string
until it is expanded, and its expansion is a string too, which nanoidp then
coerces to the field's type. A plain JSON Schema check therefore flags
`port: ${PORT:8000}` against `"type": "integer"`. Use `nanoidp
validate-config` for that check - it runs the real loader.

## Validating your configuration

Unknown keys are reported, not ignored. What "reported" means is a choice:

```yaml
# settings.yaml
config_validation: warn     # default: log the key and its path, keep loading
# config_validation: strict # refuse to start
```

The value belongs to the configuration directory as a whole: `users.yaml`
and `bootstrap.yaml` follow what `settings.yaml` declares. Wrong types and
refused values are errors in both modes and always have been; `strict` is
only about the unknown key. `settings.yaml` and `users.yaml` are validated
on startup and on every reload; `bootstrap.yaml` is validated when the
bootstrap surface is loaded, at startup (`validate-config` checks all
three, so for `bootstrap.yaml` it reports what would stop the NEXT
startup, not the next reload). A load that fails validates and commits
nothing: the running settings, users, validation mode and hooks stay
exactly as they were, in the same fail-without-commit contract as the
hook registry. The server flag `--strict-config` turns strict
on for one run, wins over the file, and is never written back:

```bash
nanoidp --strict-config          # unknown key -> refuse to start
```

To check a directory without starting anything:

```bash
$ nanoidp validate-config --config ./config
validate-config: ./config
warning: config/settings.yaml: unknown key oauth.isuer
0 error(s), 1 warning(s)
$ echo $?
0
$ nanoidp validate-config --config ./config --strict
validate-config: ./config (strict)
warning: config/settings.yaml: unknown key oauth.isuer
0 error(s), 1 warning(s) (strict: warnings fail)
$ echo $?
1
```

One line per finding; exit 0 when clean, or with warnings only and no
`--strict`; exit 1 on any error, and on any warning under `--strict` (a
directory that declares `config_validation: strict` is strict either way,
since that is a directory the server would refuse to start on).

The command reads the three files through the same loaders the server uses,
and does nothing else: no server, no `ConfigManager`, no hook dispatched, no
plugin imported. `bootstrap.yaml` is checked for its shape only, because a
lint step that ran the commands a directory declares would be a remote
execution primitive triggered by looking at it. That is what makes it safe
as a pre-commit or CI step:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: nanoidp-validate-config
        name: nanoidp validate-config
        entry: nanoidp validate-config --config ./config --strict
        language: system
        files: ^config/.*\.yaml$
        pass_filenames: false
```

MCP agents have the same check as the read-only `validate_config` tool,
which returns `{valid, findings}` for the running config directory.

## Users (`config/users.yaml`)

```yaml
users:
  admin:
    password: "admin"
    description: "Full administrator"   # optional, max 200 chars, display-only
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

`description` is optional and display-only: it's shown next to the username
in the [persona login](#login-mode-persona-login) picker so you can tell
configured users apart at a glance (e.g. "Finance approver", "Read-only
auditor"). It is never a claim, never exported over SAML, and never part of
a token - just a note for the person picking a user, capped at 200
characters.


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
    description: "Standard internal user" # optional, shown in the picker
```

See the [Security guide](../guides/SECURITY.md#persona-login-mode) for the
full contract, including why the OAuth `password` grant is unaffected and
the SAML `AuthnContextClassRef` detail.

### Auto-login

`login.auto_login` (default `false`) is a further opt-in on top of persona
mode, for driving a real OIDC client library in automated integration tests
(#250) - no username/password entry, no HTTP calls of your own into
nanoidp's login form:

```yaml
# settings.yaml
login:
  mode: persona
  auto_login: true   # default: false; has no effect unless mode is persona
```

With both set, an OIDC `/authorize` request whose `login_hint` is exactly
`persona-auto-login:USERNAME` logs that user in directly - no picker, no
HTML - straight to an authorization code. Any other `login_hint` is an
ordinary hint outside this feature and is left untouched, and with the flag
off a prefixed hint is inert too, so the picker still shows. An unknown
persona reports through the standard OAuth error redirect
(`error=invalid_request`, `state` preserved), never a bare `400`. First
implementation surface is OIDC `/authorize` only - the device flow and SAML
have no equivalent transport for the hint today.

## Settings (`config/settings.yaml`)

```yaml
server:
  host: "127.0.0.1"        # loopback by default; set 0.0.0.0 to expose on a network
  port: 8000
  rate_limit_enabled: false        # optional; rate-limit POST /token (#304). Enforced
                                   # for real since 3.0 - it used to log "enabled" while
                                   # enforcing nothing. stricter-dev forces it on.
  rate_limit_token_endpoint: "10/minute"  # optional; flask-limiter notation

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
      layout: "horizontal"         # optional; "vertical" (default) or "horizontal" (#249):
                                    # horizontal places the client info and login form side by
                                    # side, collapsing back to a single column on narrow viewports
    - client_id: "scoped-client"
      client_secret: "secret"
      description: "Client restricted to a scope subset"
      allowed_scopes:           # optional; see "Registered scopes" below
        - "openid"
        - "profile"
    - client_id: "cli-client"
      token_endpoint_auth_method: "none"  # public client (#188): no secret
      description: "CLI / SPA / MCP client that cannot keep a secret"
    - client_id: "mcp-client"
      client_secret: "secret"
      description: "Client bound to specific MCP servers (RFC 8707, #187)"
      allowed_resources:        # optional; see "Resource indicators" below
        - "https://mcp.example/server"
  # logos_dir: "./static/logos"    # optional; defaults to src/nanoidp/static/logos
  # scopes_supported:               # optional; the global scope vocabulary
  #   - openid                      # (default: openid, profile, email, offline_access)
  #   - profile
  #   - email
  #   - offline_access
  # scope_enforcement: true          # optional; false is a dev-only escape
                                      # hatch back to "any scope string is
                                      # accepted" - see "Registered scopes"

saml:
  # Both optional: when absent they are derived from the effective issuer as
  # <issuer>/saml and <issuer>/saml/sso, so they follow issuer_from_request and
  # the reverse-proxy settings exactly like OIDC discovery does (#181). Set
  # them only when the SP needs a different, fixed value.
  # entity_id: "http://localhost:8000/saml"
  # sso_url: "http://localhost:8000/saml/sso"
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
#   mode: persona     # password (default) | persona
#   auto_login: true  # default: false; requires mode: persona - see "Auto-login" above

# Optional; how an unknown key is reported - see "Validating your configuration"
# below. Also settable at startup with --strict-config, which wins over this
# value for that run only and is never written back
# config_validation: strict   # warn (default) | strict

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
any absolute URI, the permissive dev default.

**Registered scopes** (issue #186): `oauth.scopes_supported` is the global
scope vocabulary (default: `openid`, `profile`, `email`, `offline_access`,
also what discovery's `scopes_supported` advertises); a client's
`allowed_scopes` is an optional subset of it. A requested scope outside the
vocabulary is `invalid_scope` for every client (RFC 6749 §3.3, §4.1.2.1,
§5.2) - `scopes_supported` is a contract, not a suggestion. A requested
scope outside a client's own `allowed_scopes`, when set, is `invalid_scope`
for that client specifically; a client without the field may obtain any
vocabulary scope, the permissive dev default (same "empty = unrestricted"
convention as `redirect_uris` above). Enforced at `/authorize`, every
`/token` grant (including `client_credentials`, RFC 6749 §4.4), and
`/device_authorization`. `oauth.scope_enforcement: false` is a dev-only
escape hatch back to the pre-#186 behavior - any scope string accepted,
unchecked; refused outside the `dev` profile.

**Public clients** (issue #188): `token_endpoint_auth_method: "none"`
declares a client that cannot keep a secret - a CLI, desktop or native
app, SPA, or MCP client. `client_secret` becomes optional (and is ignored
if present: a stored secret never authenticates a public client);
`/token` identifies the client by `client_id` alone. In exchange, the
protections that replace client authentication are mandatory regardless
of profile: `/authorize` requires PKCE with `S256` (OAuth 2.1 §7.5.1),
the `client_credentials` grant is refused with `unauthorized_client`
(it IS client authentication), and refresh tokens always rotate with
reuse detection (OAuth 2.1 §4.3.1/§6.1), whatever
`refresh_token_rotation` says. `/revoke` accepts a public client's
`client_id` with an ownership check - the token's own `client_id` claim
must match, otherwise the response is still `200` and nothing is revoked
(RFC 7009 §2.1 and its privacy guidance). `/introspect` stays
authenticated (RFC 7662): a public `client_id` is not authentication.
`/device_authorization` accepts a public client by `client_id` alone
(RFC 8628 §3.1, #255) - it presents the `client_id` as a parameter, not
via HTTP Basic or a secret, and the issued `device_code` is bound to it.
A confidential client authenticates on every grant, `authorization_code`
included (RFC 6749 §3.2.1); a missing or wrong secret is `invalid_client`.
The registered `token_endpoint_auth_method` is enforced (RFC 7591) at
**every** client-authenticated endpoint - `/token`, `/introspect`,
`/revoke` and `/device_authorization` (issue #262): the default
`client_secret_basic` requires HTTP Basic and rejects a body secret,
while `client_secret_post` requires `client_id` + `client_secret` as POST
body parameters and rejects Basic; presenting both HTTP Basic and a body
secret in one request is rejected (RFC 6749 §2.3). Applying the one
registered method across all of these endpoints is nanoidp's consistency
policy, not an obligation of every RFC: RFC 7009 and RFC 8628 do tie
`/revoke` and `/device_authorization` to the token-endpoint method, while
RFC 7662 requires *some* client authentication at `/introspect` but leaves
the method open - nanoidp reuses the registered method there too rather
than introduce a second field. A client that authenticated to these
endpoints over the other channel before must now use the channel its
`token_endpoint_auth_method` names (or be re-registered for the method it
actually uses).

Public-client handling differs by endpoint (each follows its own RFC), so
here it is in one place:

| Endpoint | A public client (`token_endpoint_auth_method: "none"`) |
|----------|--------------------------------------------------------|
| `/authorize` | Accepted; PKCE with `S256` is mandatory regardless of profile (OAuth 2.1 §7.5.1). |
| `/token` - `authorization_code`, `refresh_token`, `device_code` | Identified by `client_id` alone; refresh tokens always rotate with reuse detection. |
| `/token` - `client_credentials` | Refused with `unauthorized_client` (the grant IS client authentication). |
| `/device_authorization` | Accepted by `client_id` alone (RFC 8628 §3.1); HTTP Basic or a `client_secret` is rejected; the `device_code` is bound to the client. |
| `/revoke` | Accepted by `client_id` alone; an ownership check on the token's `client_id` claim stands in for authentication (RFC 7009 §2.1). |
| `/introspect` | Refused - a public `client_id` is not authentication (RFC 7662); `none` is not in `introspection_endpoint_auth_methods_supported`. |

**Authorization response `iss`** (issue #189, RFC 9207): `/authorize`
returns `iss=<effective issuer>` on every response delivered through a
validated `redirect_uri` - success and error alike - so a client can
detect an authorization-server mix-up. `iss` is delivered exactly when
discovery advertises `authorization_response_iss_parameter_supported`: a
single condition drives both, so metadata and behaviour never disagree.
RFC 9207 requires the issuer to be an `https` URL with a host and no query
or fragment, so the default `http://localhost:8000` dev issuer sends no
`iss` and advertises `false`; point the issuer at `https` (directly, or
reflected via `issuer_from_request` behind a TLS proxy) to turn RFC 9207
on. The value follows `issuer_from_request`. Errors are OAuth error
redirects (`error`, `error_description`, `state`, `iss`) once the
`redirect_uri` is validated; an error before that - an unknown client, a
malformed or unregistered `redirect_uri` - stays a local JSON response,
never a redirect to an unvalidated URI.

**Resource indicators** (issue #187, RFC 8707): a client may send one or
more `resource` parameters on `/authorize`, `/token` and
`/device_authorization`, and the access token's `aud` is bound to those
resources - a token minted for one MCP server is then rejected by
another. A `resource` must be an absolute URI without a fragment,
otherwise the request is `invalid_target`. Per-client `allowed_resources`
gates which resources a client may target (empty = any valid resource,
the dev default, same "empty = unrestricted" convention as
`allowed_scopes`). A `/token` request may narrow the resources a prior
step bound (an authorization code, a refresh token) but never widen them.
Sending no `resource` leaves `aud` at `oauth.audience`, unchanged for
existing clients. `/introspect` reports the token's `aud`; there is no
`resource_indicators_supported` discovery metadata (RFC 8707 defines
none). An MCP client sends `resource` on both `/authorize` and `/token`
(MCP Authorization).

**Native apps (RFC 8252)**: two things a native client needs are built
in. A private-use scheme URI such as `com.example.app:/oauth2redirect`
(§7.1: a scheme and a path, no host) is a valid `redirect_uri` and can be
registered like any other. §7.1 requires such schemes to be a domain the
app controls, in reverse order; NanoIDP applies the minimum rule the RFC
asks of an authorization server, rejecting any non-`http(s)` scheme that
contains no period (`myapp://callback` is answered with `400
invalid_request` naming the rule), and does not verify domain ownership.
A registered loopback URI,
`http://127.0.0.1:{port}/callback` or `http://[::1]:{port}/callback`,
matches any port (§7.3), because the app binds an ephemeral port at
runtime; register it with any placeholder port (`:0` reads well). Only
the port is variable: scheme, host, path and query stay exact, and
`localhost` gets no port flexibility (§7.3 and §8.3 recommend the IP
literals precisely because `localhost` can be remapped). The `oauth21`
profile keeps the loopback exception, as the OAuth 2.1 draft does.

```yaml
    - client_id: "native-client"
      client_secret: "secret"
      redirect_uris:
        - "com.example.app:/oauth2redirect"   # private-use scheme, exact
        - "http://127.0.0.1:0/callback"       # loopback: any port matches
```

**Login page branding**: for demos and prototyping, a client can show its
`client_id` and `description` on the `/authorize` login page and use custom
colors, so testers can see which application they're signing in to. All
fields are optional and safe by construction: colors must be a plain
`#rrggbb` hex string (validated on save, rejected otherwise), never raw CSS
or markup, and a logo is a local file, never a remote URL. To add a logo,
drop an image at `<logos_dir>/<client_id>.{svg,png,jpg,jpeg,webp}` (default
`logos_dir`: `src/nanoidp/static/logos`, overridable via `oauth.logos_dir`);
it's picked up by filename, no config entry needed.

`layout` (#249) controls the card's composition: `"vertical"` (default) is
the single-column card - header, client info, then the login form, footer;
`"horizontal"` places the client info and the login form side by side, with
the header and footer still full width, collapsing back to the vertical
stack on narrow viewports. It's one of exactly two nanoidp-owned layouts,
not a general styling knob - there's no per-client CSS or column widths.

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
profiles, `require_pkce`, key management, `jwt.external_keys`, the
config UI's opt-in [login gate](../guides/SECURITY.md#config-ui-login-gate)
(`session.require_ui_login`), the invalid-bcrypt-hash
[fallback removal](../guides/SECURITY.md#invalid-bcrypt-hash-fallback)
(`session.enforce_password_check`), and the
[management secret](../guides/SECURITY.md#management-secret) write guard
shared by MCP, `/api/*`, and the web UI (`session.management_secret`) - all
YAML-only, like `session.secret_key` (see
[Session Cookie Trust](../guides/SECURITY.md#session-cookie-trust-secret_key)
for why that one matters here too).

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

## Hooks and plugins (`hooks:`, `plugins:`)

Two optional top-level sections, absent by default, declare the extension
points described in [Extending nanoidp: hooks and plugins](../guides/extending.md):
`hooks:` holds shell commands for `on_before_load`, `on_config_saved` and
`on_audit_event` plus `strict` and `timeout_seconds` (shell hooks only);
`plugins:` maps a plugin's entry-point name to its own settings (the only
section whose inner keys nanoidp does not validate). Both are YAML-only:
`GET /api/config` and the MCP `get_settings` tool report hook names,
sources and failure counters, never the commands (which may embed expanded
`${VAR}` secrets), and neither surface can change them. Policy values
declared here override `bootstrap.yaml`'s; undeclared ones keep the
bootstrap value. Hooks
that must run before `settings.yaml` exists go in `bootstrap.yaml` (same two
keys) or in `NANOIDP_BOOTSTRAP_HOOK` / `NANOIDP_BOOTSTRAP_PLUGIN`.

```yaml
hooks:
  on_config_saved: "git -C {config_dir} add {path} && git -C {config_dir} commit -q -m 'nanoidp: {kind}' || true"
  strict: false
  timeout_seconds: 10
plugins:
  echo:
    record: /tmp/nanoidp-hooks.jsonl
```

## Placeholders and the config directory as the interface

Both files accept `${VAR}` and `${VAR:default}` placeholders in any scalar
value except `config_version` (a literal integer, see above), expanded from
the environment when the file is loaded:

```yaml
# settings.yaml
oauth:
  issuer: ${OAUTH_ISSUER:http://localhost:8000}
  clients:
    - client_id: my-app
      client_secret: ${MY_APP_SECRET}      # no default: empty when unset

# users.yaml
users:
  alice:
    password: ${ALICE_PASSWORD}              # unset: load fails, a password cannot be empty
    email: ${ALICE_EMAIL:alice@example.org}
```

What a save does to placeholders differs between the two files. In
`settings.yaml` a web UI or MCP save rewrites only the fields it changed, so
untouched placeholders survive. In `users.yaml` a save of one user rewrites
that user's entry from its loaded (expanded) values and leaves every other
user's text intact; the MCP `save_config` tool rewrites the whole user map
and therefore materializes every expanded placeholder in it. Keep
placeholder-backed users out of the UI/MCP edit path, or regenerate the
file from its source after editing.

This makes the config directory the whole interface between NanoIDP and
whatever produces its configuration. Three use cases that need nothing
beyond it:

- **One file, many environments**: commit `settings.yaml` with placeholders
  and set the variables per environment (shell, Compose `environment:`,
  a Kubernetes `env:` block).
- **Secrets kept out of the file**: point the placeholder at a variable
  that an init step renders from wherever the secret lives; NanoIDP only
  ever sees the environment.
- **Files produced elsewhere**: generate or copy both YAML files into
  `NANOIDP_CONFIG_DIR` before start (an init container, a mounted volume, a
  script), then `POST /api/config/reload` or the MCP `reload_config` tool
  to pick up a later change without a restart. Reloading re-reads the
  files, re-expands placeholders and re-applies the CLI `--profile`.

NanoIDP does not read from or write to any store other than these files;
a sync with an external system is the deploy's job, on either side of the
directory.

## Environment variables

The environment variables (`NANOIDP_CONFIG_DIR`, `NANOIDP_MANAGEMENT_SECRET`,
the legacy `NANOIDP_MCP_ADMIN_SECRET` alias, `NANOIDP_MCP_READONLY`, `PORT`)
are listed in the
[Security guide](../guides/SECURITY.md#environment-variables).
