# Configuration

NanoIDP is configured through two YAML files in the config directory
(`./config` by default, `--config` or `NANOIDP_CONFIG_DIR` to change it).
Everything below can also be managed from the web UI at
`http://localhost:8000`:

- **Dashboard** - overview and quick stats
- **Users** - create, edit, delete users
- **OAuth Clients** - manage OAuth2 client credentials
- **Settings** - configure IdP settings (issuer, audience, SAML)
- **Keys & Certs** - view and regenerate RSA keys
- **Claims** - configure authority prefix mappings
- **Audit Log** - view and export authentication events
- **Token Tester** - generate and inspect tokens

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
    tenant: "default"
    source_acl:
      - "ACL_READ"
      - "ACL_WRITE"

default_user: "admin"
```

How these attributes end up in tokens - including the `authority_prefixes`
mapping below - is described in [Tokens and claims](tokens.md).

## Settings (`config/settings.yaml`)

```yaml
server:
  host: "0.0.0.0"
  port: 8000

oauth:
  issuer: "http://localhost:8000"
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

saml:
  entity_id: "http://localhost:8000/saml"
  sso_url: "http://localhost:8000/saml/sso"
  default_acs_url: "http://localhost:8080/login/saml2/sso/nanoidp"
  sign_responses: true  # Set to false for testing unsigned SAML flows
  want_authn_requests_signed: false  # verify AuthnRequest signatures (see SAML options)
  # sp_certificates:                 # PEM files, required when the above is true
  #   - /path/to/sp-cert.pem

# Optional; also settable at startup with --profile (which wins over YAML)
# security_profile: oauth21   # dev (default) | stricter-dev | oauth21

authority_prefixes:
  roles: "ROLE_"
  identity_class: "IDENTITY_"
  entitlements: "ENT_"

logging:
  verbose_logging: true  # Include usernames/client_ids in logs (default: true)
```

**Registered redirect URIs** - a client with a non-empty `redirect_uris`
list gets exact-string matching on `/authorize` (RFC 6749 §3.1.2.3,
OAuth 2.1 §4.1.1): no prefix, host or path normalization, and a mismatch
is answered with `400 invalid_request` directly - never by redirecting to
the unvalidated URI (§3.1.2.4). Clients without the field keep accepting
any syntactically valid URI, the permissive dev default.

The SAML options (`strict_binding`, `sign_responses`, `c14n_algorithm`)
are covered in detail in [SAML options](saml.md). Security-related
settings - profiles, `require_pkce`, key management, `jwt.external_keys` -
are covered in the [Security guide](../guides/SECURITY.md).

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
