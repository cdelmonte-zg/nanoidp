# Endpoints

## OAuth2 / OIDC

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /.well-known/jwks.json` | JSON Web Key Set |
| `GET/POST /authorize` | Authorization endpoint (login page) |
| `POST /token` | Token endpoint |
| `GET/POST /userinfo` | UserInfo endpoint |
| `POST /introspect` | Token Introspection (RFC 7662) |
| `POST /revoke` | Token Revocation (RFC 7009) |
| `GET/POST /logout` | OIDC End Session / Logout (alias: `/end_session`) |
| `GET /ui/logout` | Dashboard session logout (the web UI's Logout button) |
| `POST /device_authorization` | Device Authorization (RFC 8628; alias: `/device/code`) |
| `GET/POST /device` | Device verification page |

curl examples for every grant are in
[Requesting tokens](../guides/token-requests.md).

The standard OIDC `profile` / `email` claims (`email`, `email_verified`,
`preferred_username`, ...) are served from `GET /userinfo`, not embedded
in the tokens - see [Tokens and claims](tokens.md#where-do-the-email--profile-claims-come-from).

## SAML

| Endpoint | Description |
|----------|-------------|
| `GET /saml/metadata` | IdP Metadata |
| `GET /saml/cert.pem` | IdP signing certificate (PEM) |
| `GET/POST /saml/sso` | Single Sign-On (supports both HTTP-POST and HTTP-Redirect bindings) |
| `POST /saml/attribute-query` | Attribute Query |

Bindings, strict-binding mode, response signing, and canonicalization are
covered in [SAML options](saml.md).

## REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check |
| `GET /api/users` | List users |
| `GET /api/users/{username}` | Get user details |
| `POST /api/users/{username}/token` | Generate token |
| `GET /api/audit` | Get audit log |
| `GET /api/audit/stats` | Audit log statistics |
| `POST /api/audit/clear` | Clear the audit log |
| `GET /api/config` | Get current configuration |
| `POST /api/config/reload` | Reload configuration |
| `POST /api/keys/rotate` | Rotate cryptographic keys |
| `GET /api/keys/info` | Get key information |
