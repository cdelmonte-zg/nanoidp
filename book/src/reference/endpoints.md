# Endpoints

## OAuth2 / OIDC

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /.well-known/oauth-authorization-server` | The same document under the RFC 8414 name |
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
| `POST /clients/forget` | Drop one cached client ID metadata document (web UI) |
| `POST /register` | Dynamic client registration (RFC 7591), opt-in |
| `GET/DELETE /register/<client_id>` | Read or remove a registration (RFC 7592) |

The two discovery paths return the same document: nanoidp is one server with
one set of endpoints, and a client that speaks only OAuth looks under the
RFC 8414 name. Both derive the issuer the same way, so `issuer_from_request`
applies to both. The metadata is served at the root form of the name only,
which is the correct one for an issuer without a path component; an issuer
with a path would want RFC 8414's path-suffixed form, and nanoidp's OIDC
document has always assumed the root form too.

The two `/register` paths exist only while
`oauth.dynamic_registration.enabled` is set, and are open when they do:
the flag is the gate, not the `management_secret`. See
[Dynamic client registration](../guides/dynamic-client-registration.md).

An accepted `GET /authorize` stores the validated request as an
**authorization transaction** on the server (#346), bound to the browser
through the session cookie, and renders a login page whose forms carry its
`transaction_id`. The request (`response_type`, `client_id`, `redirect_uri`,
`scope`, `state`, PKCE, `nonce`, `claims`, `resource`) is validated once, on
that GET; the `POST` that completes the login uses what the transaction
holds and never reads OAuth parameters from its body. A transaction expires
after 10 minutes, yields at most one code, and can only be used with the
cookie of the browser that created it. It is a snapshot: a configuration
change while it is open does not revalidate it, and only a client that no
longer exists ends it.

A `POST` names its transaction with `transaction_id`; when its own query
string also carries OAuth request parameters, they must be exactly those of
the request that created the transaction. A POST without `transaction_id`
whose query string carries a complete OAuth request is a direct entry
point, with or without a GET before it: that request is validated on the
POST like a GET's, and the login runs against a transaction that ends with
the POST unless a TOTP code is still to come. A POST with neither, such as
a script posting `username`/`password` after its GET with the same cookie
jar, continues the one pending transaction of that browser; with none or
several pending it is refused with `invalid_request` rather than guessing.
A `GET` without OAuth request parameters (other query parameters do not
count) follows the same "exactly one" rule, which is how a GET carrying
only `login_hint` applies the hint to the pending request
(#250/#325/#328/#346).

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
| `POST /saml/attribute-query` | Attribute Query (SOAP, backend-to-backend) |

Bindings, strict-binding mode, response signing, and canonicalization are
covered in [SAML options](saml.md).

`/saml/attribute-query` is **unauthenticated by design** - the same model as
the REST read surfaces (reads are never gated): nanoidp is a testing IdP and
its user directory is test data. On a shared instance, anyone who can reach
the endpoint can read any configured user's attributes; deploy accordingly.
An unknown NameID gets a SAML error status (`Requester`/`UnknownPrincipal`),
never a fabricated assertion. Every query it answers is audited, refusals
included (#309), so the same reachability that lets a stranger read
attributes also lets one fill the audit ring and push older entries out of
it; the recorded query id is truncated so a single request cannot store more
than a name's worth of text - in the audit entry only: the `InResponseTo` of
the answer carries the id exactly as it was sent.

## REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check |
| `GET /api/users` | List the effective users, declared and runtime, each with its `origin` |
| `GET /api/users/{username}` | Get user details, declared or runtime (`origin`) |
| `POST /api/users/{username}/token` | Generate a token for a user (testing); the user and `client_id` resolve like any login, runtime ones included. Optional JSON body: `exp_minutes`, and `client_id` (must name a real client) which binds the token and issues a spendable `refresh_token`; without `client_id` the response is an access token only (no `refresh_token`, since one with no client binding is refused since 3.0, #73). |
| `GET /api/audit` | Get audit log |
| `GET /api/audit/stats` | Audit log statistics |
| `POST /api/audit/clear` | Clear the audit log |
| `GET /api/config` | Get current configuration |
| `POST /api/config/reload` | Reload configuration. A rejected reload answers a JSON `422` (`kind`: `invalid` for files that cannot be read or do not validate, `activation` for a signing configuration that cannot be used) and the running configuration stays in effect; a strict hook or plugin failure answers `503` |
| `POST /api/keys/rotate` | Rotate cryptographic keys; `409` when `jwt.external_keys` is configured, since the operator's key is not nanoidp's to replace |
| `GET /api/keys/info` | Get key information |

### Runtime identities

Disposable users and clients for a test run, created on the running IdP and
never written to the declared files unless promoted; see
[Disposable test identities](../guides/runtime-identities.md).

| Endpoint | Description |
|----------|-------------|
| `POST /api/runtime/users` | Create a runtime user: a `users.yaml` entry plus `username` |
| `GET /api/runtime/users` | List runtime users |
| `GET /api/runtime/users/{username}` | Get a runtime user |
| `DELETE /api/runtime/users/{username}` | Delete a runtime user |
| `POST /api/runtime/users/{username}/promote` | Write it into `users.yaml` and retire the runtime object |
| `POST /api/runtime/clients` | Create a runtime client: an `oauth.clients[]` entry |
| `GET /api/runtime/clients` | List runtime clients |
| `GET /api/runtime/clients/{client_id}` | Get a runtime client |
| `DELETE /api/runtime/clients/{client_id}` | Delete a runtime client |
| `POST /api/runtime/clients/{client_id}/promote` | Write it into `settings.yaml` and retire the runtime object |
| `DELETE /api/runtime` | Remove every runtime user and client; answers `users_deleted` and `clients_deleted` |
