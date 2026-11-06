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
| `GET/POST /logout` | OIDC End Session / Logout (alias: `/end_session`); ends the browser's authenticated session at `/authorize` (#468) |
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
`scope`, `state`, PKCE, `nonce`, `claims`, `resource`, `prompt`, `max_age`,
`id_token_hint`, `response_mode`) is validated once, on
that GET; the `POST` that completes the login uses what the transaction
holds and never reads OAuth parameters from its body. The same request
sent as a form `POST` (OIDC Core 3.1.2.1, #467), its parameters
form-encoded in the body (`application/x-www-form-urlencoded`, Core 13.2;
a `multipart/form-data` body is read the same way) and no login field
beside them, is answered with a `303 See Other` to the same request in
GET form, and the GET then validates it. The 303 carries the fields the
GET reads (the parameters listed above and `login_hint`), from the body
only and as sent, empty and repeated values included; anything else in
the body, and the POST's own URL parameters, are left behind, and a
non-empty `request` or `request_uri` value is replaced by a placeholder,
so the GET refuses it as it refuses any (#463) without the object ever
entering a URL. The redirect is what keeps the browser's session: the session cookie
is `SameSite=Lax`, which a browser sends on a top-level GET navigation but
not on a cross-site POST, so a form POST from another site's page arrives
without it, while the GET it is redirected to carries it, and the request
joins the transactions, second factor and web UI login that browser
already has at the IdP. The 303 itself validates nothing and sets no
cookie. The request then lives in a URL, so a body longer
than what the server in front accepts as a request line is not served:
request objects, the one reason for a long request, are refused anyway
(#463). A transaction expires
after 10 minutes, yields at most one code, and can only be used with the
cookie of the browser that created it. It is a snapshot: a configuration
change while it is open does not revalidate it, and only a client that no
longer exists ends it. Request objects (OIDC Core section 6) are not
implemented: a request carrying a non-empty `request` is refused with
`request_not_supported`, one carrying a non-empty `request_uri` with
`request_uri_not_supported`, whatever else the request says or lacks.
The refusal goes to the `redirect_uri` when the request names a known
client (looked up as any request's is, a metadata document included) and
a `redirect_uri` the ordinary validation accepts for it, with `state` and
`iss` like any other error after it, and stays local otherwise; the
audit event says which, and why when it stayed local. The discovery
document publishes
`request_parameter_supported` and `request_uri_parameter_supported` as
`false` (#463).

A successful login at `/authorize` leaves the browser an **authenticated
session** (#468, OIDC Core 3.1.2.1): a record in the runtime store bound
to the browser through the same cookie value as its transactions, holding
who authenticated, how, and when (`auth_time`), for
`login.session_minutes` (default 60, counted from the authentication and
not renewed by reuse; the value in force when a request arrives bounds a
session established under a longer one; `0` keeps and consults none). It is distinct from
the web UI's login; `/device` and SAML neither create nor use it. While it
lives, a request that carries no `prompt`, `max_age` or `id_token_hint`
is answered with a code at once, no login page, and the ID token carries
the session's `auth_time`: single sign-on, as a real OP does. A script
that always GETs and then POSTs credentials with one cookie jar must
expect the code on the GET once a session exists. The session is only as
good as its login is today: a user that no longer exists, a persona
selection under password mode, a password login under persona mode or one
made before a TOTP code became required of that user, are no session.
`/logout` ends it, and so does `DELETE /api/runtime`. The direct entry
point (the request in the query string, credentials in the body)
authenticates with the credentials it carries and never takes a code from
the session. A persona auto-login `login_hint` names the persona: a
session for another user is not reused for it, the hinted persona is
logged in and the session is theirs.

The three parameters that speak to the session are decided after the
`redirect_uri`, so every answer reaches the client with `state` and
`iss`. `prompt=none` is never a page: a code resting on a usable session,
else `login_required`; persona auto-login does not stand in for a
session, and the direct entry point, which carries credentials, answers
it with `login_required`. `prompt=login` and `max_age=0` ask for the user's own
interaction: the login page, whatever session exists, a new `auth_time`,
and no auto-login, not even on a later hint-only GET resuming that
transaction. `max_age=N` reuses a session whose authentication is no
older than N seconds and shows the page otherwise, and that page asks the
user: a `max_age` no session satisfied is actively re-authenticated, not
auto-logged in. `prompt=consent` is
`consent_required`: there is no consent screen. `prompt=select_account`
is `account_selection_required` under password mode, and the picker, as
an interaction, under persona mode. `prompt=none` combined with another
value, an unknown value, or a `max_age` that is not a non-negative
integer, is `invalid_request`. `id_token_hint` is verified with the
server keys (signature by `kid`, issuer, an ID token; its expiry does not
matter) and names the subject: a session for that user is reused, one for
another is not, and a login that follows is accepted only from that user,
any other being `login_required`; a hint that does not verify is
`invalid_request`, and so is a repeated `id_token_hint`. In a form POST
(#467) the hint never enters the URL:
the 303 carries a single-use reference, resolved by the GET within a
minute. The hint is parked only for a client the server already knows
(declared, runtime, or a cached metadata document); for any other the
reference resolves to nothing and the GET answers `invalid_request`.

**Response modes** (#472, OAuth 2.0 Multiple Response Type Encoding
Practices, OAuth 2.0 Form Post Response Mode). A code, and every error
decided after the `redirect_uri`, is delivered the way `response_mode`
asks: `query` (the default, also for an empty value), `fragment`, or
`form_post`, a page with `Cache-Control: no-store` whose form posts
`code` or `error` and `error_description`, `state` when sent, and `iss`
under the usual rule, to the `redirect_uri` and submits itself, and which
names this server as its only allowed CORS origin, since it holds a code
in a readable body. The mode
is resolved before any answer is built, the request-object refusal
included, so that refusal follows it too. An unknown value, or a repeated
`response_mode`, names no usable channel and is a plain local `400`,
without `Location` and without OAuth error parameters (Core 3.1.2.6). A
`form_post` can only reach an absolute HTTP(S) `redirect_uri` with an
explicit host: with a private-scheme one (a native client) it is a local
`400`, while `query` and `fragment` reach such a URI as any redirect does. The mode is kept by
the transaction, so the login POST delivers the code in it, and travels
into the GET form of a form-serialized request. The discovery document
publishes `response_modes_supported: ["query", "fragment", "form_post"]`.

One browser fact: the session cookie is `SameSite=Lax`, which a browser
sends on a top-level navigation and not from a cross-site iframe. A
silent login (`prompt=none`) as a top-level redirect finds the session;
a silent renew in a hidden iframe from an application on another site
does not, and is answered `login_required`, unless the application and
NanoIDP share a site.

An authorization code is redeemed once. A second redemption is denied
with `invalid_grant` and revokes what the first issued (RFC 6749 4.1.2):
the access token until its own expiry and the whole refresh token family,
so that `/userinfo` refuses the token, `/introspect` reports it inactive
and the refresh token grant is refused; a request that does not bind to
the code (another client, another redirect URI, a wrong verifier) is
refused and revokes nothing. A code not yet redeemed lives ten minutes; a
redeemed one is kept as long as the access token it issued, so that a
replay in that time still revokes. Two limits remain: once the record is
gone, a later replay leaves a refresh family that is still live usable,
and access tokens already minted through a refresh of the family stay
valid until their own expiry even when the family is revoked (#466).

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
What makes a POST a login rather than a form-serialized request is a login
field (`username`, `password`, `totp_code`, `pending_second_factor`,
`change_username`) or `transaction_id` in its body, present even if empty:
such a POST never reads OAuth parameters from its body, and any it carries
are recorded in the audit log as ignored.
A `GET` without OAuth request parameters (other query parameters do not
count) follows the same "exactly one" rule, which is how a GET carrying
only `login_hint` applies the hint to the pending request
(#250/#325/#328/#346).

curl examples for every grant are in
[Requesting tokens](../guides/token-requests.md).

What `/token`, `/device_authorization`, `/userinfo`, `/introspect` and
`POST /api/users/{username}/token` answer carries `Cache-Control: no-store`
and `Pragma: no-cache`, success and error alike (RFC 6749 §5.1 for the
responses that carry tokens or credentials; a policy of nanoidp's own for
user data and token state, so that nothing between a test client and the
IdP answers from a cache). The two registration responses that carry
credentials (#190) say the same, and the page that carries a
`SAMLResponse` answers `Cache-Control: no-cache, no-store` and `Pragma:
no-cache`, as SAML Bindings 3.5.5.1 words it (#478). That page and the
`form_post` page hold a credential in a readable body, so each names the
IdP as its only allowed CORS origin. A response the endpoint itself did not
build, such as a 405, a 429 from the rate limiter or a 503 while the
configuration cannot be read, carries neither; nor do the discovery
documents and the JWKS, which are public and cacheable.

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
| `POST /api/keys/rotate` | Rotate cryptographic keys. A refusal is `{"success": false, "error": <fixed message>, "kind": ...}`: `409` when `jwt.external_keys` is configured, since the operator's key is not nanoidp's to replace (`external_keys_not_rotatable`), and when this process cannot write the keys directory (`keys_directory_not_writable`, or `lock_namespace_unavailable` when its lock file cannot even exist); `503` when the directory's lock, shared with other NanoIDP processes, could not be taken: `lock_timeout` (another process is starting or rotating) with `Retry-After`, `lock_unsupported` (the filesystem has no advisory locks) without, since a retry does not help. The directory a refusal is about is in the server log, not in the body |
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
| `DELETE /api/runtime` | Remove every runtime user and client, end every authenticated session at `/authorize` and drop the parked `id_token_hint` references; answers `users_deleted`, `clients_deleted` and `sessions_ended` |
