# Tokens and claims

## Audiences and the `aud` claim

NanoIDP follows the OpenID Connect / OAuth specs for the `aud` claim:

- **ID Token**: `aud` is the requesting client's `client_id` (OpenID
  Connect Core 1.0 §2). This lets you test multiple clients independently.
  Configure `additional_audiences` on a client to append extra audiences;
  if this produces more than one distinct audience value, `aud` is emitted
  as an array and NanoIDP also emits an `azp` claim equal to the
  `client_id` so you can exercise authorized-party validation.
- **Access Token**: `aud` is the resource audience from `oauth.audience`
  (RFC 9068 §2.2), independent of the client.

## Access Token

The access token `aud` is the resource audience (`oauth.audience`). The
user's attributes from `users.yaml` are carried both as individual claims
and flattened into `authorities` via the configured `authority_prefixes`:

```json
{
  "iss": "http://localhost:8000",
  "sub": "admin",
  "aud": "my-app",
  "iat": 1704100000,
  "exp": 1704103600,
  "roles": ["USER", "ADMIN"],
  "tenant": "default",
  "identity_class": "INTERNAL",
  "entitlements": ["ADMIN_ACCESS", "USER_MANAGEMENT"],
  "authorities": [
    "ROLE_USER",
    "ROLE_ADMIN",
    "IDENTITY_INTERNAL",
    "ENT_ADMIN_ACCESS",
    "ENT_USER_MANAGEMENT",
    "ACL_READ",
    "ACL_WRITE"
  ]
}
```

## ID Token

Issued when the `openid` scope is requested. Its `aud` is the client's
`client_id`:

```json
{
  "iss": "http://localhost:8000",
  "sub": "admin",
  "aud": "demo-client",
  "iat": 1704100000,
  "exp": 1704103600,
  "nonce": "..."
}
```

ID Tokens also carry `auth_time` (when the end-user actually
authenticated, preserved across refreshes, OIDC Core §12.2) and `at_hash`
(binding to the access token issued alongside, §3.1.3.6). By default they
do **not** carry `email` or other profile claims - see [Where do the
`email` / `profile` claims come from?](#where-do-the-email--profile-claims-come-from)
below.

If `additional_audiences` produces more than one distinct audience value,
`aud` becomes an array and `azp` is added:

```json
{
  "iss": "http://localhost:8000",
  "sub": "admin",
  "aud": ["multi-aud-client", "https://api.example.com", "urn:service:billing"],
  "azp": "multi-aud-client",
  "iat": 1704100000,
  "exp": 1704103600
}
```

## Where do the `email` / `profile` claims come from?

A common surprise: you request `scope=openid email`, then look for an
`email` claim inside the ID Token or access token and don't find it.

That is expected. The **standard OpenID Connect profile/email claims**
(`email`, `email_verified`, `preferred_username`; plus NanoIDP-specific and
custom claims where configured) are **not embedded in the tokens**. For the
authorization code flow they are served from the **UserInfo endpoint**,
using the access token (OpenID Connect Core 1.0 §5.4). The discovery
document advertises what is available - `scopes_supported` (`openid`,
`profile`, `email`, `offline_access`) and `claims_supported` - but those
scope-based claims are returned from `GET /userinfo`, not from the tokens
themselves.

```bash
curl 'http://localhost:8000/userinfo' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

```json
{
  "sub": "admin",
  "email": "admin@example.org",
  "email_verified": true,
  "preferred_username": "admin",
  "roles": ["USER", "ADMIN"],
  "tenant": "default",
  "identity_class": "INTERNAL"
}
```

### Scope gating

Under the default `dev` profile, `/userinfo` returns these claims
unconditionally. Under the `stricter-dev` and `oauth21` profiles the
standard OIDC claims are gated by the granted scope (OIDC Core §5.4):
`email` / `email_verified` require the `email` scope and
`preferred_username` requires the `profile` scope. The granted scope is
carried on the access token as the `scope` claim (RFC 9068 §2.2.3).
NanoIDP-specific claims (`roles`, `tenant`, `identity_class`,
`attributes`) have no standard scope and are always returned.

## Requesting claims in the ID Token (`claims` parameter)

If your client specifically needs a claim **inside the ID Token**, use the
OpenID Connect `claims` request parameter at `/authorize` (OIDC Core §5.5)
- the standards-aligned way to ask for it. Discovery advertises
`claims_parameter_supported: true`.

```
GET /authorize?response_type=code&client_id=demo-client
  &redirect_uri=http://localhost:3000/callback&scope=openid
  &claims={"id_token":{"email":null,"email_verified":null}}
```

(URL-encode the `claims` value in a real request.) After the code
exchange, the ID Token then carries the requested claims:

```json
{
  "iss": "http://localhost:8000",
  "sub": "admin",
  "aud": "demo-client",
  "iat": 1704100000,
  "exp": 1704103600,
  "email": "admin@example.org",
  "email_verified": true
}
```

The `userinfo` member (e.g. `{"userinfo":{"email":null}}`) works the same
way for `/userinfo` and composes with the scope gating above, so a client
can pull a specific claim even under a stricter profile that would
otherwise gate it out. Claims are resolved from the user and added only
when available (voluntary form, §5.5.1); protocol claims are never
overwritten and unknown names are skipped. The `claims` parameter is
accepted on the authorization code grant, carried through the
refresh_token grant (below), and mirrored by the MCP `generate_token`
tool (`id_token_claims` / `userinfo_claims`).

The requested claim names are persisted in the refresh token (like the
granted scope and `auth_time`), so a refreshed ID Token keeps carrying
the requested claims and `/userinfo` keeps honouring the `userinfo`
member for the refreshed access token (OIDC Core §12.2). The `nonce` is
the deliberate exception: it binds the original authentication request
and is never re-issued on refresh. Note that a claims request binds to
the original authorization and is orthogonal to scope (§5.5), so it is
**not** shed by narrowing the scope on refresh: under a stricter profile,
a claim requested via the `userinfo` member keeps being returned by
`/userinfo` even after the client drops the scope that would otherwise
gate it. To shed a claims request, start a new authorization.

All tokens are signed with RS256; verify them against the JWKS at
`/.well-known/jwks.json` (see [Endpoints](endpoints.md)).
