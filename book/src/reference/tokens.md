# Tokens and claims

## Audiences and the `aud` claim

NanoIDP follows the OpenID Connect / OAuth specs for the `aud` claim:

- **ID Token** — `aud` is the requesting client's `client_id` (OpenID
  Connect Core 1.0 §2). This lets you test multiple clients independently.
  Configure `additional_audiences` on a client to append extra audiences;
  if this produces more than one distinct audience value, `aud` is emitted
  as an array and NanoIDP also emits an `azp` claim equal to the
  `client_id` so you can exercise authorized-party validation.
- **Access Token** — `aud` is the resource audience from `oauth.audience`
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
authenticated, preserved across refreshes — OIDC Core §12.2) and `at_hash`
(binding to the access token issued alongside — §3.1.3.6).

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

All tokens are signed with RS256; verify them against the JWKS at
`/.well-known/jwks.json` (see [Endpoints](endpoints.md)).
