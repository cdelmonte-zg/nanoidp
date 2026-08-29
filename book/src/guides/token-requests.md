# Requesting tokens

curl examples for every supported grant, against the default
`demo-client` / `demo-secret` client from a fresh
[Quickstart](../getting-started/quickstart.md) setup.

## Password grant

```bash
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=password&username=admin&password=admin'
```

Add `&scope=openid` to also receive an ID Token: see
[Tokens and claims](../reference/tokens.md) for what comes back.

> Under the `oauth21` profile this grant is rejected with `400` and does
> not appear in `grant_types_supported`: OAuth 2.1 removes it entirely.

## Client credentials grant

```bash
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=client_credentials'
```

The response carries no `refresh_token`: the client authenticates itself
on every request, so there is nothing a refresh token could stand in for
(RFC 6749 §4.4.3, "A refresh token SHOULD NOT be included"). Request a
new access token the same way when the current one expires.

## Refresh token

```bash
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN'
```

If the original grant included the `openid` scope, the refresh re-issues
an ID Token as well. A `scope` parameter may narrow, but never broaden,
the originally granted scope (RFC 6749 §6). Claims requested via the
OIDC `claims` parameter persist across the refresh, including a
narrowed one; see
[Tokens and claims](../reference/tokens.md#requesting-claims-in-the-id-token-claims-parameter).
With `oauth.refresh_token_rotation: true`, each refresh invalidates the
consumed refresh token; reuse revokes the whole rotation family
(RFC 9700 §4.14.2).

## Public clients (no secret)

A client registered with `token_endpoint_auth_method: none` (a CLI,
desktop or native app, SPA, or MCP client - see the public-clients note
in the [configuration reference](../reference/configuration.md)) has no
secret, so it sends no `-u`: it is identified by `client_id` in the body,
and the PKCE `code_verifier` is what proves it started the flow. The
`code` comes from the browser step (`GET /authorize` with a
`code_challenge`, then login), which cannot be scripted with curl; only
the exchange is shown here.

```bash
curl -X POST 'http://localhost:8000/token' \
  -d 'grant_type=authorization_code' \
  -d 'code=CODE_FROM_THE_AUTHORIZE_REDIRECT' \
  -d 'client_id=cli-client' \
  -d 'redirect_uri=http://127.0.0.1:8765/callback' \
  -d 'code_verifier=YOUR_PKCE_CODE_VERIFIER'
```

A public client MUST use PKCE with `S256` (the request is rejected
without it), cannot use the `client_credentials` grant, and always gets a
rotating refresh token. A `client_secret` sent by a public client is
ignored.

## Device authorization flow

```bash
# 1. Request device code
curl -X POST 'http://localhost:8000/device_authorization' \
  -u 'demo-client:demo-secret' \
  -d 'scope=openid'

# Response:
# {
#   "device_code": "...",
#   "user_code": "ABCD1234",
#   "verification_uri": "http://localhost:8000/device",
#   "expires_in": 600
# }

# 2. User visits verification_uri and enters user_code

# 3. Poll for token
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=YOUR_DEVICE_CODE'
```

## UserInfo

The `email` / `profile` claims (`email`, `email_verified`,
`preferred_username`, ...) are returned here, using the access token - not
embedded in the ID Token. See
[Tokens and claims](../reference/tokens.md#where-do-the-email--profile-claims-come-from)
for the details and for the `claims` request parameter that can put a
claim inside the ID Token.

```bash
curl 'http://localhost:8000/userinfo' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

## Token introspection

```bash
curl -X POST 'http://localhost:8000/introspect' \
  -u 'demo-client:demo-secret' \
  -d 'token=YOUR_ACCESS_TOKEN'
```

## Token revocation

```bash
curl -X POST 'http://localhost:8000/revoke' \
  -u 'demo-client:demo-secret' \
  -d 'token=YOUR_ACCESS_TOKEN'
```
