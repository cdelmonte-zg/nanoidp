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

Add `&scope=openid` to also receive an ID Token - see
[Tokens and claims](../reference/tokens.md) for what comes back.

> Under the `oauth21` profile this grant is rejected with `400` and does
> not appear in `grant_types_supported` - OAuth 2.1 removes it entirely.

## Client credentials grant

```bash
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=client_credentials'
```

## Refresh token

```bash
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN'
```

If the original grant included the `openid` scope, the refresh re-issues
an ID Token as well. A `scope` parameter may narrow, but never broaden,
the originally granted scope (RFC 6749 §6). With
`oauth.refresh_token_rotation: true`, each refresh invalidates the
consumed refresh token; reuse revokes the whole rotation family
(RFC 9700 §4.14.2).

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
