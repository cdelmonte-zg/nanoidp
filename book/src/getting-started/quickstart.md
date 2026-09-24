# Quickstart

From a fresh install to a token you have verified, in a couple of minutes.

## 1. Create a configuration

```bash
# Create config in ./config (default)
python -m nanoidp init

# Or specify a custom path
python -m nanoidp init ./my-idp-config
```

This creates:

- `users.yaml`: user definitions (a default `admin`/`admin` user)
- `settings.yaml`: OAuth/SAML settings (a default `demo-client` with
  secret `demo-secret`)
- `keys/`: RSA keys, auto-generated on first startup

Prefer a guided setup? The interactive wizard walks through server
configuration, OAuth clients, admin user, and token settings:

```bash
python -m nanoidp wizard
```

## 2. Run the server

```bash
# Default config directory (./config)
python -m nanoidp

# Custom config directory
python -m nanoidp --config ./my-idp-config

# Or via environment variable
NANOIDP_CONFIG_DIR=./my-idp-config python -m nanoidp
```

The server listens on `http://localhost:8000` (`--port` to change it).

## 3. Get a token

```bash
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=password&username=admin&password=admin&scope=openid'
```

The response carries an `access_token` (its `aud` is the resource audience
from `oauth.audience`) and, because the request included the `openid`
scope, an `id_token` (its `aud` is the client's `client_id`).

The password grant is used here because it is one request. It is a legacy
grant that OAuth 2.1 removes, so do not model a real login on it: a browser
login is Authorization Code with PKCE, see
[Public clients](../guides/token-requests.md#public-clients-no-secret).

## 4. Verify the token

Verify it the way your client or API would: find the keys through
discovery, then check the signature, the issuer and the audience. PyJWT is
installed with nanoidp, so this runs as is:

```bash
TOKEN=$(curl -s -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=password&username=admin&password=admin&scope=openid' \
  | python -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')

python - "$TOKEN" <<'EOF'
import json, sys, urllib.request
import jwt  # PyJWT, installed with nanoidp

token = sys.argv[1]
discovery = json.load(urllib.request.urlopen(
    "http://localhost:8000/.well-known/openid-configuration"))
key = jwt.PyJWKClient(discovery["jwks_uri"]).get_signing_key_from_jwt(token)
claims = jwt.decode(token, key, algorithms=["RS256"],
                    issuer=discovery["issuer"], audience="my-app")
print("valid:", claims["sub"], claims["iss"], claims["aud"])
EOF
```

```
valid: admin http://localhost:8000 my-app
```

Change `audience="my-app"` to any other value and the same script fails with
`InvalidAudienceError`: that rejection is what your API must do with a
token issued for someone else.

## 5. Open the web UI

The admin UI at [http://localhost:8000](http://localhost:8000) covers the
rest: users, OAuth clients, settings, keys and certificates, claims
mappings, an audit log, and a token tester for generating and inspecting
tokens interactively.

## Next steps

- Exercise every grant with curl: [Requesting tokens](../guides/token-requests.md)
- Drive it from Claude Code: [MCP with Claude Code](../guides/MCP_WORKFLOW.md)
- Understand the trade-offs and the `stricter-dev` profile:
  [Security guide](../guides/SECURITY.md)
- The full reference: [Configuration](../reference/configuration.md),
  [Endpoints](../reference/endpoints.md),
  [Tokens and claims](../reference/tokens.md),
  [SAML options](../reference/saml.md)
