# Quickstart

From a fresh install to a verified token in a couple of minutes.

## 1. Create a configuration

```bash
# Create config in ./config (default)
python -m nanoidp init

# Or specify a custom path
python -m nanoidp init ./my-idp-config
```

This creates:

- `users.yaml` — user definitions (a default `admin`/`admin` user)
- `settings.yaml` — OAuth/SAML settings (a default `demo-client` with
  secret `demo-secret`)
- `keys/` — RSA keys, auto-generated on first startup

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
from `oauth.audience`) and — because the request included the `openid`
scope — an `id_token` (its `aud` is the client's `client_id`).

Verify it the way your client would, via discovery and JWKS:

```bash
curl http://localhost:8000/.well-known/openid-configuration
curl http://localhost:8000/.well-known/jwks.json
```

## 4. Open the web UI

The admin UI at [http://localhost:8000](http://localhost:8000) covers the
rest: users, OAuth clients, settings, keys and certificates, claims
mappings, an audit log, and a token tester for generating and inspecting
tokens interactively.

## Next steps

- Drive it from Claude Code: [MCP with Claude Code](../guides/MCP_WORKFLOW.md)
- Understand the trade-offs and the `stricter-dev` profile:
  [Security guide](../guides/SECURITY.md)
- The full endpoint and configuration reference currently lives in the
  [README](https://github.com/cdelmonte-zg/nanoidp#readme).
