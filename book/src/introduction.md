# NanoIDP

**A lightweight identity provider for development and testing.**

You are building or testing a client that speaks OAuth2/OIDC or SAML 2.0.
You need a real identity provider to integrate against, but standing up
Keycloak or wiring a cloud tenant is a project in itself. NanoIDP is the
alternative: `pip install`, two YAML files, go.

```bash
pip install nanoidp
python -m nanoidp init && python -m nanoidp
```

```bash
$ curl -s -X POST 'http://localhost:8000/token' \
    -u 'demo-client:demo-secret' \
    -d 'grant_type=password&username=admin&password=admin&scope=openid'
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  ...
}
```

The product is **confidence**: the behaviors NanoIDP advertises and
implements are grounded in the relevant specifications, so clients can test
against them without depending on accidental or invented semantics.

## What it is for

- **Test OAuth2/OIDC flows.** Authorization Code with PKCE, Password,
  Client Credentials, Refresh Token (with optional rotation), and Device
  Authorization grants, plus introspection, revocation, and RP-initiated
  logout. See the [Quickstart](getting-started/quickstart.md).
- **Test against draft OAuth 2.1.** The `oauth21` profile enforces the
  draft's strictness: PKCE required with S256 only, rotation on, no
  password grant, and registered redirect URIs with exact matching. The
  discovery document reflects it.
- **Test SAML 2.0.** SSO over HTTP-POST and HTTP-Redirect bindings and
  AttributeQuery, with configurable response signing, strict-binding mode,
  canonicalization algorithms, and opt-in verification of signed
  AuthnRequests against registered SP certificates.
- **Drive it from an agent.** An [MCP server](guides/MCP_WORKFLOW.md)
  exposes users, clients, tokens, keys, and settings to Claude Code and
  other MCP-compatible tools.
- **Configure it your way.** A full web UI, plain YAML files, a REST API.
  No database required.

## What it is not

NanoIDP is **not a production identity provider** and must not operate as
one. Defaults favor getting a first token in under a minute: plaintext
passwords in config files, permissive CORS, open redirects. Hardening is
opt-in where testing needs it: the `stricter-dev` (runtime) and
`oauth21` (protocol) profiles, `require_pkce`, `refresh_token_rotation`,
`want_authn_requests_signed`; the [Security guide](guides/SECURITY.md)
draws the line precisely.

What it promises instead: **metadata never lies.** Discovery advertises
exactly what the endpoints implement, and spec-relevant behavior is
RFC-citable. The full set of principles and non-goals is in the
[Vision](project/vision.md).
