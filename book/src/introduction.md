# NanoIDP

**A test identity provider: real OAuth2/OIDC and SAML 2.0, built for testing.**

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

That first token uses the password grant because it is one request; it is
a legacy grant that OAuth 2.1 removes. The
[Quickstart](getting-started/quickstart.md) then verifies the token the way
an API would, and points to Authorization Code with PKCE for a real login.

## Start from what you are testing

- **A single-page app's login.** A public client with PKCE, the login
  scripted for CI, and the cases that must fail:
  [Test an SPA login with Authorization Code and PKCE](use-cases/spa-login-pkce.md).
- **An identity provider inside your CI pipeline.** Started in the job,
  checked for readiness, a user per test, isolated and cleaned up:
  [Run a real OIDC provider in CI with GitHub Actions](use-cases/oidc-provider-in-ci.md).
- **A SAML service provider, such as a Spring Boot app.** Metadata,
  signed assertions, roles mapped to authorities, a login tested without a
  browser: [Test a Spring Boot SAML service provider without a real IdP](use-cases/spring-boot-saml.md).
- **Service-to-service calls.** Client credentials, a scope per operation,
  an audience per API, and the tokens an API must refuse:
  [Test service-to-service auth with client credentials](use-cases/service-to-service-client-credentials.md).
- **An MCP server that requires OAuth.** Scoped tools, a token for the
  wrong audience rejected, revocation versus JWKS validation:
  [Testing an MCP client against nanoidp](guides/testing-an-mcp-client.md).
- **An MCP host such as n8n, end to end.** A real host runs discovery,
  PKCE and resource indicators against nanoidp, allowed and denied cases
  included: [Test MCP OAuth with n8n and NanoIDP](guides/n8n-end-to-end.md).
- **Tests that need users and clients for one run.** Create them on a
  running IdP through a REST API and remove them all with one call, without
  touching the declared files:
  [Disposable test identities](guides/runtime-identities.md).
- **Two processes that must see the same state,** such as an app server
  and a CLI talking to the same IdP: [Two processes, one runtime state](guides/shared-runtime-store.md).
- **A client that registers itself.** Dynamic client registration (RFC
  7591) and client ID metadata documents, both opt-in:
  [Dynamic client registration](guides/dynamic-client-registration.md),
  [Client ID metadata documents](guides/client-metadata-documents.md).
- **Every grant with curl.** Authorization Code with PKCE, client
  credentials, refresh, device flow, resource indicators:
  [Requesting tokens](guides/token-requests.md).

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
- **Test MCP authorization.** Issue tokens with the audience, scopes and
  resource indicators an MCP server checks, and watch it accept or refuse
  them. See [Testing an MCP client against nanoidp](guides/testing-an-mcp-client.md).
- **Manage it from an agent.** A separate [MCP server](guides/MCP_WORKFLOW.md)
  exposes users, clients, tokens, keys, and settings to Claude Code and
  other MCP-compatible tools.
- **See who you're testing as.** Persona login mode lists your configured
  users right in the interactive login UI, so you sign in by picking one
  instead of hunting down a password in `users.yaml` - opt-in, off by
  default. See the [Security guide](guides/SECURITY.md#persona-login-mode).
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
