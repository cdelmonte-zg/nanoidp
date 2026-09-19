<p align="center">
  <img src="docs/images/Gnome%20guardian%20of%20digital%20identity.png" alt="NanoIDP" width="200">
</p>

<h1 align="center">NanoIDP</h1>

<p align="center">
  <a href="https://github.com/cdelmonte-zg/nanoidp/actions/workflows/tests.yml"><img src="https://github.com/cdelmonte-zg/nanoidp/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
</p>

<p align="center">
  Test real OAuth2/OIDC, SAML 2.0 and MCP authorization flows locally,<br>
  without running a production IAM stack.
</p>

<p align="center">
  📖 <a href="https://cdelmonte-zg.github.io/nanoidp/"><b>Documentation</b></a>
</p>

> Design principles, non-goals and direction live in [VISION.md](VISION.md).

Need a real OAuth2/OIDC or SAML counterpart for an integration test, a demo or
an agent, without standing up Keycloak or provisioning a cloud tenant?

NanoIDP is a test identity provider: a real, spec-honest OAuth2/OIDC and
SAML 2.0 provider built for testing, which you install with `pip`,
configure with two YAML files and throw away when the test is done. It is
not a mock: it implements the protocols instead of imitating their
answers, and what it advertises is what it implements, so your client is
tested against the specification and not against a mock's guesses. It is
not a production IdP either: it never serves real users.

## Quick Start

```bash
pip install nanoidp

python -m nanoidp init    # create ./config (users, settings, keys)
python -m nanoidp         # serve on http://localhost:8000
```

Get a first token:

```bash
curl -X POST 'http://localhost:8000/token' \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=client_credentials'
```

The admin UI runs at `http://localhost:8000`. Prefer Docker?

```bash
docker run --rm -p 8000:8000 \
  -v $(pwd)/config:/app/config \
  ghcr.io/cdelmonte-zg/nanoidp:latest
```

From here: the
[Quickstart](https://cdelmonte-zg.github.io/nanoidp/getting-started/quickstart.html)
walks through users, clients and the Authorization Code + PKCE flow;
[Requesting tokens](https://cdelmonte-zg.github.io/nanoidp/guides/token-requests.html)
has a copy-paste request for every grant;
[Install](https://cdelmonte-zg.github.io/nanoidp/getting-started/install.html)
covers the wizard, custom config paths and docker-compose.

## What you can test against it

- **OAuth2 / OIDC**: Authorization Code with PKCE, Client Credentials,
  Refresh Token with rotation, Device Authorization (RFC 8628) and the
  Password grant for legacy clients; introspection (RFC 7662), revocation
  (RFC 7009) and RP-initiated logout; per-client scopes and audiences,
  claims mapping and authority prefixes; an opt-in `oauth21` profile that
  enforces draft OAuth 2.1 strictness.
- **Clients that were not declared in advance**: public clients with
  mandatory PKCE, resource indicators (RFC 8707), `iss` in the
  authorization response (RFC 9207) and authorization server metadata
  (RFC 8414); opt-in dynamic client registration (RFC 7591, with the read
  and delete of RFC 7592) and opt-in client ID metadata documents, where
  the `client_id` is an `https` URL the server fetches under an explicit
  host allowlist.
- **SAML 2.0**: SSO and AttributeQuery with signed assertions, and opt-in
  verification of signed AuthnRequests.
- **Login experience**: a passwordless persona login for demos, two-step
  login, and a declarative TOTP second factor for testing a client against
  an MFA login (asked on `/authorize`, `/login`, SAML SSO and the device
  page).
- **Agents and MCP**: an MCP server that lets an agent create users and
  clients, mint tokens and read the audit log, with a read-only mode; MCP
  tools and the HTTP API expose the same capabilities.
- **Disposable test identities**: a CI job creates users and clients on a
  running instance over `/api/runtime`, uses them in every flow and removes
  them, without touching the YAML files; one that should stay is promoted
  into the configuration explicitly.
- **Running it**: two schema-versioned YAML files with validation, security
  profiles, an audit log, hooks and plugins for wiring the deploy in, a
  Docker image and a Helm chart.

Every item above has its reference page in the documentation below.

## Documentation

The full documentation lives at
**<https://cdelmonte-zg.github.io/nanoidp/>**:

- [Requesting tokens](https://cdelmonte-zg.github.io/nanoidp/guides/token-requests.html): curl examples for every grant, introspection, revocation
- [Disposable test identities](https://cdelmonte-zg.github.io/nanoidp/guides/runtime-identities.html): users and clients for one CI run, over `/api/runtime`
- [Dynamic client registration](https://cdelmonte-zg.github.io/nanoidp/guides/dynamic-client-registration.html): RFC 7591/7592 for a client that was handed only a server URL
- [Client ID metadata documents](https://cdelmonte-zg.github.io/nanoidp/guides/client-metadata-documents.html): a `client_id` that is a URL, and what the server will and will not fetch
- [MCP workflow](https://cdelmonte-zg.github.io/nanoidp/guides/MCP_WORKFLOW.html): drive NanoIDP from Claude Code or any MCP host
- [Security guide](https://cdelmonte-zg.github.io/nanoidp/guides/SECURITY.html): profiles, key management, MCP hardening
- [Configuration](https://cdelmonte-zg.github.io/nanoidp/reference/configuration.html): `users.yaml`, `settings.yaml`, logging
- [Endpoints](https://cdelmonte-zg.github.io/nanoidp/reference/endpoints.html): OAuth2/OIDC, SAML, REST API
- [Tokens and claims](https://cdelmonte-zg.github.io/nanoidp/reference/tokens.html): token structure and `aud` semantics
- [SAML options](https://cdelmonte-zg.github.io/nanoidp/reference/saml.html): bindings, strict mode, signing, canonicalization
- [MCP server](https://cdelmonte-zg.github.io/nanoidp/reference/mcp.html): all tools and Claude Code/Desktop setup

## Security

NanoIDP is a **development/testing tool** and must NOT be used in
production. Defaults favor convenience (plaintext passwords in config,
permissive CORS, open redirects); hardening is opt-in via the
`stricter-dev` (runtime) and `oauth21` (draft OAuth 2.1 protocol
strictness) profiles and explicit settings. The
[Security guide](https://cdelmonte-zg.github.io/nanoidp/guides/SECURITY.html)
draws the line precisely.

## Development

```bash
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the
end-to-end test agent, code quality tooling, and the release process.

## Adopters

Organizations using NanoIDP in their development or testing workflows:

- [World Direct](https://www.world-direct.at)

Listing means NanoIDP is in use there. It does not imply sponsorship or
endorsement. If you use it and would like to be listed, open an issue or a
pull request against this section.

## License

MIT License. See [LICENSE](LICENSE) for details.

## ❤️ Support NanoIDP

NanoIDP is maintained as an open-source project.

If it helps you test OAuth2, OpenID Connect, or SAML flows,
you can support its development here:

- 💖 GitHub Sponsors: https://github.com/sponsors/cdelmonte-zg
- ☕ Buy Me a Coffee: https://buymeacoffee.com/nanoidp
