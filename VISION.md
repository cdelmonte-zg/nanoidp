# Vision

## What nanoidp is

nanoidp is a lightweight identity provider for **development and testing**:
an identity test environment for applications and agentic systems.
It gives developers, and through its MCP server AI agents, a real,
spec-honest OAuth2/OIDC and SAML 2.0 counterpart to integrate against,
without standing up Keycloak or wiring a cloud tenant: `pip install`, two
YAML files, go.

The product is **confidence**: the behaviors nanoidp advertises and
implements are grounded in the relevant specifications, so clients can
test against them without depending on accidental or invented semantics.

Two secondary, supported uses: running local demos and prototyping a
client's login experience, and serving as the identity provider of a
shared development stack (a team's Docker Compose or Kubernetes dev
environment on a trusted network, reachable by several developers and
their agents). In both it stays a dev tool: the users are developers and
test personas, never real end users, and the instance is disposable.

## Principles

These are the criteria every change is judged by. They have been applied
implicitly throughout the project's history; this writes them down.

1. **A dev tool, not a production IdP.** Tradeoffs are primarily weighed
   by asking *"would this mislead someone testing against it?"*, rather
   than *"is this hardened enough to operate as a production identity
   provider?"*. Security behaviors (PKCE, rotation, client binding) are
   first-class precisely because clients need to test them; what nanoidp
   does not promise is production-grade operation. Convenience that
   doesn't distort spec behavior is welcome; hardening that costs
   convenience must be optional. The same test applies to the
   shared-dev-stack use: a change is in scope when it helps a team run
   and configure a disposable stack, and out of scope when its purpose
   is to protect real users or data.
2. **Metadata never lies.** Discovery and documentation advertise exactly
   what the endpoints implement: a missing feature is acceptable, a
   pretended one is not (see #41: `response_type=token` was advertised but
   unimplemented, and was removed rather than implemented).
3. **Hardening is opt-in, defaults stay permissive.** Strictness lives in
   security profiles (`stricter-dev`) and explicit settings (`require_pkce`,
   `refresh_token_rotation`); the out-of-the-box experience favors getting
   a first token in under a minute.
4. **MCP/HTTP parity.** Every administrative and testing capability that
   is meaningful to agents is exposed through MCP, with shared builders
   and models wherever possible so equivalent surfaces cannot drift (see
   #40: the shared discovery builder). Protocol surfaces themselves,
   authorization redirects, SAML SSO, UserInfo, are exercised over HTTP,
   as a real client would.
5. **Features ship whole.** A feature lands together with its MCP exposure
   (where applicable), its `examples/test_agent.py` e2e coverage and its
   docs, in the same PR.
6. **RFC-citable behavior.** Token and protocol behaviors reference the
   spec paragraph that justifies them, in code comments and changelog
   entries alike. When a reviewer disagrees, the RFC arbitrates.
7. **Presentation is data, not code.** Because nanoidp is also used for
   local demos and prototyping a login experience, some per-client
   presentation - the client's id and description, a logo - is in scope.
   But anything a user can set that ends up rendered in a page must be
   structured data or an operator-provided local asset, never free-form
   markup, CSS, or a remote URL fetched into the page. This rules out
   arbitrary per-client CSS (an injection surface on the auth UI) and
   remote logo URLs (attribute-injection plus a third-party beacon that
   sees every visitor), while allowing a client's id, description, or a
   locally-served logo file. Cosmetic customization must never become an
   injection or tracking vector on the authentication UI.

## Non-goals

- **Production or hosted use.** No HA, no hardening guarantees, no real
  user data. A shared dev stack is supported (above); an instance that
  serves people who are not its operators is not. Opt-in management
  guards (`require_ui_login`, `management_secret`) are locks for a
  trusted network, not an access-control system: there are no roles, no
  per-user audit, no tenant isolation, and none are planned.
- **External configuration backends.** Declared configuration remains
  schema-versioned YAML you can read, edit and `git diff`. Secrets and
  users reach nanoidp through YAML files and `${VAR}` placeholders
  rendered by the deploy (Vault Agent, External Secrets, an init
  container); nanoidp does not use a database, Vault or another service
  as a configuration source of truth, and there is no pluggable
  configuration backend. The hooks and plugins shipped in 2.7.0 are the
  way to react to configuration events from outside (mirror, notify,
  bootstrap): nanoidp provides the extension points, the deploy provides
  whatever sits behind them.
- **Production persistence and distributed state.** Runtime state
  (authorization and device codes, token revocations and refresh-token
  families, the audit log, runtime-created clients and users) is in
  memory by default. An optional
  local SQLite runtime store gives durable runtime state and lets several
  nanoidp processes on one host share it (HTTP workers and the separate
  `nanoidp-mcp` process alike); it is not a distributed store.
  Distributed databases, HA and multi-node state coordination are not
  goals. Durable is not declared: a runtime-created object can survive a
  restart without becoming part of the operator's configuration unless it
  is explicitly saved to it.
- **Real identity backends.** No LDAP/AD federation, no social login.
- **Spec completeness for its own sake.** Extensions are added when they
  help someone test a client, not to fill a compliance matrix.

## Direction

Medium-term themes, deliberately undated. Concrete work is tracked in
GitHub issues attached to the corresponding
[milestones](https://github.com/cdelmonte-zg/nanoidp/milestones):

1. **[OAuth 2.1 profile](https://github.com/cdelmonte-zg/nanoidp/milestone/1)**:
   an opt-in profile aligning nanoidp's strictest behavior with draft
   OAuth 2.1: PKCE required everywhere, refresh token rotation on by
   default, S256 only.
2. **[SAML hardening](https://github.com/cdelmonte-zg/nanoidp/milestone/2)**:
   optional validation of signed AuthnRequests, for testing SPs that sign
   their requests.
3. **[Typing strictness](https://github.com/cdelmonte-zg/nanoidp/milestone/3)**:
   tighten the mypy baseline module by module (`disallow_untyped_defs`)
   until `src/` is fully annotated.
4. **[CI quality gates](https://github.com/cdelmonte-zg/nanoidp/milestone/4)**:
   enforce a coverage threshold in CI and fail on Codecov upload errors.
5. **[3.0 breaking cleanups](https://github.com/cdelmonte-zg/nanoidp/milestone/5)**:
   deferred breaking changes for the next major; first entry: refresh
   tokens without a `client_id` binding claim stop being accepted
   (transitional compatibility introduced in 2.2.0).
6. **[Agentic OAuth / MCP interoperability](https://github.com/cdelmonte-zg/nanoidp/milestone/11)**:
   the auth cases of agentic systems, with MCP clients and servers as
   ordinary OAuth parties: per-client scopes, RFC 8707 resource
   indicators, public clients with mandatory PKCE, RFC 9207, opt-in
   Dynamic Client Registration with a CIMD-ready registry, a mock
   protected MCP server as an e2e fixture, a runtime store as the
   boundary for execution state (memory by default, SQLite opt-in for
   several workers on one host), and a config/state split for
   multi-agent use (runtime-created objects with conflict detection,
   export/import, and an actor recorded in the audit log). nanoidp stays
   a dev/testing IdP extended to these cases, not "an IdP for AI".

Anything not covered here is fair game for discussion: open an issue. The
principles above, not this list, are the contract.
