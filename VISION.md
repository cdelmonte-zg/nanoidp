# Vision

## What nanoidp is

nanoidp is a **test identity provider**: a real OAuth2/OIDC and SAML 2.0
identity provider whose purpose is testing. It gives developers, and
through its MCP server AI agents, a spec-honest counterpart to integrate
against, without standing up Keycloak or wiring a cloud tenant:
`pip install`, two YAML files, go.

Two things it is not. It is **not a mock**: it does not imitate a
provider's answers, it implements the protocols, keeps the state they
require and refuses what they refuse, and on top of that it offers what a
test needs and a production IdP has no reason to offer (identities
declared in a file, disposable ones created for a single run, an audit log
a test can read, profiles that switch strictness on). And it is **not a
production IdP**: it never serves real users or protects real data. That
second line, not size or feature count, is what bounds the project: it can
grow as deep as testing requires.

The product is **confidence**: the behaviors nanoidp advertises and
implements are grounded in the relevant specifications, so clients can
test against them without depending on accidental or invented semantics.

Two secondary, supported uses: running local demos and prototyping a
client's login experience, and serving as the identity provider of a
shared development stack (a team's Docker Compose or Kubernetes dev
environment on a trusted network, reachable by several developers and
their agents). In both it stays a development and test tool: the users
are developers and test personas, never real end users, and the instance
is disposable.

## Principles

These are the criteria every change is judged by. They have been applied
implicitly throughout the project's history; this writes them down.

1. **A test tool, not a production IdP.** Tradeoffs are primarily weighed
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
   as a real client would. The same rule generalizes past MCP: a domain
   policy has ONE home, and routes/tools are adapters that delegate to it
   rather than reinterpret it - CONTRIBUTING's "Domain invariants have
   one home" (#285) is this principle stated as a review criterion.
5. **Features ship whole.** A feature lands together with its MCP exposure
   (where applicable), its `e2e/test_agent.py` e2e coverage and its
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
  (authorization transactions and codes, device codes, token revocations
  and refresh-token families, the audit log, runtime-created clients and
  users) is in memory today and ends with the process. Runtime-created
  users and clients are disposable test state, kept apart from the
  declared configuration: one becomes part of the operator's files only
  when it is explicitly promoted. The direction below adds an optional
  local SQLite runtime store, so that several nanoidp processes on one
  host (HTTP workers and the separate `nanoidp-mcp` process alike) share
  that state and a test run can outlive a restart; it is a store for one
  host and one test environment, not a distributed one. Distributed
  databases, HA and multi-node state coordination are not goals.
- **Real identity backends.** No LDAP/AD federation, no social login.
- **Spec completeness for its own sake.** Extensions are added when they
  help someone test a client, not to fill a compliance matrix.

## Direction

Deliberately undated. Concrete work is tracked in GitHub issues attached
to the corresponding
[milestones](https://github.com/cdelmonte-zg/nanoidp/milestones).

### What has shipped

The themes this section used to announce, each tracked by the milestone
named here:

1. **[OAuth 2.1 profile](https://github.com/cdelmonte-zg/nanoidp/milestone/1)**:
   the opt-in `oauth21` profile aligns nanoidp's strictest behavior with
   draft OAuth 2.1: PKCE required everywhere, refresh token rotation, S256
   only.
2. **[SAML hardening](https://github.com/cdelmonte-zg/nanoidp/milestone/2)**:
   optional validation of signed AuthnRequests, for testing SPs that sign
   their requests.
3. **[Typing strictness](https://github.com/cdelmonte-zg/nanoidp/milestone/3)**
   and **[CI quality gates](https://github.com/cdelmonte-zg/nanoidp/milestone/4)**:
   an annotated `src/` under a strict mypy baseline, and a coverage
   threshold enforced in CI.
4. **[3.0 breaking cleanups](https://github.com/cdelmonte-zg/nanoidp/milestone/5)**:
   the deferred breaking changes went out with 3.0.0.
5. **[Agentic OAuth / MCP interoperability](https://github.com/cdelmonte-zg/nanoidp/milestone/11)**:
   the auth cases of agentic systems, with MCP clients and servers as
   ordinary OAuth parties: per-client scopes, RFC 8707 resource
   indicators, public clients with mandatory PKCE, RFC 9207, RFC 8414
   metadata, opt-in dynamic client registration (RFC 7591/7592) and client
   ID metadata documents, a mock protected MCP server as an e2e fixture,
   and a real agent host (n8n) tested end to end. nanoidp stays a
   dev/testing IdP extended to these cases, not "an IdP for AI".
6. **Disposable test identities**: users and clients created on a running
   instance over `/api/runtime`, for one CI run. This is what the earlier
   plan of a config/state split for multi-agent use became once it was
   measured against a test case: no export/import and no actor taxonomy
   in the audit log, only runtime objects that are separate from the
   declared configuration, resolved by every protocol flow, removed on
   request and promoted into the files one at a time.
7. **[One home](https://github.com/cdelmonte-zg/nanoidp/milestone/17)**:
   principle 4 applied to the code that predated it, so that each protocol
   rule lives in one place and the routes, the UI and the MCP tools
   delegate to it.

### What comes next

One direction is written down, as a chain in which each step only makes
sense after the one before it:

1. [#363](https://github.com/cdelmonte-zg/nanoidp/issues/363): the rest of
   the execution state (authorization and device codes, revocations, the
   audit log) moves behind the runtime store boundary that today holds
   runtime users and clients.
2. [#354](https://github.com/cdelmonte-zg/nanoidp/issues/354): an optional
   local SQLite runtime store behind that boundary, so that several
   nanoidp processes on one host share runtime state. Memory stays the
   default.
3. [#193](https://github.com/cdelmonte-zg/nanoidp/issues/193): an MCP
   Streamable HTTP transport for nanoidp's own MCP server, a separate
   process and the first consumer of the shared store.

Beyond that chain the project stays open to extension, and the test for
an extension is principle 1 rather than a feature freeze: it belongs when
it makes nanoidp a better instrument for testing a client, a server or an
agent, and it does not when its purpose is to operate an identity
provider for real users. Agent-to-agent identity (token exchange, DPoP,
workload federation,
[#195](https://github.com/cdelmonte-zg/nanoidp/issues/195)) is the
example of a theme that is in bounds and waiting for a concrete test case:
the issue was closed without a scope and is kept as a decision record,
and a use case reopens the subject with a new one.

Anything not covered here is fair game for discussion: open an issue. The
principles above, not this list, are the contract.
