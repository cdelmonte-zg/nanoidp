# Vision

## What nanoidp is

nanoidp is a lightweight identity provider for **development and testing**.
It gives developers — and, through its MCP server, AI agents — a real,
spec-honest OAuth2/OIDC and SAML 2.0 counterpart to integrate against,
without standing up Keycloak or wiring a cloud tenant: `pip install`, two
YAML files, go.

The product is **confidence**: the behaviors nanoidp advertises and
implements are grounded in the relevant specifications, so clients can
test against them without depending on accidental or invented semantics.

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
   convenience must be optional.
2. **Metadata never lies.** Discovery and documentation advertise exactly
   what the endpoints implement — a missing feature is acceptable, a
   pretended one is not (see #41: `response_type=token` was advertised but
   unimplemented, and was removed rather than implemented).
3. **Hardening is opt-in, defaults stay permissive.** Strictness lives in
   security profiles (`stricter-dev`) and explicit settings (`require_pkce`,
   `refresh_token_rotation`); the out-of-the-box experience favors getting
   a first token in under a minute.
4. **MCP/HTTP parity.** Every administrative and testing capability that
   is meaningful to agents is exposed through MCP, with shared builders
   and models wherever possible so equivalent surfaces cannot drift (see
   #40: the shared discovery builder). Protocol surfaces themselves —
   authorization redirects, SAML SSO, UserInfo — are exercised over HTTP,
   as a real client would.
5. **Features ship whole.** A feature lands together with its MCP exposure
   (where applicable), its `examples/test_agent.py` e2e coverage and its
   docs — in the same PR.
6. **RFC-citable behavior.** Token and protocol behaviors reference the
   spec paragraph that justifies them, in code comments and changelog
   entries alike. When a reviewer disagrees, the RFC arbitrates.

## Non-goals

- **Production use.** No HA, no hardening guarantees, no real user data.
- **Database persistence.** YAML files plus in-memory runtime state are a
  feature: state you can read, edit and `git diff`.
- **Real identity backends.** No LDAP/AD federation, no social login.
- **Spec completeness for its own sake.** Extensions are added when they
  help someone test a client, not to fill a compliance matrix.

## Direction

Medium-term themes, deliberately undated. Concrete work is tracked in
GitHub issues attached to the corresponding
[milestones](https://github.com/cdelmonte-zg/nanoidp/milestones):

1. **[OAuth 2.1 profile](https://github.com/cdelmonte-zg/nanoidp/milestone/1)** —
   an opt-in profile aligning nanoidp's strictest behavior with draft
   OAuth 2.1: PKCE required everywhere, refresh token rotation on by
   default, S256 only.
2. **[SAML hardening](https://github.com/cdelmonte-zg/nanoidp/milestone/2)** —
   optional validation of signed AuthnRequests, for testing SPs that sign
   their requests.
3. **[Typing strictness](https://github.com/cdelmonte-zg/nanoidp/milestone/3)** —
   tighten the mypy baseline module by module (`disallow_untyped_defs`)
   until `src/` is fully annotated.
4. **[CI quality gates](https://github.com/cdelmonte-zg/nanoidp/milestone/4)** —
   enforce a coverage threshold in CI and fail on Codecov upload errors.
5. **[3.0 breaking cleanups](https://github.com/cdelmonte-zg/nanoidp/milestone/5)** —
   deferred breaking changes for the next major; first entry: refresh
   tokens without a `client_id` binding claim stop being accepted
   (transitional compatibility introduced in 2.2.0).

Anything not covered here is fair game for discussion — open an issue. The
principles above, not this list, are the contract.
