# Auto-Login Personas - Implementation Plan

Tracking doc for [issue #250](https://github.com/cdelmonte-zg/nanoidp/issues/250)
(auto-login personas for automated integration testing). This file is a working
plan, not published documentation - remove or fold relevant bits into `docs/` /
`book/` once the feature ships. Target: 3.0.0 if ready while it is still in rc,
otherwise 3.1 - no deadline either way (maintainer's comments on the issue).

The judgment calls the contract left open, plus one pre-existing gap found
while planning (all marked `#250-assumption` below), are each resolved with a
concrete default rather than left pending, so the PR can go up today without
waiting on a reply - each is small, reversible, and called out explicitly in
the PR description for the maintainer to confirm or override after the fact.

## Design contract (from maintainer, issue #250)

1. New config `login.auto_login: bool = False` (default off), only meaningful
   together with `login.mode: persona`. Independent of `security_profile` - no
   profile gate, since one of the main use cases is exercising a client
   library's own test suite under `oauth21`.
2. `login_hint` value with the exact prefix `persona-auto-login:USERNAME` is the
   trigger. Any other `login_hint` is an ordinary hint outside this feature
   (nanoidp may ignore it, per OIDC Core 3.1.2.1). With `auto_login: false`, a
   prefixed hint is ignored too and the picker shows as usual - the flag being
   off must not change error behavior.
3. Fail fast through the protocol's own error channel, not a bare `400`. The
   auto-login branch runs **after** `_validate_authorize_redirect_uri()`
   ([`routes/oauth.py`](../../src/nanoidp/routes/oauth.py)), so an unknown
   persona reports via the standard `error=invalid_request` redirect (RFC 6749
   §4.1.2.1 / OIDC Core 3.1.2.6) with `state` preserved - the same channel
   every other post-redirect-uri `/authorize` error already uses.
4. Audit and session data must keep the two persona variants apart:
   - Audit events distinguish a persona picker selection from an auto-login.
   - `session["auth_method"]` must not just be `"persona"` for both - SAML's
     [`routes/saml.py`](../../src/nanoidp/routes/saml.py) checks
     `auth_method == "persona"` literally to decide between
     `AuthnContextClassRef: unspecified` and `PasswordProtectedTransport`
     (`_sso_authenticate_inline()`, and the OIDC login form's
     [`routes/ui.py`](../../src/nanoidp/routes/ui.py) `login()` sets the same
     key). An auto-login session reused later by SAML must still resolve to
     `unspecified`, not silently claim a password was used.
5. First implementation surface: OIDC `/authorize` only. Device flow (no
   transport for `login_hint` on the verification page - would need a new
   nanoidp extension on `/device_authorization`) and SAML (no `login_hint`
   equivalent; `<saml:Subject>` is a stronger match than an OIDC hint and
   nanoidp's response `NameID` doesn't currently match a
   `persona-auto-login:` prefixed subject) are explicitly **out of scope**
   here - separate future design if there is demand.
6. Ships whole: config schema + persistence, settings UI, `/api/config`, MCP
   `get_settings`/`update_settings`, e2e agent coverage (success, unknown
   persona -> error redirect with `state` preserved, flag off -> picker
   shown), and persona-login docs.
7. Out of scope entirely: per-client allow-list of auto-login personas, signed
   hints, `prompt=none` semantics beyond what falls out naturally.

## Breakdown into commits (single feature branch / PR)

### 1. Data model + config plumbing (no behavior change)
- [ ] [`models.py`](../../src/nanoidp/models.py): `Settings.auto_login: bool =
      False` - no validator rejecting it without `login_mode: persona`
      (`#250-assumption` 1, see below); derived property alongside
      `persona_mode_enabled`, e.g. `auto_login_enabled = persona_mode_enabled
      and self.auto_login`, following the `login_mode` field's
      docstring style near line 500-634.
- [ ] [`config_documents.py`](../../src/nanoidp/config_documents.py):
      `LoginSection.auto_login: bool = False` (next to `mode`, line ~213-216).
- [ ] [`config.py`](../../src/nanoidp/config.py): load `login.auto_login` the
      same way `login.mode` is loaded today; normalize a bare `login:` /
      `login: {mode: ...}` document without `auto_login` to the default
      (reuse whatever null-section guard already exists for `login.mode`).
- [ ] No manual schema edit needed: [`config_schema.py`](../../src/nanoidp/config_schema.py)
      renders [`docs/schema/config.v1.json`](../../docs/schema/config.v1.json)
      straight from `config_documents.py`'s pydantic models ("cannot become a
      seventh restatement of the contract", #174) - just regenerate with
      `nanoidp config-schema --write` once `LoginSection.auto_login` exists,
      and a test fails if the committed artifact and the live models diverge.
- [ ] [`services/yaml_writer.py`](../../src/nanoidp/services/yaml_writer.py):
      extend `update_login_settings()` / `_mutate_login_mode()` (line
      ~68-410) to round-trip `auto_login`, omitted at the `False` default,
      same convention as `login.mode`.
- [ ] Tests: extend `tests/test_config.py`, `tests/test_config_schema.py`,
      `tests/test_config_documents.py`, `tests/test_persistence_unification.py`.
      Cover: default off, on+persona round-trips, on without persona mode
      (loads fine, `auto_login_enabled` is `False` - `#250-assumption` 1),
      bare `login:\n` / `login: {mode: persona}\n` still loads.

### 2. OIDC `/authorize`: recognize the hint, authenticate, distinguish auth_method
- [ ] [`routes/oauth.py`](../../src/nanoidp/routes/oauth.py) `_AuthorizeParams`
      (line ~114-130) and `_read_authorize_params()` (line ~135): add a
      `login_hint` field - it is not read at all today, ordinary or
      prefixed, so it needs plumbing through the same GET-query /
      session-fallback pattern as the other nine params before anything can
      act on it.
- [ ] `authorize()`: new validation step after `_validate_authorize_redirect_uri()`
      (line ~598) and before `_render_authorize_login()` - detect
      `login_hint.startswith("persona-auto-login:")` when
      `config.settings.auto_login_enabled`, extract the username, look it up
      via the same accessor `interactive_authenticate`/`get_user` persona
      login already uses.
- [ ] On a known persona: set `session["user"]`, a **distinct**
      `session["auth_method"]` value (`"persona_auto"`, not `"persona"` -
      `#250-assumption`, see below) per contract point 4, `session.permanent
      = True`, then continue the normal authorize flow (skip
      `_render_authorize_login()` entirely - no HTML, no picker).
- [ ] On an unknown persona: redirect to the client via
      [`_authorize_error_redirect()`](../../src/nanoidp/routes/oauth.py) (line
      ~194 - the same helper `_validate_authorize_response_type`/
      `_validate_authorize_scope`/`_validate_authorize_pkce` already use),
      `error=invalid_request`, descriptive `error_description`, `state`
      preserved and `iss` attached automatically by that helper.
- [ ] With the flag off, or `login.mode != persona` (`#250-assumption`, see
      below): the prefixed hint must be inert - falls through to the
      ordinary login page/picker unchanged, same as any other `login_hint`.
- [ ] Audit: new distinct event (or a `details`/`method` field on the
      existing `login` event) that lets audits tell a picker selection apart
      from an auto-login - check [`services/audit.py`](../../src/nanoidp/services/audit.py)
      for the existing `audit_event("login", "success", ...)` shape used by
      `routes/ui.py`/`routes/saml.py` and extend consistently.
- [ ] Tests: new `tests/test_auto_login.py` (or extend
      `tests/test_persona_login_flows.py`) - happy path, unknown persona
      error redirect (assert `state` is preserved and the redirect target is
      the client's `redirect_uri`, not a bare 400), flag off + prefixed hint
      falls through to the picker, mode `password` + flag on is a no-op,
      ordinary non-prefixed `login_hint` is unaffected.

### 3. SAML `auth_method` regression guard (NOT SAML auto-login - out of scope per contract point 5)
- [ ] This step does **not** add a SAML-side auto-login trigger (no
      `<saml:Subject>`/`login_hint` equivalent for SAML - stays out of scope,
      "can be designed separately if there is demand"). It only guards an
      *existing* SAML code path against a regression the new `auth_method`
      value would otherwise cause on session reuse.
- [ ] [`routes/saml.py`](../../src/nanoidp/routes/saml.py) `_sso_authenticate_inline()`
      returns early on an already-set `session["user"]` (line ~439-442)
      without touching `auth_method`, so a session established a moment
      earlier via OIDC `/authorize` auto-login and then reused by
      `/saml/sso` keeps whatever `auth_method` step 2 set. The response
      builder's `authn_context` selection (line ~538-543) currently does a
      literal `session.get("auth_method", "password") == "persona"` - with
      the new distinct value that literal check would fall through to
      `PasswordProtectedTransport`, exactly the false claim the persona-mode
      contract already ruled out. Widen the check to treat every
      non-password auth method as `unspecified`, e.g. `session.get("auth_method",
      "password") != "password"` (only three values exist today: `password`,
      `persona`, and the new one from step 2).
- [ ] Test: session created via `/authorize` auto-login, then reused for
      `/saml/sso` - assert `unspecified`, not `PasswordProtectedTransport`.

### 4. MCP exposure
- [ ] [`mcp_server/handlers_config.py`](../../src/nanoidp/mcp_server/handlers_config.py):
      expose `auto_login` next to `login_mode` in `get_settings`/
      `update_settings` (line ~54, ~148), enum/bool-validated by the tool's
      `input_schema` so an invalid combination never reaches the handler.
- [ ] [`mcp_server/schemas.py`](../../src/nanoidp/mcp_server/schemas.py):
      add `auto_login` to the relevant tool input schema(s).
- [ ] Tests: extend `tests/test_mcp.py` / `tests/test_mcp_tool_branches.py`
      for the new field; check whether `tests/test_mcp_security.py`'s
      mutating-tool count or `examples/mcp_smoke_test.py`'s `EXPECTED_TOOLS`
      need bumping (likely not - no new tool, just a new field on existing
      ones, but verify against the live stdio server).

### 5. Settings UI persistence + `/api/config` exposure
- [ ] [`templates/settings.html`](../../src/nanoidp/templates/settings.html):
      new "Auto-Login" toggle next to the "Login Mode" select, disabled/
      hidden unless `login_mode == persona` (follow whatever pattern already
      conditions persona-only UI elements).
- [ ] [`routes/ui.py`](../../src/nanoidp/routes/ui.py) `settings()`: wire the
      form's `auto_login` checkbox (absent = unchanged, same convention as
      `login_mode`) to `update_login_settings()`.
- [ ] **Pre-existing gap found while planning, fixed here rather than left
      behind**: [`routes/api.py`](../../src/nanoidp/routes/api.py)
      `get_configuration()` (`/api/config`, line ~139-213) never gained a
      `login` section when persona mode shipped - `login_mode` is absent
      from the response entirely. This belongs here, not with MCP (step 4):
      `test_api_config_parity.py` exists precisely because the settings
      page/e2e agent rebuilds its form FROM `/api/config`, and a field
      missing there gets posted back blank, which the "blank = clear"
      contract (#131, #165) then silently wipes from settings.yaml. Adding
      `auto_login` alone, without its sibling `login_mode`, would repeat
      that exact bug, so add both: a `"login": {"mode": ...,
      "auto_login": ...}` block, same style as the neighboring `saml`/
      `logging` blocks.
- [ ] Tests: extend the settings-UI test class in
      `tests/test_persona_login_flows.py` (or wherever
      `TestSettingsUiLoginMode` lives) - toggle persists, omitted at
      default, and (per `#250-assumption` 1) still saves fine outside
      persona mode without erroring. Extend
      `tests/test_api_config_parity.py` for the new `login` block, following
      its existing SAML-parity pattern (field present, then a settings-form
      round-trip through `/api/config` doesn't clear it).

### 6. E2E coverage
- [ ] [`e2e/test_agent.py`](../../e2e/test_agent.py): extend
      `test_persona_login_mode()` (or add a new `test_auto_login()` under
      `TestCategory.PERSONA`) - toggle `auto_login: true` via `/settings`,
      drive `/authorize` with `login_hint=persona-auto-login:<user>` and
      assert a redirect straight to the client with a code (no HTML), then
      the two negatives: unknown persona -> error redirect with `state`
      preserved, flag off -> picker shown. Restore settings + delete any
      temp user in a `finally`.

### 7. Docs (last)
- [ ] `book/src/reference/configuration.md` - new "Auto-login" subsection
      under the existing "Login mode (persona login)" section, plus a
      commented `auto_login: false` line in the settings.yaml example.
- [ ] `docs/SECURITY.md` (symlinked as `book/src/guides/SECURITY.md`) - short
      note alongside the existing persona-login security section: auto-login
      is a further-opt-in, local dev/testing convenience only.
- [ ] `examples/persona-login/README.md` - mention `auto_login` and the
      `persona-auto-login:` hint prefix, since that example already
      demonstrates persona mode.
- [ ] `CHANGELOG.md` - left to the maintainer, per the persona-login-mode
      precedent; draft an entry here once behavior is finalized instead of
      committing it directly.

## Assumptions and defaults (`#250-assumption`, documented for maintainer review - not blocking)

The contract left some points as judgment calls rather than fully specifying
them, and one pre-existing gap surfaced while planning. Each is resolved here
with a concrete, reversible default so implementation isn't blocked waiting on
a reply; each gets its own callout in the PR description asking the maintainer
to confirm or override.

1. **Precedence when `auto_login: true` but `login.mode != persona`.**
   Decision: **inert, not rejected**. `Settings` accepts the combination
   without a validation error; `auto_login_enabled` is a derived property
   (`persona_mode_enabled and self.auto_login`) that is simply `False` in
   that case, so a stray `persona-auto-login:` hint just falls through to
   the ordinary flow. Rationale: matches how `security_profile` and
   `login.mode` already compose orthogonally elsewhere in this codebase
   (no cross-field rejection precedent), and avoids a config load ever
   failing on account of a field that is merely inactive rather than
   contradictory.
2. **Exact new `auth_method` value: `\"persona_auto\"`.** Distinct from
   `\"persona\"` and `\"password\"`, snake_case to match the existing two.
   `routes/saml.py`'s `authn_context` selection (step 3) is widened from an
   `== \"persona\"` literal to `!= \"password\"` so it does not need to
   enumerate every non-password value by name going forward - resolves the
   distinguishability requirement (contract point 4) without a second
   literal to keep in sync.
3. **Redirect-error helper: already resolved by inspection, not an
   assumption.** [`_authorize_error_redirect()`](../../src/nanoidp/routes/oauth.py)
   (line ~194) is the existing helper `_validate_authorize_response_type`,
   `_validate_authorize_scope`, and `_validate_authorize_pkce` all use for a
   post-redirect_uri `invalid_request` - it already preserves `state` and
   attaches `iss`, and audits a `failed` `authorization_request` event. Step
   2 reuses it as-is rather than hand-rolling a new redirect builder.
4. **`/api/config` gets both `login_mode` and `auto_login` (see step 5).**
   [`routes/api.py`](../../src/nanoidp/routes/api.py) `get_configuration()`
   (line ~139-213) never exposed `login_mode` at all - a pre-existing gap
   from the persona-login-mode feature, not something this PR's own scope
   would otherwise touch. `test_api_config_parity.py` exists precisely
   because the settings page rebuilds its form from `/api/config`, so a
   missing field there risks the "blank = clear" bug (#131/#165) on the
   next save. Shipping `auto_login` there without its sibling `login_mode`
   would repeat that exact bug, so the assumption is to add both. Worth
   flagging as a deliberate small scope expansion, not an oversight.
