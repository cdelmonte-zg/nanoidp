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
- [x] [`models.py`](../../src/nanoidp/models.py): `Settings.auto_login: bool =
      False` - no validator rejecting it without `login_mode: persona`
      (`#250-assumption` 1, see below); derived property alongside
      `persona_mode_enabled`, e.g. `auto_login_enabled = persona_mode_enabled
      and self.auto_login`, following the `login_mode` field's
      docstring style near line 500-634.
- [x] [`config_documents.py`](../../src/nanoidp/config_documents.py):
      `LoginSection.auto_login: bool = False` (next to `mode`, line ~213-216).
- [x] `config.py` needed no change: it never reads `login.mode` directly
      either, only through `SettingsDocument(...).to_settings()`
      (`config_documents.py`), which now passes `auto_login` through too -
      the bare-`login:`/null-section guard already lives there
      (`_bare_login_is_empty`) and covers the sibling field for free.
- [x] No manual schema edit needed: [`config_schema.py`](../../src/nanoidp/config_schema.py)
      renders [`docs/schema/config.v1.json`](../../docs/schema/config.v1.json)
      straight from `config_documents.py`'s pydantic models ("cannot become a
      seventh restatement of the contract", #174) - just regenerate with
      `nanoidp config-schema --write` once `LoginSection.auto_login` exists,
      and a test fails if the committed artifact and the live models diverge.
- [x] [`services/yaml_writer.py`](../../src/nanoidp/services/yaml_writer.py):
      extend `update_login_settings()` / `_mutate_login_mode()` (line
      ~68-410) to round-trip `auto_login`, omitted at the `False` default,
      same convention as `login.mode`.
- [x] Tests: extend `tests/test_config.py`, `tests/test_config_schema.py`,
      `tests/test_config_documents.py`, `tests/test_persistence_unification.py`.
      Cover: default off, on+persona round-trips, on without persona mode
      (loads fine, `auto_login_enabled` is `False` - `#250-assumption` 1),
      bare `login:\n` / `login: {mode: persona}\n` still loads.

### 2. OIDC `/authorize`: recognize the hint, authenticate, distinguish auth_method
- [x] [`routes/oauth.py`](../../src/nanoidp/routes/oauth.py) `_AuthorizeParams`
      (line ~114-130) and `_read_authorize_params()` (line ~135): add a
      `login_hint` field - it is not read at all today, ordinary or
      prefixed, so it needs plumbing through the same GET-query /
      session-fallback pattern as the other nine params before anything can
      act on it.
- [x] `authorize()`: new validation step after `_validate_authorize_redirect_uri()`
      (line ~598) and before `_render_authorize_login()` - detect
      `login_hint.startswith("persona-auto-login:")` when
      `config.settings.auto_login_enabled`, extract the username, look it up
      via the same accessor `interactive_authenticate`/`get_user` persona
      login already uses.
- [x] **Revised while implementing (`#250-assumption` 2, see below): no
      session/`auth_method` change needed.** `_handle_authorize_login()`'s
      success branch never set `session["user"]`/`session["auth_method"]` -
      /authorize's inline login (password or persona picker) has always
      gone straight from credentials to the auth-code redirect, unlike
      `/login` and `/saml/sso`, which do establish a session. Auto-login
      does the same: on a known persona it calls the same code-issuance
      path (extracted into `_issue_authorization_code()`, shared with the
      regular success branch) with no session write, `session.permanent`
      or otherwise. `state`/`iss` are preserved exactly as the normal path
      already does.
- [x] On an unknown persona: redirect to the client via
      [`_authorize_error_redirect()`](../../src/nanoidp/routes/oauth.py) (line
      ~194 - the same helper `_validate_authorize_response_type`/
      `_validate_authorize_scope`/`_validate_authorize_pkce` already use),
      `error=invalid_request`, descriptive `error_description`, `state`
      preserved and `iss` attached automatically by that helper.
- [x] With the flag off, or `login.mode != persona` (`#250-assumption`, see
      below): the prefixed hint must be inert - falls through to the
      ordinary login page/picker unchanged, same as any other `login_hint`.
- [x] Audit: `_issue_authorization_code()`'s `details` dict carries
      `"auto_login": True` only on the auto-login path, so the existing
      `authorization_request`/`success` event (not a new event type) lets
      audits tell a picker selection apart from an auto-login - the
      distinguishability contract point 4 actually asks for, now that no
      session value needs distinguishing (see above).
- [x] Tests: `TestAuthorizeAutoLogin` in `tests/test_persona_login_flows.py`
      - happy path (known persona issues a code directly, no picker),
      unknown persona error redirect (`state` preserved, target is the
      client's `redirect_uri`, not a bare 400), flag off + prefixed hint
      falls through to the picker, mode `password` + flag on is a no-op,
      ordinary non-prefixed `login_hint` is unaffected, and the audit
      `details.auto_login` distinction itself.

### 3. SAML `auth_method` regression guard - NOT NEEDED (found while implementing step 2)
- [x] **No code change required.** The plan assumed OIDC auto-login would
      establish a session SAML could later reuse, the way `/login` and
      `/saml/sso`'s own inline login do; step 2 found that `/authorize`'s
      inline login (password or persona, before or after this feature)
      never touches `session["user"]`/`session["auth_method"]` at all - it
      is a one-shot code issuance, not a session establishment. With no new
      value ever reaching `session["auth_method"]` from this surface,
      `routes/saml.py`'s `_sso_authenticate_inline()`/`authn_context`
      literal `== "persona"` check (line ~439-442, ~538-543) has nothing to
      regress against; it is untouched, unlike this plan originally
      assumed (`#250-assumption` 2, see below).
- [x] Test (defensive, proves the above rather than guards a fix):
      `test_known_persona_issues_code_directly_no_picker` in step 2's
      `TestAuthorizeAutoLogin` already exercises the auto-login path
      end-to-end; no session-reuse-by-SAML test is meaningful here since
      there is no session to reuse. If a future SAML-side `login_hint`
      equivalent is ever added (out of scope, contract point 5), *that*
      work would need this analysis redone.

### 4. MCP exposure
- [x] [`mcp_server/handlers_config.py`](../../src/nanoidp/mcp_server/handlers_config.py):
      expose `auto_login` next to `login_mode` in `get_settings`/
      `update_settings` (line ~54, ~148), enum/bool-validated by the tool's
      `input_schema` so an invalid combination never reaches the handler.
- [x] [`mcp_server/normalize.py`](../../src/nanoidp/mcp_server/normalize.py):
      `auto_login` added to `_UPDATE_SETTINGS_FIELDS` (its presence there is
      what makes `update_settings` accept and `setattr` it - no normalizer
      needed, a plain bool).
- [x] [`mcp_server/schemas.py`](../../src/nanoidp/mcp_server/schemas.py):
      `auto_login` (boolean) added to `update_settings`' input schema, next
      to `login_mode`.
- [x] Tests: extended `tests/test_mcp.py` (`TestMCPUserDescription`, where
      the pre-existing `login_mode` MCP tests already live, a pre-existing
      misplacement left alone rather than fixed here) - `get_settings`
      includes `auto_login`, `update_settings` can enable it alongside
      `login_mode: persona`, it is accepted-but-inert without persona mode
      (`#250-assumption` 1), and a non-boolean value is rejected by the
      schema before dispatch. `test_settings_plumbing_parity.py`'s
      `_UPDATE_SETTINGS_FIELDS`-vs-schema parity test needed no change -
      it already asserts the two stay in sync generically. No new tool was
      added (just a field on two existing ones), so
      `tests/test_mcp_security.py`'s mutating-tool count and
      `e2e/mcp_smoke_test.py`'s `EXPECTED_TOOLS` are unaffected by
      inspection; not re-verified against a live stdio server.

### 5. Settings UI persistence + `/api/config` exposure
- [x] [`templates/settings.html`](../../src/nanoidp/templates/settings.html):
      new "Auto-Login" checkbox in the existing "Login Mode" card, next to
      the select. **Revised while implementing**: no JS show/hide toggle
      gated on `login_mode == persona` - this template has no precedent for
      conditionally hiding one field based on another (`require_pkce`,
      `refresh_token_rotation` etc. are always visible regardless of
      `security_profile` too), so the checkbox is always visible with help
      text stating it has no effect outside persona mode, consistent with
      `#250-assumption` 1's "inert, not rejected" choice. Wired into the
      existing `updatePreview()` JS and the `__on_form` hidden-marker block
      (#131 "absent = unchanged" convention) like every other checkbox here.
- [x] [`routes/ui.py`](../../src/nanoidp/routes/ui.py) `settings()`: wire the
      form's `auto_login` checkbox (via `_form_bool`, absent = unchanged) to
      `update_settings_form()`'s new `auto_login` parameter (added in step 1),
      alongside the existing `login_mode=_form_text("login_mode")` line.
- [x] **Pre-existing gap found while planning, fixed here rather than left
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
- [x] Tests: `TestSettingsUiAutoLogin` in `tests/test_persona_login.py`
      (mirroring `TestSettingsUiLoginMode` in the same file, the actual
      home of the login-mode UI tests) - checkbox rendered, enabling
      persists alongside `login_mode: persona`, enabling without persona
      mode still saves (`#250-assumption` 1), unchecking persists and
      leaves the sibling `mode` key alone, and the `__on_form` marker's
      absent-vs-unchecked distinction. New `TestApiConfigLoginParity` in
      `tests/test_api_config_parity.py`, mirroring the existing SAML-parity
      class - both fields exposed, and a settings-form round-trip rebuilt
      from `/api/config` (the e2e agent's own pattern) doesn't clear
      `auto_login`.


### 6. E2E coverage
- [x] [`e2e/test_agent.py`](../../e2e/test_agent.py): new `test_auto_login()`
      under `TestCategory.PERSONA`, registered alongside
      `test_persona_login_mode` - enables persona mode, creates a
      password-less test user, then checks in order: the prefixed hint is
      inert while `auto_login` is off (picker still shown, same as any
      other `login_hint`); with the flag on, a known persona logs in
      directly via `GET /authorize` (a 302 straight to the client with a
      code, no HTML, exchanged for a real token); an unknown persona
      reports through the ordinary OAuth error redirect
      (`error=invalid_request`, `state` preserved, target is the client's
      `redirect_uri` - never a bare 400). Restores `login_mode`/`auto_login`
      and deletes the test user in a `finally`. Verified live against
      `nanoidp --debug` on port 8899 (this machine's port 8000 collides
      with a VS Code helper process): 62/62 e2e checks pass, including both
      `Persona Login Mode` and the new `Auto-Login Personas`. The run's
      only side effect was `config/users.yaml` picking up the YAML writer's
      own re-indentation style on the unrelated pre-existing seed users (a
      known side effect of any write through it, not something this
      feature introduced) - reverted rather than committed.

### 7. Docs (last)
- [x] `book/src/reference/configuration.md` - new "Auto-login" subsection
      under the existing "Login mode (persona login)" section, plus a
      commented `auto_login: true` line (mirroring `login.mode`'s own
      comment style) in the settings.yaml example.
- [x] `docs/SECURITY.md` (symlinked as `book/src/guides/SECURITY.md` - one
      edit covers both) - new "Auto-Login (automated testing)" subsection
      right after "Persona Login Mode": the config, the `login_hint`
      contract, the error-redirect behavior, and the "OIDC `/authorize`
      only for now" scope note.
- [x] `examples/persona-login/README.md` - new "Auto-login for automated
      tests" section with a working `curl` example against this preset;
      `examples/persona-login/settings.yaml` gets a commented
      `# auto_login: true` line next to `mode: persona` (left commented,
      not enabled, so the example's own "Open the login page" walkthrough
      still shows the picker as documented). Verified with
      `nanoidp validate-config --config examples/persona-login --strict`:
      no findings.
- [ ] `CHANGELOG.md` - left to the maintainer, per the persona-login-mode
      precedent; draft entry below instead of committing it directly.

## Proposed CHANGELOG entry (for the maintainer)

Drafted to fit the existing `[Unreleased]` / `### Added` format and tone,
then deliberately **not** committed to `CHANGELOG.md` - left for the
maintainer to add on their own terms, per the persona-login-mode precedent:

```markdown
- **Auto-login personas** (#250, opt-in, off by default): with
  `login.mode: persona`, a new `login.auto_login: true` lets an OIDC
  `/authorize` request log a configured user in directly - no picker, no
  HTML - by sending `login_hint: persona-auto-login:USERNAME`, for driving a
  real OIDC client library in automated integration tests. Any other
  `login_hint` is passed through unchanged, and with the flag off a
  prefixed hint is inert too, so the picker still shows exactly as before.
  An unknown persona reports through the standard OAuth error redirect
  (`error=invalid_request`, `state` preserved), never a bare `400`. First
  implementation surface is OIDC `/authorize` only; the device flow and
  SAML have no defined transport for the hint yet. Ships with settings UI
  and MCP (`get_settings`/`update_settings`) exposure, an `/api/config`
  `login` block (which also picked up the pre-existing `login_mode` field
  it was missing since persona mode shipped), and an
  `examples/persona-login` walkthrough. Like the rest of NanoIDP, a local
  development/testing convenience only - not an authentication mode for
  deployed environments.
```

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
2. **No new `auth_method` value was needed, and `routes/saml.py` is
   untouched (revised while implementing step 2).** The contract's concern
   (SAML's literal `== "persona"` check misreporting a reused auto-login
   session) presumed OIDC auto-login would establish a session the way
   `/login`/`/saml/sso` do. Implementing step 2 found that `/authorize`'s
   inline login - password, persona picker, or now auto-login - never
   writes `session["user"]`/`session["auth_method"]` at all; it is a
   one-shot code issuance. With nothing new ever reaching that session key
   from this surface, there is no regression to guard against, and
   `routes/saml.py` needed no change. Contract point 4's audit
   distinguishability is instead satisfied by a `details.auto_login: True`
   flag on the existing `authorization_request`/`success` audit event
   (`_issue_authorization_code()`), not a new event type or session value.
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

## Review Round 1 (PR #318, head `c4c71ff`)

All four `#250-assumption` call-outs above were accepted as-is. Two
blocking findings, both reproduced live; the rest are pre-merge polish.

### Blocking - both fixed

1. **A stale session `login_hint` triggers auto-login on requests that
   never sent one.** `_read_authorize_params()` gives `login_hint` the same
   session-fallback-and-store treatment as the other nine `/authorize`
   parameters, but unlike them it decides *who gets authenticated*, and the
   stored hint survives every leg that doesn't end in a successful code
   issuance (`_authorize_error_redirect` and an abandoned picker clear
   nothing). Two measured consequences: (a) an unknown-persona probe
   "poisons" the session - every subsequent `/authorize` in that browser,
   even with no `login_hint` at all, keeps hitting the error redirect
   instead of the picker, until cookies are cleared; (b) a picker selection
   can be silently overridden - hint stored while the flag was off, flag
   then enabled, and the next POST's explicit `username=bob` loses to the
   session's leftover `alice` hint, since the auto-login check (which never
   renders a form) runs before `_handle_authorize_login` reads the POST
   body. Fix: act only on a `login_hint` present in the **current**
   request (`request.args`/`request.form` directly, not the session
   fallback `_read_authorize_params()` uses for the other params) - the
   auto-login branch never has a POST leg of its own, so it never needed
   the session fallback in the first place. Needs tests for both measured
   cases.
   **Fixed**: `login_hint` is now read from `params.get("login_hint", "")`
   only (no `session.get(...)` fallback) and is deliberately never stored
   in the session on the GET leg. Two new regression tests in
   `TestAuthorizeAutoLogin` (`tests/test_persona_login_flows.py`)
   reproduce both measured consequences verbatim - confirmed to fail
   against the pre-fix code (302 instead of 200 for (a); 400 instead of a
   302 carrying the right user for (b)) and pass with the fix.
2. **`tests/test_config.py`: `TestAutoLogin` swallowed the
   `class TestUsersYamlPasswordOptional:` header.** Root cause identified
   (own editing mistake, not a recurring tool bug): the original insertion
   used that class header as trailing anchor context in the edit's "find"
   text to place `TestAutoLogin` immediately before it, but the
   replacement text never repeated the header - the edit tool did exactly
   what was asked, replacing text that included the header with text that
   didn't, silently deleting it. Its docstring became a stray string
   literal as `TestAutoLogin`'s last statement, and every
   `TestUsersYamlPasswordOptional` method quietly became a `TestAutoLogin`
   method instead (collection count unaffected: 68 -> 73, nothing lost,
   nothing failed - exactly why it needed a human review to catch).
   **Fixed**: header restored above the docstring;
   `pytest -k TestUsersYamlPasswordOptional` selects its own test again.
   Noted in memory to catch this shape of mistake earlier next time
   (verify a class/def count, or diff the hunk, after any insertion
   anchored on a following line).

### Non-blocking (before merge / optional)

- Pass the attempted username into the failed auto-login audit event, not
  just inside `reason`'s free text - `_handle_authorize_login`'s failed
  picker/password attempts already audit a `username` field; the auto-login
  error redirect should too, so a consumer filtering failed
  `authorization_request` events by `username` doesn't see every
  `persona-auto-login:<name>` probe as anonymous.
  **Done**: `_authorize_error_redirect()` takes an optional keyword-only
  `username`, passed through from the unknown-persona auto-login call site;
  every other caller is unaffected (defaults to `None`, same as before).
  New test: `test_unknown_persona_audits_the_attempted_username`.
- Drop `docs/plans/auto-login.md` before merge, per the #247 precedent and
  its own header - fold the four `#250-assumption` call-outs into the PR
  description (where they were always meant to live) first.
  **Deferred deliberately** to its own explicit final commit, not bundled
  with this round's fixes - this file is still the active tracking scratch
  pad for as long as review is ongoing.
- Add one sentence to the new `docs/SECURITY.md` section: with
  `auto_login` on and a client with no registered `redirect_uris` (the
  permissive dev default), a plain GET mints a code for any persona to any
  `redirect_uri` with zero interaction (measured live). Pre-existing and
  out of scope, but auto-login removes the one human click persona mode
  still required, so recommend registering `redirect_uris` for any client
  used with auto-login.
  **Done**: one sentence added at the end of the "Auto-Login (automated
  testing)" section.
- Optional cleanups, all **done**: `_login_settings_defaults()` in
  `yaml_writer.py` shares one `document_defaults()` lookup between
  `update_login_settings`/`update_settings_form` instead of each rebuilding
  a full `SettingsDocument` twice; `update_login_settings`'s now-redundant
  early no-op branch removed (the `mutate` closure was already a no-op for
  the same inputs); `AUTO_LOGIN_QS` now derives from `AUTHORIZE_QS`,
  `_enable_auto_login` calls `_enable_persona_mode`, and
  `TestSettingsUiLoginMode`/`TestSettingsUiAutoLogin`'s `_base_form`/
  `_login_as_admin` both delegate to shared module-level functions instead
  of three independent copies; `_AuthorizeParams`' docstring no longer
  states a parameter count.

CHANGELOG: leaving it to the maintainer per the persona-login-mode
precedent confirmed fine - the draft above is good as-is, milestone
decision (3.0.0-in-rc vs 3.1) resolved at merge time.

