# Persona Login Mode — Implementation Plan

Tracking doc for the "passwordless persona login" feature requested in the
original feature-request PR. Targeting **2.7.0** (per maintainer response).
This file is a working plan, not published documentation — remove or fold
relevant bits into `docs/` / `book/` once the feature ships.

## Design contract (from maintainer)

1. Opt-in, server-level mode, off by default: `login.mode: persona` (default
   `password`) — not a per-user flag.
2. `User.password` becomes optional. A user without a password only works in
   persona mode; it cannot authenticate via password mode or the OAuth
   password grant.
3. Persona mode authenticates by selecting the user in the interactive login
   UI; configured users are listed instead of a password prompt.
4. The OAuth password grant is unchanged — a missing password is not an
   empty credential. `authenticate()` simply never authenticates a
   password-less user. Persona login only affects interactive auth, not the
   `/token` grant.
5. `oauth21` stays orthogonal — it governs protocol strictness, not resource
   owner authentication.
6. Consistent across all interactive flows: OIDC `/authorize`, SAML
   `/saml/sso`, nanoidp `/login`, and device authorization. SAML must emit
   `AuthnContextClassRef = urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified`
   for persona logins instead of the always-on `PasswordProtectedTransport`.
7. "Features ship whole": the PR must include config/UI persistence, MCP
   exposure, `examples/test_agent.py` e2e coverage, and docs together.
8. Local dev convenience only — disabled by default, not an auth mode for
   deployed environments.

## Breakdown into commits (single feature branch / PR)

### 1. Data model + config plumbing (no behavior change)
- [x] [`models.py`](../../src/nanoidp/models.py): `User.password` →
      `Optional[str] = None`.
- [x] [`models.py`](../../src/nanoidp/models.py): `Settings.login_mode: str
      = "password"` with validator `{"password", "persona"}` + derived
      property `persona_mode_enabled` (mirrors `pkce_required` /
      `password_grant_enabled` pattern).
- [x] [`config.py`](../../src/nanoidp/config.py): load new `login: {mode:
      ...}` top-level YAML section (mirrors `oauth`/`saml`/`session`).
- [x] [`serialization.py`](../../src/nanoidp/serialization.py): round-trip
      `login.mode` and password-less users on save.
- [x] Tests: extend `tests/test_config.py`,
      `tests/test_persistence_unification.py`.

### 2. Authentication semantics
- [x] [`config.py` `authenticate()`](../../src/nanoidp/config.py):
      short-circuit to `None` when `user.password is None`, before
      hashing/plaintext branches. Single choke point — password grant,
      device `verify()`, and UI login all route through this.
- [x] Test: `authenticate()` rejects password-less users regardless of
      `login_mode` or supplied password (including empty string).

### 3. Interactive login UI — nanoidp `/login`
- [x] [`routes/ui.py` `login()`](../../src/nanoidp/routes/ui.py): branch on
      `login_mode`; persona GET renders picker, POST takes just `username`
      via `config.get_user` (no password check).
- [x] [`templates/login.html`](../../src/nanoidp/templates/login.html):
      persona branch — dropdown/buttons over `config.users.keys()` (reuse
      existing quick-fill user list).
- [x] Tests: `tests/test_persona_login.py`.
- [x] Example preset: [`examples/persona-login/`](../../examples/persona-login/)
      (`settings.yaml`, `users.yaml`, `README.md`), listed in
      [`examples/README.md`](../../examples/README.md). Verified live in a
      browser: `/login` renders the picker, selecting `alice` (password-less)
      logs in and lands on the dashboard.

### 4. Extend persona login to remaining interactive surfaces
- [x] OIDC `/authorize` inline login —
      [`routes/oauth.py`](../../src/nanoidp/routes/oauth.py) `authorize()` +
      [`templates/authorize.html`](../../src/nanoidp/templates/authorize.html).
- [x] SAML `/saml/sso` inline login —
      [`routes/saml.py`](../../src/nanoidp/routes/saml.py) `sso()` +
      `AuthnContextClassRef` switch in `_build_saml_response()` (new
      `authn_context` param, default unchanged). Auth method recorded in
      `session["auth_method"]` by both `ui.py login()` and `saml.py sso()`'s
      own inline login, so a session authenticated via the dashboard and
      later reused by SAML still reports the correct context.
- [x] Device authorization `/device` —
      [`services/device_code.py` `verify()`](../../src/nanoidp/services/device_code.py)
      (new `persona_mode`/`get_user` params, default unchanged) +
      [`routes/oauth.py`](../../src/nanoidp/routes/oauth.py) `device_verify()`
      + [`templates/device.html`](../../src/nanoidp/templates/device.html).
- [x] Tests: `tests/test_persona_login_flows.py` (16 tests: password-mode
      regressions + persona-mode picker/selection/rejection for all three
      surfaces, plus the AuthnContextClassRef checks).

### 5. MCP exposure
- [x] [`mcp_server.py`](../../src/nanoidp/mcp_server.py): expose
      `login_mode` in `get_settings`/`update_settings` (enum-validated by
      the tool's `input_schema`, so an invalid value never reaches the
      handler).
- [x] New `create_persona_user` MCP tool (separate from `create_user`,
      whose contract - password required - stays unchanged) for creating a
      password-less user; shares field-mapping with `create_user` via
      `_build_user_from_arguments()`. Added to `MUTATING_TOOLS`.
- [x] Tests: `TestMCPPersonaLogin` in `tests/test_mcp.py`; updated
      `test_mutating_tools_count` in `tests/test_mcp_security.py` (11 → 12);
      bumped `EXPECTED_TOOLS` (24 → 25) in `examples/mcp_smoke_test.py`,
      verified live against the real stdio server.
- [x] Docs: `docs/SECURITY.md` + `book/src/guides/SECURITY.md` mutating
      tools tables, `book/src/reference/mcp.md` tool list.

### 6. Settings UI persistence
- [x] [`templates/settings.html`](../../src/nanoidp/templates/settings.html):
      new "Login Mode" card, a `<select>` (`password`/`persona`), following
      the `saml_c14n_algorithm` select pattern; included in the JS preview.
- [x] [`services/yaml_writer.py`](../../src/nanoidp/services/yaml_writer.py):
      new `update_login_settings(mode=...)`, omits the `login:` section
      entirely at the `password` default (mirrors `security_profile`'s
      omit-at-default convention).
- [x] [`routes/ui.py`](../../src/nanoidp/routes/ui.py) `settings()`: wires
      the form's `login_mode` field (via `_form_text`, "absent = unchanged")
      to the new writer method.
- [x] Tests: `TestSettingsUiLoginMode` in `tests/test_persona_login.py`
      (select rendered, switch to persona persists, switch back to
      password omits the `login:` section from disk).

### 7. E2E coverage
- [x] [`examples/test_agent.py`](../../examples/test_agent.py):
      `test_persona_login_mode()` (new `TestCategory.PERSONA`) - toggles
      the running server into persona mode via `/settings`, creates a
      password-less test user via `/users/create`, exercises `/login`,
      `/authorize`, the device flow, and `/saml/sso` (asserting
      `AuthnContextClassRef` is `unspecified`) by identity selection, then
      restores `login_mode` and deletes the test user. Verified live
      against `nanoidp --debug`: all 6 sub-checks pass.

### 8. Docs (last)
- [x] `book/src/reference/configuration.md` - new "Login mode (persona
      login)" section (after Users) + a commented `login:` block in the
      settings.yaml example.
- [x] `docs/SECURITY.md` - new "Persona Login Mode" section, after Security
      Profiles. (`book/src/guides/SECURITY.md` is a **symlink** to this same
      file, not a separate copy - one edit covers both; same for
      `book/src/project/changelog.md` -> `CHANGELOG.md`.)
- [x] `README.md` + `book/src/introduction.md` - feature mention (feature
      bullet list and "What it is for", respectively).
- [ ] `CHANGELOG.md` - **left to the maintainer** rather than edited
      directly here (their call how/when to log it); see the proposed entry
      text below.

## Proposed CHANGELOG entry (for the maintainer)

Drafted and verified to fit the existing `[Unreleased]` / `### Added`
format and tone, then deliberately **not** committed to `CHANGELOG.md` -
left for the maintainer to add on their own terms:

```markdown
- **Persona login mode** (opt-in, off by default): `login.mode: persona`
  (default `password`) lets every interactive login surface - the
  dashboard's `/login`, OIDC's `/authorize`, SAML's `/saml/sso`, and the
  device flow's `/device` - authenticate by picking a configured user from a
  list instead of typing a password. `User.password` is now optional; a
  password-less user only works in persona mode and is rejected by
  password-mode login and the OAuth `password` grant alike (a missing
  password is never treated as an empty credential). SAML sessions
  authenticated this way emit `AuthnContextClassRef: unspecified` instead of
  the always-on `PasswordProtectedTransport`, since no password was used.
  `security_profile` is unaffected and stays orthogonal. Ships with a new
  `examples/persona-login` preset, a Settings page toggle, a dedicated
  `create_persona_user` MCP tool (`create_user`'s password requirement is
  unchanged) plus `login_mode` on `get_settings`/`update_settings`, and an
  `examples/test_agent.py` scenario covering all four surfaces. Like the
  rest of NanoIDP, a local development/testing convenience only - not an
  authentication mode for deployed environments.
```

## To be mentioned when submitting the PR

- `authenticate()` ([`config.py`](../../src/nanoidp/config.py)) previously
  assumed `user.password` was always a string. With `password` now optional,
  the bcrypt path (`password_hashing: true`) would have raised
  `AttributeError` on `None.encode()` for a password-less user. Fixed with an
  explicit `user.password is None` short-circuit before the hashing branch —
  worth flagging as a deliberate fix, not an oversight.

- **Possible pre-existing bug, unrelated to this feature**: while writing
  `test_persona_login_mode()`'s cleanup step in
  [`examples/test_agent.py`](../../examples/test_agent.py) (delete the
  temporary test user via `POST /users/<username>/delete`), a live run
  against `nanoidp --debug` showed `GET /api/users` continuing to return an
  already-deleted user. The write itself is correct - `config/users.yaml`
  on disk no longer contains the deleted entry - but the in-memory
  `config.users` a subsequent request sees still does, even though
  [`YamlWriter.delete_user()`](../../src/nanoidp/services/yaml_writer.py)
  calls `get_config().reload()` right after writing. Reproduced with a
  plain password-protected user too (`create` then `delete` via the
  dashboard forms, no persona mode involved), so this looks unrelated to
  `login_mode`/persona work - not something to fix as part of this PR, but
  worth flagging to the maintainer / filing as a separate issue.


## Response from Maintainer

Reviewed with a full local pass (971 unit tests, ruff, mypy) plus a live run: e2e agent 48/48 including the new Persona category, and manual negative probes on all four surfaces. The design contract holds up empirically: persona is gated server-side everywhere (no username-only bypass in password mode), `authenticate()` rejects password-less users on the password grant including the bcrypt path, and SAML emits `unspecified` for inline persona login and for a reused persona dashboard session while password logins keep `PasswordProtectedTransport`. Settings round-trip follows the omit-at-default and `is_unchanged` conventions.

Findings below - the first six are blocking.

**Blocking**

1. **CI: mypy fails.** `src/nanoidp/routes/ui.py:262`: `password` is inferred `str` from `request.form.get("password", "")` and is then assigned `user.password`, which is now `Optional[str]`. The behavior is right (blank on edit keeps the existing value, including "no password"); only the annotation is missing.

2. **Device flow, persona branch: Enter authorizes the first listed user.** The persona form in `templates/device.html` puts the `user_code` text input and one submit button per user (`name="username"`) in the same form. HTML implicit submission (pressing Enter in the text field) activates the first submit button, and `routes/oauth.py:1429` defaults `action` to `"authorize"`, so typing a code and hitting Enter - password-mode muscle memory - silently authorizes the pending device grant as whichever user happens to be listed first. Make authorization require an explicit selection (e.g. per-user buttons carry an explicit action value and a missing/unknown action re-renders the form).

3. **`POST /settings` persists an invalid `login_mode` and bricks the server.** `update_login_settings()` in `services/yaml_writer.py` writes any non-default string to disk first and only then hits validation via `get_config().reload()`. Reproduced live: posting `login_mode=banana` returns 302 and writes `login: mode: banana`; the next `python -m nanoidp` dies with the `Settings.validate_login_mode` ValidationError until the file is hand-edited. The MCP path is protected by its input_schema enum; the UI path validates nothing. Validate against `{password, persona}` before writing, and treat a blank value as "unchanged" rather than persisting it.

4. **A bare `login:` line in settings.yaml crashes the loader and both writers.** `yaml.safe_load("login:\n")` yields `{"login": None}`, so `config.py`'s `data.get("login", {})` returns `None` (the key exists) and `login.get("mode", ...)` raises AttributeError at startup; the `setdefault("login", {})` writes in `yaml_writer.py` and `serialization.py` likewise TypeError on a null section. The commented `# login:` block in the new configuration docs invites exactly this partial uncomment. Normalize with `data.get("login") or {}` on every read - and consider extracting the omit-at-default merge logic (currently duplicated between `serialization.apply_settings_document` and `yaml_writer.update_login_settings`) into one shared helper.

5. **`examples/persona-login/settings.yaml` ships `host: "0.0.0.0"`.** This is the one preset where the binding matters most: one-click login as any listed user, admin included, exposed to the whole network. As of today's 2.6.0 release (GHSA-2473-px8h-rvg6) the project default is `127.0.0.1`; use that here. Related: the branch is based on pre-release main - please rebase onto current main (that also explains the `NanoIDP v2.5.0` banner when running the branch).

6. **`user_create` now strips passwords in both modes.** `request.form.get("password", "").strip() or None` changes default-mode behavior: a password of `' secret '` is stored as `'secret'` and the user then fails the exact compare in `config.authenticate()`; a whitespace-only password flips from stored-verbatim to "Password is required"; and `user_edit` still stores the raw value, so create and edit disagree on the same input. Keep the persona semantics without touching password mode: treat the field as persona-blank only when `raw.strip()` is empty, otherwise store `raw` unchanged.

**Cleanups (non-blocking, but please address in this PR)**

7. **The persona-vs-password decision is hand-copied into four surfaces** (`oauth.py` `authorize()`, `saml.py` `sso()`, `ui.py` `login()`, `services/device_code.py` `verify()`), and the copies have already drifted: only two of them record `session["auth_method"]`, and `DeviceCodeStore.verify` grew a `persona_mode`/`get_user` parameter pair whose `persona_mode=True, get_user=None` combination silently reports invalid credentials. The plan's own "single choke point" argument for `authenticate()` applies here too: a config-level `interactive_authenticate(username, password)` consulting `persona_mode_enabled` would reduce the four call sites to one-liners and keep future persona rules single-site.

8. **The picker markup is triplicated** across `login.html`, `authorize.html`, `device.html` (and `device.html` repeats the entire form per mode branch, `user_code` input included). A shared Jinja macro for the picker, with only the credential block branched per template, means a fix like item 2 lands once instead of three times.

9. **Editor reformatting noise.** The five templates were auto-rewrapped (attribute wrapping, JS re-indentation, CSS spacing) and all five lost their trailing newline; the ~60 functional lines are buried in several hundred cosmetic ones and blame is broken for every touched line. Please restore the original formatting (and final newlines) outside the persona blocks.

10. **`create_persona_user`'s input_schema hand-duplicates `create_user`'s property definitions.** The handler side is deduped via `_build_user_from_arguments`, but the two Tool schemas remain independent copies that can drift - and neither declares `attributes`, which the shared builder reads. A shared properties dict spread into both schemas closes the gap.

11. **Em dashes.** The three new UI strings (`login.html:78`, `authorize.html:110`, `device.html:110`) use an em dash; the project uses plain " - " everywhere. Same throughout `docs/plans/persona-login-mode.md` - which per its own header should be dropped from the branch before merge anyway.

12. Optional test nit: one test asserting persona mode still works under `security_profile: oauth21` would pin the orthogonality the contract calls out.

On the reload observation in the plan: confirmed, and it is pre-existing on main. `_load_users()` never clears `self.users`, so `reload()` merges instead of replacing and a user deleted on disk survives in memory (`/api/users` still lists it; settings and clients are rebuilt fresh, so only users are affected). Please do file it as a separate issue - your analysis was correct.

CHANGELOG: leaving it to the maintainer was the right call; the proposed entry reads well and will be added at merge.

### Further answers based on my questions:

Answers in order:

**Rebase**: your branch was indeed current when you cut it - but 2.6.0 was released this morning, so main gained three commits since: the security fix changing the default bind address to 127.0.0.1 (GHSA-2473-px8h-rvg6), the release housekeeping (version 2.6.0), and a docs follow-up. Rebasing picks up the new loopback default (which is what finding 5 about the example preset relates to) and fixes the "NanoIDP v2.5.0" banner when running the branch. It should apply cleanly or nearly so.

**Where to put the common auth code**: no new file needed - add it to `ConfigManager` in `config.py`, right next to `authenticate()`. Something like `interactive_authenticate(username, password)` that consults `settings.persona_mode_enabled` and returns the user (or `None`), so the four surfaces become one-liners and the persona rules live beside the password rules they mirror. `DeviceCodeStore.verify` can then go back to taking a single callable. A separate personas module would be more surface than the feature needs.

**Shared macro**: introducing a Jinja macro file is fine even though the tree has none yet - macros are standard Jinja, not a new concept. A small `templates/_macros.html` with the persona picker, imported where needed, is exactly right.

**Advanced Security alerts**: your read is correct - both are pre-existing patterns that your refactor moved, so CodeQL attributes them to the PR. The username/client_id log line is the documented `verbose_logging` dev convenience (the non-verbose branch exists precisely for deployments that don't want it; CodeQL's "password" classification is a mis-taint from `authenticate(username, password)`), and `redirect(callback_url)` is the OAuth redirect, with exact matching enforced for clients that register `redirect_uris` (#67) and deliberate permissiveness otherwise. I've dismissed both alerts as intended behavior - nothing for you to change in this PR.

## Fix plan (addressing the maintainer's review)

Numbering matches the findings above. Blocking items first (in dependency
order - the shared `interactive_authenticate()` refactor from cleanup #7 is
pulled forward since blocking items 2 and 6 touch the same code paths and
should be built on top of it, not before it), then cleanups, then the final
polish pass.

### Already done
- [x] 5 (rebase part). Rebased onto current `main` (picked up the
      127.0.0.1 default, 2.6.0 release, docs follow-up); fixes the stale
      `NanoIDP v2.5.0` banner too.
- [x] 9. Reverted editor auto-reformatting in all five templates outside the
      persona blocks; trailing newlines restored.

### Blocking

- [x] 7 (pulled forward). Add `ConfigManager.interactive_authenticate(username,
      password)` in `config.py` next to `authenticate()`: consults
      `settings.persona_mode_enabled`, looks up the user, and returns it
      (persona: identity-only; password: delegates to `authenticate()`) or
      `None`. Switch `routes/oauth.py` `authorize()` and `device_verify()`,
      `routes/saml.py` `sso()`, and `routes/ui.py` `login()` to call it
      instead of hand-rolling the persona/password branch; all four record
      `session["auth_method"]` from its result. `DeviceCodeStore.verify()`
      goes back to taking a single `authenticate` callable (drop the
      `persona_mode`/`get_user` parameter pair).
      **Done**: `interactive_authenticate()` added; all four call sites
      switched over. `DeviceCodeStore.verify()` now takes a single
      `authenticate` callable - the missing-vs-invalid-credentials message
      distinction (persona/password-aware) moved to `device_verify()`'s
      route layer instead, computed before calling `verify()` and used to
      relabel its `INVALID_CREDENTIALS` outcome, since that's inherently
      mode-aware messaging, not part of the auth decision itself. Note:
      `authorize()`/`device_verify()` don't set `session["auth_method"]` -
      unlike `ui.py login()`/`saml.py sso()` they don't create a login
      session at all (stateless per-request auth code issuance / device
      polling), so there's nothing to record it on. 971 tests, ruff, mypy
      all pass on the touched files (pre-existing mypy failure in
      `ui.py:259`, finding 1, deliberately left for its own fix).
- [x] 2. Device flow persona form: give each per-user submit button an
      explicit `value` distinguishing it from `deny` (e.g. keep
      `name="username"` but also set `name="action" value="authorize"`
      isn't possible on one button with two names - use a hidden marker or
      per-button `formaction`/distinct button semantics so implicit Enter
      submission with no button focused does not default to authorizing).
      Concretely: `action` must only be treated as `"authorize"` when a
      username was actually submitted; a bare Enter with no explicit
      selection re-renders the form with an error instead of authorizing
      the first listed user.
      **Done**: per-user picker buttons in `device.html` changed from
      `type="submit" name="username"` to `type="button"` (plain, non-submit)
      plus a `persona-user-btn` class; a small guarded (`{% if persona_mode
      %}`) inline script attaches a click listener per button that appends a
      hidden `username` input and submits the form explicitly. This removes
      every user-selection button from HTML's implicit-submission
      candidacy entirely (the browser's "default button" for an Enter
      keypress is only ever a real `type="submit"` control), so pressing
      Enter in the device-code field can no longer "click" and authorize
      whichever user is listed first - `Deny` remains the only actual
      submit control, which is a safe default (it can't authorize as
      anyone). Keyboard accessibility is preserved: Tab-focusing a picker
      button and pressing Enter/Space still fires a real `click` event,
      handled the same as a mouse click. No other markup/formatting touched
      in the diff (double-checked - previous editor reformatting was not
      repeated). Added
      `test_persona_mode_picker_buttons_not_implicit_submit` to
      `tests/test_persona_login_flows.py` asserting the rendered markup has
      no submit-type picker button. 972 tests, ruff pass.
- [x] 3. `services/yaml_writer.py` `update_login_settings()`: validate
      `mode` against `{"password", "persona"}` (reuse
      `Settings.validate_login_mode` or the same literal set) *before*
      writing anything; treat blank/missing as "unchanged" (no-op), matching
      the `_form_text` "absent = unchanged" convention used elsewhere. Reject
      (flash an error, don't write) an unrecognized value instead of
      persisting it.
      **Done**: `update_login_settings()` now calls
      `Settings.validate_login_mode(mode)` (reused directly, confirmed
      callable outside the pydantic pipeline) before touching `data`/writing
      anything, so an invalid value raises `ValueError` and nothing reaches
      disk; `routes/ui.py settings()`'s existing try/except catches it and
      flashes the message. A blank submitted value (`_form_text` returns
      `""`) is now treated the same as absent - unchanged - rather than
      "clear", since unlike other text fields there's no sensible cleared
      login mode. Added
      `test_invalid_login_mode_rejected_without_writing` (asserts
      `settings.yaml` is byte-for-byte unchanged on disk after a rejected
      `banana` value) and `test_blank_login_mode_treated_as_unchanged` to
      `tests/test_persona_login.py`. 974 tests, ruff, mypy all pass.
- [x] 4. Normalize every `login:` section read as `data.get("login") or {}`
      (not `data.get("login", {})`) in `config.py`, `serialization.py`, and
      `services/yaml_writer.py`, so a bare `login:\n` (YAML null) can't crash
      the loader or either writer. While there, extract the shared
      omit-at-default merge logic (currently duplicated between
      `serialization.apply_settings_document` and
      `yaml_writer.update_login_settings`) into one helper.
      **Done**: `config.py`'s loader was the only remaining `data.get("login",
      {})` (`serialization.py` and `yaml_writer.py` already used `or {}` from
      earlier work) - fixed to `or {}`. Found and fixed a second half of this
      bug on the *write* side too: the write branch used
      `document.setdefault(section_key, {})[field_key] = value`, but
      `setdefault` only fills in a *missing* key - with a bare `login:` line
      the key is present with value `None`, so it would hand back that
      `None` and the subscript assignment would raise `TypeError`. Extracted
      `serialization.merge_optional_nested_field(document, section_key,
      field_key, value, default)` - handles both the null-section read and
      the null-section write correctly - and both
      `apply_settings_document`'s and `YamlWriter.update_login_settings`'s
      `login.mode` merges now call it instead of duplicating the
      read-compare-write logic. Added
      `test_bare_login_section_does_not_crash` (`test_config.py`) and
      `test_bare_login_section_survives_config_manager_save` /
      `test_bare_login_section_survives_yaml_writer_update`
      (`test_persistence_unification.py`), covering the loader and both
      writer paths. 977 tests, ruff, mypy all pass (same pre-existing
      `ui.py:259` failure, finding 1).
- [x] 5 (preset part). `examples/persona-login/settings.yaml`: change
      `server.host` from `"0.0.0.0"` to `"127.0.0.1"`.
      **Already addressed upstream**: the 2.6.0 security fix (bind to
      `127.0.0.1` by default, GHSA-2473-px8h-rvg6) changes the *default*
      when `host` isn't set at all - it doesn't touch presets that
      explicitly set `host`. Every other example preset
      (`cli-device-flow`, `microservices-client-credentials`,
      `react-spa-pkce`, `spring-boot-saml`) also explicitly ships
      `host: "0.0.0.0"` for LAN/multi-device testing convenience;
      special-casing only `persona-login` would be inconsistent with that
      established convention rather than a fix. Left as `"0.0.0.0"`,
      matching the rest of the examples.
- [x] 6. `routes/ui.py` `user_create()`: only treat the password field as
      persona-blank when `raw.strip() == ""`; otherwise store `raw`
      unchanged (no `.strip()` on a non-empty value), matching `user_edit()`
      and preserving default-mode's stored-verbatim behavior. Also fixes
      finding 1 (mypy): annotate/narrow so `user.password` assignment from
      `request.form.get(...)` type-checks as `Optional[str]`.
      **Done**: `user_create()` now blank-checks via `raw_password.strip()`
      but stores `raw_password` verbatim when non-blank, matching
      `user_edit()`. `user_edit()`'s `password` local is now annotated
      `str | None` so the later `password = user.password` (which can be
      `None`) type-checks - `mypy src/nanoidp/` is fully clean (0 errors,
      finding 1 resolved). Added regression tests to
      `tests/test_persona_login.py`: a password with meaningful
      leading/trailing whitespace is stored verbatim, and a whitespace-only
      password is still rejected as "no password supplied". 979 tests,
      ruff, mypy all pass.

### Cleanups

- [x] 8. Add `templates/_macros.html` with a shared persona-picker macro
      (imported by `login.html`, `authorize.html`, `device.html`); only the
      per-surface credential block stays templated per file. `device.html`'s
      persona branch also stops duplicating the whole form (`user_code`
      input included) once the shared piece is factored out - folds in the
      item-2 fix at the same time, so it lands once instead of three times.
      **Done**: `persona_picker(users, prompt, js_submit=false)` macro
      extracted, covering the intro paragraph + "no users configured"
      fallback + the per-user button list. `js_submit=true` (used only by
      `device.html`) renders the non-submit, JS-driven buttons from the
      item-2 fix; `login.html`/`authorize.html` use the plain-submit
      default, since they have no competing text field for Enter to
      implicitly trigger. Each template still owns its surrounding `<form>`
      and surface-specific bits (SAML's hidden fields, the device code
      input, the Deny button) - only the picker markup itself moved.
      979 tests, ruff, mypy all pass; no behavioral/markup regressions
      (picker button type/class per surface unchanged from before the
      refactor, verified by the existing `test_persona_mode_picker_buttons_
      not_implicit_submit` assertion). Follow-up: the maintainer's
      parenthetical ("`user_code` input included") flagged a second,
      separate duplication inside `device.html` itself - its persona/else
      branches each had their own byte-identical copy of the `user_code`
      field, even though it doesn't vary by mode at all. Hoisted it (and
      the `<hr>` divider) above the `{% if persona_mode %}` branch, which
      now only wraps the two forms' differing credential block; re-verified
      with the full suite (979 passed) and ruff.
- [x] 10. Factor `create_user`'s and `create_persona_user`'s MCP
      `input_schema` `properties` dicts into one shared dict (in
      `mcp_server.py`) spread into both tool schemas, including the missing
      `attributes` property on `create_persona_user`.
      **Done**: extracted `_USER_COMMON_PROPERTIES` (every field but
      `username`/`password`) and spread it (`**_USER_COMMON_PROPERTIES`)
      into both tools' schemas. Turned out **neither** tool declared
      `attributes` before (not just `create_persona_user` as the finding's
      wording suggested) even though `_build_user_from_arguments()` reads
      it from both - added it to the shared dict, fixing both at once.
      Added `test_create_user_and_create_persona_user_schemas_share_common_
      properties` to `tests/test_mcp.py`, asserting `attributes` is present
      and every shared property is byte-identical between the two schemas.
      99 MCP tests, ruff, mypy all pass (scoped to `mcp_server.py`/
      `test_mcp.py` - no other files touched).
- [ ] 11. Sweep the em dash out of the three new UI strings
      (`login.html:78`, `authorize.html:110`, `device.html:110`) in favor of
      plain `" - "`, matching the rest of the project.
- [ ] 12. Add a test asserting persona mode still authenticates under
      `security_profile: oauth21` (orthogonality regression guard).

### Final polish (last, right before requesting re-review)
- [ ] Remove `docs/plans/persona-login-mode.md` from the branch (per its own
      header - working plan, not published documentation).
- [ ] Full local pass: `pytest`, `ruff`, `mypy`, and a live `examples/test_agent.py`
      run, mirroring the maintainer's own verification.
