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

## Not "just a UI change" — scope clarification

Passwords never appear in issued tokens/assertions
([`User.to_dict()`](../../src/nanoidp/models.py#L92) excludes `password`), so
persona mode has **no token-payload impact**. But two things beyond the login
template genuinely need code changes:

- The "username and password required" check lives server-side in each of
  the 4 route handlers, not just in the HTML form. In `persona` mode the fix
  isn't to drop that check — it's to skip `authenticate()` entirely and go
  straight to `config.get_user(username)` (pure identity selection, no
  credential check), gated on `login_mode`. That's 4 separate call sites:
  [`routes/ui.py`](../../src/nanoidp/routes/ui.py#L71-L76),
  [`routes/oauth.py`](../../src/nanoidp/routes/oauth.py#L298-L301),
  [`routes/saml.py`](../../src/nanoidp/routes/saml.py#L450-L453),
  [`device_code.py verify()`](../../src/nanoidp/services/device_code.py#L176-L178).

  The common shape for all 4 (the `password`-mode branch is byte-for-byte
  today's existing code, so backward compatibility is trivially provable):

  ```python
  if config.settings.persona_mode_enabled:
      # persona: identity only, no credential check
      if not username:
          return redirect(url_for("ui.login", error="Select a user"))
      user = config.get_user(username)
  else:
      # existing behavior, unchanged
      if not username or not password:
          return redirect(url_for("ui.login", error="Username and password required"))
      user = config.authenticate(username, password)
  ```
- SAML's `AuthnContextClassRef` is hardcoded to `PasswordProtectedTransport`
  at [`routes/saml.py`](../../src/nanoidp/routes/saml.py#L267) regardless of
  how the user authenticated. This isn't about the password value — it's a
  claim to the SP about the *authentication method*, which SPs may use for
  step-up-auth decisions. A persona login must not claim
  `PasswordProtectedTransport`; this requires threading an auth-method
  signal (e.g. `session["auth_method"]`) from login time through to the
  assertion builder. (For comparison: OIDC ID tokens here don't emit
  `acr`/`amr` claims at all, so there's no equivalent false-claim risk on
  that side.)

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
- [ ] [`templates/settings.html`](../../src/nanoidp/templates/settings.html)
      + save route: `login_mode` toggle in the dashboard.

### 7. E2E coverage + docs (last)
- [ ] [`examples/test_agent.py`](../../examples/test_agent.py): persona-mode
      scenario across all 4 surfaces.
- [ ] Docs together: `book/src/reference/configuration.md`,
      `docs/SECURITY.md`, `README.md`, `CHANGELOG.md`.

## Sequencing rationale

Steps 1-2 are safe standalone (password-less users just can't log in yet —
no UI exposes it). Step 3 delivers one working vertical slice
(nanoidp `/login`) to validate the pattern before repeating it 3x in step 4.
Steps 5-7 close out the "ships whole" checklist last, once behavior is
stable.

## How this gets tested

No dedicated interactive test harness exists for this repo — testing is
layered:

1. **Manual/interactive**: run `nanoidp --debug` (or `docker-compose up`),
   configure a password-less user + `login.mode: persona` in
   `config/users.yaml` / `config/settings.yaml`. There's no admin-UI nav
   link to the login page ([`base.html`](../../src/nanoidp/templates/base.html#L284)
   only shows a "Logout" button once authenticated), so each surface needs
   reaching directly:
   - `/login` — browse to it directly, no setup needed.
   - `/authorize` — hand-craft a URL, e.g.
     `http://localhost:8000/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:9999/cb&scope=openid&state=x`
     (`redirect_uri` doesn't need to resolve to anything for a visual check).
   - `/device` — `curl -X POST localhost:8000/device_authorization -d client_id=demo-client`
     for a `user_code`, then browse to `/device?user_code=XXXX-XXXX`.
   - `/saml/sso` — `SAMLRequest` is DEFLATE-compressed + base64, impractical
     to hand-type. Reuse the AuthnRequest-building code already in
     `test_saml_sso_redirect_binding`
     ([`examples/test_agent.py`](../../examples/test_agent.py#L1670-L1712))
     in a throwaway script that prints a ready-to-open URL, instead of
     standing up the full `examples/spring-boot-saml` sample.
   The dashboard's `/test` "Token Tester" page
   ([`templates/test.html`](../../src/nanoidp/templates/test.html)) is also
   useful for manually generating tokens for a selected user.
2. **Scripted e2e against a running server** (not interactive, but
   end-to-end): [`examples/test_agent.py`](../../examples/test_agent.py)
   drives every OAuth/OIDC/SAML/device flow over HTTP; extended in step 6
   with a persona-mode scenario.
   [`examples/mcp_smoke_test.py`](../../examples/mcp_smoke_test.py) exercises
   the real `nanoidp-mcp` stdio server end-to-end.
3. **Unit/integration suite** (bulk of coverage, no live server): `pytest`
   against `tests/*.py` using Flask's test client — this is where most of
   steps 1-5 get verified (form posts, session state, SAML assertion XML,
   MCP tool dispatch).

## To be mentioned when submitting the PR

- `authenticate()` ([`config.py`](../../src/nanoidp/config.py)) previously
  assumed `user.password` was always a string. With `password` now optional,
  the bcrypt path (`password_hashing: true`) would have raised
  `AttributeError` on `None.encode()` for a password-less user. Fixed with an
  explicit `user.password is None` short-circuit before the hashing branch —
  worth flagging as a deliberate fix, not an oversight.
