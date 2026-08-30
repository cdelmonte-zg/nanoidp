# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

This release tightens and unifies nanoidp's OAuth **client-authentication
contract**. A confidential client that already presents its registered method
over the matching channel, and any public client, are unaffected; a client that
authenticated over a different channel at one of these endpoints - which the
previous leniency allowed - needs a one-time adjustment.

- **The registered `token_endpoint_auth_method` is now enforced at every
  client-authenticated endpoint** (#188, #262): `/token`, `/introspect`,
  `/revoke` and `/device_authorization`.
  - A **confidential client must authenticate on `authorization_code`** too -
    the code exchange no longer has a client-authentication exemption (RFC 6749
    §3.2.1). *Migration:* present the client secret on the code exchange, or
    re-register the client as `token_endpoint_auth_method: "none"` if it cannot
    keep a secret (and use PKCE).
  - The registered method decides the **channel**: a `client_secret_basic`
    client must use HTTP Basic and a `client_secret_post` client must use the
    request body - the wrong channel is rejected with `invalid_client`.
    Previously a body secret was accepted (or silently ignored) regardless of
    the registered method. Applying the one registered method across all four
    endpoints is nanoidp's **consistency policy**: RFC 7009 and RFC 8628 tie
    `/revoke` and `/device_authorization` to the token-endpoint method, while
    RFC 7662 permits client authentication at `/introspect` but does not mandate
    reusing that method - so a client that legitimately used a different channel
    for introspection stops working here by nanoidp's choice, not because it was
    non-compliant. *Migration:* send credentials over the channel the client is
    registered for; set `token_endpoint_auth_method` to match how your client
    actually authenticates.
  - **Two authentication methods in one request are rejected** (HTTP Basic and a
    body `client_secret` together, RFC 6749 §2.3) - Basic no longer silently
    wins. *Migration:* send credentials one way only.
  - Public-client policy: `/introspect` refuses public clients (RFC 7662),
    `/revoke` keeps its RFC 7009 §2.1 ownership relaxation, and
    `/device_authorization` now accepts a public client by client_id alone
    (RFC 8628, see the device-flow entry below).
- **`/authorize` reports errors after `redirect_uri` validation by redirecting
  to the client** (#189, RFC 6749 §4.1.2.1 / RFC 9207): `unsupported_response_type`,
  `invalid_scope`, PKCE errors and `invalid_target` are now `302` redirects
  carrying `error`, `error_description`, `state` and `iss`, not a local JSON
  `400`. Errors before `redirect_uri` is validated (unknown client,
  missing/malformed/unregistered `redirect_uri`) still return JSON locally.
  *Migration:* a client that parsed the `400` body should read the error from
  the redirect query instead - which is what a spec-compliant client already does.
- **A refresh token without a `client_id` binding claim is rejected** (#73,
  `invalid_grant`, RFC 6749 §5.2). The binding was added in 2.2.0 (#56);
  tokens minted before it were still spendable by any authenticated client
  until they expired - a transitional compat deferred to the next major, now
  closed. *Migration:* discard refresh tokens minted before 2.2.0 and obtain
  new ones (every grant since 2.2.0 already binds them). The MCP `generate_token`
  tool gains an optional `client_id` (which must name a real client) that binds
  the minted token and issues a refresh token spendable by it; without it the
  tool mints an unbound access token with no refresh token at all, rather than
  hand back one that could not be spent. The HTTP testing endpoint
  `POST /api/users/<username>/token` gets the same treatment - a new optional
  `client_id` binds the token, and it no longer returns a `refresh_token` when
  unbound - so all three token minters (a grant, the MCP tool, this endpoint)
  agree.

### Added
- **Horizontal `/authorize` login card composition** (#249). New per-client
  `layout` field, `"vertical"` (default, unchanged) or `"horizontal"`: the
  latter places the client info block and the login form side by side in a
  Bootstrap two-column split, with the header and footer still full width,
  collapsing back to the single-column stack on narrow viewports. One of
  exactly two nanoidp-owned layouts - no per-client CSS or column widths.
  Full support across settings.yaml, the UI client form, and the MCP
  `create_client`/`update_client` tools; omitted (or `"vertical"`) writes
  nothing to YAML, matching every other default-valued client field.
- **Public clients on the device flow** (#255, RFC 8628). A public client
  (`token_endpoint_auth_method: "none"`) can now use the device authorization
  grant: it presents its `client_id` alone at `/device_authorization` (§3.1)
  and again when polling `/token` (§3.4), with no secret. The issued
  `device_code` is bound to that `client_id` and only it can redeem it, which
  stands in for client authentication (it presents client_id as a parameter,
  not via HTTP Basic or a secret, RFC 8628 §3.1; both are rejected). Confidential
  clients still authenticate as before; #188 shipped public clients for
  authorization_code + PKCE, and this completes the pair for CLI/TV/IoT-style
  clients. Because an unauthenticated device authorization request is cheaper to
  spam, the in-memory device-code store is now capacity-bounded: at the cap it
  returns a plain `503` (with `Retry-After`) rather than growing without bound or
  evicting a live authorization - not an OAuth error code, since RFC 6749 §5.2
  has no registered code for server saturation.
- **Mock protected MCP server as an e2e fixture** (#191). `e2e/mock_mcp_server.py`
  is a minimal MCP Streamable HTTP resource server (the `mcp` SDK's
  resource-server mode) with three scope-gated tools (`read_document` /
  `documents:read`, `delete_document` / `documents:write`, `admin_operation`
  / `admin`). It validates bearer tokens JWKS-only against nanoidp (signature,
  `iss`, `aud` == its own resource URL, `exp`, scopes), serves the RFC 9728
  `/.well-known/oauth-protected-resource` document naming nanoidp as its
  authorization server, and answers an unauthenticated call with `401` +
  `WWW-Authenticate` pointing at that metadata. It demonstrates two
  authorization layers, kept distinct: a resource-level scope floor
  (`documents:read`), enforced by the SDK's bearer middleware, which returns
  the conformant MCP/RFC 9728 `403` `WWW-Authenticate: Bearer
  error="insufficient_scope"` + `resource_metadata` challenge before any tool
  runs; and an application-level per-tool check inside each tool for the finer
  `documents:write` / `admin` operations, which surfaces as an in-band MCP
  tool error. `e2e/test_agent.py` gains an `--mcp` suite that drives the
  whole loop deterministically as the MCP client (401 -> RFC 9728 discovery ->
  `/authorize` with PKCE and `resource=` -> `/token` -> `tools/call`):
  delegated login as a PUBLIC client (PKCE, no secret) yielding a
  resource-bound token accepted for a scoped tool; a wrong-audience token
  rejected with `401` at the transport (asserted at the HTTP layer); the
  conformant `403` insufficient-scope challenge; the application-level
  per-tool refusal; a refresh token that cannot be widened in scope on refresh
  (RFC 6749 §6); a client_credentials workload; a token revoked at nanoidp
  still accepted by the JWKS-only server until `exp` (the documented
  consequence of self-contained tokens); and a pre-rotation token still
  verifying after a key rotation, with the test asserting nanoidp retains the
  previous key's `kid` in its published JWKS. Adds the `mcp-public-client`
  (`token_endpoint_auth_method: none`) to the example config. New guide
  "Testing an MCP client against nanoidp". This is the deliverable that ties
  #186 (scopes), #187 (resource indicators) and #188 (public clients)
  together into a demonstrable OAuth/MCP round trip.
- **RFC 9207: `iss` on the authorization response** (#189). `/authorize`
  returns `iss=<effective issuer>` on every response delivered through a
  validated `redirect_uri` - success and error alike - so a client can
  detect an authorization-server mix-up (MCP 2026-07-28 recommends this).
  The value is the per-request effective issuer, so it stays correct under
  `issuer_from_request` (#126). `iss` is delivered exactly when discovery
  advertises `authorization_response_iss_parameter_supported`: one
  condition drives both, so metadata and behaviour never disagree. RFC
  9207 requires an `https` issuer with a host and no query or fragment, so
  the default `http://localhost:8000` sends no `iss` and advertises
  `false`; point the issuer at `https` (directly or reflected via
  `issuer_from_request` behind a TLS proxy) to turn RFC 9207 on. **Related
  behaviour change**: authorization errors that occur after the
  `redirect_uri` is validated (invalid_scope, PKCE errors, invalid_target)
  are now OAuth error redirects to the client (`error`,
  `error_description`, `state`, `iss`) instead of a local JSON 400, per
  RFC 6749 §4.1.2.1 - completing the RFC 9207 "error responses too"
  requirement. `unsupported_response_type` (a non-`code` `response_type`)
  is validated after the `redirect_uri` too, so it redirects as well.
  Errors before the `redirect_uri` is trusted (unknown client, malformed
  or unregistered `redirect_uri`) stay local JSON. A `redirect_uri` that
  carries its own query keeps it: the response parameters are appended,
  never fold into an existing value. The device flow is unaffected.
- **RFC 8707 Resource Indicators: `resource` binds the access token
  audience** (#187). A client may send one or more `resource` parameters
  on `/authorize`, `/token` (every grant) and `/device_authorization`;
  the access token's `aud` is then those resources (a plain string for
  one, an array for several) instead of the global `oauth.audience`, so a
  token minted for one MCP server is rejected by another and a
  wrong-audience test can finally be written. A `resource` must be an
  absolute URI without a fragment or the request is `invalid_target`
  (RFC 8707 §2). New per-client `allowed_resources` gates which resources
  a client may target (empty = any valid resource, the dev default, same
  "empty = unrestricted" convention as `allowed_scopes`). The
  authorization code and refresh token remember the bound resources; a
  `/token` request may narrow them to a subset but never widen them.
  Narrowing the access token does not narrow the refresh token, which keeps
  the full original grant so a later refresh can still request any resource
  the authorization covered (RFC 8707 §2.2).
  Sending no `resource` leaves `aud` at `oauth.audience` - **no change
  for existing clients**. `/introspect` reports the token's `aud`, and
  now verifies a token's signature without pinning its audience (so a
  resource-bound token can be introspected and revoked); `/userinfo`
  still requires the OP audience. No `resource_indicators_supported`
  discovery metadata (RFC 8707 defines none). Full support across
  settings.yaml (`allowed_resources`), the UI client form and the MCP
  `create_client`/`update_client` tools.
- **Public clients: `token_endpoint_auth_method: "none"` with mandatory
  PKCE S256** (#188). A client that cannot keep a secret (CLI, desktop
  app, SPA, MCP client) can now be declared with
  `token_endpoint_auth_method: "none"`: `client_secret` becomes optional
  (ignored - and never a credential - if present), and `/token`
  identifies the client by `client_id` alone. The protections that stand
  in for client authentication are enforced regardless of profile:
  `/authorize` requires PKCE with `S256` (OAuth 2.1 §7.5.1),
  `client_credentials` is refused with `unauthorized_client`, and
  refresh tokens always rotate with reuse detection (OAuth 2.1
  §4.3.1/§6.1) whatever `refresh_token_rotation` says. `/revoke` accepts
  a public client's `client_id` with an ownership check (the token's
  `client_id` claim must match; otherwise still `200`, nothing revoked -
  RFC 7009 §2.1 and its privacy guidance). `/introspect` deliberately
  stays authenticated (RFC 7662) and its discovery list does not gain
  `none`; the token and revocation lists do. Full support across
  settings.yaml, the UI client form, and the MCP
  `create_client`/`update_client` tools (`client_secret` no longer
  required when the method is `none`). At `/token` the registered method
  is **enforced**, not just recorded (RFC 7591): a `client_secret_basic`
  client must present its secret over HTTP Basic and a
  `client_secret_post` client in the request body - the wrong channel is
  rejected with `invalid_client`. `client_secret_post` is now validated
  at `/token`, `/introspect`, `/revoke` and `/device_authorization`;
  discovery had advertised it forever while the body secret was silently
  ignored. (The three non-token endpoints accept a confidential secret
  over either channel; only `/token` enforces the registered method.)
  Confidential clients now authenticate on **every** grant, including
  `authorization_code` (RFC 6749 §3.2.1): the code exchange no longer had
  a client-authentication exemption - a confidential client doing
  `authorization_code` + PKCE must now present its secret or be
  re-registered as `token_endpoint_auth_method: none`. And **access
  tokens carry a `client_id` claim** (RFC 9068 §2.2) binding them to the
  client they were issued to, as refresh tokens have since 2.2.0.

### Changed
- **The end-to-end test harness moved from `examples/` to a dedicated `e2e/`
  directory.** `test_agent.py`, `mock_mcp_server.py`, `mcp_smoke_test.py` and
  `gen_sp_keypair.py` now live under `e2e/`; `examples/` keeps only the real
  usage examples (client integrations, plugins). The harness was never a
  usage example - it is the CI end-to-end suite - and mixing the two made the
  repository harder to read. Invocations change from `python examples/...` to
  `python e2e/...` (CI, CONTRIBUTING and the docs are updated); no behaviour
  and no packaged code changed.
- **Resource indicators are validated per RFC 3986 component, not by a single
  character whitelist** (#257). A `resource` is still an absolute URI without a
  fragment (RFC 8707 §2), but each component is now checked against its own
  ABNF: `[`/`]` are accepted only inside an IP-literal host (so
  `https://host/a[b]` is rejected where it used to pass), a port is `*DIGIT`
  (no numeric-range limit, matching RFC 3986 §3.2.3), and IPv6 host literals
  are validated (a scoped `[fe80::1%eth0]` is rejected: RFC 3986 IPv6address
  has no ZoneID, per RFC 9844). Mostly a tightening on malformed input to an
  opt-in feature; it also stops rejecting a valid path-empty absolute URI
  (RFC 3986 §3, e.g. `about:`). No audience bypass or escalation.

## [2.8.0] - 2026-08-29

### Fixed
- **MCP `update_user` can now update custom `attributes`** (#280): the field
  was accepted by `create_user` and returned by every read surface, but the
  `update_user` schema and handler silently lacked it - an agent could set
  attributes at creation and never change them again. The new mapping
  replaces the whole `attributes` object, like every other field there.
- **`get_crypto_service` honours `keys_dir` on every call** (#281): once the
  singleton existed the argument was silently ignored, so a config reload
  that changed `keys_dir` kept signing tokens and serving JWKS from the old
  directory. The service is now recreated when the requested directory
  differs; operator-provided external keys (`init_crypto_service`) stay
  authoritative and are never discarded over a `keys_dir` change.
- **The wizard and `init` write configuration atomically and validated**
  (#282): both used to write raw template text with `open()`, bypassing the
  temp-then-replace primitive every other config writer uses - a crash could
  leave a torn file, and a template error reached disk unvalidated. Both now
  validate through the document models before anything touches disk.
- **`client_credentials` no longer returns a refresh token** (#239). RFC
  6749 §4.4.3: "A refresh token SHOULD NOT be included" - the client
  authenticates itself on every request, and the token handed out was a
  second, 7-day credential bound to the default user (or the synthetic
  service account) that the grant never authenticated, spendable at
  `grant_type=refresh_token` for user-context tokens. The response now
  has no `refresh_token` key at all; every other grant is unchanged. A
  client that refreshed a client-credentials token must request a new
  one with its credentials, which is what the RFC asks of it.
- **/saml/sso rejects a request with nowhere to send the assertion** (#227):
  an AuthnRequest without `AssertionConsumerServiceURL` against a config
  whose `saml.default_acs_url` is blank now gets a 400 naming both missing
  sources (with a failed `saml_request` audit entry), instead of rendering
  an auto-submit form posting to `action=""` - the IdP's own page.
- **`client_credentials` no longer 500s when `default_user` names a missing
  user** (#241): the synthetic `service-account` fallback was built with an
  empty password, which `User` rejects since #158 made `password` optional
  with `min_length=1`. The fallback now carries no password, as it never
  authenticates with one, and the grant answers with `sub=service-account`
  again.
- **The dashboard's Logout button logs the UI session out again** (#221).
  The UI logout route registered the same `/logout` rule as the OIDC
  end-session endpoint and always lost: clicking Logout landed on the
  end-session confirmation page and the UI logout audit event was never
  written. The UI logout now lives at `GET /ui/logout` (the button follows
  automatically via `url_for`), redirects back to the dashboard, and writes
  its `logout` audit event; `/logout` (alias `/end_session`) remains the
  OIDC endpoint, unchanged.
- **Regenerating a client secret no longer resets the client's branding**
  (#213 review): `/clients/<id>/regenerate-secret` rebuilt the client with
  only five fields, silently dropping `background_color`, `header_color`
  and `footer_color` and resetting `show_client_id`/`show_description` to
  their defaults - the same rebuild-by-hand shape that lost
  `additional_audiences` in #32. The route now copies the client and
  changes only the secret, so every field (present and future) is carried.

### Added
- **MCP callers can make `save_config` conflict-checked** (#229 phase 5,
  the MCP leg of the same loop the web UI's forms got in phase 4): the
  read tools return the revision of the file the runtime was loaded
  from (`list_users`/`get_user` carry `users_revision`;
  `list_clients`/`get_client`/`get_settings` carry `settings_revision`),
  and `save_config` accepts them back as `expected_users_revision` /
  `expected_settings_revision`, refusing the save with
  `{"success": false, "kind": "conflict"}` - nothing written - when
  another writer (the web UI, another agent, a second nanoidp process
  on the same directory) moved a file since. `reload_config` and a
  successful `save_config` return fresh revisions, so the retry loop is
  reload, reapply, save. The revision is deliberately the one the
  runtime was LOADED from, not the file's hash at ask time: on a
  runtime that is stale against the directory, a fresh disk hash would
  pass the precondition exactly when the lost update is real. Because
  `save_config` always writes both files, there are exactly two modes:
  omitting both revisions keeps the save unconditional (last write
  wins, same as before), and supplying either makes the whole save
  conflict-checked, with the omitted revision defaulting to the one
  this runtime was loaded from - a save guarded on one file can never
  silently overwrite the other from a stale snapshot.
- **Display-only `description` on users, shown in the persona login
  picker** (#244): a user in `users.yaml` can carry an optional
  `description` (max 200 characters, plain text) rendered next to the
  username on every interactive persona picker (`/login`, `/authorize`,
  `/saml/sso`, the device flow's `/device`), so a directory of test
  personas (`admin`, `reader`, `tenant-a-manager`, ...) is
  self-explanatory at the point of selection. It is a first-class field,
  not a custom attribute: never a claim, never a SAML attribute, never
  part of a token. Settable from the UI create/edit form and the MCP
  `create_user`/`create_persona_user`/`update_user` tools, and exposed
  by the read-only `/api/users` responses.
  `User` now validates on assignment as well (`validate_assignment=True`,
  the rule `OAuthClient` has followed since #37), and the MCP
  `update_user` tool applies every requested field to a scratch copy
  before replacing the live user, so one invalid field can no longer
  leave the user half-updated. Behaviour change for an existing file: a
  `description:` key already present under a user used to fold into that
  user's `attributes` and therefore shipped inside the token's
  `attributes` claim; it is now the display-only field and no longer
  appears in any token.
- **Per-client allowed scopes and `invalid_scope`** (#186). `oauth.scopes_supported`
  is the global scope vocabulary (default `openid`, `profile`, `email`,
  `offline_access`, also what discovery's `scopes_supported` now advertises
  instead of a hardcoded list); a client's new `allowed_scopes` is an
  optional subset of it. A requested scope outside the vocabulary is
  `invalid_scope` for every client - a small behavior change, since any
  scope string used to be accepted unchecked; a scope outside a client's own
  `allowed_scopes`, when set, is `invalid_scope` for that client
  specifically. Enforced at `/authorize`, every `/token` grant (including
  `client_credentials`, RFC 6749 §4.4, which previously dropped any
  requested scope entirely) and `/device_authorization`; an omitted `scope`
  defaults to the client's full allowed set, or today's default when
  unrestricted. Every `/token` rejection - including the pre-existing
  refresh-token scope-narrowing check - now returns the RFC 6749 §5.2 JSON
  error shape (`{"error": "invalid_scope", ...}`) instead of a bare 400.
  `oauth.scope_enforcement: false` is a dev-only escape hatch back to the
  pre-#186 behavior (any scope string accepted, unchecked); refused outside
  the `dev` profile. `allowed_scopes` is settable from the clients UI form
  and the MCP `create_client`/`update_client` tools, same as
  `additional_audiences`/`redirect_uris`.

### Changed
- **`ConfigManager.save()` writes `users.yaml` and `settings.yaml` as one
  coordinated, conflict-checked save** (#229): both files' preconditions (an optional
  content-hash revision per file, for a future caller that supplies one)
  are checked before either file is written, both are then written, both
  fire their own `on_config_saved` hook, and the running configuration is
  refreshed from disk exactly once before any `hooks.strict` failure is
  raised - matching the `write -> notify -> reload_local -> raise`
  contract the web UI's writer already had. Previously a hook failure on
  `users.yaml` under `hooks.strict` left `settings.yaml` unwritten even
  when nothing was actually wrong with it; now a hook failure on either
  file still raises, but by then both files are already saved and the
  runtime already reflects them - only the mirror push failed. This also
  closes a gap where MCP's `save_config` tool left the process holding
  its pre-save view of anything the save's read-modify-write cycle picked
  up from disk: it now sees the refreshed state too. The precondition
  revisions were unused when this entry was first written; MCP's
  `save_config` now supplies them (see Added).
  The runtime refresh can itself fail (an in-memory value that bypassed
  field validation, since `Settings` has no `validate_assignment`, can
  reach the file and then fail to parse back in) - `save()` now tells
  that apart from every other outcome: a new `ReloadAfterSaveError` means
  both files ARE written but the runtime could not adopt them, and it
  never replaces or hides a pending `hooks.strict` failure, which keeps
  priority. `save_config`'s MCP response carries a `kind` for all three
  failure shapes (`conflict`, the hook's own kind, or
  `reload_after_save`) so a caller can tell them apart without parsing
  the error text. The advisory cross-process lock now fails as a named
  `LockUnavailableError` - instead of a bare `OSError` or an indefinite
  hang - when the lock file's filesystem does not support advisory locks
  or a peer process holds it for more than 10 seconds.
- **The web UI's writer (`YamlWriter`) now uses the same write primitive
  as `ConfigManager.save()`** (#229): `save_user`, `delete_user`,
  `save_client`, `delete_client` and the rest of its write methods route
  through `compare_and_replace`, and each gained an optional
  `expected_revision` precondition. The practical effect: creating or
  deleting a user/client now checks "does this already exist / does
  this exist at all" against the same document it writes, under the
  same lock, instead of against a copy loaded before the write started.
  Previously, two near-simultaneous submissions creating the same new
  user or client could both pass their "already exists" check and the
  second would silently overwrite the first, with no error to either
  request; that lost update is now impossible - the second request
  correctly gets an "already exists" error instead.
- **Every web UI form that writes `users.yaml`/`settings.yaml` now
  carries the revision it was rendered with, and refuses a stale
  submission** (#229 phase 4): create/edit/delete user, create/edit
  client, regenerate client secret, settings, and authority prefixes
  all send a hidden `expected_revision` field and get a clear
  "changed since it was last read - please reload and try again" flash
  instead of silently overwriting someone else's concurrent change (an
  edit based on a page loaded before another admin deleted or changed
  the same user/client, for instance). The settings page's OAuth, SAML,
  identity-classes and login-mode fields are now applied as one write
  instead of four separate ones, so a conflict there is all-or-nothing,
  the same guarantee every other form already had - an earlier version
  of this ran four writes chained by revision, which meant a conflict
  partway through could leave the earlier sections already saved while
  the page reported that nothing had changed. A submission with no
  `expected_revision` at all (an old cached page, a script, the e2e
  test agent) keeps today's unconditional last-write-wins - nothing
  about this requires an existing caller to opt in.

### Security
- **Opt-in `management_secret` mutation gate** (#163): one shared secret that
  gates state-changing calls across all three management surfaces - the MCP
  server (via the existing `admin_secret` tool argument, which now reads from
  this setting instead of a standalone env var), `/api/*` (via a new
  `X-Management-Secret` request header on mutating calls), and the config web
  UI (a one-time "unlock" form at `/login` that then trusts the session for
  further mutating requests). Off by default - unset, nothing changes.
  Configurable via `settings.yaml`'s `session.management_secret` or the
  `NANOIDP_MANAGEMENT_SECRET` env var; the previous MCP-only
  `NANOIDP_MCP_ADMIN_SECRET` still works as an alias, though an explicit
  `management_secret: null`/`""` in `settings.yaml` now wins over either env
  var rather than falling through to it. Independent of `require_ui_login`:
  that gate is the UI's session front door (who can view the dashboard),
  this is the write guard (who can change anything) - either, both, or
  neither can be enabled; the unlock form stays reachable even when
  `require_ui_login` is also on. YAML-only, same treatment as
  `require_ui_login`/`secret_key`. Hardened since first landing: the UI
  unlock flag is now an HMAC of the secret itself (not a bare session
  boolean), so it can't be forged just by knowing `secret_key`'s public
  default; a non-ASCII or non-string secret compares safely instead of
  500ing; an unlocked UI session now also satisfies the `/api/*` gate, so
  the dashboard's own buttons (generate token, clear audit log) keep working
  after one unlock; and the MCP check now always reads the `ConfigManager`
  actually serving the request.

## [2.7.0] - 2026-08-25

### Changed
- **Configuration files load through document models** (#175, piece 2).
  `settings.yaml` and `users.yaml` are now parsed into Pydantic document
  models that mirror the YAML sections one to one
  (`nanoidp.config_documents`), and the domain `Settings` / `User` objects
  are built from them; the hand-written `.get(key, default)` mapping in
  `config.py` is gone and the defaults live on the models, which the writer
  reads as well. No file format change and no behavioural change for files
  that loaded before. One visible improvement: an unknown key (a typo such
  as `oauth.isuer`, or a key nanoidp does not know) is now logged as a
  warning with its dotted path and ignored, instead of vanishing silently;
  keys that shipped presets carry but the loader never consumed
  (`cors_allowed_origins`, `device_flow`, `logging.format`,
  `oauth.refresh_token_expiry_minutes`, `session.permanent`) are declared so
  they do not warn. Fields inside a user entry keep folding into
  `attributes`, as always. Stricter handling is a later piece.

### Config schema
- `config_version` 1 introduced (#175, piece 1). No changes required to
  existing files: a file without the key is version 1. The version is the
  contract of the config directory as a whole: both files declare the same
  number, each is checked independently, and it must be a literal integer
  (checked before `${VAR}` expansion).

### Added
- **Generated config schema, `validate-config` and strict validation** (#175,
  pieces 3 and 4). Three additions to the config contract, none of which
  restates it a seventh time:
  - `nanoidp config-schema` prints the JSON Schema of `settings.yaml`,
    `users.yaml` and `bootstrap.yaml`, generated from the document models
    (`--file` for one of them, `--write` to regenerate the committed
    artifact from a source checkout). The artifact is
    `docs/schema/config.v1.json`: one standalone schema per file under the
    keys `settings`, `users` and `bootstrap`, next to the `config_version`
    they describe, ready to point an editor's YAML-schema support at. A test
    fails when the committed file no longer matches the models, and parity
    tests fail when the MCP `update_settings` tool or the web UI's settings
    form grows a knob that is not a key of the contract - or offers one of
    the YAML-only fields (`secret_key`, `require_ui_login`, `hooks`,
    `plugins`).
  - `config_validation: warn|strict` (top level of `settings.yaml`, default
    `warn`) and the server flag `--strict-config` decide what an unknown key
    does: log its path and keep loading, or refuse to start and refuse every
    later reload with the same message. The flag wins over the file for that
    run only and is never written back, like `--profile` (#172). One
    contract per directory: `users.yaml` and `bootstrap.yaml` follow what
    `settings.yaml` declares. Wrong types stay errors in both modes.
  - `nanoidp validate-config [--config DIR] [--strict]` lints a
    configuration directory without starting anything: one line per finding,
    exit 0 when clean or with warnings only, exit 1 on errors and on
    warnings under `--strict`. It reads the three files through the same
    loaders the server uses and nothing else - no `ConfigManager`, no hook
    dispatched, no plugin imported, `bootstrap.yaml` checked for its shape
    only - so it is safe as a pre-commit or CI step on a directory whose
    hooks name commands. MCP agents get the same check as the read-only
    `validate_config` tool (`{valid, findings}`), which brings the MCP
    surface to 26 tools.
- **Hooks and plugins v1** (#185): extension points for external
  configuration stores, not backends. Three synchronous hooks with
  `HOOK_API_VERSION = 1`: `on_before_load(config_dir)` before the files are
  read (startup and every reload), `on_config_saved(path, kind)` after an
  atomic write of `settings.yaml` or `users.yaml`, `on_audit_event(event)`
  after an audit entry. Implement them as shell commands under `hooks:` in
  `settings.yaml` (placeholders `{config_dir}`, `{path}`, `{kind}`,
  `{event_type}`, audit event JSON on stdin) or as Python plugins packaged
  separately and discovered through the `nanoidp.plugins` entry-point group,
  configured under `plugins.<name>:`. Per-hook error policy: `on_before_load`
  may block under `hooks.strict`, `on_config_saved` is propagated to the
  caller under `strict` after the write (the local save is always
  committed and the running configuration reloaded from it, so only the
  mirror is behind), `on_audit_event` never propagates. Commands are never
  reported by `/api/config` or MCP (they may embed expanded secrets) and a
  propagated error names the hook and its source only; the bootstrap
  surface is the baseline for `strict`/`timeout_seconds`, `settings.yaml`
  overrides only what it declares. Bootstrap surface for hooks
  that must run before `settings.yaml` exists: `NANOIDP_BOOTSTRAP_HOOK` /
  `--bootstrap-hook`, `NANOIDP_BOOTSTRAP_PLUGIN` with
  `NANOIDP_PLUGIN_<NAME>_<KEY>` settings, and `bootstrap.yaml` in the config
  directory (`hooks:` and `plugins:` only). `nanoidp plugins`, `GET
  /api/config` and the MCP `get_settings` tool report what is loaded, from
  which surface, with failure counters and the plugins that could not be
  loaded (`plugins_failed`: a missing package or a wrong `hook_api_version`
  is reported, never fatal unless `strict`); `hooks:`/`plugins:` are
  YAML-only. `bootstrap.yaml` goes through the same loader as
  `settings.yaml` (placeholders, unknown-key warnings). A strict
  `on_before_load` failure is a JSON `503` on `POST /api/config/reload` and
  an error result from the MCP `reload_config` tool. Audit logging never
  constructs the configuration and an audit event produced inside a load is
  not dispatched to hooks. An unchanged `hooks:`/`plugins:` declaration is
  not re-applied on the refresh that follows a local write, so plugins are
  not re-instantiated on every save. Reference plugin
  `examples/plugins/nanoidp-echo`; guide "Extending nanoidp: hooks and
  plugins".
- **Import contracts enforced in CI** (#149): `import-linter` now pins the
  package layering (`routes -> services -> config`) and the invariant that
  `serialization.py` has no runtime imports from the package (it is what
  lets `config.py` import it without a cycle). Both used to live only in
  comments; `lint-imports` runs next to ruff and mypy in the Tests workflow
  and fails when a change adds a forbidden import.
- **`config_version` field** (#175, piece 1): `settings.yaml` and
  `users.yaml` accept a top-level integer `config_version: 1`. Absent means
  1, so existing files load unchanged; a value that is not a positive
  integer, or newer than the running release supports, is refused at
  startup with a message naming the file, the value and the supported
  version. `nanoidp init` and the wizard write it into the files they
  create; UI/MCP saves preserve an existing key and never add one. `GET
  /api/config` and the MCP `get_settings` tool expose the effective value;
  the e2e agent asserts it. Bumps only on renames, removals or semantic
  changes (with a loader migration), never on optional additions.
- **Native-app redirect URIs** (#81, RFC 8252): `/authorize` accepts
  private-use scheme redirect URIs such as `com.example.app:/oauth2redirect`
  (§7.1: a scheme and a path, no authority) as absolute URIs and applies
  §7.1's minimum rule to them (a non-`http(s)` scheme without a period,
  such as `myapp://`, is rejected with a message naming the rule; domain
  ownership is not verified), and a
  registered loopback URI (`http://127.0.0.1:{port}/...`,
  `http://[::1]:{port}/...`) matches any port (§7.3), since native apps
  bind an ephemeral port. Everything else keeps exact string matching (RFC
  6749 §3.1.2.3): scheme, host, path and query of a loopback URI, every
  port of a non-loopback or `localhost` registration. Fragments are now
  rejected explicitly (§3.1.2). One shared matcher,
  `services/redirect_uri.py`, serves both legs of `/authorize`; MCP tool
  descriptions and `examples/test_agent.py` updated.
- **Persona login mode** (#156): opt-in `login.mode: persona` lists the
  configured users on every interactive login surface (`/login`,
  `/authorize`, `/saml/sso` and the device flow's verification page) and
  signs in by selecting one, with no password prompt - a local
  development/testing convenience, off by default. `User.password` is now
  optional: a password-less user can only authenticate via persona-mode
  interactive login, never via password-mode login or the OAuth password
  grant. Persona-authenticated sessions emit SAML
  `AuthnContextClassRef: unspecified` instead of falsely claiming
  `PasswordProtectedTransport`. New MCP tool `create_persona_user`, a
  `persona-login` example preset, settings-UI persistence and e2e coverage.
- **Per-client login page branding**: optional per-client colors (background,
  header, footer, all as validated hex values), show/hide client_id and
  description on the `/authorize` login page, and per-client logo images
  stored locally in `static/logos/` keyed by client ID (no YAML config needed
  for logos; place the image file and it's served automatically; the
  directory is overridable via `oauth.logos_dir`). Colours and toggles are
  editable from the OAuth client form in the UI and from the MCP
  `create_client`/`update_client`/`get_client` tools, descriptions are
  already supported, and logos are deployed by the operator to the server
  filesystem. Designed for demos and prototyping; colours are structured
  (not free-form CSS) to prevent stored-XSS on the auth UI, and logos are
  local files only (no remote URLs) to avoid beacons.

### Fixed
- **The unit suite no longer rewrites the repo's `config/` files.** Tests
  that build an app without an explicit config directory used to load the
  committed preset through ConfigManager's `./config` fallback, and any save
  that followed rewrote `config/settings.yaml` or `users.yaml` in the
  checkout - twice committed by accident during review. `tests/conftest.py`
  now points `NANOIDP_CONFIG_DIR` at a fresh copy of `config/` for every
  test and resets the `yaml_writer` singleton alongside the others.
- **`--profile` overrides settings.yaml for every value and survives reloads**
  (#172). An explicit `--profile dev` could not bring a file configured with
  `oauth21`/`stricter-dev` back to `dev` (the flag defaulted to `dev`, so the
  code could not tell "asked for dev" from "omitted"), and any CLI profile was
  dropped by the first configuration reload, i.e. by the first web UI or MCP
  save. Worse, the `stricter-dev` runtime hardening (`require_pkce`,
  `password_hashing`, `rate_limit_enabled`, debug off) was applied once in
  `create_app()` and silently lost on that same first reload, even when the
  profile came from `settings.yaml` itself. The override now lives on
  `ConfigManager` (`--profile` defaults to none, `init_config(...,
  profile_override=)`), the effective profile and its hardening are re-derived
  after every settings load, and a save serializes the DECLARED state
  (`ConfigManager.persistable_settings()`), so neither the override nor
  the hardening it implies is ever written into the operator's file. `GET /api/config` and the MCP `get_settings` tool expose `security_profile`,
  `profile_override` and the derived `effective` values; the e2e agent checks
  they are stable across a reload.
- **`users.yaml` now expands `${VAR}` / `${VAR:default}` placeholders** like
  `settings.yaml` always did (#175 review). A `password: ${ALICE_PASSWORD}`
  used to be taken literally, so the documented "secrets kept out of the
  file" use case only worked for settings. A UI/MCP save of one user still
  rewrites only that user's entry; the MCP `save_config` tool rewrites the
  whole map and materializes expanded placeholders, as documented.
- **SAML `entity_id`/`sso_url` follow the effective issuer** (#181). With
  `oauth.issuer_from_request` on (or behind a proxy), OIDC discovery reflected
  the request host while `/saml/metadata`, the `<Issuer>` in responses and
  assertions and the SSO location kept the fixed `http://localhost:8000/...`
  strings. Both settings are now optional: absent (or blank in the UI/MCP)
  means derived as `<effective issuer>/saml` and `<effective issuer>/saml/sso`
  through one helper shared by every SAML surface, an explicit value still
  wins, and a derived value is never written back to `settings.yaml`. SAML 2.0
  Metadata 2.3.2 requires `entityID` to be the value used as `<Issuer>` (Core
  2.2.5). `/api/config` and the MCP `get_settings` tool report the effective
  values plus `entity_id_derived`/`sso_url_derived`; `update_settings` gains
  `saml_entity_id`/`saml_sso_url` (empty string clears); the e2e agent checks
  metadata against discovery and no longer posts derived values back as
  explicit ones.
- **Example presets now bind to `127.0.0.1`** (#164). All four pre-2.6.0
  presets (`cli-device-flow`, `microservices-client-credentials`,
  `react-spa-pkce`, `spring-boot-saml`) still shipped an explicit
  `host: "0.0.0.0"`, overriding the loopback default introduced with
  GHSA-2473-px8h-rvg6 for anyone who copied them. Each now ships loopback
  with a commented `# host: "0.0.0.0"` opt-in line, matching the
  `persona-login` preset and the reverse-proxy guide's framing.
- **`/api/config` now exposes `saml.default_acs_url`** (#165). The e2e agent
  rebuilds the settings form from that document, so the missing field was
  posted back blank on every run and the "present-but-blank = clear"
  contract (#131) silently wiped `default_acs_url` from `settings.yaml`.

### Security
- **Opt-in login gate for the config web UI**: new `session.require_ui_login`
  setting (off by default) makes `/login` actually enforce a logged-in
  session on the dashboard, users, clients, settings, keys, claims, audit log
  and token tester pages - previously `/login`/`/logout` existed but nothing
  gated on them, so the login page implied protection it didn't provide.
  Does not affect the separate `/api/*` management API, which remains
  unauthenticated by design regardless. YAML-only for now, following the
  `secret_key`/`security_profile` precedent. Related to the network-binding
  hardening in GHSA-2473-px8h-rvg6.
- **Opt-in removal of the invalid-bcrypt-hash plaintext fallback**: new
  `session.enforce_password_check` setting (off by default). When
  `password_hashing` is on, a `users.yaml` password that isn't a valid
  bcrypt hash previously fell back to plaintext comparison with only a
  warning logged - this setting removes that fallback, rejecting the login
  outright instead. Default behavior (the fallback) is unchanged; opt-in
  only. YAML-only, same treatment as `require_ui_login`.

## [2.6.0] - 2026-08-21

### Documentation
- **New guide: [Running behind a TLS-terminating reverse proxy](book/src/guides/reverse-proxy.md)**,
  walking through composing `oauth.issuer`, `issuer_from_request`,
  `issuer_from_proxy_headers`, `issuer_allowlist`, `device_verification_base_url`
  and `POST /api/config/reload` for a proxied/containerized deployment, with
  the security caveats inline.

### Added
- **First-class group support**: users gain a `groups` list alongside `roles`,
  modelled exactly the same way. It is loaded from and persisted to
  `users.yaml` (omitted when empty), emitted as a `groups` claim on the access
  token and from `/userinfo`, requestable in the ID Token via the OIDC `claims`
  parameter, advertised in `claims_supported`, and flattened into `authorities`
  using the new `groups` authority prefix (default `GROUP_`, editable on the
  Claims page). Groups are editable from the user form, shown on the users list
  and user detail pages, exposed by `/api/users`, and settable through the MCP
  `create_user` / `update_user` tools. Users without groups behave exactly as
  before: no claim, no authorities, nothing written to YAML.
- **Optional SAML export of roles and groups**: new `saml.export_roles` /
  `saml.export_groups` toggles (both off by default, so the previous behaviour
  is preserved) with companion `saml.roles_attr_name` / `saml.groups_attr_name`
  settings defaulting to `roles` and `groups`. Roles and groups are not
  standard SAML attributes and every SP expects a different name, so the name
  is configurable; blanking it restores the default. Both toggles are on the
  Settings page and the MCP `update_settings` tool, and apply to both the SSO
  assertion and the AttributeQuery endpoint, with one `AttributeValue` per
  entry.
- **`oauth.issuer_from_request`** (off by default): when enabled, the
  discovery document's `issuer`, every minted token's `iss`, and the device
  flow's `verification_uri` are derived from the incoming request's own Host
  header instead of the fixed `oauth.issuer`. Lets the same NanoIDP be
  reachable under more than one hostname (e.g. a Docker Compose service name
  from other containers and `localhost` from the host browser) without a
  discovery/token issuer mismatch - each hostname advertises and issues
  tokens against itself. The MCP `get_oidc_discovery`/`get_settings` tools
  have no request of their own and always report the fixed `issuer`.
- **`oauth.issuer_allowlist`**: restricts `issuer_from_request` to a list of
  allowed origins (e.g. `["http://localhost:8000", "http://nanoidp:9900"]`).
  Empty (default) allows any Host header, unchanged from before; when set, a
  request whose Host doesn't match falls back to the fixed `oauth.issuer`
  instead of trusting an arbitrary Host header. Settable from the Settings
  page and the MCP `update_settings` tool.
- **`oauth.device_verification_base_url`**: pins the device flow's
  `verification_uri` to a fixed, human-reachable URL (e.g.
  `https://idp.example.com`), overriding `issuer_from_request`'s derivation
  for that field only - discovery's `issuer` and a token's `iss` are
  unaffected. Fixes a backend/container caller of `/device_authorization`
  (e.g. `Host: nanoidp:9900`) otherwise leaking its own Host into a URL the
  end user's browser can't open. Unset by default. Settable from the
  Settings page and the MCP `update_settings` tool.
- **`oauth.issuer_from_proxy_headers`** (off by default): trusts
  `X-Forwarded-Proto`/`X-Forwarded-Host`/`X-Forwarded-For` from a single
  reverse-proxy hop (via werkzeug's `ProxyFix`), so `issuer_from_request` and
  rate-limit and audit-log client IPs see the original scheme/host/client
  instead of the
  proxy's own connection when TLS is terminated upstream. Only changes the
  derived issuer/`iss`/`verification_uri` when `issuer_from_request` is also
  on; the rate-limit effect applies regardless. Only enable this when
  NanoIDP is deployed directly behind exactly one trusted proxy - these
  headers are otherwise spoofable by any client. Readable/settable via the
  Settings page and the MCP `get_settings`/`update_settings` tools; since
  `ProxyFix` is wired at app startup, a value changed at runtime only takes
  effect after a restart.

### Changed
- **Raised the `PyJWT` floor to `>=2.13.0`** (was `>=2.8.0`). `/userinfo` and
  `/introspect` pass a client-supplied token to `jwt.decode()`, and 2.8.0-2.12.1
  are affected by CVE-2026-48525 (unbounded Base64URL decoding of a `b64=false`
  detached JWS payload, a DoS vector).
- **Added a CI license gate** (#148): the build fails if a dependency in the
  redistributed closure carries a GPL/LGPL/AGPL/SSPL/EUPL license, which the
  project's dependency-license policy blocks from redistribution without
  explicit review.
- **Lowered the `cryptography` floor from `>=46.0.3` to `>=45.0.0`** (#140). The
  previous floor came from a generic dependency bump, not a real requirement:
  our own API usage needs nothing newer than ~3.1. The effective minimum is set
  by `signxml`, which imports `x509.verification.ExtensionPolicy` (added in
  cryptography 45.0.0) at load time. This unblocks installs on environments
  pinned to a `cryptography` between 45 and 46.
- **Consolidated the OAuth client YAML merge logic** into a single
  `serialization.merge_client_entry()` helper, shared by the settings save
  path (`merge_oauth_clients()`) and `YamlWriter.save_client()`'s web UI
  edit path, which previously duplicated the same field-by-field merge
  rules. Internal cleanup, no behavior change.
- **Migrated the MCP server to the mcp 2.0 SDK** and pinned `mcp>=2,<3`. mcp 2.0
  replaced the lowlevel `Server` decorators (`@server.list_tools()` /
  `@server.call_tool()`) with `on_*` constructor parameters, so a fresh install
  resolving to 2.0 could not import `nanoidp.mcp_server` at all. Handlers now
  take `(ctx, params)` and return `ListToolsResult` / `CallToolResult` instead
  of relying on the SDK's removed return-value wrapping. The tool set, tool
  schemas, readonly mode, and the admin-secret gate are unchanged, and the
  stdio transport and `nanoidp-mcp` entry point are untouched.
- **Rejected and failed MCP tool calls now set `is_error: true`.** mcp 2.0 no
  longer converts a handler exception into an error-flagged result, so nanoidp
  builds it explicitly for every case that previously came back as a
  successful result whose JSON body happened to carry an `error` key:
  readonly-mode and admin-secret rejections, an unknown tool name, arguments
  that fail schema validation (see below), and tool-level failures such as
  "user not found" or "client already exists". The response body is
  unchanged.
- **Tool arguments are now validated against each tool's schema before
  dispatch.** mcp 1.x's `@server.call_tool(validate_input=True)` did this
  automatically; mcp 2.0's `on_call_tool` does not, so nanoidp now runs the
  same check itself and returns an `is_error: true` result (`code:
  "MCP_INVALID_ARGUMENTS"`) instead of letting a missing required field reach
  the tool implementation as a bare `KeyError`.
- **Consolidated the MCP `isError` contract** (#120): the rule is now written
  once as a table in the `mcp_server` module docstring (a negative query answer
  is not a failure) and the code follows it. `verify_token` on an invalid token
  returns `{"valid": false, "reason": ...}` (was `error`) so a rejected token,
  the tool's designed answer, is no longer flagged `is_error`. A domain-failure
  audit entry now records the failure reason instead of only the tool name; the
  uncaught-exception path now carries a `code` (`MCP_INTERNAL_ERROR`) and `tool`
  like the guard rejections; and `_execute_tool`'s unreachable unknown-tool
  fallback now raises rather than returning a divergent shape. The MCP audit
  `details` codes are namespaced (`MCP_READONLY_MODE`,
  `MCP_ADMIN_SECRET_REQUIRED`, `MCP_UNKNOWN_TOOL`, `MCP_INVALID_ARGUMENTS`),
  observable via `get_audit_log` and `/api/audit`.
- **Precompiled MCP tool-argument validators** (#121): each tool's JSON Schema
  is compiled once at import (`Draft202012Validator`) instead of being
  recompiled on every `tools/call`, which also surfaces a malformed schema at
  import time. The direct `jsonschema` floor is raised to `>=4.20.0` to match
  what mcp 2.0 already resolves.
- **MCP tests drive the real protocol** (#122): the test harness now calls
  tools through the mcp 2.0 in-memory client (real SDK dispatch and result
  serialization) instead of invoking the lowlevel handlers with a fake request
  context, so wire-level regressions fail the suite instead of only breaking a
  real client.

### Fixed
- **Duplicate OAuth `client_id`s are rejected at load** (#127). Two clients
  that resolve to the same effective id (including two `${VAR}` placeholders
  expanding to the same value) made client lookup ambiguous and caused the
  save-merge to match the wrong raw entry, materializing a secret; the loader
  now fails fast with a clear error instead.
- **Import no longer crashes when package metadata is absent** (#139). Running
  from an uninstalled source tree (vendored, or copied into an image without
  `pip install`) raised `PackageNotFoundError`; the version now falls back to
  reading `pyproject.toml`, then to a static string.
- **Default admin user's `identity_class` is `INTERNAL`, not `INTERN`**. The
  no-`users.yaml` fallback used a typo'd class that didn't match the generated
  template or the default allowed classes.
- **Env-backed `client_id` placeholders are preserved on save** (#127). When a
  client's `client_id` was itself a placeholder (`client_id: ${CLIENT_ID:app1}`),
  the settings save matched the raw entry against the expanded id, missed it,
  and rewrote the client from expanded values - losing the placeholders and
  materializing the client secret; the web UI path appended a duplicate entry,
  and `delete_client` could not find the client at all. Client matching now
  expands the placeholder before comparing (`client_id_matches()`), used by the
  settings save, `save_client()` and `delete_client()`.
- **Saving settings no longer discards comments, inline `#` text or `${VAR:default}`
  placeholders in `settings.yaml`** (#127): the settings writer now round-trips
  the file with `ruamel.yaml` (comments and quote style survive) and only
  rewrites a field when its expanded on-disk value actually differs from the
  new one, so an untouched `${PORT:8000}`-style placeholder is no longer
  replaced by its resolved value on the next save. Free-form text
  (`description`, `client_secret`, `password`, attribute values) is now quoted
  on write so an embedded `#` can't be mistaken for a comment. Applies to both
  the web UI settings form and the MCP `save_config` tool.
- **Env-backed client secrets and empty optional placeholders are preserved when
  unrelated settings change.** The OAuth client merge now updates entries by
  `client_id` field-by-field instead of rewriting the whole list, so an
  unchanged `${APP1_SECRET:dev}` secret stays in the raw file even when a
  sibling client is edited. Empty optional values such as
  `${DEVICE_URL:}` are also treated as unchanged when they still expand to an
  empty string, instead of being popped out of the YAML on a save that changed
  some other field.
- **`/api/config` now exposes `issuer_allowlist`, `device_verification_base_url`
  and `issuer_from_proxy_headers`** alongside `issuer_from_request`. The
  config-agnostic e2e agent reads the allowlist from `/api/config` to predict
  the effective issuer; without the exposure it assumed an empty allowlist and
  failed on any server with one configured. The agent also takes its
  fixed-issuer baseline from `/api/config`'s `oauth.issuer` now: a plain
  discovery response reflects the request's own Host when the flag is on, so
  it is only a valid baseline when the flag is off.
- **`examples/test_agent.py` SAML export check honours the configured attribute
  names**: it now reads `saml.roles_attr_name` / `saml.groups_attr_name` from
  `/api/config` instead of assuming the default `roles` / `groups` names, so it
  no longer fails on servers exporting under custom names.
- **SAML export: colliding attribute names merge instead of overwriting, and
  values are passed as lists** (#134). With both exports enabled and
  `saml_roles_attr_name` equal to `saml_groups_attr_name` (e.g. both
  `memberOf`), the groups list silently replaced the roles list; the two are
  now merged into the single shared attribute, roles first, deduplicated. The
  AttributeQuery path also passes roles/groups (and entitlements) to the
  response builder as lists instead of comma-joined strings, so a legitimate
  comma-bearing value like `"Finance, EMEA"` stays one `AttributeValue`, as it
  already did in the SSO assertion.
- **`/api/users/<username>/token` now honours `issuer_from_request`** (#133):
  the endpoint mints real JWTs but kept using the fixed `settings.issuer`,
  so with the flag on its tokens carried an `iss` that failed validation
  against the discovery document the same hostname had just advertised. The
  effective-issuer resolution (including the allowlist fallback) now lives in
  a shared routes helper used by discovery, `/token`, the device flow and the
  API token endpoint alike; the MCP tools remain the documented exception.
  Also clarified in the setting descriptions that `issuer_from_proxy_headers`
  affects the audit log's recorded client IP as well as the rate limiter's.
- **`POST /settings` no longer resets settings that were not on the submitted
  form** (#131). Previously every checkbox absent from the form was stored as
  `false` and every absent text field was cleared, so any partial form (a
  stale tab, a script, the e2e agent's c14n round-trip) silently wiped
  unrelated configuration - observed live as `issuer_from_request`,
  `issuer_from_proxy_headers` and the SAML export toggles flipping off and the
  allowlist, device verification URL and attribute names being deleted
  mid-test-run. The handler now follows an "absent = unchanged" contract: text
  fields and textareas are only applied when present (present-but-blank still
  clears), and each checkbox is paired with a hidden `__on_form` marker so
  "rendered but unchecked" (persist `false`) is distinguishable from "not on
  this form" (leave unchanged).

### Security
- **Default server bind address is now `127.0.0.1` (loopback) instead of
  `0.0.0.0`** (GHSA-2473-px8h-rvg6, CWE-306). The unauthenticated `/api/*`
  management API (which can mint admin tokens, rotate signing keys and clear
  the audit log) is a deliberate dev-tool convenience, but the previous
  all-interfaces default exposed it to any network-reachable host without the
  operator choosing to. The out-of-the-box experience is unchanged for local
  development (clients still reach `localhost:8000`). To expose NanoIDP on a
  network, set `server.host` (or `--host 0.0.0.0`) explicitly; a startup
  warning is logged whenever the bind address covers all interfaces. This
  aligns `nanoidp init` with the value `nanoidp wizard` already wrote, and the
  bundled Docker image is unaffected (its entrypoint already passes
  `--host 0.0.0.0`).

## [2.5.0] - 2026-07-19

### Added
- **`claims` parameter requests persist across token refresh** (#112, OIDC
  Core §12.2): the claim names requested via the OIDC `claims` parameter are
  now persisted in the refresh token (`req_id_token_claims` /
  `req_userinfo_claims`, alongside `scope` and `auth_time`), so a refreshed ID
  Token keeps the requested claims and `/userinfo` keeps honouring the
  `userinfo` member for the refreshed access token. Refresh tokens minted
  before this change carry neither claim and refresh as before. Both names are
  reserved: they cannot be requested via the `claims` parameter nor injected
  through the `/token` `extra` parameter. Requested-claims values are
  sanitized at the token service (`sanitize_claim_names`): a hand-crafted
  refresh or access token carrying a non-list value (or non-string entries)
  refreshes and serves `/userinfo` cleanly instead of failing token issuance
  after the refresh token was consumed. A claims request deliberately
  survives scope narrowing on refresh (OIDC Core §5.5 is orthogonal to
  scope); see the token reference docs.
- **MCP `generate_token` gains `userinfo_claims`** (#113): parity with the
  HTTP `claims` flow's `userinfo` member; the names are stamped on the access
  token as `req_userinfo_claims` and honoured by `/userinfo`. Both
  `id_token_claims` and `userinfo_claims` are now validated like
  `additional_audiences`: a non-list value is rejected with a clean error
  instead of being minted into the token.

### Changed
- **`/userinfo` reuses `resolve_user_claim` for its default claim assembly**
  (#113): the scope-gated standard claims and the nanoidp-specific claims now
  come from the same resolver that backs the `claims` request parameter, so
  the two mappings cannot diverge. No behavior change.

### Fixed
- **`claims` parameter could overwrite registered ID Token claims** (#110): a
  requested claim name that collided with a user attribute (e.g. an attribute
  named `aud` or `exp`) could hijack the corresponding registered claim, because
  `create_jwt` applies `extra` after setting the registered claims and the
  `setdefault` guard only covered the protocol claims. `resolve_user_claim` now
  refuses reserved registered/protocol names outright (`iss`, `sub`, `aud`,
  `exp`, `iat`, `nbf`, `jti`, `token_use`, `auth_time`, `at_hash`, `azp`,
  `nonce`, `scope`, `req_userinfo_claims`), protecting both the ID Token and
  `/userinfo` paths at a single choke point.

## [2.4.0] - 2026-07-08

### Added
- **`scope` claim on access tokens** (#102): access tokens now advertise the
  granted scope (RFC 9068 §2.2.3), letting resource endpoints reason about it.
  Set authoritatively in `TokenService.create_token`, so a caller-supplied
  `extra_claims` cannot override it.
- **OIDC `claims` request parameter** (#104, OIDC Core §5.5): `/authorize`
  accepts a `claims` parameter to request specific claims in the ID Token
  (`id_token` member) or from UserInfo (`userinfo` member), e.g.
  `claims={"id_token":{"email":null}}`. Requested claims are resolved from the
  user and added when available (voluntary form, §5.5.1); protocol claims are
  never overwritten and unresolvable names are skipped. Malformed input is
  ignored with a warning rather than failing the flow. Discovery advertises
  `claims_parameter_supported: true`, and the MCP `generate_token` tool gains an
  `id_token_claims` argument. Scoped to the authorization code grant; the
  requested claims are not yet persisted across a refresh.
  `TokenService.create_token` now strips `scope`/`req_userinfo_claims` from a
  caller-supplied `extra` before setting them authoritatively, so the `/token`
  `extra` parameter can never smuggle scope-gated claims past `/userinfo`
  (closes a spoofing gap in the #102 scope handling too).

### Changed
- **`/userinfo` gates `email`/`profile` claims by granted scope** (#102, OIDC
  Core §5.4): `email`/`email_verified` require the `email` scope and
  `preferred_username` requires the `profile` scope. Enforced only under the
  `stricter-dev` and `oauth21` profiles; the default `dev` profile keeps
  returning them unconditionally, so this is not a breaking change for existing
  setups. nanoidp-specific claims (`roles`, `tenant`, `identity_class`,
  `attributes`) have no standard scope and are always returned.

## [2.3.0] - 2026-07-08

### Added
- **`oauth21` security profile** (#68): opt-in draft-OAuth-2.1 protocol
  strictness alongside `dev` and `stricter-dev`: PKCE required on the
  authorization code flow with S256 only (draft-ietf-oauth-v2-1 §4.1.1,
  §7.5.2), refresh token rotation forced on (§4.3.1), the password grant
  removed (RFC 6749 §5.2) and absent from discovery, and registered
  redirect URIs mandatory at `/authorize`. Protocol behavior lives in
  derived `Settings` properties consumed by both the routes and the shared
  discovery builder, so the profile means the same thing from `--profile`
  or `settings.yaml` and discovery can never advertise what the endpoints
  refuse. Deliberately orthogonal to `stricter-dev` (runtime hardening).
- **Registered redirect URIs with exact matching** (#67): clients gain an
  optional `redirect_uris` list; when non-empty, `/authorize` compares the
  requested `redirect_uri` with simple string comparison (RFC 6749
  §3.1.2.3, OAuth 2.1 §4.1.1) and answers a mismatch with
  `400 invalid_request` directly, never by redirecting to the unvalidated
  URI (§3.1.2.4). Exposed in the web UI, MCP client tools and YAML.
- **Signed AuthnRequest verification** (#69): with
  `saml.want_authn_requests_signed: true` and PEM certificates in
  `saml.sp_certificates`, nanoidp requires and verifies AuthnRequest
  signatures under both bindings: the HTTP-Redirect query-string
  signature over the raw transmitted fragment (SAML 2.0 Bindings
  §3.4.4.1; rsa-sha256/rsa-sha512/legacy rsa-sha1) and the HTTP-POST
  enveloped `ds:Signature` (Core §5), rejecting unsigned or invalid
  requests with 400, failing closed without registered certificates. The
  verified Redirect request is bound server-side in the session, so the
  inline-login leg only accepts byte-identical values. Metadata advertises
  `WantAuthnRequestsSigned="true"` if and only if enforcement is on.
  `examples/gen_sp_keypair.py` generates a test SP keypair.
- **E2E workflow in CI** (#79): every PR now boots real servers and runs
  `examples/test_agent.py` against them (default profile, `--oauth21`,
  `--saml-signed` with a generated SP keypair) plus an MCP **stdio** smoke
  test (`examples/mcp_smoke_test.py`) driving the real transport, the
  regression guard for the class of bug where the stdio entrypoint crashed
  unnoticed because unit tests bypass it (#56).
- **Coverage gate in CI** (#71, #72): `--cov-fail-under`, introduced at 70
  and ratcheted to 75 after the wizard went from 0% to 99% coverage;
  measured coverage 78%. The dead Codecov upload (never configured, failed
  silently since inception) was removed in favor of in-CI enforcement.
- **Documentation site**: mdBook on GitHub Pages
  (<https://cdelmonte-zg.github.io/nanoidp/>) with getting-started, guides
  and a full reference; canonical docs are symlinked so there is a single
  source of truth, and the README became a landing page.
- **Web UI parity** (#94): `require_pkce` and `refresh_token_rotation`
  toggles on the settings page; SP-certificates and signed-AuthnRequests
  fields (#69); `redirect_uris` on the client form (#67); the dashboard
  badge distinguishes the `oauth21` profile.
- MCP: `get_settings` reports `security_profile`; `update_settings` covers
  the SAML verification fields; client tools carry `redirect_uris`.

### Changed
- **`src/` is fully annotated** and mypy runs with a global
  `disallow_untyped_defs` (#70): new unannotated code fails CI.
- **Internal architecture** (behavior-invariant, #83–#86): one shared YAML
  serialization path for `ConfigManager` and the UI writer; the token
  endpoint dispatches to per-grant handlers with device-flow and
  revocation state in dedicated services (`DeviceCodeStore`,
  `RevocationStore`); a single `audit_event` helper replaced 58 duplicated
  audit blocks (invariance proven by a before/after snapshot harness); the
  Pydantic models moved to `models.py` with compatibility re-exports.
- `security_profile` is now read from `settings.yaml` (top-level key) and
  round-trips on save; the CLI `--profile` still wins. A YAML-declared
  `stricter-dev` now applies its runtime hardening (previously the YAML
  value was silently ignored).

### Fixed
- **`ConfigManager.save()` was lossy** (#87): the save path behind MCP
  `save_config` rewrote `settings.yaml` from scratch, silently deleting
  every section it didn't own: `jwt` (external keys!), `session`,
  `logging` levels, `server.debug` and custom keys. Saving is now
  read-modify-write and preserves them, atomically and with a `.bak`
  backup like the UI path always did.

## [2.2.0] - 2026-06-11

### Added
- The **refresh_token** grant now re-issues an ID Token when the original grant
  included the `openid` scope (OIDC Core §12.2, #39). The granted scope is
  persisted in the refresh token claims and recovered on refresh; a `scope`
  form parameter may narrow, but never broaden, the original grant (RFC 6749
  §6: broadening is rejected with `400`). The refreshed ID Token carries no
  `nonce` (it binds the original authentication request). Refresh tokens minted
  before this change have no persisted scope and keep the old behavior.
- ID Tokens now carry `auth_time` and `at_hash` (#42). `auth_time` reflects
  when the end-user actually authenticated: the login page for the
  authorization code flow, the `/device` verification for the device flow,
  the request itself for the password grant. It is preserved unchanged
  across refreshes (OIDC Core §12.2), carried in the refresh token claims
  like the scope. `at_hash` binds the ID Token to the access token issued
  alongside it (left half of SHA-256, base64url, §3.1.3.6). Discovery
  `claims_supported` now also advertises `auth_time`, `nonce` and `at_hash`.
- Optional **refresh token rotation** (#46): with `oauth.refresh_token_rotation: true`
  (default off), each refresh atomically invalidates the consumed refresh
  token, so its reuse fails with 401; reuse of a consumed token revokes its
  whole rotation family, including the live descendant (RFC 9700 §4.14.2).
- **PKCE enforcement** (#47): new `require_pkce` setting (enabled by the
  `stricter-dev` profile, persisted in `settings.yaml`) rejects `/authorize`
  requests without a `code_challenge`; `stricter-dev` also rejects
  `code_challenge_method=plain`, whether explicit or implicit via the RFC 7636 §4.3
  omitted-parameter default, and discovery only advertises `S256` there.
  Unsupported methods are rejected at the authorization endpoint (§4.4.1).
  Default profile unchanged.
- **MCP audit & key tools** (#48): `get_audit_log`, `get_audit_stats`,
  `clear_audit_log`, `get_keys_info` and `rotate_keys` mirror the HTTP API,
  so agent workflows can inspect what the IdP recorded and exercise JWKS
  refresh handling. `clear_audit_log`/`rotate_keys` count as mutating tools
  (admin secret / readonly rules apply). MCP `get_settings`/`update_settings`
  expose the new `refresh_token_rotation` and `require_pkce` settings, and
  `generate_token` accepts an optional `scope` argument and returns an
  `id_token` when `openid` is included, matching the HTTP token endpoint.
- CI now lints with **ruff** (#45) and type-checks `src/` with **mypy**
  (#55, documented gradual-adoption baseline in `pyproject.toml`). The
  codebase is lint-clean, 153 findings fixed (#49): deprecated
  `datetime.utcnow()` replaced (removes 80 DeprecationWarnings), unused
  imports/variables dropped, imports sorted and moved to module level,
  `Optional[...]` type hints in the crypto service, `verify_jwt` accepts an
  array audience, exceptions re-raised with `from e`, and mypy-clean (40
  baseline errors fixed; the baseline also surfaced the broken `nanoidp-mcp`
  entrypoint below).

### Fixed
- **The `nanoidp-mcp` stdio entrypoint crashed at startup** ("a coroutine
  was expected"): `stdio_server()` is an async context manager yielding the
  message streams, not a coroutine. Verified with a JSON-RPC initialize
  handshake.
- Review follow-ups of the 2026-06-11 merge block (#56):
  - **Refresh tokens are bound to their client**: the issuing `client_id` is
    persisted in the refresh token claims and the refresh grant rejects any
    other client (RFC 9700 §4.14), which also guarantees the refreshed ID
    Token keeps the original `aud` (OIDC Core §12.2). Tokens minted before
    the claim existed keep working.
  - **Rotation is atomic and revokes families on reuse**: the revocation
    check and the claim of the consumed token now happen in one critical
    section, so two concurrent refreshes of the same token can no longer
    both succeed. Each grant starts a refresh-token family (`rt_family`
    claim, stable across rotations); reusing an already-consumed token
    revokes the whole family, including the live descendant (RFC 9700
    §4.14.2).
  - **PKCE `plain` can no longer slip through stricter-dev by omitting the
    method**: per RFC 7636 §4.3 an absent `code_challenge_method` defaults
    to `plain`; the method is now normalized before validation, and unknown
    methods are rejected at the authorization endpoint (§4.4.1).
  - **`require_pkce` is persisted**: it is now read from and written to
    `settings.yaml` (oauth section), so `update_settings` → `save_config` →
    `reload_config` no longer silently reverts it.
  - **The token response reports the scope actually granted** (RFC 6749
    §5.1) instead of a hardcoded `"openid"`; when no scope was involved the
    parameter is omitted, and a narrowed refresh reports the narrowed scope.
- The token endpoint validates `exp` and `extra` before the grant dispatch:
  with rotation enabled, a malformed value can no longer consume the refresh
  token without delivering its replacement (the last tradeoff noted in the
  #56 review). Validation is semantic, not just syntactic: `extra` must be a
  JSON object (a scalar/array used to raise a `TypeError` 500 later) and
  `exp` must be an integer within the same `1..1440` bounds the Settings
  model enforces (non-numeric values used to be an unhandled `ValueError`
  500; astronomical ones an `OverflowError` 500).
- Thread-safety hardening for shared in-memory state (#43): the
  authorization code store now performs its check-then-mark sequence under a
  lock (one-time use can no longer be defeated by concurrent redemptions),
  device codes are claimed/transitioned atomically and pruned when expired,
  and the lazily-created service singletons (config, token, crypto, audit,
  auth codes) use double-checked locking so concurrent first access creates
  exactly one instance.
- The MCP `get_oidc_discovery` tool now returns the exact same document as the
  HTTP `/.well-known/openid-configuration` endpoint (#40). Both build it via a
  new shared helper (`services.discovery.build_discovery_document`), so the
  MCP tool now advertises `claims_supported` (including `azp`),
  `response_types_supported`, `id_token_signing_alg_values_supported`,
  `code_challenge_methods_supported` and the endpoint auth methods. The
  two documents can no longer drift apart.
- Discovery no longer advertises the `token` response type (#41): the implicit
  flow was never implemented (`/authorize` only accepts `response_type=code`)
  and is deprecated by the OAuth 2.0 Security BCP, so advertising it misled
  clients. `response_types_supported` is now `["code"]`.

### Documentation
- The MCP tools tables in the README and `docs/MCP_WORKFLOW.md` now list all
  24 tools (#44, #48); the README was missing `create_client`,
  `update_client`, `delete_client`, `update_user`, `update_settings` and
  `save_config`.

## [2.1.0] - 2026-05-26

### Added
- ID Tokens are now issued for the **password** and **device** (RFC 8628) grants
  when `openid` scope is requested, not just `authorization_code` (#36). These
  grants authenticate an end-user, so an ID Token is meaningful; `client_credentials`
  still never emits one (no end-user).

### Fixed
- Friendlier loading of client `additional_audiences` from `settings.yaml` (#35):
  a scalar value (`additional_audiences: api://x`) is coerced to a one-element list,
  and an unsupported shape (e.g. a non-string item) now fails with a clear,
  client-scoped error instead of an opaque Pydantic `ValidationError` at startup.
- Minor hardening/polish from the #32 review (#37): `OAuthClient` now validates on
  direct attribute assignment (`validate_assignment`), discovery advertises `azp` in
  `claims_supported`, and the MCP `_normalize_audiences` rejects falsy non-list inputs
  instead of silently returning an empty list.

### Security
- Harden the ID Token vs access-token boundary (#34). The resource audience
  (`oauth.audience`) is now filtered out of the ID Token `aud` even if a client
  lists it in `additional_audiences`, and every token carries a `token_use`
  marker (`access` / `id` / `refresh`). `/userinfo` rejects tokens marked as ID or
  refresh tokens and `/introspect` reports ID Tokens as inactive, so an ID Token can
  no longer be spent as an access token. (Refresh tokens stay introspectable per
  RFC 7662.)

## [2.0.0] - 2026-05-25

### Changed
- **ID Token `aud`** now contains the requesting client's `client_id`, as required by
  OpenID Connect Core 1.0 §2 (was previously the static `oauth.audience`). This makes
  it possible to test multiple clients and brings nanoidp in line with the OIDC spec.
  - **Breaking:** relying parties that validated the ID Token `aud` against the old
    static `oauth.audience` value must now expect their own `client_id`.
  - The **access token** `aud` is unchanged and still reflects `oauth.audience`
    (the resource audience, per RFC 9068 §2.2).

### Added
- `additional_audiences` per-client setting: extra audiences appended to the ID Token
  `aud`. If this produces more than one distinct audience value, `aud` is emitted as an
  array and nanoidp also emits `azp` equal to the `client_id`, so clients can test
  authorized-party handling.

## [1.4.0] - 2026-04-28

### Added
- Environment variable substitution in `settings.yaml` using `${NAME}` / `${NAME:default}` syntax
- `PORT` env var honoured in the Docker image via shell expansion in `CMD`

## [1.3.3] - 2026-04-22
  
### Fixed
- Return `id_token` in /token response for Authorization Code Flow when `openid` scope is requested, as required by OIDC Core spec (Section 3.1.3.3)
- Include `nonce` claim in `id_token` when provided by the client

### Changed
- Use `pyproject.toml` as single source of truth for version number
- Remove outdated version label from Dockerfile

## [1.3.2] - 2026-03-27

### Fixed
- Token endpoint now rejects requests when `client_id` cannot be determined from either the request body or the `Authorization` header
- Token endpoint now rejects requests where `client_id` in the body conflicts with the authenticated client in the `Authorization` header

### Added
- Tests for client_id mismatch and missing client_id edge cases

## [1.3.1] - 2026-03-26

### Fixed
- Allow authorization code flow without `Authorization` header for PKCE public clients (RFC 6749 §2.1)
  - Libraries like authlib send `client_id` in the request body instead of the header when no client secret exists
  - Auth header validation is now only enforced for grant types other than `authorization_code`

### Added
- Test for PKCE plain flow without auth header (`test_pkce_plain_flow_no_auth_header`)

## [1.3.0] - 2026-03-25

### Added
- GitHub Actions workflow to build and publish Docker images to GitHub Container Registry (GHCR)
  - Triggered on version tags (`v*`), builds multi-platform images (`linux/amd64`, `linux/arm64`)
  - `latest` tag published only for non-prerelease versions
- Docker usage instructions in README (`docker pull` and `docker run` examples)

### Changed
- Dockerfile healthcheck switched from Python `urllib` to `curl` for Podman compatibility and reduced overhead
- Updated `actions/checkout` from v4 to v6 in publish workflow

## [1.2.3] - 2026-03-03

### Fixed
- Dockerfile and docker-compose.yml: replaced `curl` with Python's `urllib` for healthcheck: avoids adding `curl` as a system dependency in the image

### Docs
- Added mascotte/logo images to the project

## [1.2.2] - 2026-01-19

### Added
- New `strict_saml_binding` setting to enforce SAML 2.0 binding compliance
  - When `false` (default): lenient mode accepts GET with uncompressed data (useful for debugging)
  - When `true`: strict mode rejects non-compliant requests per SAML spec
- Setting exposed in UI (Settings page), REST API (`/api/config`), and MCP server
- Exclusive C14N (`exc_c14n`) is now the default XML canonicalization algorithm
  - Standard for SAML 2.0 signatures, handles namespace isolation correctly
  - Available algorithms: `exc_c14n` (Exclusive C14N 1.0, default), `c14n` (C14N 1.0), `c14n11` (C14N 1.1)
- UI select dropdown for C14N algorithm in Settings page
- `strict_saml_binding` and `verbose_logging` now persist correctly on save/reload
- Comprehensive E2E test coverage for all SAML flows in `test_agent.py`:
  - `test_saml_metadata_bindings` - verifies both HTTP-POST and HTTP-Redirect advertised
  - `test_saml_sso_post_binding` - SP-initiated SSO with HTTP-POST (InResponseTo verification)
  - `test_saml_sso_redirect_binding` - SP-initiated SSO with HTTP-Redirect (InResponseTo verification)
  - `test_saml_idp_initiated_not_supported` - documents IdP-initiated SSO is not supported
  - `test_saml_strict_binding_mode` - tests strict/lenient binding behavior
  - `test_saml_attribute_query_verification` - verifies actual attributes returned
- Unit tests for inline login flow (`test_inline_login_flow_preserves_post/redirect_binding`)
- Unit test for strict mode + inline login (`test_strict_mode_inline_login_preserves_redirect_binding`)
- Unit test for Exclusive C14N configuration (`test_c14n_algorithm_configurable_to_exclusive`)

### Fixed
- SAML SSO now correctly handles both HTTP-POST and HTTP-Redirect bindings
- Parser always tries DEFLATE decompression first, falls back to raw XML (handles all edge cases)
- Strict mode now works with inline login by passing original HTTP verb via hidden field
  - Fixes: GET compressed → login form → POST would fail in strict mode
  - Stateless: no server-side session needed, works in CI/CD pipelines
- Explicit `|e` escape filter in login template hidden fields (XSS defense-in-depth)
- Normalized `original_verb` handling (uppercase, validated to GET/POST)
- Quick-fill username buttons use `tojson` filter to handle special characters safely

## [1.2.1] - 2026-01-16

### Fixed
- SAML SSO now correctly handles HTTP-POST binding (uncompressed SAMLRequest)
- Previously, `_parse_saml_request` unconditionally attempted DEFLATE decompression, causing parsing to fail for POST requests
- Now uses HTTP method to determine binding type: GET = HTTP-Redirect (compressed), POST = HTTP-POST (uncompressed)

### Changed
- E2E test agent now verifies actual SAML parsing (InResponseTo matching) instead of just endpoint availability
- Added separate tests for HTTP-POST and HTTP-Redirect bindings in `test_agent.py`

### Changed (Architecture)
- **Inline login for SAML SSO**: `/saml/sso` now shows login form directly instead of redirecting to `/login`
  - This preserves SAML binding context naturally (no redirect = no method change)
  - Follows the pattern used by Keycloak and other IdPs
  - Removes the complex edge cases caused by redirect-based login
- `/login` endpoint simplified - now only used for direct web UI access, not SAML flows
- Login form now posts to current URL (no hardcoded action) - works for both `/login` and `/saml/sso`

### Changed
- SAML metadata now advertises both HTTP-POST and HTTP-Redirect bindings for SingleSignOnService
- Audit stats now track SAML SSO and Attribute Query separately (`saml_sso_requests`, `saml_attribute_queries`)
- Dashboard shows combined SAML total with SSO/AttrQuery breakdown
- E2E test agent expanded to 35 tests (was 28), now covering all SAML flows with parsing verification

## [1.2.0] - 2026-01-14

### Added
- Configurable `verbose_logging` setting to control sensitive data in logs
- `verbose_logging` exposed in MCP `get_settings` and `update_settings` tools
- `logging.verbose_logging` exposed in REST API `/api/config` endpoint
- MCP tests (`tests/test_mcp.py`) with 8 tests for MCP functionality
- Verbose logging test in E2E test agent

### Changed
- Replaced deprecated `defusedxml.lxml` with native lxml secure parser for XXE protection
- Added `html.escape` for XSS prevention in SAML responses
- Audit logging now respects `verbose_logging` setting (usernames/client_ids only when enabled)

### Security
- XXE (XML External Entity) protection using secure lxml parser configuration
- XSS prevention in SAML response forms
- Configurable sensitive data logging (verbose_logging defaults to true for dev convenience)

## [1.1.1] - 2026-01-14

### Added
- Configurable XML canonicalization algorithm via `saml.c14n_algorithm` setting

## [1.1.0] - 2026-01-14

### Added
- Configurable SAML response signing via `saml.sign_responses` setting
- UI toggle for SAML signing in Settings page (`/settings`)
- `sign_responses` exposed in `/api/config` endpoint
- Test agent (`examples/test_agent.py`) for comprehensive endpoint testing

### Changed
- SAML SSO and AttributeQuery endpoints now respect `sign_responses` configuration
- Changed default XML canonicalization to C14N 1.0 for maximum compatibility
- Updated documentation with SAML signing configuration instructions

## [1.0.0] - 2025-12-04

### Added
- Initial release
- OAuth2/OIDC support (Authorization Code, Password, Client Credentials, Refresh Token, Device Flow)
- PKCE support (S256 and plain methods)
- Token Introspection (RFC 7662) and Revocation (RFC 7009)
- OIDC Logout / End Session endpoint
- Device Authorization Grant (RFC 8628)
- SAML 2.0 SSO and AttributeQuery endpoints with signed assertions
- MCP Server integration for Claude Code
- Web UI for configuration (users, clients, settings, keys, audit log)
- YAML-based configuration
- Attribute-based access control with configurable authority prefixes
- Audit logging
- Docker support
- Security profiles (`dev` and `stricter-dev`)
- Key rotation with JWKS support for multiple keys
- External key import support

[2.8.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.7.0...v2.8.0
[2.7.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.3...v1.4.0
[1.3.3]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.3...v1.3.0
[1.2.3]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/cdelmonte-zg/nanoidp/releases/tag/v1.0.0
